/*

Copyright 2018 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/

#ifndef _WIN32
#include "../config.h"
#endif
#include "Enclave_t.h"
#include <string.h>
#include <sgx_utils.h>
#include <sgx_tae_service.h>
#include <sgx_tkey_exchange.h>
#include <sgx_tcrypto.h>
#include "sgx_tseal.h"

#include <verify.h>

#define PSE_RETRIES	5	/* Arbitrary. Not too long, not too short. */

/* data for enclave's asymmetric key */
uint8_t *sealed_key;

/*----------------------------------------------------------------------
 * WARNING
 *----------------------------------------------------------------------
 *
 * End developers should not normally be calling these functions
 * directly when doing remote attestation:
 *
 *    sgx_get_ps_sec_prop()
 *    sgx_get_quote()
 *    sgx_get_quote_size()
 *    sgx_get_report()
 *    sgx_init_quote()
 *
 * These functions short-circuits the RA process in order
 * to generate an enclave quote directly!
 *
 * The high-level functions provided for remote attestation take
 * care of the low-level details of quote generation for you:
 *
 *   sgx_ra_init()
 *   sgx_ra_get_msg1
 *   sgx_ra_proc_msg2
 *
 *----------------------------------------------------------------------
 */

/*
 * This doesn't really need to be a C++ source file, but a bug in 
 * 2.1.3 and earlier implementations of the SGX SDK left a stray
 * C++ symbol in libsgx_tkey_exchange.so so it won't link without
 * a C++ compiler. Just making the source C++ was the easiest way
 * to deal with that.
 */

// sgx_status_t get_report(sgx_report_t *report, sgx_target_info_t *target_info)
// {
// #ifdef SGX_HW_SIM
// 	return sgx_create_report(NULL, NULL, report);
// #else
// 	return sgx_create_report(target_info, NULL, report);
// #endif
// }

// size_t get_pse_manifest_size ()
// {
// 	return sizeof(sgx_ps_sec_prop_desc_t);
// }

// sgx_status_t get_pse_manifest(char *buf, size_t sz)
// {
// 	sgx_ps_sec_prop_desc_t ps_sec_prop_desc;
// 	sgx_status_t status= SGX_ERROR_SERVICE_UNAVAILABLE;
// 	int retries= PSE_RETRIES;

// 	do {
// 		status= sgx_create_pse_session();
// 		if ( status != SGX_SUCCESS ) return status;
// 	} while (status == SGX_ERROR_BUSY && retries--);
// 	if ( status != SGX_SUCCESS ) return status;

// 	status= sgx_get_ps_sec_prop(&ps_sec_prop_desc);
// 	if ( status != SGX_SUCCESS ) return status;

// 	memcpy(buf, &ps_sec_prop_desc, sizeof(ps_sec_prop_desc));

// 	sgx_close_pse_session();

// 	return status;
// }

sgx_status_t enclave_ra_init(sgx_ec256_public_t key, int b_pse,
	sgx_ra_context_t *ctx, sgx_status_t *pse_status)
{
	sgx_status_t ra_status;

	/*
	 * If we want platform services, we must create a PSE session 
	 * before calling sgx_ra_init()
	 */

	if ( b_pse ) {
		int retries= PSE_RETRIES;
		do {
			*pse_status= sgx_create_pse_session();
			if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
		} while (*pse_status == SGX_ERROR_BUSY && retries--);
		if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
	}

	ra_status= sgx_ra_init(&key, b_pse, ctx);

	if ( b_pse ) {
		int retries= PSE_RETRIES;
		do {
			*pse_status= sgx_create_pse_session();
			if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
		} while (*pse_status == SGX_ERROR_BUSY && retries--);
		if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
	}

	return ra_status;
}

sgx_status_t ecall_create_keys() {
	BIGNUM *bn = BN_new();
	if (bn == NULL) {
		return SGX_ERROR_UNEXPECTED;
	}
	int ret = BN_set_word(bn, RSA_F4);
	if (!ret) {
		return SGX_ERROR_UNEXPECTED;
	}

	RSA *keypair = RSA_new();
	if (keypair == NULL) {
		return SGX_ERROR_UNEXPECTED;
	}
	ret = RSA_generate_key_ex(keypair, 4096, bn, NULL);
	if (!ret) {
		return SGX_ERROR_UNEXPECTED;
	}

	// EVP_PKEY *evp_pkey = EVP_PKEY_new();
	// if (evp_pkey == NULL) {
	// 	return SGX_ERROR_UNEXPECTED;
	// }
	// EVP_PKEY_assign_RSA(evp_pkey, keypair);
	
	// size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(evp_pkey_st);
    // sealed_key = (uint8_t *) malloc(sealed_size);
    // sgx_status_t status = sgx_seal_data(0, NULL, sizeof(evp_pkey_st), 
    //     (uint8_t *) evp_pkey, sealed_size, (sgx_sealed_data_t *) sealed_key);

	BN_free(bn);
	// EVP_PKEY_free(evp_pkey);
	RSA_free(keypair);

    // return status;
}

/* Enclave message verification */
sgx_status_t ecall_verify_proof(char *cipher, size_t cipher_size, sgx_ra_context_t ctx) 
{
    ocall_print("Enclave: Inside enclave to verify the proof");

	/* First, get symmetric key to decrypt */
	/* TODO: And verification key? check signature? */
	sgx_ra_key_128_t k;
	sgx_status_t status = sgx_ra_get_keys(ctx, SGX_RA_KEY_SK, &k);
	EVP_CIPHER_CTX *kctx;
	int outlen, ret;
	unsigned char decrypted[cipher_size];
	kctx = EVP_CIPHER_CTX_new();
	/* Select cipher */
	EVP_DecryptInit_ex(kctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
	/* Specify key and IV */
	EVP_DecryptInit_ex(kctx, NULL, NULL, (const unsigned char *) &k, (const unsigned char *) nonce);
	/* Decrypt plaintext */
	ret = EVP_DecryptUpdate(kctx, decrypted, &outlen, (const unsigned char *) cipher, cipher_size);
	EVP_CIPHER_CTX_free(kctx);
	if (!ret) {
		ocall_print("proof decryption failed");
		return SGX_ERROR_UNEXPECTED;
	}
	ocall_print("proof decryption succeeded");

    // verify proof
	if (verify(decrypted)) {
		return SGX_ERROR_UNEXPECTED;
	}
	ocall_print("verifying proof succeeded");
    return SGX_SUCCESS;
}

/*
 * Return a SHA256 hash of the requested key. KEYS SHOULD NEVER BE
 * SENT OUTSIDE THE ENCLAVE IN PLAIN TEXT. This function let's us
 * get proof of possession of the key without exposing it to untrusted
 * memory.
 */

sgx_status_t enclave_ra_get_key_hash(sgx_status_t *get_keys_ret,
	sgx_ra_context_t ctx, sgx_ra_key_type_t type, sgx_sha256_hash_t *hash)
{
	sgx_status_t sha_ret;
	sgx_ra_key_128_t k;

	// First get the requested key which is one of:
	//  * SGX_RA_KEY_MK 
	//  * SGX_RA_KEY_SK
	// per sgx_ra_get_keys().

	*get_keys_ret= sgx_ra_get_keys(ctx, type, &k);
	if ( *get_keys_ret != SGX_SUCCESS ) return *get_keys_ret;

	/* Now generate a SHA hash */

	sha_ret= sgx_sha256_msg((const uint8_t *) &k, sizeof(k), 
		(sgx_sha256_hash_t *) hash); // Sigh.

	/* Let's be thorough */

	memset(k, 0, sizeof(k));

	return sha_ret;
}

sgx_status_t enclave_ra_close(sgx_ra_context_t ctx)
{
	sgx_status_t ret;
	ret = sgx_ra_close(ctx);
	return ret;
}
