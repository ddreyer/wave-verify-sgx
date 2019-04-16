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
#include <string.h>
#include <sgx_utils.h>
#include <sgx_tae_service.h>
#include <sgx_tkey_exchange.h>
#include <sgx_tcrypto.h>
#include <sgx_tseal.h>
#include "Enclave_t.h"
#include "verify.hpp"
#include "lqibe/lqibe.h"

// const unsigned char *key;
// const unsigned char *iv;
uint8_t *sealed_key_iv;
struct key_iv *key_and_iv;
struct key_iv {
	const unsigned char *key;
	const unsigned char *iv;
};

sgx_status_t enclave_ra_init(sgx_ec256_public_t key, int b_pse,
	sgx_ra_context_t *ctx)
{
	return sgx_ra_init(&key, b_pse, ctx);
}

sgx_status_t ecall_instantiate_key() {
    uint32_t plaintext_size = sizeof(struct key_iv);
    sgx_status_t status = sgx_unseal_data((sgx_sealed_data_t *) sealed_key_iv, NULL, NULL, 
        (uint8_t*) &key_and_iv, &plaintext_size);

    if (status != SGX_SUCCESS)
    {
        // verify_print("Failed to unseal key");
		key_and_iv = (key_iv *) malloc(sizeof(struct key_iv));
		key_and_iv->key = (const unsigned char *) malloc(16);
		key_and_iv->iv = (const unsigned char *) malloc(12);
		return SGX_SUCCESS;
    }
	verify_print("unsealing, key");
	verify_print(key_and_iv->key);
	verify_print("iv:");
	verify_print(key_and_iv->iv);
	return SGX_SUCCESS;
	
}

sgx_status_t ecall_provision_key(char *k, char *v) {
	verify_print("provisioning:key");
	verify_print(k);
	verify_print("iv:");
	verify_print(v);
    memcpy(key_and_iv->key, k, 16);
	memcpy(key_and_iv->iv, v, 12);
	size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(struct key_iv);
	free(sealed_key_iv);
    sealed_key_iv = (uint8_t *) malloc(sealed_size);
    sgx_status_t status = sgx_seal_data(0, NULL, sizeof(struct key_iv), 
        (uint8_t *) key_and_iv, sealed_size, (sgx_sealed_data_t *) sealed_key_iv);
    if (status != SGX_SUCCESS) {
		verify_print("Failed to seal key");
		return status;
	}
	return SGX_SUCCESS;
	
}

// TODO: check attestations and entities for expiry/revocation
long ecall_verify_proof(char *proof_cipher, size_t proof_cipher_size, char *subject, 
	size_t subj_size, char *policyDER, size_t policyDER_size) 
{
    verify_print("Inside enclave to verify the proof");

	verify_print("about to start decrypting:key");
	verify_print(key_and_iv->key);
	verify_print("iv:");
	verify_print(key_and_iv->iv);
	verify_print("Decrypting proof");


	// embedded_pairing_lqibe_ciphertext_get_marshalled_length();
	// embedded_pairing_lqibe_ciphertext_t ciphertext;
	// embedded_pairing_lqibe_ciphertext_unmarshal(&ciphertext, proof_cipher+2, true, false);
	// char symmetric[28];
	// embedded_pairing_lqibe_decrypt(symmetric, 28, &ciphertext, );


	// EVP_CIPHER_CTX *kctx;
	// int outlen;
	// unsigned char decrypted[proof_cipher_size-98];
	// if (!(kctx = EVP_CIPHER_CTX_new())) {
	// 	verify_print("error initializing crypto");
	// 	return -2;
	// }
	// if (1 != EVP_DecryptInit_ex(kctx, EVP_aes_128_gcm(), NULL, symmetric, symmetric[16])) {
	// 	verify_print("error initializing decryption");
	// 	return -2;
	// }
	// if (1 != EVP_DecryptUpdate(kctx, decrypted, &outlen, 
	// 	(const unsigned char *) proof_cipher+98, proof_cipher_size-98)) {
	// 	verify_print("error decrypting proof");
	// 	return -2;
	// }
	// EVP_CIPHER_CTX_free(kctx);

	// gofunc: VerifyProof
	return verifyProof(proof_cipher, proof_cipher_size, subject, subj_size, policyDER, policyDER_size);
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
