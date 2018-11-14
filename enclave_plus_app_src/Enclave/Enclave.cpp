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

sgx_status_t enclave_ra_init(sgx_ec256_public_t key, int b_pse,
	sgx_ra_context_t *ctx)
{
	return sgx_ra_init(&key, b_pse, ctx);
}

/* Enclave message verification */
sgx_status_t ecall_verify_proof(char *proof_cipher, size_t proof_cipher_size, char *subject, 
	size_t subj_size, char *policyDER, size_t policyDER_size) 
{
    ocall_print("Enclave: Inside enclave to verify the proof");
	/* First, get symmetric key to decrypt */
	/* TODO: sign message? */
	/* TODO: use correct key */
	// sgx_ra_key_128_t k;
	// sgx_status_t status = sgx_ra_get_keys(ctx, SGX_RA_KEY_SK, &k);
	// sgx_ra_key_128_t *k = (sgx_ra_key_128_t *)"0123456789012345";
	// /* TODO: fix IV */
	// unsigned char *iv = (unsigned char *)"0123456789012345";
	// EVP_CIPHER_CTX *kctx;
	// int outlen, ret;
	// unsigned char decrypted[proof_cipher_size];
	// if (!(kctx = EVP_CIPHER_CTX_new())) {
	// 	ocall_print("error initializing crypto");
	// 	return SGX_ERROR_UNEXPECTED;
	// }
	// /* Select cipher */
	// if (1 != EVP_DecryptInit_ex(kctx, EVP_aes_128_gcm(), NULL, 
	// 	(const unsigned char *) k, iv)) {
	// 	ocall_print("error initializing decryption");
	// 	return SGX_ERROR_UNEXPECTED;
	// }
	// /* Decrypt ciphertext */
	// if (1 != EVP_DecryptUpdate(kctx, decrypted, &outlen, 
	// 	(const unsigned char *) proof_cipher, cipher_size)) {
	// 	ocall_print("error decrypting proof");
	// 	return SGX_ERROR_UNEXPECTED;
	// }
	// EVP_CIPHER_CTX_free(kctx);
	// ocall_print("proof decryption succeeded");

	/* verify proof */
	RVerifyRTreeProof *resp = verify_rtree_proof((char *) proof_cipher);
	if (resp == nullptr) {
		return verify_error("error in verify rtree proof");
	}
	ocall_print("verify_rtree_proof succeeded");

	// Double check attestations


	if (policyDER != nullptr) {
		RTreePolicy_t *policy = 0;
		policy = (RTreePolicy_t *) unmarshal(policyDER, policyDER_size, policy, &asn_DEF_RTreePolicy);
        if (policy == nullptr) {
           	return verify_error("unexpected policy error");
        }

		// gofunc: IsSubsetOf
		OCTET_STRING_t *superset_ns = HashSchemeInstanceFor(&resp->get_policy());
		OCTET_STRING_t *lhs_ns = HashSchemeInstanceFor(policy);
		// not doing multihash
		if (OCTET_STRING_compare(&asn_DEF_OCTET_STRING, superset_ns, lhs_ns)) {
			return verify_error("proof is well formed but grants insufficient permissions");
		}

		
	}
	// Check subject
	OCTET_STRING_t *subj = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, subject, subj_size);
	if (OCTET_STRING_compare(&asn_DEF_OCTET_STRING, subj, &resp->get_subject())) {
		return verify_error("proof is well formed but subject does not match");
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
