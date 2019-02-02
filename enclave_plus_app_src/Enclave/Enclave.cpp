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
// TODO: check attestations and entities for expiry/revocation
long ecall_verify_proof(char *proof_cipher, size_t proof_cipher_size, char *subject, 
	size_t subj_size, char *policyDER, size_t policyDER_size) 
{
    enclave_print("Inside enclave to verify the proof");
	/* First, get symmetric key to decrypt */
	/* TODO: sign message? */
	/* TODO: use correct key */
	// enclave_print("Decrypting proof\n");
	// sgx_ra_key_128_t k;
	// sgx_status_t status = sgx_ra_get_keys(ctx, SGX_RA_KEY_SK, &k);
	// sgx_ra_key_128_t *k = (sgx_ra_key_128_t *)"0123456789012345";
	// /* TODO: fix IV */
	// unsigned char *iv = (unsigned char *)"0123456789012345";
	// EVP_CIPHER_CTX *kctx;
	// int outlen, ret;
	// unsigned char decrypted[proof_cipher_size];
	// if (!(kctx = EVP_CIPHER_CTX_new())) {
	// 	enclave_print("error initializing crypto");
	// 	return SGX_ERROR_UNEXPECTED;
	// }
	// /* Select cipher */
	// if (1 != EVP_DecryptInit_ex(kctx, EVP_aes_128_gcm(), NULL, 
	// 	(const unsigned char *) k, iv)) {
	// 	enclave_print("error initializing decryption");
	// 	return SGX_ERROR_UNEXPECTED;
	// }
	// /* Decrypt ciphertext */
	// if (1 != EVP_DecryptUpdate(kctx, decrypted, &outlen, 
	// 	(const unsigned char *) proof_cipher, cipher_size)) {
	// 	enclave_print("error decrypting proof");
	// 	return SGX_ERROR_UNEXPECTED;
	// }
	// EVP_CIPHER_CTX_free(kctx);
	// enclave_print("proof decryption succeeded");

	// gofunc: VerifyProof
	auto [finalsubject, superset_ns, supersetStatements, expiry, pathpolicies] = 
		verify_rtree_proof(proof_cipher, proof_cipher_size);
	if (expiry == -1) {
		enclave_print("\nerror in verify rtree proof");
		return -1;
	}

	// Check that proof policy is a superset of required policy
	// gofunc: IsSubsetOf
	string returnStr = string("verifying proof succeeded");;
	RTreePolicy_t *policy = 0;
	if (policyDER != nullptr) {
		enclave_print("comparing proof policy to required policy");
		WaveWireObject_t *wwoPtr = 0;
    	wwoPtr = (WaveWireObject_t *) unmarshal((uint8_t *) policyDER, policyDER_size, wwoPtr, &asn_DEF_WaveWireObject);
		if (wwoPtr == nullptr) {
			returnStr = string("failed to unmarshal wave wire object");
			goto errorReturn;
		}
		ANY_t type = wwoPtr->encoding.choice.single_ASN1_type;
		policy = (RTreePolicy_t *) unmarshal(type.buf, type.size, policy, &asn_DEF_RTreePolicy);
		asn_DEF_WaveWireObject.op->free_struct(&asn_DEF_WaveWireObject, wwoPtr, ASFM_FREE_EVERYTHING);
		if (policy == nullptr) {
           	returnStr = string("unexpected error unmarshaling policy");
			goto errorReturn;
        }

		OCTET_STRING_t *lhs_ns = HashSchemeInstanceFor(policy);
		// not doing multihash
		if (OCTET_STRING_compare(&asn_DEF_OCTET_STRING, superset_ns, lhs_ns)) {
			asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, lhs_ns, ASFM_FREE_EVERYTHING);
			returnStr = string("proof is well formed but namespaces don't match");
			goto errorReturn;
		}
		asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, lhs_ns, ASFM_FREE_EVERYTHING);

		RTreePolicy_t::RTreePolicy__statements policyStatements = policy->statements;
		int lhs_index = 0;
		while (lhs_index < policyStatements.list.count) {
			RTreeStatementItem *leftStatement = statementToItem(policyStatements.list.array[lhs_index]);
			lhs_index++;
			int superset_index = 0;
			bool superset = false;
			while (superset_index < supersetStatements->size()) {
				RTreeStatementItem *supersetStatement = supersetStatements->at(superset_index);
				superset_index++;
				if (isStatementSupersetOf(leftStatement, supersetStatement)) {
					superset = true;
					break;
				}
			}
			delete leftStatement;
			if (!superset) {
				returnStr = string("proof is well formed but grants insufficient permissions");
				goto errorReturn;
			}
		}
	}
	enclave_print("proof grants sufficient permissions\n");

	// Check subject
	if (memcmp(subject, finalsubject->buf, subj_size)) {
		returnStr = string("proof is well formed but subject does not match");
		goto errorReturn;
	}
	enclave_print("subjects match\n");
	goto Return;

errorReturn:
	expiry = -1;
Return:
	enclave_print(returnStr.c_str());
    asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, finalsubject, ASFM_FREE_EVERYTHING);
    asn_DEF_RTreePolicy.op->free_struct(&asn_DEF_RTreePolicy, policy, ASFM_FREE_EVERYTHING);
	asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, superset_ns, ASFM_FREE_EVERYTHING);
	for (int i = 0; i < pathpolicies->size(); i++) {
        asn_DEF_RTreePolicy.op->free_struct(&asn_DEF_RTreePolicy, pathpolicies->at(i), ASFM_FREE_EVERYTHING);
    }
	delete pathpolicies;
	for (int i = 0; i < supersetStatements->size(); i++) {
		delete supersetStatements->at(i);
	}
	delete supersetStatements;
	return expiry;
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
