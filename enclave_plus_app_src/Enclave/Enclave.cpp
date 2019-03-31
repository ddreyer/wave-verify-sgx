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
        enclave_print("Failed to unseal key");
		key_and_iv = malloc(sizeof(struct key_iv));
		key_and_iv->key = (const unsigned char *) malloc(16);
		key_and_iv->iv = (const unsigned char *) malloc(12);
		return SGX_SUCCESS;
    }
	enclave_print("unsealing, key");
	enclave_print(key_and_iv->key);
	enclave_print("iv:");
	enclave_print(key_and_iv->iv);
	return SGX_SUCCESS;
	
}

sgx_status_t ecall_provision_key(char *k, char *v) {
	enclave_print("provisioning:key");
	enclave_print(k);
	enclave_print("iv:");
	enclave_print(v);
    memcpy(key_and_iv->key, k, 16);
	memcpy(key_and_iv->iv, v, 12);
	size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(struct key_iv);
	free(sealed_key_iv);
    sealed_key_iv = (uint8_t *) malloc(sealed_size);
    sgx_status_t status = sgx_seal_data(0, NULL, sizeof(struct key_iv), 
        (uint8_t *) key_and_iv, sealed_size, (sgx_sealed_data_t *) sealed_key_iv);
    if (status != SGX_SUCCESS) {
		enclave_print("Failed to seal key");
		return status;
	}
	return SGX_SUCCESS;
	
}

// TODO: check attestations and entities for expiry/revocation
long ecall_verify_proof(char *proof_cipher, size_t proof_cipher_size, char *subject, 
	size_t subj_size, char *policyDER, size_t policyDER_size) 
{
    enclave_print("Inside enclave to verify the proof");
	string returnStr = string("verifying proof succeeded");
	WaveWireObject_t *wwoPtr = 0;
    wwoPtr = (WaveWireObject_t *) unmarshal((uint8_t *) proof_cipher, proof_cipher_size, wwoPtr, &asn_DEF_WaveWireObject);
    if (wwoPtr == nullptr) {
        returnStr = string("failed to unmarshal wire object");
        goto decryptReturn;
    }

	WaveEncryptedMessage_t *msg = 0;
	MessageKeyWR1_t *wr1key = 0;
	ANY_t type = wwoPtr->encoding.choice.single_ASN1_type;
	msg = (WaveEncryptedMessage_t *) unmarshal(type.buf, type.size, msg, &asn_DEF_WaveEncryptedMessage);
	asn_DEF_WaveWireObject.op->free_struct(&asn_DEF_WaveWireObject, wwoPtr, ASFM_FREE_EVERYTHING);
	if (msg == nullptr) {
		returnStr = string("failed to unmarshal encrypted message");
		goto decryptReturn;
	}

	enclave_print("about to start decrypting:key");
	enclave_print(key_and_iv->key);
	enclave_print("iv:");
	enclave_print(key_and_iv->iv);
	enclave_print("Decrypting proof");

	WaveEncryptedMessage_t::WaveEncryptedMessage__keys keys = msg->keys;
	EXTERNAL_t *k = keys.list.array[0];
	type = k->encoding.choice.single_ASN1_type;
	wr1key = (MessageKeyWR1_t *) unmarshal(type.buf, type.size, wr1key, &asn_DEF_MessageKeyWR1);
	if (wr1key == nullptr) {
		returnStr = string("failed to unmarshal wr1key");
		goto decryptReturn;
	}

	EVP_CIPHER_CTX *kctx;
	int outlen;
	unsigned char envelopeKey[28];
	if (!(kctx = EVP_CIPHER_CTX_new())) {
		returnStr = string("error initializing crypto");
		goto decryptReturn;
	}
	if (1 != EVP_DecryptInit_ex(kctx, EVP_aes_128_gcm(), NULL, key_and_iv->key, key_and_iv->iv)) {
		returnStr = string("error initializing decryption");
		goto decryptReturn;
	}
	if (1 != EVP_DecryptUpdate(kctx, envelopeKey, &outlen, 
		(const unsigned char *) (wr1key->envelopeKey_ibe_BLS12381.buf+98), 28)) {
		returnStr = string("error decrypting envelope key");
		goto decryptReturn;
	}

	enclave_print("this is the envelope key");
	enclave_print(string((const char *) envelopeKey, 28).c_str());
	unsigned char envelopeDER[wr1key->envelope.size];
	if (1 != EVP_DecryptInit_ex(kctx, EVP_aes_128_gcm(), NULL, envelopeKey, envelopeKey+16)) {
		returnStr = string("error initializing decryption");
		goto decryptReturn;
	}
	if (1 != EVP_DecryptUpdate(kctx, envelopeDER, &outlen, 
		(const unsigned char *) wr1key->envelope.buf, wr1key->envelope.size)) {
		returnStr = string("error decrypting envelope");
		goto decryptReturn;
	}
	enclave_print("this is the envelope DER");
	enclave_print(string((const char *) envelopeDER, 32).c_str());

	MessageKeyWR1Envelope_t *envelope = 0;
	envelope = (MessageKeyWR1Envelope_t *) unmarshal((uint8_t *) envelopeDER, wr1key->envelope.size, envelope, &asn_DEF_MessageKeyWR1Envelope);
	if (envelope == nullptr) {
		returnStr = string("failed unmarshaling envelope");
		goto decryptReturn;
	}

	unsigned char decrypted[msg->contents.size];
	// if (1 != EVP_DecryptInit_ex(kctx, EVP_aes_128_gcm(), NULL, envelopeKey, envelopeKey+16)) {
	// 	returnStr = string("error initializing decryption");
	// 	goto decryptReturn;
	// }
	// if (1 != EVP_DecryptUpdate(kctx, envelopeDER, &outlen, 
	// 	(const unsigned char *) msg->contents.buf, msg->contents.size)) {
	// 	returnStr = string("error decrypting proof");
	// 	goto decryptReturn;
	// }
	EVP_CIPHER_CTX_free(kctx);
	asn_DEF_MessageKeyWR1.op->free_struct(&asn_DEF_MessageKeyWR1, wr1key, ASFM_FREE_EVERYTHING);
	asn_DEF_MessageKeyWR1Envelope.op->free_struct(&asn_DEF_MessageKeyWR1Envelope, envelope, ASFM_FREE_EVERYTHING);
	asn_DEF_WaveEncryptedMessage.op->free_struct(&asn_DEF_WaveEncryptedMessage, msg, ASFM_FREE_EVERYTHING);

	return -1;
	// gofunc: VerifyProof
	auto [finalsubject, superset_ns, supersetStatements, expiry, pathpolicies] = 
		verify_rtree_proof((char *) decrypted, outlen);
	if (expiry == -1) {
		enclave_print("\nerror in verify rtree proof");
		return -1;
	} else if (expiry == -2) {
		enclave_print("\nerror unmarshaling proof wire object, most likely a decryption error");
		return -2;
	}
	// Check that proof policy is a superset of required policy
	// gofunc: IsSubsetOf
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

decryptReturn:
	enclave_print(returnStr.c_str());
	asn_DEF_MessageKeyWR1.op->free_struct(&asn_DEF_MessageKeyWR1, wr1key, ASFM_FREE_EVERYTHING);
	asn_DEF_MessageKeyWR1Envelope.op->free_struct(&asn_DEF_MessageKeyWR1Envelope, envelope, ASFM_FREE_EVERYTHING);
	asn_DEF_WaveEncryptedMessage.op->free_struct(&asn_DEF_WaveEncryptedMessage, msg, ASFM_FREE_EVERYTHING);
	return -2;
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
