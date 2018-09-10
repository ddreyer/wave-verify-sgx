#ifndef __VERIFY_H_INCLUDED__
#define __VERIFY_H_INCLUDED__

#include "Enclave_t.h"

#include "objects.h"
// #include "aes-gcm/gcm.h"
// #include "ed25519/src/ed25519.h"
// #include "hash-library/keccak.h"

#include <fstream>
#include <streambuf>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include <algorithm>
#include <string>
#include <list>
#include <unordered_map>
#include <vector>

class EntityItem {
private:
    WaveEntity *entity;
    std::string entityDer;
public:
    EntityItem(WaveEntity *entity, std::string entityDer);
    WaveEntity * get_entity();
    std::string get_der();
};

class AttestationItem {
private:
    WaveAttestation *attestation;
    AttestationVerifierBody decryptedBody;
public:
    AttestationItem(WaveAttestation *att, AttestationVerifierBody dBody);
    WaveAttestation * get_att();
    AttestationVerifierBody get_body();
};

class RTreeStatementItem {
private:
    RTreeStatement::permissionSet permissionSet;
    std::list<std::string> permissions;
    std::string intersectionResource;
public:
    RTreeStatementItem(RTreeStatement::permissionSet pSet, std::list<std::string> perms, std::string iResource);
    RTreeStatement::permissionSet get_permissionSet();
    std::list<std::string> get_permissions();
    std::string get_interResource();
};

class ASN1Exception {
private:
    int code;
public:
    ASN1Exception(int asn1_code);
    ASN1Exception(const ASN1Exception & that);
    int get_code() const;
};

int verify(std::string pemContent);

#endif