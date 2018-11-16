package main

/*
#include "enclave_app.h"
#cgo CFLAGS: -I. -I../utils -I/home/sgx/linux-sgx/linux/installer/bin/sgxsdk/include
#cgo LDFLAGS: -ltee -L.
*/
import "C"

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"unsafe"
)

const WAVEMQPermissionSet = "\x1b\x20\x14\x33\x74\xb3\x2f\xd2\x74\x39\x54\xfe\x47\x86\xf6\xcf\x86\xd4\x03\x72\x0f\x5e\xc4\x42\x36\xb6\x58\xc2\x6a\x1e\x68\x0f\x6e\x01"
const WAVEMQPublish = "publish"

func main() {
	contents, err := ioutil.ReadFile("proof0.2.2.pem")
	if err != nil {
		fmt.Printf("could not read file %q: %v\n", "proof.pem", err)
	}
	block, _ := pem.Decode(contents)
	if block == nil {
		fmt.Printf("file %q is not a PEM file\n", "proof.pem")
	}
	proofPointer := unsafe.Pointer(&block.Bytes[0])
	proofDER := (*C.char)(proofPointer)
	proofSize := len(block.Bytes)
	fmt.Println(proofSize)
	// defer C.free(proofPointer)
	// ehash := iapi.HashSchemeInstanceFromMultihash([]byte("hello"))
	// if !ehash.Supported() {
	// 	fmt.Printf("hash not supported")
	// }
	// ext := ehash.CanonicalForm()
	// pol := serdes.RTreePolicy{
	// 	Namespace: *ext,
	// 	Statements: []serdes.RTreeStatement{
	// 		{
	// 			PermissionSet: asn1.NewExternal([]byte(WAVEMQPermissionSet)),
	// 			Permissions:   []string{WAVEMQPublish},
	// 			Resource:      "temp",
	// 		},
	// 	},
	// }
	// polBytes, err := asn1.Marshal(pol)
	// if err != nil {
	// 	fmt.Printf("error marshaling", err)
	// }
	// polEnc := base64.StdEncoding.EncodeToString(polBytes)
	// polDER := C.CString(polEnc)
	// defer C.free(unsafe.Pointer(polDER))

	// presp, err := am.wave.VerifyProof(ctx, &eapipb.VerifyProofParams{
	// 	ProofDER: m.ProofDER,
	// 	Subject:  m.Tbs.SourceEntity,
	// 	RequiredRTreePolicy: &eapipb.RTreePolicy{
	// 		Namespace: m.Tbs.Namespace,
	// 		Statements: []*eapipb.RTreePolicyStatement{
	// 			{
	// 				PermissionSet: []byte(WAVEMQPermissionSet),
	// 				Permissions:   []string{WAVEMQPublish},
	// 				Resource:      m.Tbs.Uri,
	// 			},
	// 		},
	// 	},
	// })

	// subj := base64.StdEncoding.EncodeToString([]byte{'t'})
	// subject := C.CString(subj)
	// defer C.free(unsafe.Pointer(subject))
	// C.init_and_verify(proofDER, C.ulong(proofSize), subject, C.ulong(len(subj)), polDER, C.ulong(len(polEnc)))
	C.verify(proofDER, C.ulong(proofSize), nil, 0, nil, 0)
	fmt.Println("hello")
	C.init_enclave()
	// C.init_and_verify(proofDER, C.ulong(proofSize), nil, 0, nil, 0)
	C.verify(proofDER, C.ulong(proofSize), nil, 0, nil, 0)
}
