package main

/*
#include "enclave_app.h"
#cgo CFLAGS: -I. -I../utils -I/home/sgx/linux-sgx/linux/installer/bin/sgxsdk/include
#cgo LDFLAGS: -ltee -L.
*/
import "C"

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"unsafe"
)

func main() {
	contents, err := ioutil.ReadFile("proof0.2.2.pem")
	if err != nil {
		fmt.Printf("could not read file %q: %v\n", "proof.pem", err)
	}
	block, _ := pem.Decode(contents)
	if block == nil {
		fmt.Printf("file %q is not a PEM file\n", "proof.pem")
	}
	encoded := base64.StdEncoding.EncodeToString(block.Bytes)
	n := len(encoded)
	proofDER := C.CString(encoded)
	defer C.free(unsafe.Pointer(proofDER))

	// pol := serdes.RTreePolicy{
	// 	Namespace: asn1.NewExternal([]byte("hello")),
	// 	Statements: []serdes.RTreeStatement{
	// 		{
	// 			PermissionSet: asn1.NewExternal([]byte(core.WAVEMQPermissionSet)),
	// 			Permissions:   []string{core.WAVEMQPublish},
	// 			Resource:      "temp",
	// 		},
	// 	},
	// }
	// polBytes, err := asn1.Marshal(pol)
	// if err != nil {
	// 	fmt.Printf("error marshaling", err)
	// }
	// polDER := C.CString(base64.StdEncoding.EncodeToString(polBytes))
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

	// subject := C.CString(base64.StdEncoding.EncodeToString())
	C.init_and_verify(proofDER, C.ulong(n), nil, 0, nil, 0)
}
