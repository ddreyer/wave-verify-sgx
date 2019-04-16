package verify

/*
#cgo CFLAGS: -I../../enclave_plus_app_src -I../../utils -I/home/sgx/linux-sgx/linux/installer/bin/sgxsdk/include
#cgo LDFLAGS: ${SRCDIR}/../../enclave_plus_app_src/libverify.so
#include "enclave_app.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"strconv"
	"time"
	"unsafe"

	"github.com/immesys/asn1"
	"github.com/immesys/wave/eapi/pb"
	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/serdes"
	"github.com/immesys/wave/wve"
)

// Initializes the enclave, returning the result
func InitEnclave() error {
	ret := C.init_enclave()
	if ret != 0 {
		return errors.New("failed to initialize enclave")
	}
	return nil
}

// Verifies a proof given the proof DER, expected subject, and required policy.
// Returns the proof expiry as a long and possibly any errors that may have occurred.
func VerifyProof(DER []byte, subjectHash []byte, reqPol *pb.RTreePolicy) (time.Time, error) {
	var statements []serdes.RTreeStatement
	for _, statement := range reqPol.Statements {
		phash := iapi.HashSchemeInstanceFromMultihash(statement.PermissionSet)
		if !phash.Supported() {
			return time.Now(), wve.Err(wve.InvalidParameter, "bad namespace")
		}
		pext := phash.CanonicalForm()
		s := serdes.RTreeStatement{
			PermissionSet: *pext,
			Permissions:   statement.Permissions,
			Resource:      statement.Resource,
		}
		statements = append(statements, s)
	}

	ehash := iapi.HashSchemeInstanceFromMultihash(reqPol.Namespace)
	if !ehash.Supported() {
		return time.Now(), wve.Err(wve.InvalidParameter, "bad namespace")
	}
	ext := ehash.CanonicalForm()
	spol := serdes.RTreePolicy{
		Namespace:  *ext,
		Statements: statements,
	}
	//This is not important
	nsloc := iapi.NewLocationSchemeInstanceURL("https://foo.com", 1).CanonicalForm()
	spol.NamespaceLocation = *nsloc

	wrappedPol := serdes.WaveWireObject{
		Content: asn1.NewExternal(spol),
	}
	polBytes, err := asn1.Marshal(wrappedPol.Content)
	if err != nil {
		return time.Now(), wve.ErrW(wve.InternalError, "cannot marshal policy", err)
	}

	polDER := (*C.char)(unsafe.Pointer(&polBytes[0]))
	subject := (*C.char)(unsafe.Pointer(&subjectHash[2]))
	proofDER := (*C.char)(unsafe.Pointer(&DER[0]))
	CExpiry := C.verify(proofDER, C.ulong(len(DER)), subject, C.ulong(len(subjectHash)-2), polDER, C.ulong(len(polBytes)))
	if int64(CExpiry) == -1 {
		return time.Now(), wve.Err(wve.ProofInvalid, "failed to C verify proof")
	}
	expiryStr := strconv.FormatInt(int64(CExpiry), 10)
	proofExpiry := fmt.Sprintf("20%s-%s-%sT%s:%s:%sZ", expiryStr[0:2], expiryStr[2:4],
		expiryStr[4:6], expiryStr[6:8], expiryStr[8:10], expiryStr[10:12])
	proofTime, _ := time.Parse(time.RFC3339, proofExpiry)
	return proofTime, nil
}

// func ProvisionKey() error {

// }
