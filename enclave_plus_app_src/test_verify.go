package main

/*
#include "enclave_app.h"
#cgo CFLAGS: -I. -I../utils -I/home/sgx/linux-sgx/linux/installer/bin/sgxsdk/include
#cgo LDFLAGS: -lverify -L.
*/
import "C"

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/immesys/asn1"
	"github.com/immesys/wave/eapi"
	"github.com/immesys/wave/eapi/pb"
	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/serdes"
	"github.com/immesys/wave/wve"
	"google.golang.org/grpc"
)

type TestFunc func() TestVerifyError

var tests = map[string]TestFunc{
	/* tests that should not cause errors */
	// "BASIC": testBasic,
	// "BASIC WITH OPTIONALS": testBasicWithOptionals,
	// "MULTIPLE STATEMENTS": testMultipleStatements,
	// "MULTIPLE ATTESTATIONS": testMultipleAttestations,
	// "ATTESTATION CHAIN": testAttestationChain,
	// "RESOURCE PATHS": testResourcePaths,
	// "NO PERMISSIONS": testNoPermissions,
	/* tests that should cause errors */
	"BAD POLICY PERMISSION": testBadPolicyPermission,
	"BAD POLICY RESOURCE":   testBadPolicyResource,
	"BAD POLICY PSET":       testBadPolicyPset,
	"BAD POLICY NAMESPACE":  testBadPolicyNamespace,
	"BAD POLICY SUBJECT":    testBadPolicySubject,
	"BAD POLICY":            testBadPolicy,
	/* enclave memory management test */
	// "BULK VERIFY": testBulkVerify,
}

var waveconn pb.WAVEClient
var Src *pb.CreateEntityResponse
var Dst *pb.CreateEntityResponse

type TestVerifyError struct {
	wveError     string
	enclaveError string
	expiryError  string
}

func (error *TestVerifyError) Error() string {
	if error.wveError == "" {
		error.wveError = "none"
	}
	if error.enclaveError == "" {
		error.enclaveError = "none"
	}
	errStr := "\n\twave verify error: " + error.wveError + "\n\tenclave verify error: " + error.enclaveError
	if error.wveError == "" && error.enclaveError == "" {
		errStr += "\n\texpiry error: " + error.expiryError
	}
	return errStr
}

// initializes waved connection, enclave, two default entities with no expiry, and an attestation
func init() {
	conn, err := grpc.Dial("127.0.0.1:410", grpc.WithInsecure(), grpc.FailOnNonTempDialError(true), grpc.WithBlock())
	if err != nil {
		fmt.Printf("failed to connect to agent: %v\n", err)
		os.Exit(1)
	}
	waveconn = pb.NewWAVEClient(conn)
	ret := C.init_enclave()
	if ret != 0 {
		fmt.Printf("error initializing enclave")
		os.Exit(1)
	}
	Src, err = waveconn.CreateEntity(context.Background(), &pb.CreateEntityParams{})
	if err != nil {
		panic(err)
	}
	if Src.Error != nil {
		panic(Src.Error.Message)
	}
	Dst, err = waveconn.CreateEntity(context.Background(), &pb.CreateEntityParams{})
	if err != nil {
		panic(err)
	}
	if Dst.Error != nil {
		panic(Dst.Error.Message)
	}
	srcresp, err := waveconn.PublishEntity(context.Background(), &pb.PublishEntityParams{
		DER: Src.PublicDER,
	})
	if err != nil {
		panic(err)
	}
	if srcresp.Error != nil {
		panic(srcresp.Error.Message)
	}
	dstresp, err := waveconn.PublishEntity(context.Background(), &pb.PublishEntityParams{
		DER: Dst.PublicDER,
	})
	if err != nil {
		panic(err)
	}
	if dstresp.Error != nil {
		panic(dstresp.Error.Message)
	}
	attresp, err := waveconn.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Src.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace:    Src.Hash,
				Indirections: 20,
				Statements: []*pb.RTreePolicyStatement{
					&pb.RTreePolicyStatement{
						PermissionSet: Src.Hash,
						Permissions:   []string{"default"},
						Resource:      "default",
					},
				},
			},
		},
		Publish: true,
	})
	if err != nil {
		panic(err)
	}
	if attresp.Error != nil {
		panic(attresp.Error.Message)
	}
}

// verifies proof using waved and enclave
func checkVerification(DER []byte, spol *serdes.RTreePolicy, pbPol *pb.RTreePolicy, subjectHash []byte) TestVerifyError {
	var wveError string
	var enclaveError string
	var expiryError string
	var proofTime time.Time
	verifyresp, err := waveconn.VerifyProof(context.Background(), &pb.VerifyProofParams{
		ProofDER:            DER,
		Subject:             subjectHash,
		RequiredRTreePolicy: pbPol,
	})
	if err != nil {
		wveError = wve.ErrW(wve.ProofInvalid, "failed to WAVE verify proof", err).Error()
	}
	if verifyresp.Error != nil {
		wveError = verifyresp.Error.Message
	}
	waveTime := time.Unix(verifyresp.Result.GetExpiry()/1e3, 0)

	//This is not important
	nsloc := iapi.NewLocationSchemeInstanceURL("https://foo.com", 1).CanonicalForm()
	(*spol).NamespaceLocation = *nsloc

	wrappedPol := serdes.WaveWireObject{
		Content: asn1.NewExternal(*spol),
	}
	polBytes, err := asn1.Marshal(wrappedPol.Content)
	if err != nil {
		panic(err)
	}

	polDER := (*C.char)(unsafe.Pointer(&polBytes[0]))
	subject := (*C.char)(unsafe.Pointer(&subjectHash[2]))
	proofDER := (*C.char)(unsafe.Pointer(&DER[0]))

	CExpiry := C.verify(proofDER, C.ulong(len(DER)), subject, C.ulong(len(subjectHash)-2),
		polDER, C.ulong(len(polBytes)))
	if int64(CExpiry) == -1 {
		enclaveError = wve.Err(wve.EnclaveError, "failed to C verify proof").Error()
	} else {
		expiryStr := strconv.FormatInt(int64(CExpiry), 10)
		proofExpiry := fmt.Sprintf("20%s-%s-%sT%s:%s:%sZ", expiryStr[0:2], expiryStr[2:4],
			expiryStr[4:6], expiryStr[6:8], expiryStr[8:10], expiryStr[10:12])
		proofTime, _ = time.Parse(time.RFC3339, proofExpiry)
	}
	if wveError == "" && enclaveError == "" {
		if !waveTime.Equal(proofTime) {
			expiryError = fmt.Sprintf("wave: %s enclave: %s", waveTime, proofTime)
		}
	}

	return TestVerifyError{
		wveError:     wveError,
		enclaveError: enclaveError,
		expiryError:  expiryError,
	}
}

// tests basic attestation
func testBasic() TestVerifyError {
	proofresp, err := waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Dst.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Namespace:   Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
		ResyncFirst: true,
	})
	if err != nil {
		panic(err)
	}
	if proofresp.Error != nil {
		panic(proofresp.Error.Message)
	}

	ehash := iapi.HashSchemeInstanceFromMultihash(Src.Hash)
	if !ehash.Supported() {
		panic(wve.Err(wve.InvalidParameter, "bad namespace"))
	}
	ext := ehash.CanonicalForm()

	spol := serdes.RTreePolicy{
		Namespace: *ext,
		Statements: []serdes.RTreeStatement{
			{
				PermissionSet: *ext,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
	}

	pbPol := pb.RTreePolicy{
		Namespace: Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
	}
	return checkVerification(proofresp.ProofDER, &spol, &pbPol, Dst.Hash)
}

// tests policy permission which doesn't match proof
func testBadPolicyPermission() TestVerifyError {
	proofresp, err := waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Dst.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Namespace:   Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
		ResyncFirst: true,
	})
	if err != nil {
		panic(err)
	}
	if proofresp.Error != nil {
		panic(proofresp.Error.Message)
	}

	ehash := iapi.HashSchemeInstanceFromMultihash(Src.Hash)
	if !ehash.Supported() {
		panic(wve.Err(wve.InvalidParameter, "bad namespace"))
	}
	ext := ehash.CanonicalForm()

	spol := serdes.RTreePolicy{
		Namespace: *ext,
		Statements: []serdes.RTreeStatement{
			{
				PermissionSet: *ext,
				Permissions:   []string{"garbage"},
				Resource:      "default",
			},
		},
	}

	pbPol := pb.RTreePolicy{
		Namespace: Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"garbage"},
				Resource:      "default",
			},
		},
	}
	return checkVerification(proofresp.ProofDER, &spol, &pbPol, Dst.Hash)
}

// tests policy resource which doesn't match proof
func testBadPolicyResource() TestVerifyError {
	proofresp, err := waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Dst.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Namespace:   Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
		ResyncFirst: true,
	})
	if err != nil {
		panic(err)
	}
	if proofresp.Error != nil {
		panic(proofresp.Error.Message)
	}

	ehash := iapi.HashSchemeInstanceFromMultihash(Src.Hash)
	if !ehash.Supported() {
		panic(wve.Err(wve.InvalidParameter, "bad namespace"))
	}
	ext := ehash.CanonicalForm()

	spol := serdes.RTreePolicy{
		Namespace: *ext,
		Statements: []serdes.RTreeStatement{
			{
				PermissionSet: *ext,
				Permissions:   []string{"default"},
				Resource:      "garbage",
			},
		},
	}

	pbPol := pb.RTreePolicy{
		Namespace: Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "garbage",
			},
		},
	}
	return checkVerification(proofresp.ProofDER, &spol, &pbPol, Dst.Hash)
}

// tests policy pset which doesn't match proof
func testBadPolicyPset() TestVerifyError {
	proofresp, err := waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Dst.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Namespace:   Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
		ResyncFirst: true,
	})
	if err != nil {
		panic(err)
	}
	if proofresp.Error != nil {
		panic(proofresp.Error.Message)
	}

	ehash := iapi.HashSchemeInstanceFromMultihash(Src.Hash)
	if !ehash.Supported() {
		panic(wve.Err(wve.InvalidParameter, "bad namespace"))
	}
	ext := ehash.CanonicalForm()

	psethash := iapi.HashSchemeInstanceFromMultihash(Dst.Hash)
	if !psethash.Supported() {
		panic(wve.Err(wve.InvalidParameter, "bad namespace"))
	}
	pset := psethash.CanonicalForm()

	spol := serdes.RTreePolicy{
		Namespace: *ext,
		Statements: []serdes.RTreeStatement{
			{
				PermissionSet: *pset,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
	}

	pbPol := pb.RTreePolicy{
		Namespace: Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Dst.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
	}
	return checkVerification(proofresp.ProofDER, &spol, &pbPol, Dst.Hash)
}

// tests policy namespace which doesn't match proof
func testBadPolicyNamespace() TestVerifyError {
	proofresp, err := waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Dst.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Namespace:   Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
		ResyncFirst: true,
	})
	if err != nil {
		panic(err)
	}
	if proofresp.Error != nil {
		panic(proofresp.Error.Message)
	}

	ehash := iapi.HashSchemeInstanceFromMultihash(Dst.Hash)
	if !ehash.Supported() {
		panic(wve.Err(wve.InvalidParameter, "bad namespace"))
	}
	ext := ehash.CanonicalForm()

	psethash := iapi.HashSchemeInstanceFromMultihash(Src.Hash)
	if !psethash.Supported() {
		panic(wve.Err(wve.InvalidParameter, "bad namespace"))
	}
	pset := psethash.CanonicalForm()

	spol := serdes.RTreePolicy{
		Namespace: *ext,
		Statements: []serdes.RTreeStatement{
			{
				PermissionSet: *pset,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
	}

	pbPol := pb.RTreePolicy{
		Namespace: Dst.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
	}
	return checkVerification(proofresp.ProofDER, &spol, &pbPol, Dst.Hash)
}

// tests policy subject which doesn't match proof
func testBadPolicySubject() TestVerifyError {
	proofresp, err := waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Dst.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Namespace:   Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
		ResyncFirst: true,
	})
	if err != nil {
		panic(err)
	}
	if proofresp.Error != nil {
		panic(proofresp.Error.Message)
	}

	ehash := iapi.HashSchemeInstanceFromMultihash(Src.Hash)
	if !ehash.Supported() {
		panic(wve.Err(wve.InvalidParameter, "bad namespace"))
	}
	ext := ehash.CanonicalForm()

	spol := serdes.RTreePolicy{
		Namespace: *ext,
		Statements: []serdes.RTreeStatement{
			{
				PermissionSet: *ext,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
	}

	pbPol := pb.RTreePolicy{
		Namespace: Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
	}
	return checkVerification(proofresp.ProofDER, &spol, &pbPol, Src.Hash)
}

// tests proof which doesn't contain a superset of the needed permissions
func testBadPolicy() TestVerifyError {
	proofresp, err := waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Dst.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Namespace:   Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
		ResyncFirst: true,
	})
	if err != nil {
		panic(err)
	}
	if proofresp.Error != nil {
		panic(proofresp.Error.Message)
	}

	ehash := iapi.HashSchemeInstanceFromMultihash(Src.Hash)
	if !ehash.Supported() {
		panic(wve.Err(wve.InvalidParameter, "bad namespace"))
	}
	ext := ehash.CanonicalForm()

	spol := serdes.RTreePolicy{
		Namespace: *ext,
		Statements: []serdes.RTreeStatement{
			{
				PermissionSet: *ext,
				Permissions:   []string{"default", "extra"},
				Resource:      "default",
			},
		},
	}

	pbPol := pb.RTreePolicy{
		Namespace: Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default", "extra"},
				Resource:      "default",
			},
		},
	}
	return checkVerification(proofresp.ProofDER, &spol, &pbPol, Dst.Hash)
}

// tests verifying policy of no permissions with proof
func testNoPermissions() TestVerifyError {
	proofresp, err := waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Dst.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Namespace:   Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
		ResyncFirst: true,
	})
	if err != nil {
		panic(err)
	}
	if proofresp.Error != nil {
		panic(proofresp.Error.Message)
	}

	ehash := iapi.HashSchemeInstanceFromMultihash(Src.Hash)
	if !ehash.Supported() {
		panic(wve.Err(wve.InvalidParameter, "bad namespace"))
	}
	ext := ehash.CanonicalForm()

	spol := serdes.RTreePolicy{
		Namespace: *ext,
		Statements: []serdes.RTreeStatement{
			{
				PermissionSet: *ext,
				Permissions:   []string{},
				Resource:      "default",
			},
		},
	}

	pbPol := pb.RTreePolicy{
		Namespace: Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{},
				Resource:      "default",
			},
		},
	}
	return checkVerification(proofresp.ProofDER, &spol, &pbPol, Dst.Hash)
}

// tests interesting resource paths and regex patterns
func testResourcePaths() TestVerifyError {
	resource := "default/foo/bar"
	attresp, err := waveconn.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Src.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace: Src.Hash,
				Statements: []*pb.RTreePolicyStatement{
					&pb.RTreePolicyStatement{
						PermissionSet: Src.Hash,
						Permissions:   []string{"default"},
						Resource:      resource,
					},
				},
			},
		},
		Publish: true,
	})
	if err != nil {
		panic(err)
	}
	if attresp.Error != nil {
		panic(attresp.Error.Message)
	}
	proofresp, err := waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Dst.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Namespace:   Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      resource,
			},
		},
		ResyncFirst: true,
	})
	if err != nil {
		panic(err)
	}
	if proofresp.Error != nil {
		panic(proofresp.Error.Message)
	}

	ehash := iapi.HashSchemeInstanceFromMultihash(Src.Hash)
	if !ehash.Supported() {
		panic(wve.Err(wve.InvalidParameter, "bad namespace"))
	}
	ext := ehash.CanonicalForm()

	spol := serdes.RTreePolicy{
		Namespace: *ext,
		Statements: []serdes.RTreeStatement{
			{
				PermissionSet: *ext,
				Permissions:   []string{"default"},
				Resource:      resource,
			},
		},
	}

	pbPol := pb.RTreePolicy{
		Namespace: Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      resource,
			},
		},
	}
	if err := checkVerification(proofresp.ProofDER, &spol, &pbPol, Dst.Hash); err.wveError != "" || err.enclaveError != "" || err.expiryError != "" {
		err.enclaveError += " failed verifying resource string " + resource
		return err
	}

	resource = "default/foo/*"
	attresp, err = waveconn.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Src.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace: Src.Hash,
				Statements: []*pb.RTreePolicyStatement{
					&pb.RTreePolicyStatement{
						PermissionSet: Src.Hash,
						Permissions:   []string{"default"},
						Resource:      resource,
					},
				},
			},
		},
		Publish: true,
	})
	if err != nil {
		panic(err)
	}
	if attresp.Error != nil {
		panic(attresp.Error.Message)
	}
	resource = "default/foo/bazbar"
	proofresp, err = waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Dst.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Namespace:   Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      resource,
			},
		},
		ResyncFirst: true,
	})
	if err != nil {
		panic(err)
	}
	if proofresp.Error != nil {
		panic(proofresp.Error.Message)
	}
	spol.Statements[0].Resource = resource
	pbPol.Statements[0].Resource = resource
	if err := checkVerification(proofresp.ProofDER, &spol, &pbPol, Dst.Hash); err.wveError != "" || err.enclaveError != "" || err.expiryError != "" {
		err.enclaveError += " failed verifying resource string " + resource
		return err
	}

	resource = "default/*"
	attresp, err = waveconn.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Src.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace: Src.Hash,
				Statements: []*pb.RTreePolicyStatement{
					&pb.RTreePolicyStatement{
						PermissionSet: Src.Hash,
						Permissions:   []string{"default"},
						Resource:      resource,
					},
				},
			},
		},
		Publish: true,
	})
	if err != nil {
		panic(err)
	}
	if attresp.Error != nil {
		panic(attresp.Error.Message)
	}
	resource = "default/baz/bar/foo"
	proofresp, err = waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Dst.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Namespace:   Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      resource,
			},
		},
		ResyncFirst: true,
	})
	if err != nil {
		panic(err)
	}
	if proofresp.Error != nil {
		panic(proofresp.Error.Message)
	}
	spol.Statements[0].Resource = resource
	pbPol.Statements[0].Resource = resource
	if err := checkVerification(proofresp.ProofDER, &spol, &pbPol, Dst.Hash); err.wveError != "" || err.enclaveError != "" || err.expiryError != "" {
		err.enclaveError += " failed verifying resource string " + resource
		return err
	}

	return TestVerifyError{
		wveError:     "",
		enclaveError: "",
		expiryError:  "",
	}
}

// tests proof which contains multiple policy statements
func testMultipleStatements() TestVerifyError {
	const pset = "\x1b\x20\x14\x33\x74\xb3\x2f\xd2\x74\x39\x54\xfe\x47\x86\xf6\xcf\x86\xd4\x03\x72\x0f\x5e\xc4\x42\x36\xb6\x58\xc2\x6a\x1e\x68\x0f\x6e\x01"
	attresp, err := waveconn.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Src.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace: Src.Hash,
				Statements: []*pb.RTreePolicyStatement{
					&pb.RTreePolicyStatement{
						PermissionSet: []byte(pset),
						Permissions:   []string{"bar"},
						Resource:      "baz",
					},
				},
			},
		},
		Publish: true,
	})
	if err != nil {
		panic(err)
	}
	if attresp.Error != nil {
		panic(attresp.Error.Message)
	}
	proofresp, err := waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Dst.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Namespace:   Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
			&pb.RTreePolicyStatement{
				PermissionSet: []byte(pset),
				Permissions:   []string{"bar"},
				Resource:      "baz",
			},
		},
		ResyncFirst: true,
	})
	if err != nil {
		panic(err)
	}
	if proofresp.Error != nil {
		panic(proofresp.Error.Message)
	}
	ehash := iapi.HashSchemeInstanceFromMultihash(Src.Hash)
	if !ehash.Supported() {
		panic(wve.Err(wve.InvalidParameter, "bad namespace"))
	}
	ext := ehash.CanonicalForm()
	phash := iapi.HashSchemeInstanceFromMultihash([]byte(pset))
	if !phash.Supported() {
		panic(wve.Err(wve.InvalidParameter, "bad namespace"))
	}
	pext := phash.CanonicalForm()

	spol := serdes.RTreePolicy{
		Namespace: *ext,
		Statements: []serdes.RTreeStatement{
			{
				PermissionSet: *ext,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
			{
				PermissionSet: *pext,
				Permissions:   []string{"bar"},
				Resource:      "baz",
			},
		},
	}

	pbPol := pb.RTreePolicy{
		Namespace: Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
			&pb.RTreePolicyStatement{
				PermissionSet: []byte(pset),
				Permissions:   []string{"bar"},
				Resource:      "baz",
			},
		},
	}
	return checkVerification(proofresp.ProofDER, &spol, &pbPol, Dst.Hash)
}

// tests proof which contains multiple attestations
func testMultipleAttestations() TestVerifyError {
	attresp, err := waveconn.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Src.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace: Src.Hash,
				Statements: []*pb.RTreePolicyStatement{
					&pb.RTreePolicyStatement{
						PermissionSet: Src.Hash,
						Permissions:   []string{"default2"},
						Resource:      "default",
					},
				},
			},
		},
		Publish: true,
	})
	if err != nil {
		panic(err)
	}
	if attresp.Error != nil {
		panic(attresp.Error.Message)
	}
	attresp, err = waveconn.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Src.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace: Src.Hash,
				Statements: []*pb.RTreePolicyStatement{
					&pb.RTreePolicyStatement{
						PermissionSet: Src.Hash,
						Permissions:   []string{"default3"},
						Resource:      "default",
					},
				},
			},
		},
		Publish: true,
	})
	if err != nil {
		panic(err)
	}
	if attresp.Error != nil {
		panic(attresp.Error.Message)
	}
	proofresp, err := waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Dst.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Namespace:   Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default2"},
				Resource:      "default",
			},
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default3"},
				Resource:      "default",
			},
		},
		ResyncFirst: true,
	})
	if err != nil {
		panic(err)
	}
	if proofresp.Error != nil {
		panic(proofresp.Error.Message)
	}

	ehash := iapi.HashSchemeInstanceFromMultihash(Src.Hash)
	if !ehash.Supported() {
		panic(wve.Err(wve.InvalidParameter, "bad namespace"))
	}
	ext := ehash.CanonicalForm()

	spol := serdes.RTreePolicy{
		Namespace: *ext,
		Statements: []serdes.RTreeStatement{
			{
				PermissionSet: *ext,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
			{
				PermissionSet: *ext,
				Permissions:   []string{"default2"},
				Resource:      "default",
			},
			{
				PermissionSet: *ext,
				Permissions:   []string{"default3"},
				Resource:      "default",
			},
		},
	}

	pbPol := pb.RTreePolicy{
		Namespace: Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default2"},
				Resource:      "default",
			},
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default3"},
				Resource:      "default",
			},
		},
	}
	return checkVerification(proofresp.ProofDER, &spol, &pbPol, Dst.Hash)
}

// tests proof which contains multiple attestations
func testAttestationChain() TestVerifyError {
	prevEnt := Dst
	var ent *pb.CreateEntityResponse
	var err error
	for i := 0; i < 1; i++ {
		ent, err = waveconn.CreateEntity(context.Background(), &pb.CreateEntityParams{})
		if err != nil {
			panic(err)
		}
		if ent.Error != nil {
			panic(ent.Error.Message)
		}
		entresp, err := waveconn.PublishEntity(context.Background(), &pb.PublishEntityParams{
			DER: ent.PublicDER,
		})
		if err != nil {
			panic(err)
		}
		if entresp.Error != nil {
			panic(entresp.Error.Message)
		}
		attresp, err := waveconn.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
			Perspective: &pb.Perspective{
				EntitySecret: &pb.EntitySecret{
					DER: prevEnt.SecretDER,
				},
			},
			SubjectHash: ent.Hash,
			Policy: &pb.Policy{
				RTreePolicy: &pb.RTreePolicy{
					Namespace:    Src.Hash,
					Indirections: 20,
					Statements: []*pb.RTreePolicyStatement{
						&pb.RTreePolicyStatement{
							PermissionSet: Src.Hash,
							Permissions:   []string{"default"},
							Resource:      "default",
						},
					},
				},
			},
			Publish: true,
		})
		if err != nil {
			panic(err)
		}
		if attresp.Error != nil {
			panic(attresp.Error.Message)
		}
		prevEnt = ent
	}
	proofresp, err := waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: ent.SecretDER,
			},
		},
		SubjectHash: ent.Hash,
		Namespace:   Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
		ResyncFirst: true,
	})
	if err != nil {
		panic(err)
	}
	if proofresp.Error != nil {
		panic(proofresp.Error.Message)
	}

	ehash := iapi.HashSchemeInstanceFromMultihash(Src.Hash)
	if !ehash.Supported() {
		panic(wve.Err(wve.InvalidParameter, "bad namespace"))
	}
	ext := ehash.CanonicalForm()

	spol := serdes.RTreePolicy{
		Namespace: *ext,
		Statements: []serdes.RTreeStatement{
			{
				PermissionSet: *ext,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
	}

	pbPol := pb.RTreePolicy{
		Namespace: Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
	}

	return checkVerification(proofresp.ProofDER, &spol, &pbPol, ent.Hash)
}

// tests entities and attestations with optional fields
func testBasicWithOptionals() TestVerifyError {
	src, err := waveconn.CreateEntity(context.Background(), &pb.CreateEntityParams{
		ValidFrom:  time.Now().Add(time.Second).UnixNano() / 1e6,
		ValidUntil: time.Now().Add(time.Minute*10).UnixNano() / 1e6,
	})
	if err != nil {
		panic(err)
	}
	if src.Error != nil {
		panic(src.Error.Message)
	}
	dst, err := waveconn.CreateEntity(context.Background(), &pb.CreateEntityParams{
		ValidUntil:       time.Now().Add(time.Minute*20).UnixNano() / 1e6,
		SecretPassphrase: "wave",
	})
	if err != nil {
		panic(err)
	}
	if dst.Error != nil {
		panic(dst.Error.Message)
	}
	srcresp, err := waveconn.PublishEntity(context.Background(), &pb.PublishEntityParams{
		DER: src.PublicDER,
		Location: &pb.Location{
			AgentLocation: "default",
		},
	})
	if err != nil {
		panic(err)
	}
	if srcresp.Error != nil {
		panic(srcresp.Error.Message)
	}
	dstresp, err := waveconn.PublishEntity(context.Background(), &pb.PublishEntityParams{
		DER: dst.PublicDER,
	})
	if err != nil {
		panic(err)
	}
	if dstresp.Error != nil {
		panic(dstresp.Error.Message)
	}
	time.Sleep(time.Second)
	attresp, err := waveconn.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: src.SecretDER,
			},
			Location: &pb.Location{
				AgentLocation: "default",
			},
		},
		ValidFrom:   time.Now().Add(time.Second).UnixNano() / 1e6,
		ValidUntil:  time.Now().Add(24*time.Hour).UnixNano() / 1e6,
		BodyScheme:  eapi.BodySchemeWaveRef1,
		SubjectHash: dst.Hash,
		SubjectLocation: &pb.Location{
			AgentLocation: "default",
		},
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace:    srcresp.Hash,
				Indirections: 4,
				Statements: []*pb.RTreePolicyStatement{
					&pb.RTreePolicyStatement{
						PermissionSet: srcresp.Hash,
						Permissions:   []string{"foo1", "foo2", "foo3", "foo4"},
						Resource:      "bar",
					},
				},
			},
		},
		Publish: true,
	})
	if err != nil {
		panic(err)
	}
	if attresp.Error != nil {
		panic(attresp.Error.Message)
	}
	time.Sleep(time.Second)
	proofresp, err := waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER:        dst.SecretDER,
				Passphrase: []byte{'w', 'a', 'v', 'e'},
			},
			Location: &pb.Location{
				AgentLocation: "default",
			},
		},
		SubjectHash: dstresp.Hash,
		Namespace:   srcresp.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: srcresp.Hash,
				Permissions:   []string{"foo1", "foo2", "foo3", "foo4"},
				Resource:      "bar",
			},
		},
		ResyncFirst: true,
	})
	if err != nil {
		panic(err)
	}
	if proofresp.Error != nil {
		panic(proofresp.Error.Message)
	}

	ehash := iapi.HashSchemeInstanceFromMultihash(srcresp.Hash)
	if !ehash.Supported() {
		panic(wve.Err(wve.InvalidParameter, "bad namespace"))
	}
	ext := ehash.CanonicalForm()

	spol := serdes.RTreePolicy{
		Namespace: *ext,
		Statements: []serdes.RTreeStatement{
			{
				PermissionSet: *ext,
				Permissions:   []string{"foo1", "foo2", "foo3", "foo4"},
				Resource:      "bar",
			},
		},
	}

	pbPol := pb.RTreePolicy{
		Namespace: srcresp.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: srcresp.Hash,
				Permissions:   []string{"foo1", "foo2", "foo3", "foo4"},
				Resource:      "bar",
			},
		},
	}
	return checkVerification(proofresp.ProofDER, &spol, &pbPol, dst.Hash)
}

// tests memory management of enclave by verifying many proofs
func testBulkVerify() TestVerifyError {
	proofresp, err := waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Dst.SecretDER,
			},
		},
		SubjectHash: Dst.Hash,
		Namespace:   Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
		ResyncFirst: true,
	})
	if err != nil {
		panic(err)
	}
	if proofresp.Error != nil {
		panic(proofresp.Error.Message)
	}

	ehash := iapi.HashSchemeInstanceFromMultihash(Src.Hash)
	if !ehash.Supported() {
		panic(wve.Err(wve.InvalidParameter, "bad namespace"))
	}
	ext := ehash.CanonicalForm()

	spol := serdes.RTreePolicy{
		Namespace: *ext,
		Statements: []serdes.RTreeStatement{
			{
				PermissionSet: *ext,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
	}

	pbPol := pb.RTreePolicy{
		Namespace: Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default"},
				Resource:      "default",
			},
		},
	}

	for i := 0; i < 80; i++ {
		fmt.Printf("Test Bulk Verify: Starting iteration %d\n", i)
		if err := checkVerification(proofresp.ProofDER, &spol, &pbPol, Dst.Hash); err.wveError != "" || err.enclaveError != "" || err.expiryError != "" {
			fmt.Printf("failed bulk verify on iteration %d\n", i)
			return err
		}
	}
	return TestVerifyError{
		wveError:     "",
		enclaveError: "",
		expiryError:  "",
	}
}

func main() {
	var results []string
	for name, test := range tests {
		fmt.Println("======== BEGIN TEST " + name + " ========")
		err := test()
		if !strings.Contains(name, "BAD") && (err.wveError != "" || err.enclaveError != "" || err.expiryError != "") {
			results = append(results, fmt.Sprintf("error in %s: %s", name, err.Error()))
		}
		if strings.Contains(name, "BAD") && (err.wveError == "" || err.enclaveError == "") {
			results = append(results, fmt.Sprintf("error in %s: %s", name, err.Error()))
		}
		fmt.Println("======== END TEST " + name + " ========")
	}
	for _, result := range results {
		fmt.Println(result)
	}
}
