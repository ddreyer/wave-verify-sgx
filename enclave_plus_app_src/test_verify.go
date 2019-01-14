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
	"io"
	"os"
	"strconv"
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
	// "BASIC":                 testBasic,
	// "BASIC WITH EXPIRY":     testBasicWithExpiry,
	// "MULTIPLE ATTESTATIONS": testMultipleAttestations,
	// "BAD POLICY PERMISSION": testBadPolicyPermission,
	// "BAD POLICY RESOURCE":   testBadPolicyResource,
	// "BAD POLICY PSET":       testBadPolicyPset,
	// "BAD POLICY NAMESPACE":  testBadPolicyNamespace,
	"BAD POLICY SUBJECT:": testBadPolicySubject,
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
	errStr := "wave verify error: " + error.wveError + " enclave verify error: " + error.enclaveError
	if error.wveError == "" && error.enclaveError == "" {
		errStr += " expiry error: " + error.expiryError
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
		DER: Dst.PublicDER,
		Location: &pb.Location{
			AgentLocation: "default",
		},
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
			Location: &pb.Location{
				AgentLocation: "default",
			},
		},
		BodyScheme:  eapi.BodySchemeWaveRef1,
		SubjectHash: Dst.Hash,
		SubjectLocation: &pb.Location{
			AgentLocation: "default",
		},
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace:    Src.Hash,
				Indirections: 4,
				Statements: []*pb.RTreePolicyStatement{
					&pb.RTreePolicyStatement{
						PermissionSet: Src.Hash,
						Permissions:   []string{"default"},
						Resource:      "default",
					},
				},
			},
		},
	})
	if err != nil {
		panic(err)
	}
	if attresp.Error != nil {
		panic(attresp.Error.Message)
	}
	attpub, err := waveconn.PublishAttestation(context.Background(), &pb.PublishAttestationParams{
		DER: attresp.DER,
	})
	if err != nil {
		panic(err)
	}
	if attpub.Error != nil {
		panic(attpub.Error.Message)
	}
	waveconn.ResyncPerspectiveGraph(context.Background(), &pb.ResyncPerspectiveGraphParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Dst.SecretDER,
			},
		},
	})
	cl, err := waveconn.WaitForSyncComplete(context.Background(), &pb.SyncParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Dst.SecretDER,
			},
		},
	})
	if err != nil {
		panic(err)
	}
	for {
		_, err := cl.Recv()
		if err == io.EOF {
			break
		}
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
			expiryError = fmt.Sprintf("wave: %d enclave: %d", waveTime.String(), proofTime.String())
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
			Location: &pb.Location{
				AgentLocation: "default",
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
			Location: &pb.Location{
				AgentLocation: "default",
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
			Location: &pb.Location{
				AgentLocation: "default",
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
			Location: &pb.Location{
				AgentLocation: "default",
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
			Location: &pb.Location{
				AgentLocation: "default",
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
			Location: &pb.Location{
				AgentLocation: "default",
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

// tests proof which contains multiple attestations
func testMultipleAttestations() TestVerifyError {
	attresp, err := waveconn.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Src.SecretDER,
			},
			Location: &pb.Location{
				AgentLocation: "default",
			},
		},
		ValidUntil:  time.Now().Add(3*365*24*time.Hour).UnixNano() / 1e6,
		BodyScheme:  eapi.BodySchemeWaveRef1,
		SubjectHash: Dst.Hash,
		SubjectLocation: &pb.Location{
			AgentLocation: "default",
		},
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace:    Src.Hash,
				Indirections: 4,
				Statements: []*pb.RTreePolicyStatement{
					&pb.RTreePolicyStatement{
						PermissionSet: Src.Hash,
						Permissions:   []string{"default2"},
						Resource:      "default",
					},
				},
			},
		},
	})
	if err != nil {
		panic(err)
	}
	if attresp.Error != nil {
		panic(attresp.Error.Message)
	}
	attpub, err := waveconn.PublishAttestation(context.Background(), &pb.PublishAttestationParams{
		DER: attresp.DER,
	})
	if err != nil {
		panic(err)
	}
	if attpub.Error != nil {
		panic(attpub.Error.Message)
	}

	waveconn.ResyncPerspectiveGraph(context.Background(), &pb.ResyncPerspectiveGraphParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Dst.SecretDER,
			},
		},
	})
	cl, err := waveconn.WaitForSyncComplete(context.Background(), &pb.SyncParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Dst.SecretDER,
			},
		},
	})
	if err != nil {
		panic(err)
	}
	for {
		_, err := cl.Recv()
		if err == io.EOF {
			break
		}
	}
	proofresp, err := waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: Dst.SecretDER,
			},
			Location: &pb.Location{
				AgentLocation: "default",
			},
		},
		SubjectHash: Dst.Hash,
		Namespace:   Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default", "default2"},
				Resource:      "default",
			},
		},
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
				Permissions:   []string{"default", "default2"},
				Resource:      "default",
			},
		},
	}

	pbPol := pb.RTreePolicy{
		Namespace: Src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: Src.Hash,
				Permissions:   []string{"default", "default2"},
				Resource:      "default",
			},
		},
	}
	return checkVerification(proofresp.ProofDER, &spol, &pbPol, Dst.Hash)
}

// tests entities and attestations with expiries
func testBasicWithExpiry() TestVerifyError {
	src, err := waveconn.CreateEntity(context.Background(), &pb.CreateEntityParams{
		ValidFrom:  time.Now().UnixNano() / 1e6,
		ValidUntil: time.Now().Add(time.Minute*10).UnixNano() / 1e6,
	})
	if err != nil {
		panic(err)
	}
	if src.Error != nil {
		panic(src.Error.Message)
	}
	dst, err := waveconn.CreateEntity(context.Background(), &pb.CreateEntityParams{
		ValidUntil: time.Now().Add(time.Minute*20).UnixNano() / 1e6,
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
		Location: &pb.Location{
			AgentLocation: "default",
		},
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
				DER: src.SecretDER,
			},
			Location: &pb.Location{
				AgentLocation: "default",
			},
		},
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
	})
	if err != nil {
		panic(err)
	}
	if attresp.Error != nil {
		panic(attresp.Error.Message)
	}
	attpub, err := waveconn.PublishAttestation(context.Background(), &pb.PublishAttestationParams{
		DER: attresp.DER,
	})
	if err != nil {
		panic(err)
	}
	if attpub.Error != nil {
		panic(attpub.Error.Message)
	}
	waveconn.ResyncPerspectiveGraph(context.Background(), &pb.ResyncPerspectiveGraphParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: dst.SecretDER,
			},
		},
	})
	cl, err := waveconn.WaitForSyncComplete(context.Background(), &pb.SyncParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: dst.SecretDER,
			},
		},
	})
	if err != nil {
		panic(err)
	}
	for {
		_, err := cl.Recv()
		if err == io.EOF {
			break
		}
	}
	proofresp, err := waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: dst.SecretDER,
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

func main() {
	var results []string
	for name, test := range tests {
		fmt.Println("======== TEST " + name + "========")
		if err := test(); err.wveError != "" || err.enclaveError != "" || err.expiryError != "" {
			results = append(results, fmt.Sprintf("error in %s: %s", name, err.Error()))
		}
		fmt.Println("======== END " + name + "========")
	}
	for _, result := range results {
		fmt.Println(result)
	}

	// contents, err := ioutil.ReadFile("test.pem")
	// if err != nil {
	// 	fmt.Printf("could not read file %q: %v\n", "proof.pem", err)
	// }
	// block, _ := pem.Decode(contents)
	// if block == nil {
	// 	fmt.Printf("file %q is not a PEM file\n", "proof.pem")
	// }

	// proofPointer := unsafe.Pointer(&block.Bytes[0])
	// proofDER := (*C.char)(proofPointer)
	// proofSize := len(block.Bytes)
	// fmt.Println(proofSize)
	// C.verify(proofDER, C.ulong(proofSize), nil, 0, nil, 0)
}
