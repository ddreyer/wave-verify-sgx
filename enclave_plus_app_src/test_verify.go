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

var waveconn pb.WAVEClient

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
}

func checkVerification(DER []byte, spol *serdes.RTreePolicy, pbPol *pb.RTreePolicy, subjectHash []byte) error {
	if _, err := waveconn.VerifyProof(context.Background(), &pb.VerifyProofParams{
		ProofDER:            DER,
		Subject:             subjectHash,
		RequiredRTreePolicy: pbPol,
	}); err != nil {
		return wve.ErrW(wve.ProofInvalid, "invalid proof", err)
	}

	//This is not important
	nsloc := iapi.NewLocationSchemeInstanceURL("https://foo.com", 1).CanonicalForm()
	(*spol).NamespaceLocation = *nsloc

	wrappedPol := serdes.WaveWireObject{
		Content: asn1.NewExternal(*spol),
	}
	polBytes, err := asn1.Marshal(wrappedPol.Content)
	if err != nil {
		return wve.ErrW(wve.InternalError, "could not marshal policy", err)
	}

	polDER := (*C.char)(unsafe.Pointer(&polBytes[0]))
	subject := (*C.char)(unsafe.Pointer(&subjectHash[2]))
	proofDER := (*C.char)(unsafe.Pointer(&DER[0]))

	if ret := C.verify(proofDER, C.ulong(len(DER)), subject, C.ulong(len(subjectHash)-2),
		polDER, C.ulong(len(polBytes))); ret != 0 {
		return wve.Err(wve.EnclaveError, "failed to C verify proof")
	}
	return nil
}

func testBasicEntityAttestation() error {
	src, err := waveconn.CreateEntity(context.Background(), &pb.CreateEntityParams{})
	if err != nil {
		panic(err)
	}
	if src.Error != nil {
		panic(src.Error.Message)
	}
	dst, err := waveconn.CreateEntity(context.Background(), &pb.CreateEntityParams{})
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
	fmt.Printf("srcr: %x\n", srcresp.Hash)
	attresp, err := waveconn.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: src.SecretDER,
			},
			Location: &pb.Location{
				AgentLocation: "default",
			},
		},
		ValidUntil:  time.Now().Add(3*365*24*time.Hour).UnixNano() / 1e6,
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
		return wve.Err(wve.InvalidParameter, "bad namespace")
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

	if err = checkVerification(proofresp.ProofDER, &spol, &pbPol, dstresp.Hash); err != nil {
		return fmt.Errorf("error in BasicEntityAttestation: %s", err.Error())
	}
	return nil
}

func testEntityWithExpiry() error {
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
		ValidUntil: time.Now().Add(time.Minute*10).UnixNano() / 1e6,
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
	fmt.Printf("srcr: %x\n", srcresp.Hash)
	attresp, err := waveconn.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: src.SecretDER,
			},
			Location: &pb.Location{
				AgentLocation: "default",
			},
		},
		ValidUntil:  time.Now().Add(3*365*24*time.Hour).UnixNano() / 1e6,
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
		return wve.Err(wve.InvalidParameter, "bad namespace")
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

	if err = checkVerification(proofresp.ProofDER, &spol, &pbPol, dstresp.Hash); err != nil {
		return fmt.Errorf("error in EntityWithExpiry: %s", err.Error())
	}
	return nil
}

// func testUnionOfPermissions() error {
// }

func main() {
	var err1 error
	fmt.Println("======== TEST BASIC ENTITY/ATTESTATION ========")
	err1 = testBasicEntityAttestation()
	fmt.Println("======== END TEST BASIC ENTITY/ATTESTATION ========")
	var err2 error
	fmt.Println("======== TEST ENTITY WITH EXPIRY ========")
	err2 = testEntityWithExpiry()
	fmt.Println("======== END ENTITY WITH EXPIRY ========")

	if err1 != nil {
		fmt.Println(err1)
	}
	if err2 != nil {
		fmt.Println(err2)
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
