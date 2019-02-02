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
	"time"
	"unsafe"

	"github.com/immesys/asn1"
	"github.com/immesys/wave/eapi/pb"
	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/serdes"
	"github.com/immesys/wave/wve"
	"google.golang.org/grpc"
)

func main() {
	conn, err := grpc.Dial("127.0.0.1:410", grpc.WithInsecure(), grpc.FailOnNonTempDialError(true), grpc.WithBlock())
	if err != nil {
		fmt.Printf("failed to connect to agent: %v\n", err)
		os.Exit(1)
	}
	waveconn := pb.NewWAVEClient(conn)
	ret := C.init_enclave()
	if ret != 0 {
		fmt.Printf("error initializing enclave")
		os.Exit(1)
	}
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
	attresp, err := waveconn.CreateAttestation(context.Background(), &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: src.SecretDER,
			},
		},
		SubjectHash: dst.Hash,
		Policy: &pb.Policy{
			RTreePolicy: &pb.RTreePolicy{
				Namespace:    src.Hash,
				Indirections: 20,
				Statements: []*pb.RTreePolicyStatement{
					&pb.RTreePolicyStatement{
						PermissionSet: src.Hash,
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
	proofresp, err := waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER: dst.SecretDER,
			},
		},
		SubjectHash: dst.Hash,
		Namespace:   src.Hash,
		Statements: []*pb.RTreePolicyStatement{
			&pb.RTreePolicyStatement{
				PermissionSet: src.Hash,
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

	beforeTime := time.Now()
	for i := 0; i < 500; i++ {
		waveconn.VerifyProof(context.Background(), &pb.VerifyProofParams{
			ProofDER: proofresp.ProofDER,
			Subject:  dst.Hash,
			RequiredRTreePolicy: &pb.RTreePolicy{
				Namespace: src.Hash,
				Statements: []*pb.RTreePolicyStatement{
					&pb.RTreePolicyStatement{
						PermissionSet: src.Hash,
						Permissions:   []string{"default"},
						Resource:      "default",
					},
				},
			},
		})
	}
	waveTimeElapsed := time.Since(beforeTime)

	beforeTime = time.Now()
	ehash := iapi.HashSchemeInstanceFromMultihash(src.Hash)
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
	//This is not important
	nsloc := iapi.NewLocationSchemeInstanceURL("https://foo.com", 1).CanonicalForm()
	spol.NamespaceLocation = *nsloc

	wrappedPol := serdes.WaveWireObject{
		Content: asn1.NewExternal(spol),
	}
	polBytes, err := asn1.Marshal(wrappedPol.Content)
	if err != nil {
		panic(err)
	}

	polDER := (*C.char)(unsafe.Pointer(&polBytes[0]))
	subject := (*C.char)(unsafe.Pointer(&dst.Hash[2]))
	proofDER := (*C.char)(unsafe.Pointer(&proofresp.ProofDER[0]))
	proofDERlen := C.ulong(len(proofresp.ProofDER))
	for i := 0; i < 500; i++ {
		C.verify(proofDER, proofDERlen, subject, C.ulong(len(dst.Hash)-2),
			polDER, C.ulong(len(polBytes)))
	}
	fmt.Println("wave verification time: " + waveTimeElapsed.String())
	fmt.Println("enclave verification time: " + time.Since(beforeTime).String())
}
