package verify

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/immesys/wave/eapi/pb"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

var waveconn pb.WAVEClient
var Src *pb.CreateEntityResponse
var Dst *pb.CreateEntityResponse
var Proof []byte

// initializes waved connection, enclave, two default entities with no expiry, and an attestation
func init() {
	conn, err := grpc.Dial("127.0.0.1:410", grpc.WithInsecure(), grpc.FailOnNonTempDialError(true), grpc.WithBlock())
	if err != nil {
		fmt.Printf("failed to connect to agent: %v\n", err)
		os.Exit(1)
	}
	waveconn = pb.NewWAVEClient(conn)
	if err := InitEnclave(); err != nil {
		panic(err)
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
	Proof = proofresp.ProofDER

	// encresp, err := waveconn.EncryptMessage(context.Background(), &pb.EncryptMessageParams{
	// 	Namespace: Src.Hash,
	// 	Resource:  "whatever",
	// 	Content:   []byte("whatever"),
	// })
	// if err != nil {
	// 	panic(err)
	// }
	// if encresp.Error != nil {
	// 	panic(encresp.Error.Message)
	// }

	// resp, err := waveconn.GetDecryptKey(context.Background(), &pb.DecryptMessageParams{
	// 	Perspective: &pb.Perspective{
	// 		EntitySecret: &pb.EntitySecret{
	// 			DER: Dst.SecretDER,
	// 		},
	// 	},
	// 	Ciphertext:  encresp.Ciphertext,
	// 	ResyncFirst: true,
	// })
	// if err != nil {
	// 	panic(err)
	// }
	// if resp.Error != nil {
	// 	panic(resp.Error.Message)
	// }
	// Key = resp.Key
	// Id = resp.Id
	// k := (*C.char)(unsafe.Pointer(&Key[0]))
	// i := (*C.char)(unsafe.Pointer(&Iv[0]))
	// ret = C.provision_key(k, i)
	// if int32(ret) != 0 {
	// 	panic("Could not provision key")
	// }
}

func checkVerification(t *testing.T, DER []byte, subjectHash []byte, pbPol *pb.RTreePolicy) {
	// fmt.Println("key")
	// fmt.Println(string(Key))
	// fmt.Println("iv")
	// fmt.Println(string(Iv))

	// encresp, err := waveconn.EncryptProof(context.Background(), &pb.EncryptMessageParams{
	// 	Namespace: Src.Hash,
	// 	Resource:  "whatever",
	// 	Content:   proofresp.ProofDER,
	// })
	// if err != nil {
	// 	panic(err)
	// }
	// if encresp.Error != nil {
	// 	panic(encresp.Error.Message)
	// }
	// decryptedProof, err := iapi.DecryptProofWithKey(context.Background(), &iapi.PDecryptProof{
	// 	Ciphertext: DER,
	// 	Key:        Key,
	// 	Id:         Id,
	// })
	// if err != nil {
	// 	return wve.ErrW(wve.MessageDecryptionError, "failed to decrypt", err)
	// }
	verifyresp, err := waveconn.VerifyProof(context.Background(), &pb.VerifyProofParams{
		ProofDER:            DER,
		Subject:             subjectHash,
		RequiredRTreePolicy: pbPol,
	})
	require.NoError(t, err)
	waveTime := time.Unix(verifyresp.Result.GetExpiry()/1e3, 0)

	proofTime, err := VerifyProof(DER, subjectHash, pbPol)
	if verifyresp.Error == nil {
		require.NoError(t, err)
	} else {
		require.Error(t, err)
	}
	if err == nil {
		require.True(t, waveTime.Equal(proofTime))
	}
}

// tests basic attestation
func TestBasic(t *testing.T) {
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
	checkVerification(t, Proof, Dst.Hash, &pbPol)
}

// tests key sealing functionality
// func testBasicSealing() TestVerifyError {
// 	ret := C.destroy_enclave()
// 	if ret != 0 {
// 		fmt.Printf("error destroying enclave")
// 		os.Exit(1)
// 	}
// 	ret = C.init_enclave()
// 	if ret != 0 {
// 		fmt.Printf("error initializing enclave")
// 		os.Exit(1)
// 	}
// 	proofresp, err := waveconn.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
// 		Perspective: &pb.Perspective{
// 			EntitySecret: &pb.EntitySecret{
// 				DER: Dst.SecretDER,
// 			},
// 		},
// 		SubjectHash: Dst.Hash,
// 		Namespace:   Src.Hash,
// 		Statements: []*pb.RTreePolicyStatement{
// 			&pb.RTreePolicyStatement{
// 				PermissionSet: Src.Hash,
// 				Permissions:   []string{"default"},
// 				Resource:      "default",
// 			},
// 		},
// 		ResyncFirst: true,
// 	})
// 	if err != nil {
// 		panic(err)
// 	}
// 	if proofresp.Error != nil {
// 		panic(proofresp.Error.Message)
// 	}

// 	ehash := iapi.HashSchemeInstanceFromMultihash(Src.Hash)
// 	if !ehash.Supported() {
// 		panic(wve.Err(wve.InvalidParameter, "bad namespace"))
// 	}
// 	ext := ehash.CanonicalForm()

// 	spol := serdes.RTreePolicy{
// 		Namespace: *ext,
// 		Statements: []serdes.RTreeStatement{
// 			{
// 				PermissionSet: *ext,
// 				Permissions:   []string{"default"},
// 				Resource:      "default",
// 			},
// 		},
// 	}

// 	pbPol := pb.RTreePolicy{
// 		Namespace: Src.Hash,
// 		Statements: []*pb.RTreePolicyStatement{
// 			&pb.RTreePolicyStatement{
// 				PermissionSet: Src.Hash,
// 				Permissions:   []string{"default"},
// 				Resource:      "default",
// 			},
// 		},
// 	}
// 	encresp, err := waveconn.EncryptProof(context.Background(), &pb.EncryptMessageParams{
// 		Namespace: Src.Hash,
// 		Resource:  "whatever",
// 		Content:   proofresp.ProofDER,
// 	})
// 	if err != nil {
// 		panic(err)
// 	}
// 	if encresp.Error != nil {
// 		panic(encresp.Error.Message)
// 	}

// 	// resp, err := waveconn.GetDecryptKey(context.Background(), &pb.DecryptMessageParams{
// 	// 	Perspective: &pb.Perspective{
// 	// 		EntitySecret: &pb.EntitySecret{
// 	// 			DER: Dst.SecretDER,
// 	// 		},
// 	// 	},
// 	// 	Ciphertext: encresp.Ciphertext,
// 	// })
// 	// if err != nil {
// 	// 	panic(err)
// 	// }
// 	// if resp.Error != nil {
// 	// 	panic(resp.Error.Message)
// 	// }
// 	// key := resp.Content[:16]
// 	// iv := resp.Content[16:]
// 	// k := (*C.char)(unsafe.Pointer(&key[0]))
// 	// i := (*C.char)(unsafe.Pointer(&iv[0]))
// 	// ret = C.provision_key(k, i)
// 	// if int32(ret) != 0 {
// 	// 	panic("Could not provision key")
// 	// }
// 	return checkVerification(encresp.Ciphertext, &spol, &pbPol, Dst.Hash)

// 	// src, err := waveconn.CreateEntity(context.Background(), &pb.CreateEntityParams{
// 	// 	ValidFrom:  time.Now().Add(time.Second).UnixNano() / 1e6,
// 	// 	ValidUntil: time.Now().Add(time.Minute*10).UnixNano() / 1e6,
// 	// })
// 	// if err != nil {
// 	// 	panic(err)
// 	// }
// 	// if src.Error != nil {
// 	// 	panic(src.Error.Message)
// 	// }
// 	// dst, err := waveconn.CreateEntity(context.Background(), &pb.CreateEntityParams{
// 	// 	ValidUntil:       time.Now().Add(time.Minute*20).UnixNano() / 1e6,
// 	// 	SecretPassphrase: "wave",
// 	// })
// 	// if err != nil {
// 	// 	panic(err)
// 	// }
// 	// if dst.Error != nil {
// 	// 	panic(dst.Error.Message)
// 	// }
// 	// srcresp, err := waveconn.PublishEntity(context.Background(), &pb.PublishEntityParams{
// 	// 	DER: src.PublicDER,
// 	// 	Location: &pb.Location{
// 	// 		AgentLocation: "default",
// 	// 	},
// 	// })
// 	// if err != nil {
// 	// 	panic(err)
// 	// }
// 	// if srcresp.Error != nil {
// 	// 	panic(srcresp.Error.Message)
// 	// }
// 	// dstresp, err := waveconn.PublishEntity(context.Background(), &pb.PublishEntityParams{
// 	// 	DER: dst.PublicDER,
// 	// })
// 	// if err != nil {
// 	// 	panic(err)
// 	// }
// 	// if dstresp.Error != nil {
// 	// 	panic(dstresp.Error.Message)
// 	// }
// }

// tests memory management of enclave by verifying many proofs
func TestBulkVerify(t *testing.T) {
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
	for i := 0; i < 500; i++ {
		fmt.Printf("Test Bulk Verify: Starting iteration %d\n", i)
		checkVerification(t, Proof, Dst.Hash, &pbPol)
	}
}

// tests memory management of enclave by trying to verify many invalid proofs
func TestBulkInvalidProofVerify(t *testing.T) {
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
	proofCopy := make([]byte, len(Proof))
	garbage := []byte("garbagegarbage")
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < 500; i++ {
		fmt.Printf("Test Bulk Invalid Proof Verify: Starting iteration %d\n", i)
		copy(proofCopy, Proof)
		ind := r.Intn(len(proofCopy) - 14)
		copy(proofCopy[ind:ind+14], garbage)
		checkVerification(t, Proof, Dst.Hash, &pbPol)
	}
}

// tests memory management of enclave by trying to verify many proofs with an invalid policy
func TestBulkInvalidPolicyVerify(t *testing.T) {
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
	for i := 0; i < 500; i++ {
		fmt.Printf("Test Bulk Invalid Policy Verify: Starting iteration %d\n", i)
		checkVerification(t, Proof, Dst.Hash, &pbPol)
	}
}

func BenchmarkProofVerify(b *testing.B) {
	prevEnt := Dst
	ent := prevEnt
	var err error
	for i := 0; i < 0; i++ {
		ent, err = waveconn.CreateEntity(context.Background(), &pb.CreateEntityParams{})
		require.NoError(b, err)
		require.Nil(b, ent.Error)
		entresp, err := waveconn.PublishEntity(context.Background(), &pb.PublishEntityParams{
			DER: ent.PublicDER,
		})
		require.NoError(b, err)
		require.Nil(b, entresp.Error)
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
		require.NoError(b, err)
		require.Nil(b, attresp.Error)
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
	require.NoError(b, err)
	require.Nil(b, proofresp.Error)
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
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyProof(proofresp.ProofDER, ent.Hash, &pbPol)
	}
}
