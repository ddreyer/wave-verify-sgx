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
	fmt.Println(n)
	// s := string(block.Bytes[:n])
	cstr := C.CString(encoded)
	// cstr := C.CBytes(block.Bytes)
	defer C.free(unsafe.Pointer(cstr))
	C.init_and_verify(cstr, C.ulong(n))
}
