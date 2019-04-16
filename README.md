# Verifying [WAVE](https://github.com/immesys/wave) proofs using Intel SGX
This code is adapted from the [Intel Remote Attestation Sample Code](https://github.com/intel/sgx-ra-sample) and includes a WAVE proof verification [library](https://github.com/ddreyer/wave-verify) as a submodule. To use this project, make sure to have the prerequisites installed as specified in the first link.

## Other Notes
 * The file `utils/settings.h` contains options for the client and enclave/app
 * I have changed the build such that the client and enclave/app are built separately

## Using this Library
First, clone the repository into the appropriate directory in your Go source tree (`src/github.com/ddreyer/wave-verify-sgx`) and then build the library as described below. This library can be used as an imported package via `import "github.com/ddreyer/wave-verify-sgx/lang/go"`. A Go testing suite can be run via the command `go test` in the `lang/go` directory. The testing suite requires that the WAVE daemon be running. WAVE releases can be found [here](https://github.com/immesys/wave/releases)

### Building the Enclave library
 * These three paths need to be in your `LD_LIBRARY_PATH` environment variable:
    * /opt/openssl/1.1.0i/lib
    * $GOPATH/src/github.com/ddreyer/wave-verify-sgx/enclave_plus_app_src
    * Path to Intel SGX Linux libraries ($PREFIX/linux-sgx/linux/installer/bin/sgxsdk/sdk_libs)
```
  $ cd enclave_plus_app_src
  $ ./bootstrap
  $ ./configure --with-openssldir=/opt/openssl/1.1.0i
  $ make
  $ ./run-enclave-app
  $ g++ -shared *.o ../utils/*.o -L/home/sgx/linux-sgx/linux/installer/bin/sgxsdk/lib64 -L/opt/openssl/1.1.0i/lib -L/opt/intel/sgxssl/lib64   -lsgx_urts -lsgx_ukey_exchange -lsgx_uae_service -lcrypto -l:libsgx_capable.a -lpthread -ldl -lsgx_usgxssl -o libverify.so
  ```

### Building and Running the Client
  ```
  $ cd client_src
  $ ./bootstrap
  $ ./configure --with-openssldir=/opt/openssl/1.1.0i
  $ make
  $ ./run-client
  ```
