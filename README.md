# Verifying [WAVE](https://github.com/immesys/wave) proofs using Intel SGX

 * Adapted from the [Intel Remote Attestation Sample Code](https://github.com/intel/sgx-ra-sample)
 * To use this project, make sure to have prerequisites installed as specified in the above link
 * The file `utils/settings.h` contains options for the client and enclave/app
 * I have changed the build such that the client and enclave/app are built separately

## Building and Running the Client
  ```
  $ cd client_src
  $ ./bootstrap
  $ ./configure --with-openssldir=/opt/openssl/1.1.0i
  $ make
  $ ./run-client
  ```

## Building and Running the Enclave/App
```
  $ cd enclave_plus_app_src
  $ ./bootstrap
  $ ./configure --with-openssldir=/opt/openssl/1.1.0i
  $ make
  $ ./run-enclave-app
  ```

## Creating Enclave/App Shared Library
  * These three paths need to be in `$LD_LIBRARY_PATH`:
    * /opt/openssl/1.1.0i/lib
    * /home/sgx/wave-verify-sgx2/enclave_plus_app_src
    * /home/sgx/linux-sgx/linux/installer/bin/sgxsdk/sdk_libs
```
  $ make
  $ g++ -shared *.o ../utils/*.o -L/home/sgx/linux-sgx/linux/installer/bin/sgxsdk/lib64 -L/opt/openssl/1.1.0i/lib -L/opt/intel/sgxssl/lib64   -lsgx_urts -lsgx_ukey_exchange -lsgx_uae_service -lcrypto -l:libsgx_capable.a -lpthread -ldl -lsgx_usgxssl -o libtee.so
  ```

## TODO
  * build and link a static library
  * remove unneeded parts such as network code