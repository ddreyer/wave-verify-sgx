# Verifying WAVE proofs using Intel SGX

 * Adapted from the [Intel Remote Attestation Sample Code](https://github.com/intel/sgx-ra-sample)
 * To use this project, make sure to have prerequisites installed as specified in the above link
 * The file `utils/settings.h` contains options for the client and enclave/app
 * I have changed the build such that the client and enclave/app are built separately

## Building and Running the Client
  ```
  $ ./bootstrap
  $ ./configure --with-openssldir=/opt/openssl/1.1.0i
  $ make
  $ ./run-client
  ```

## Building and Running the Enclave/App
```
  $ ./bootstrap
  $ ./configure --with-openssldir=/opt/openssl/1.1.0i
  $ make
  $ ./run-enclave-app
  ```