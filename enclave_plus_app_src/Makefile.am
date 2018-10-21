## This must come first when building an application that uses Intel
## SGX enclaves.

include $(top_srcdir)/build-aux/sgx_app.am

## It sets the following automake variables:
##
##   AM_CPPFLAGS = -I$(SGXSDK_INCDIR)
##   AM_LDFLAGS = -L$(SGXSDK_LIBDIR)
##
## And a pattern rule for building proxy functions from EDL files:
##
##   %_u.h %_u.c: %.edl
##
## And sets these Makefile variables:
##
##   SGXSDK
##   SGXSDK_BINDIR
##   SGXSDK_INCDIR
##   SGXSDK_LIBDIR
##   SGXSSL
##   SGXSSL_BINDIR
##   SGXSSL_INCDIR
##   SGXSSL_LIBDIR
##   SGX_URTS_LIB
##   SGX_UAE_SERVICE_LIB
##   SGX_EDGER8R

SUBDIRS = Enclave 

## Supply additional flags to edger8r here. 
##
SGX_EDGER8R_FLAGS=--search-path $(SGXSSL_INCDIR)


## Needed to make our pattern rule work

Enclave.edl: Enclave/Enclave.edl
	ln -s $?

Enclave.signed.so: Enclave/Enclave.signed.so
	ln -s $?


## Additional automake variables
AM_CFLAGS = -fPIC
AM_CXXFLAGS = -std=c++11 -fPIC -I../utils
AM_CPPFLAGS += -fno-builtin-memset @OPENSSL_CPPFLAGS@

## Additional targets to remove with 'make clean'. You must list
## any edger8r generated files here.

CLEANFILES = Enclave_u.c Enclave_u.h Enclave.edl Enclave.signed.so

AUTOMAKE_OPTIONS = subdir-objects

## The build target

bin_PROGRAMS = enclave_app 

## You can't use $(wildcard ...) with automake so all source files 
## have to be explicitly listed.

common = ../utils/byteorder.c ../utils/common.cpp ../utils/crypto.c ../utils/hexutil.c \
		../utils/fileio.c ../utils/base64.c ../utils/msgio.cpp ../utils/logfile.c

## client 

enclave_app_SOURCES = enclave_app.cpp sgx_detect_linux.c sgx_stub.c \
	$(common)
nodist_enclave_app_SOURCES = Enclave_u.c Enclave_u.h
EXTRA_enclave_app_DEPENDENCIES = Enclave.signed.so
BUILT_SOURCES = Enclave_u.c Enclave_u.h

enclave_app_LDFLAGS= $(AM_LDFLAGS) @OPENSSL_LDFLAGS@ -L$(SGXSSL_LIBDIR)

## Library flags. At minimum, an Intel SGX application will need:
##
##   -l$(SGX_URTS_LIB)
##
## Applications that use platform services or perform attestation
## will also need:
##
##  -l$(SGX_UAE_SERVICE_LIB)
##
## Use the variables, not the actual library names to ensure these
## targets work on simulation builds.

enclave_app_LDADD=-l$(SGX_URTS_LIB) -lsgx_ukey_exchange -l$(SGX_UAE_SERVICE_LIB) \
	-lcrypto -l:libsgx_capable.a -lpthread -ldl -lsgx_usgxssl

