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


## Additional automake variables
AM_CFLAGS = -fPIC
AM_CXXFLAGS = -std=c++11 -fPIC -I../utils
AM_CPPFLAGS += -fno-builtin-memset @OPENSSL_CPPFLAGS@
AUTOMAKE_OPTIONS = subdir-objects

## The build target

bin_PROGRAMS = client

## You can't use $(wildcard ...) with automake so all source files 
## have to be explicitly listed.

common = ../utils/byteorder.c ../utils/common.cpp ../utils/crypto.c ../utils/hexutil.c \
		../utils/fileio.c ../utils/base64.c ../utils/msgio.cpp ../utils/logfile.c

## sp

client_SOURCES = client.cpp agent_wget.cpp iasrequest.cpp $(common)
if AGENT_CURL
client_SOURCES += agent_curl.cpp
endif

client_LDFLAGS= $(AM_LDFLAGS) @OPENSSL_LDFLAGS@ @CURL_LDFLAGS@

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

client_LDADD=-lcrypto @CURL_LIBS@
