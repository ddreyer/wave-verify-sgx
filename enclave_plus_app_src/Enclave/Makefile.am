## This line must come first when building an Intel SGX enclave.

include $(top_srcdir)/build-aux/sgx_enclave.am
include Makefile.am.libasncodec

## It sets the following Automake variables:
##
##   EXEEXT=.so
##   AM_CPPFLAGS = -I$(SGXSDK_INCDIR)
##   AM_LDFLAGS = -L$(SGXSDK_LIBDIR)
##   libexec_PROGRAMS = $(ENCLAVE)
##   CLEANFILES = $(ENCLAVE).signed.so
##
## and places required compiler flags in:
##
##   AM_CFLAGS
##   AM_CXXFLAGS
##
## It adds a pattern rule for building proxy functions from EDL files:
##
##   %_u.h %_u.c: %.edl
##
## And creates build targets for a signed enclave, generating a
## temporary private signing key, and a basic enclave config file:
##
##   $(ENCLAVE_CONFIG):
##   $(ENCLAVE_KEY):
##   $(ENCLAVE).signed$(EXEEXT): $(ENCLAVE)$(EXEEXT)
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
##   SGX_TRTS_LIB
##   SGX_TSERVICE_LIB
##   SGX_EDGER8R
##   SGX_SIGN

## Supply additional flags to edger8r here. 

SGX_EDGER8R_FLAGS=--search-path .. --search-path $(SGXSSL_INCDIR)

## The name of your enclave, enclave config file, and private key
## file go in these variables. The ENCLAVE variable creates the
## following automake target defn:
##
##    libexec_PROGRAMS=$(ENCLAVE)

ENCLAVE=Enclave
ENCLAVE_CONFIG=$(ENCLAVE).config.xml
ENCLAVE_KEY=$(ENCLAVE)_private.pem


## Additional Automake flags needed to build the enclave.
##
## AM_CPPFLAGS += 
## AM_CXXFLAGS +=

AM_CXXFLAGS += -I/home/sgx/go/src/github.com/samkumar/embedded-pairing/include -I$(SGX_SDK)/include/libcxx -Iwave-verify/include/verify -Iwave-verify/include/asn1c -Iwave-verify/src -I$(SGXSSL_INCDIR) -fpermissive
AM_CFLAGS += -Iwave-verify/include/asn1c

## Additional files to remove with 'make clean'. This list needs
## to include your edger8r genreated files.

CLEANFILES+= $(ENCLAVE)_t.c $(ENCLAVE)_t.h 


## Put your sources here. Don't forget to list the _t.c and _t.h 
## files. You can't use the $(ENCLAVE) variable in the build
## target name (i.e., $(ENCLAVE)_SOURCES will not work).
AUTOMAKE_OPTIONS = subdir-objects

ED_SRCS=wave-verify/src/ed25519/src/add_scalar.c wave-verify/src/ed25519/src/fe.c wave-verify/src/ed25519/src/ge.c \
wave-verify/src/ed25519/src/key_exchange.c wave-verify/src/ed25519/src/keypair.c wave-verify/src/ed25519/src/sc.c \
wave-verify/src/ed25519/src/sha512.c wave-verify/src/ed25519/src/sign.c wave-verify/src/ed25519/src/verify.c
HASH_SRCS=wave-verify/src/hash-library/keccak.cpp
VERIFY_SRCS=wave-verify/src/verify/verify.cpp

Enclave_SOURCES = Enclave_t.c Enclave_t.h $(HASH_SRCS) $(ED_SRCS) $(ASN_MODULE_SRCS) $(VERIFY_SRCS) Enclave.cpp \
	$(ENCLAVE_KEY) $(ENCLAVE_CONFIG)


## Add additional linker flags to AM_LDFLAGS here. Don't put 
## libraries flags here (see below).
##
## Be sure to use += to add to, and not replace, the default 
## AM_LDFLAGS.
##

# AM_LDFLAGS +=


## This line is REQUIRED. It can't be generically defined for 
## automake, so you must specify it for your enclave. Note that you
## can't say $(ENCLAVE)_LDADD here: you must spell out the enclave name.
## If you add flags to it, you MUST include @SGX_ENCLAVE_LDADD@ as part
## of the definition to make sure you pick up the right linker flags
## and SGX trusted libraries.

Enclave_LDADD = @SGX_ENCLAVE_LDADD@ -L$(SGXSSL_LIBDIR) /home/sgx/go/src/github.com/samkumar/embedded-pairing/pairing.a


## Place any additional trusted libraries that your enclave may need in
## SGX_EXTRA_TLIBS. This will ensure they get place inside the 
## --startgroup and --endgroup flags. (This would be where you'd add
## SGXSSL libraries, and your trusted c++ library

SGX_EXTRA_TLIBS=-lsgx_tkey_exchange -lsgx_tcxx -lsgx_tsgxssl -lsgx_tsgxssl_crypto


## This line is OPTIONAL, and comes with a WARNING.
##
## In general, you shouldn't need to use the program-specific LDFLAGS
## instead of AM_LDFLAGS. But, if you need to, then you'll need to ensure
## @SGX_ENCLAVE_LDFLAGS@ is included in the definition as this will 
## override AM_LDFLAGS.
##
## enclave_LDFLAGS = @SGX_ENCLAVE_LDFLAGS@
##
