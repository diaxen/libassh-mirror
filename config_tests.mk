#!/usr/bin/make -f

# Copyright (C) 2013-2020 Alexandre Becoulet
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/>.

.NOTPARALLEL:

MAKE=make
MAKE_TARGET=check
ASSH_PATH=.
TEST_PATH=test/

.PHONY: all auth.cfgtest gcrypt.cfgtest openssl.cfgtest builtin.cfgtest
#       basic noserver noclient nozlib nopacketpool alloca \
#        nopubkeyauth nopasswordauth nohostbasedauth nokeyboardauth \
#        nogcrypt gcrypthash gcryptalloc gcryptcipher gcryptprng \
#	noopenssl opensslhash opensslalloc opensslcipher opensslprng \
#	builtinhash builtinalloc builtincipher builtinprng \
#	nokeycreate nokeyvalidate ndebug

all: basic.cfgtest noserver.cfgtest noclient.cfgtest auth.cfgtest gcrypt.cfgtest openssl.cfgtest builtin.cfgtest nozlib.cfgtest	\
	nopacketpool.cfgtest alloca.cfgtest nokeyvalidate.cfgtest nokeycreate.cfgtest

auth.cfgtest: nopubkeyauth.cfgtest nopasswordauth.cfgtest nohostbasedauth.cfgtest nokeyboardauth.cfgtest nononeauth.cfgtest

gcrypt.cfgtest: nogcrypt.cfgtest gcrypthash.cfgtest gcryptalloc.cfgtest gcryptcipher.cfgtest gcryptprng.cfgtest
openssl.cfgtest: noopenssl.cfgtest opensslhash.cfgtest opensslalloc.cfgtest opensslcipher.cfgtest opensslprng.cfgtest
builtin.cfgtest: builtinhash.cfgtest builtinalloc.cfgtest builtincipher.cfgtest builtinprng.cfgtest

basic.cfgtest:
	$(ASSH_PATH)/configure
	grep -q "define CONFIG_ASSH_SERVER" config.h
	grep -q "define CONFIG_ASSH_CLIENT" config.h
	grep -q "define CONFIG_ASSH_PACKET_POOL" config.h
	grep -q "undef CONFIG_ASSH_ALLOCA" config.h
	grep -q "define CONFIG_ASSH_USE_ZLIB" config.h
	grep -q "define CONFIG_ASSH_USE_GCRYPT" config.h
	grep -q "define CONFIG_ASSH_USE_GCRYPT_HASH" config.h
	grep -q "define CONFIG_ASSH_USE_GCRYPT_CIPHERS" config.h
	grep -q "define CONFIG_ASSH_USE_GCRYPT_ALLOC" config.h
	grep -q "undef CONFIG_ASSH_USE_GCRYPT_PRNG" config.h
	grep -q "undef CONFIG_ASSH_USE_OPENSSL" config.h
	grep -q "undef CONFIG_ASSH_USE_OPENSSL_HASH" config.h
	grep -q "undef CONFIG_ASSH_USE_OPENSSL_CIPHERS" config.h
	grep -q "undef CONFIG_ASSH_USE_OPENSSL_ALLOC" config.h
	grep -q "undef CONFIG_ASSH_USE_OPENSSL_PRNG" config.h
	grep -q "define CONFIG_ASSH_SERVER_AUTH_NONE" config.h
	grep -q "define CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY" config.h
	grep -q "define CONFIG_ASSH_SERVER_AUTH_PUBLICKEY" config.h
	grep -q "define CONFIG_ASSH_CLIENT_AUTH_PASSWORD" config.h
	grep -q "define CONFIG_ASSH_SERVER_AUTH_PASSWORD" config.h
	grep -q "define CONFIG_ASSH_CLIENT_AUTH_HOSTBASED" config.h
	grep -q "define CONFIG_ASSH_SERVER_AUTH_HOSTBASED" config.h
	grep -q "define CONFIG_ASSH_CLIENT_AUTH_KEYBOARD" config.h
	grep -q "define CONFIG_ASSH_SERVER_AUTH_KEYBOARD" config.h
	grep -q "define CONFIG_ASSH_KEY_CREATE" config.h
	grep -q "define CONFIG_ASSH_KEY_VALIDATE" config.h
	grep -q "undef NDEBUG" config.h
	$(MAKE) $(MAKE_TARGET)
	touch $@

noserver.cfgtest:
	$(ASSH_PATH)/configure --disable-server
	grep -q "undef CONFIG_ASSH_SERVER" config.h
	$(MAKE) $(MAKE_TARGET)
	touch $@

noclient.cfgtest:
	$(ASSH_PATH)/configure --disable-client
	grep -q "undef CONFIG_ASSH_CLIENT" config.h
	$(MAKE) $(MAKE_TARGET)
	touch $@

nokeycreate.cfgtest:
	$(ASSH_PATH)/configure --disable-key-create
	grep -q "undef CONFIG_ASSH_KEY_CREATE" config.h
	$(MAKE)
	$(TEST_PATH)/kex
	touch $@

nokeyvalidate.cfgtest:
	$(ASSH_PATH)/configure --disable-key-validate
	grep -q "undef CONFIG_ASSH_KEY_VALIDATE" config.h
	$(MAKE)
	$(TEST_PATH)/kex
	touch $@

nopacketpool.cfgtest:
	$(ASSH_PATH)/configure --disable-packet-pool
	grep -q "undef CONFIG_ASSH_PACKET_POOL" config.h
	$(MAKE)
	$(TEST_PATH)/connection
	$(TEST_PATH)/userauth
	$(TEST_PATH)/userauth_server
	$(TEST_PATH)/kex
	touch $@

alloca.cfgtest:
	$(ASSH_PATH)/configure --enable-alloca
	grep -q "define CONFIG_ASSH_ALLOCA" config.h
	$(MAKE) $(MAKE_TARGET)
	touch $@

ndebug.cfgtest:
	$(ASSH_PATH)/configure --disable-assert
	grep -q "define NDEBUG" config.h
	$(MAKE) $(MAKE_TARGET)
	touch $@

nozlib.cfgtest:
	$(ASSH_PATH)/configure --without-zlib
	grep -q "undef CONFIG_ASSH_USE_ZLIB" config.h
	$(MAKE)
	$(TEST_PATH)/kex
	touch $@

nogcrypt.cfgtest:
	$(ASSH_PATH)/configure --without-gcrypt
	grep -q "undef CONFIG_ASSH_USE_GCRYPT" config.h
	grep -q "undef CONFIG_ASSH_USE_GCRYPT_HASH" config.h
	grep -q "undef CONFIG_ASSH_USE_GCRYPT_CIPHERS" config.h
	grep -q "undef CONFIG_ASSH_USE_GCRYPT_ALLOC" config.h
	grep -q "undef CONFIG_ASSH_USE_GCRYPT_PRNG" config.h
	$(MAKE)
	$(TEST_PATH)/hash
	$(TEST_PATH)/cipher
	$(TEST_PATH)/kex
	touch $@

gcrypthash.cfgtest:
	$(ASSH_PATH)/configure --with-hashes=gcrypt
	grep -q "define CONFIG_ASSH_USE_GCRYPT_HASH" config.h
	$(MAKE)
	$(TEST_PATH)/hash
	$(TEST_PATH)/signature
	touch $@

gcryptcipher.cfgtest:
	$(ASSH_PATH)/configure --with-ciphers=gcrypt
	grep -q "define CONFIG_ASSH_USE_GCRYPT_CIPHERS" config.h
	$(MAKE)
	$(TEST_PATH)/cipher
	$(TEST_PATH)/kex
	$(TEST_PATH)/key_io
	touch $@

gcryptalloc.cfgtest:
	$(ASSH_PATH)/configure --with-alloc=gcrypt
	grep -q "define CONFIG_ASSH_USE_GCRYPT_ALLOC" config.h
	$(MAKE) $(MAKE_TARGET)
	touch $@

gcryptprng.cfgtest:
	$(ASSH_PATH)/configure --with-prng=gcrypt
	grep -q "define CONFIG_ASSH_USE_GCRYPT_PRNG" config.h
	$(MAKE)
	$(TEST_PATH)/bignum
	touch $@

noopenssl.cfgtest:
	$(ASSH_PATH)/configure --without-openssl
	grep -q "undef CONFIG_ASSH_USE_OPENSSL" config.h
	grep -q "undef CONFIG_ASSH_USE_OPENSSL_HASH" config.h
	grep -q "undef CONFIG_ASSH_USE_OPENSSL_CIPHERS" config.h
	grep -q "undef CONFIG_ASSH_USE_OPENSSL_ALLOC" config.h
	grep -q "undef CONFIG_ASSH_USE_OPENSSL_PRNG" config.h
	$(MAKE)
	$(TEST_PATH)/hash
	$(TEST_PATH)/cipher
	$(TEST_PATH)/kex
	touch $@

opensslhash.cfgtest:
	$(ASSH_PATH)/configure --with-hashes=openssl
	grep -q "define CONFIG_ASSH_USE_OPENSSL_HASH" config.h
	$(MAKE)
	$(TEST_PATH)/hash
	$(TEST_PATH)/signature
	touch $@

opensslcipher.cfgtest:
	$(ASSH_PATH)/configure --with-ciphers=openssl
	grep -q "define CONFIG_ASSH_USE_OPENSSL_CIPHERS" config.h
	$(MAKE)
	$(TEST_PATH)/cipher
	$(TEST_PATH)/kex
	$(TEST_PATH)/key_io
	touch $@

opensslalloc.cfgtest:
	$(ASSH_PATH)/configure --with-alloc=openssl
	grep -q "define CONFIG_ASSH_USE_OPENSSL_ALLOC" config.h
	$(MAKE)
	touch $@

opensslprng.cfgtest:
	$(ASSH_PATH)/configure --with-prng=openssl
	grep -q "define CONFIG_ASSH_USE_OPENSSL_PRNG" config.h
	$(MAKE)
	$(TEST_PATH)/bignum
	touch $@

builtinhash.cfgtest:
	$(ASSH_PATH)/configure --with-hashes=builtin
	grep -q "undef CONFIG_ASSH_USE_GCRYPT_HASH" config.h
	grep -q "undef CONFIG_ASSH_USE_OPENSSL_HASH" config.h
	$(MAKE)
	$(TEST_PATH)/hash
	$(TEST_PATH)/signature
	touch $@

builtincipher.cfgtest:
	$(ASSH_PATH)/configure --with-ciphers=builtin
	grep -q "undef CONFIG_ASSH_USE_GCRYPT_CIPHERS" config.h
	grep -q "undef CONFIG_ASSH_USE_OPENSSL_CIPHERS" config.h
	$(MAKE)
	$(TEST_PATH)/cipher
	$(TEST_PATH)/kex
	$(TEST_PATH)/key_io
	touch $@

builtinalloc.cfgtest:
	$(ASSH_PATH)/configure --with-alloc=builtin
	grep -q "undef CONFIG_ASSH_USE_GCRYPT_ALLOC" config.h
	grep -q "undef CONFIG_ASSH_USE_OPENSSL_ALLOC" config.h
	$(MAKE)
	touch $@

builtinprng.cfgtest:
	$(ASSH_PATH)/configure --with-prng=builtin
	grep -q "undef CONFIG_ASSH_USE_GCRYPT_PRNG" config.h
	grep -q "undef CONFIG_ASSH_USE_OPENSSL_PRNG" config.h
	$(MAKE)
	$(TEST_PATH)/bignum
	touch $@

nononeauth.cfgtest:
	$(ASSH_PATH)/configure --disable-none-userauth
	grep -q "undef CONFIG_ASSH_SERVER_AUTH_NONE" config.h
	$(MAKE)
	$(TEST_PATH)/userauth
	$(TEST_PATH)/userauth_server
	touch $@

nopubkeyauth.cfgtest:
	$(ASSH_PATH)/configure --disable-publickey-userauth
	grep -q "undef CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY" config.h
	grep -q "undef CONFIG_ASSH_SERVER_AUTH_PUBLICKEY" config.h
	$(MAKE)
	$(TEST_PATH)/userauth
	$(TEST_PATH)/userauth_server
	touch $@

nopasswordauth.cfgtest:
	$(ASSH_PATH)/configure --disable-password-userauth
	grep -q "undef CONFIG_ASSH_CLIENT_AUTH_PASSWORD" config.h
	grep -q "undef CONFIG_ASSH_SERVER_AUTH_PASSWORD" config.h
	$(MAKE)
	$(TEST_PATH)/userauth
	$(TEST_PATH)/userauth_server
	touch $@

nohostbasedauth.cfgtest:
	$(ASSH_PATH)/configure --disable-hostbased-userauth
	grep -q "undef CONFIG_ASSH_CLIENT_AUTH_HOSTBASED" config.h
	grep -q "undef CONFIG_ASSH_SERVER_AUTH_HOSTBASED" config.h
	$(MAKE)
	$(TEST_PATH)/userauth
	$(TEST_PATH)/userauth_server
	touch $@

nokeyboardauth.cfgtest:
	$(ASSH_PATH)/configure --disable-keyboard-userauth
	grep -q "undef CONFIG_ASSH_CLIENT_AUTH_KEYBOARD" config.h
	grep -q "undef CONFIG_ASSH_SERVER_AUTH_KEYBOARD" config.h
	$(MAKE)
	$(TEST_PATH)/userauth
	$(TEST_PATH)/userauth_server
	touch $@
