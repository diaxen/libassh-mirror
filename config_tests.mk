#!/usr/bin/make -f

# Copyright (C) 2013 Alexandre Becoulet
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

.PHONY: all basic noserver noclient auth gcrypt nozlib nopacketpool alloca \
        nopubkeyauth nopasswordauth nohostbasedauth nokeyboardauth \
        nogcrypt nogcrypthash nogcryptalloc nogcryptcipher gcryptprng

all: basic noserver noclient auth gcrypt nozlib nopacketpool alloca

auth: nopubkeyauth nopasswordauth nohostbasedauth nokeyboardauth noneauth

gcrypt: nogcrypt nogcrypthash nogcryptalloc nogcryptcipher gcryptprng

basic:
	./configure
	grep -q "define CONFIG_ASSH_SERVER" config.h
	grep -q "define CONFIG_ASSH_CLIENT" config.h
	grep -q "define CONFIG_ASSH_PACKET_POOL" config.h
	grep -q "undef CONFIG_ASSH_ALLOCA" config.h
	grep -q "define CONFIG_ASSH_USE_ZLIB" config.h
	grep -q "define CONFIG_ASSH_USE_GCRYPT" config.h
	grep -q "define CONFIG_ASSH_USE_GCRYPT_HASH" config.h
	grep -q "define CONFIG_ASSH_USE_GCRYPT_CIPHERS" config.h
	grep -q "undef CONFIG_ASSH_USE_GCRYPT_BIGNUM" config.h
	grep -q "define CONFIG_ASSH_USE_GCRYPT_ALLOC" config.h
	grep -q "undef CONFIG_ASSH_USE_GCRYPT_PRNG" config.h
	grep -q "undef CONFIG_ASSH_SERVER_AUTH_NONE" config.h
	grep -q "define CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY" config.h
	grep -q "define CONFIG_ASSH_SERVER_AUTH_PUBLICKEY" config.h
	grep -q "define CONFIG_ASSH_CLIENT_AUTH_PASSWORD" config.h
	grep -q "define CONFIG_ASSH_SERVER_AUTH_PASSWORD" config.h
	grep -q "define CONFIG_ASSH_CLIENT_AUTH_HOSTBASED" config.h
	grep -q "define CONFIG_ASSH_SERVER_AUTH_HOSTBASED" config.h
	grep -q "define CONFIG_ASSH_CLIENT_AUTH_KEYBOARD" config.h
	grep -q "define CONFIG_ASSH_SERVER_AUTH_KEYBOARD" config.h
	$(MAKE) $(MAKE_TARGET)

noserver:
	./configure --disable-server
	grep -q "undef CONFIG_ASSH_SERVER" config.h
	$(MAKE) $(MAKE_TARGET)

noclient:
	./configure --disable-client
	grep -q "undef CONFIG_ASSH_CLIENT" config.h
	$(MAKE) $(MAKE_TARGET)

nopacketpool:
	./configure --disable-packet-pool
	grep -q "undef CONFIG_ASSH_PACKET_POOL" config.h
	$(MAKE)
	test/connection
	test/userauth
	test/userauth_server
	test/kex

alloca:
	./configure --enable-alloca
	grep -q "define CONFIG_ASSH_ALLOCA" config.h
	$(MAKE) $(MAKE_TARGET)

nozlib:
	./configure --disable-zlib
	grep -q "undef CONFIG_ASSH_USE_ZLIB" config.h
	$(MAKE)
	test/kex

nogcrypt:
	./configure --disable-gcrypt
	grep -q "undef CONFIG_ASSH_USE_GCRYPT" config.h
	$(MAKE) $(MAKE_TARGET)

nogcrypthash:
	./configure --disable-gcrypt-hash
	grep -q "undef CONFIG_ASSH_USE_GCRYPT_HASH" config.h
	$(MAKE)
	test/hash
	test/kex
	test/signature

nogcryptcipher:
	./configure --disable-gcrypt-ciphers
	grep -q "undef CONFIG_ASSH_USE_GCRYPT_CIPHERS" config.h
	$(MAKE)
	test/kex
	test/key_io

nogcryptalloc:
	./configure --disable-gcrypt-alloc
	grep -q "undef CONFIG_ASSH_USE_GCRYPT_ALLOC" config.h
	$(MAKE) $(MAKE_TARGET)

gcryptprng:
	./configure --enable-gcrypt-prng
	grep -q "define CONFIG_ASSH_USE_GCRYPT_PRNG" config.h
	$(MAKE)
	test/kex
	test/bignum

noneauth:
	./configure --enable-none-userauth
	grep -q "define CONFIG_ASSH_SERVER_AUTH_NONE" config.h
	$(MAKE)
	test/userauth
	test/userauth_server

nopubkeyauth:
	./configure --disable-publickey-userauth
	grep -q "undef CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY" config.h
	grep -q "undef CONFIG_ASSH_SERVER_AUTH_PUBLICKEY" config.h
	$(MAKE)
	test/userauth
	test/userauth_server

nopasswordauth:
	./configure --disable-password-userauth
	grep -q "undef CONFIG_ASSH_CLIENT_AUTH_PASSWORD" config.h
	grep -q "undef CONFIG_ASSH_SERVER_AUTH_PASSWORD" config.h
	$(MAKE)
	test/userauth
	test/userauth_server

nohostbasedauth:
	./configure --disable-hostbased-userauth
	grep -q "undef CONFIG_ASSH_CLIENT_AUTH_HOSTBASED" config.h
	grep -q "undef CONFIG_ASSH_SERVER_AUTH_HOSTBASED" config.h
	$(MAKE)
	test/userauth
	test/userauth_server

nokeyboardauth:
	./configure --disable-keyboard-userauth
	grep -q "undef CONFIG_ASSH_CLIENT_AUTH_KEYBOARD" config.h
	grep -q "undef CONFIG_ASSH_SERVER_AUTH_KEYBOARD" config.h
	$(MAKE)
	test/userauth
	test/userauth_server
