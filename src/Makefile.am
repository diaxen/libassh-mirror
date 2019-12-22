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

AM_CPPFLAGS = -I$(top_builddir)/src/assh
SUBDIRS = assh

lib_LTLIBRARIES = libassh.la

libassh_la_SOURCES = assh_context.c assh_session.c assh_packet.c	\
	assh_event.c assh_transport.c assh_kex.c assh_hash.c		\
	assh_algo.c assh_key.c assh_service.c assh_map.c assh_bignum.c	\
	assh_connection.c assh_debug.c assh_buffer.c			\
	kex_none.c kex_dh.c kex_dh_gex.c kex_rsa.c			\
	kex_ecdh_montgomery.c kex_ecdh_weierstrass.c			\
	ecc_weierstrass.c ecc_weierstrass.h				\
	mac_none.c							\
	key_dsa.c key_rsa.c key_eddsa.c key_ecdsa.c key_none.c		\
	sign_dsa.c sign_rsa.c sign_eddsa.c sign_ecdsa.c sign_none.c	\
	compress_none.c							\
	helper_key.c helper_io.c helper_base64.c helper_bcrypt.c	\
	prng_xswap_builtin.c helper_interactive.c helper_portfwd.c

if COND_libc_alloc
libassh_la_SOURCES +=	alloc_libc.c
endif
if COND_gcrypt_alloc
libassh_la_SOURCES +=	alloc_gcrypt.c
endif
if COND_openssl_alloc
libassh_la_SOURCES +=	alloc_openssl.c
endif

if COND_client
libassh_la_SOURCES +=   assh_userauth_client.c assh_userauth_client_none.c \
			assh_userauth_client_pv.h helper_client.c
if COND_password_userauth
libassh_la_SOURCES +=   assh_userauth_client_password.c
endif
if COND_publickey_userauth
libassh_la_SOURCES +=   assh_userauth_client_publickey.c
endif
if COND_hostbased_userauth
libassh_la_SOURCES +=   assh_userauth_client_hostbased.c
endif
if COND_keyboard_userauth
libassh_la_SOURCES +=   assh_userauth_client_keyboard.c
endif
endif

if COND_server
libassh_la_SOURCES +=   assh_userauth_server.c assh_userauth_server_pv.h \
			helper_server.c

if COND_none_userauth
libassh_la_SOURCES +=   assh_userauth_server_none.c
endif
if COND_password_userauth
libassh_la_SOURCES +=   assh_userauth_server_password.c
endif
if COND_publickey_userauth
libassh_la_SOURCES +=   assh_userauth_server_publickey.c
endif
if COND_hostbased_userauth
libassh_la_SOURCES +=   assh_userauth_server_hostbased.c
endif
if COND_keyboard_userauth
libassh_la_SOURCES +=   assh_userauth_server_keyboard.c
endif
endif

if COND_zlib
libassh_la_SOURCES +=   compress_zlib.c
endif

if COND_gcrypt_hash
libassh_la_SOURCES +=   hash_gcrypt.c mac_gcrypt.c
if COND_gcrypt_sha3
else
libassh_la_SOURCES +=   hash_sha3_builtin.c
endif
endif

if COND_openssl_hash
libassh_la_SOURCES +=   hash_openssl.c hash_sha3_builtin.c mac_openssl.c
endif
if COND_builtin_hash
libassh_la_SOURCES +=   hash_md5_builtin.c hash_sha1_builtin.c \
			hash_sha2_builtin.c hash_sha3_builtin.c mac_builtin.c
endif

libassh_la_SOURCES +=	bignum_builtin.h bignum_builtin.c bignum_builtin_vm.c \
	bignum_builtin_add.c bignum_builtin_mul.c bignum_builtin_div.c \
	bignum_builtin_shift.c bignum_builtin_prime.c bignum_builtin_mt.c

if COND_gcrypt_prng
libassh_la_SOURCES +=	prng_gcrypt.c
endif
if COND_openssl_prng
libassh_la_SOURCES +=	prng_openssl.c
endif
if COND_dev_random
libassh_la_SOURCES +=	prng_dev_random.c
endif

if COND_gcrypt_ciphers
libassh_la_SOURCES +=	cipher_gcrypt.c
endif
if COND_openssl_ciphers
libassh_la_SOURCES +=	cipher_openssl.c
endif
if COND_builtin_ciphers
libassh_la_SOURCES +=	cipher_arc4_builtin.c cipher_aes_builtin.c
endif

libassh_la_SOURCES +=	cipher_chacha_poly.c cipher_none.c
