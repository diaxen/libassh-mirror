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

libassh_la_SOURCES = assh_deps.c assh_context.c assh_session.c assh_packet.c	\
	assh_event.c assh_transport.c assh_kex.c assh_hash.c		\
	assh_algo.c assh_key.c assh_service.c assh_map.c assh_bignum.c	\
	assh_connection.c assh_debug.c assh_buffer.c			\
	kex_none.c sign_none.c cipher_none.c mac_none.c key_none.c compress_none.c \
	helper_key.c helper_io.c helper_base64.c helper_bcrypt.c	\
	helper_interactive.c helper_portfwd.c sign_rsa.h

if COND_prng_devrandom
libassh_la_SOURCES += prng_dev_random.c
endif

if COND_libc_alloc
libassh_la_SOURCES += alloc_libc.c
endif

if COND_prng_builtin
libassh_la_SOURCES += prng_builtin_xswap.c
endif

if COND_kex_builtin
libassh_la_SOURCES += kex_builtin_rsa.c kex_builtin_dh.c kex_builtin_dh_gex.c \
	              kex_builtin_ecdh_montgomery.c kex_builtin_ecdh_nist.c
endif

if COND_sign_builtin
libassh_la_SOURCES += key_builtin_dsa.h key_builtin_eddsa.h key_builtin_ecdsa_nist.h \
		      key_builtin_dsa.c key_builtin_eddsa.c key_builtin_ecdsa_nist.c \
		      sign_builtin_dsa.c sign_builtin_rsa.c sign_builtin_eddsa.c sign_builtin_ecdsa_nist.c
endif

if COND_kex_sign_builtin
libassh_la_SOURCES += key_builtin_rsa.h key_builtin_rsa.c \
		      ecc_weierstrass.c ecc_weierstrass.h
endif

if COND_bignum_builtin
libassh_la_SOURCES += bignum_builtin.h bignum_builtin.c bignum_builtin_vm.c \
	bignum_builtin_add.c bignum_builtin_mul.c bignum_builtin_div.c \
	bignum_builtin_shift.c bignum_builtin_prime.c bignum_builtin_mt.c
endif

if COND_ciphers_builtin
libassh_la_SOURCES +=	cipher_builtin_arc4.c cipher_builtin_aes.c cipher_builtin_chachapoly.c
endif

if COND_macs_builtin
libassh_la_SOURCES +=	mac_builtin.c
endif

if COND_md5_builtin
libassh_la_SOURCES +=   hash_builtin_md5.c
endif
if COND_sha1_builtin
libassh_la_SOURCES +=   hash_builtin_sha1.c
endif
if COND_sha2_builtin
libassh_la_SOURCES +=   hash_builtin_sha2.c
endif
if COND_sha3_builtin
libassh_la_SOURCES +=   hash_builtin_sha3.c
endif


if COND_hash_gcrypt
libassh_la_SOURCES +=   hash_gcrypt.c
endif
if COND_alloc_gcrypt
libassh_la_SOURCES +=	alloc_gcrypt.c
endif
if COND_ciphers_gcrypt
libassh_la_SOURCES +=	cipher_gcrypt.c
endif
if COND_macs_gcrypt
libassh_la_SOURCES +=	mac_gcrypt.c
endif
if COND_prng_gcrypt
libassh_la_SOURCES +=	prng_gcrypt.c
endif


if COND_hash_openssl
libassh_la_SOURCES +=   hash_openssl.c
endif
if COND_alloc_openssl
libassh_la_SOURCES +=	alloc_openssl.c
endif
if COND_ciphers_openssl
libassh_la_SOURCES +=	cipher_openssl.c
endif
if COND_macs_openssl
libassh_la_SOURCES +=	mac_openssl.c
endif
if COND_sign_openssl
libassh_la_SOURCES +=	sign_openssl_rsa.c key_openssl_rsa.c key_openssl_rsa.h
endif
if COND_prng_openssl
libassh_la_SOURCES +=	prng_openssl.c
endif


if COND_prng_sodium
libassh_la_SOURCES += prng_sodium.c
endif

if COND_kex_sodium
libassh_la_SOURCES += kex_sodium_curve25519.c
endif

if COND_sign_sodium
libassh_la_SOURCES += key_sodium_ed25519.c key_sodium_ed25519.h sign_sodium_ed25519.c
endif


if COND_zlib
libassh_la_SOURCES +=   compress_zlib.c
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
