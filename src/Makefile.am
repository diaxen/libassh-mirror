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

AM_CPPFLAGS = -I$(top_builddir)/src/assh
SUBDIRS = assh

lib_LTLIBRARIES = libassh.la

libassh_la_SOURCES = assh_context.c assh_session.c assh_packet.c	\
	assh_event.c assh_transport.c assh_kex.c assh_hash.c		\
	assh_algo.c assh_key.c assh_service.c assh_map.c		\
	assh_25519num.c bignum_common.c 				\
	assh_connection.c assh_userauth_client.c assh_userauth_server.c	\
	kex_none.c kex_dh.c kex_curve25519.c                            \
	cipher_none.c							\
	mac_builtin.c mac_none.c					\
	sign_dss.c sign_rsa.c sign_none.c				\
	compress_none.c							\
	helper_key.c helper_fd.c

if COND_gcrypt_hash
libassh_la_SOURCES +=   hash_gcrypt.c
else
libassh_la_SOURCES +=   hash_md5_builtin.c hash_sha1_builtin.c hash_sha2_builtin.c
endif

if COND_gcrypt_bignum
libassh_la_SOURCES +=	bignum_gcrypt.c
else
libassh_la_SOURCES +=	bignum_builtin.c
endif

if COND_gcrypt_prng
libassh_la_SOURCES +=	prng_gcrypt.c
else
libassh_la_SOURCES +=	prng_xswap_builtin.c
endif

if COND_gcrypt_ciphers
libassh_la_SOURCES +=	cipher_gcrypt.c
else
libassh_la_SOURCES +=	cipher_arc4_builtin.c 
endif


