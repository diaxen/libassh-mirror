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

AUTOMAKE_OPTIONS = serial-tests

AM_CPPFLAGS = -I$(top_builddir)/src/assh

noinst_PROGRAMS =
TESTS =

noinst_PROGRAMS += buffer
TESTS += buffer
buffer_SOURCES = buffer.c
buffer_LDADD = $(top_builddir)/src/libassh.la
buffer_CFLAGS = -I$(top_srcdir)/src

############################## crypto tests

noinst_PROGRAMS += hash
TESTS += hash
hash_SOURCES = hash.c
hash_LDADD = $(top_builddir)/src/libassh.la
hash_CFLAGS = -I$(top_srcdir)/src

noinst_PROGRAMS += cipher
TESTS += cipher
cipher_SOURCES = cipher.c
cipher_LDADD = $(top_builddir)/src/libassh.la
cipher_CFLAGS = -I$(top_srcdir)/src

noinst_PROGRAMS += mac
TESTS += mac
mac_SOURCES = mac.c
mac_LDADD = $(top_builddir)/src/libassh.la
mac_CFLAGS = -I$(top_srcdir)/src

noinst_PROGRAMS += prng
prng_SOURCES = prng.c
prng_LDADD = $(top_builddir)/src/libassh.la
prng_CFLAGS = -I$(top_srcdir)/src

############################## protocol tests

noinst_PROGRAMS += replay
TESTS += replay
replay_SOURCES = replay.c
replay_LDADD = $(top_builddir)/src/libassh.la
replay_CFLAGS = -I$(top_srcdir)/src

if COND_server
if COND_client

if COND_key_create
noinst_PROGRAMS += userauth
TESTS += userauth
userauth_SOURCES = userauth.c
userauth_LDADD = $(top_builddir)/src/libassh.la
userauth_CFLAGS = -I$(top_srcdir)/src

noinst_PROGRAMS += userauth_server
TESTS += userauth_server
userauth_server_SOURCES = userauth_server.c
userauth_server_LDADD = $(top_builddir)/src/libassh.la
userauth_server_CFLAGS = -I$(top_srcdir)/src
endif

noinst_PROGRAMS += connection
TESTS += connection
connection_SOURCES = connection.c
connection_LDADD = $(top_builddir)/src/libassh.la
connection_CFLAGS = -I$(top_srcdir)/src

noinst_PROGRAMS += connection2
TESTS += connection2
connection2_SOURCES = connection2.c
connection2_LDADD = $(top_builddir)/src/libassh.la
connection2_CFLAGS = -I$(top_srcdir)/src

noinst_PROGRAMS += kex
TESTS += kex
kex_SOURCES = kex.c
kex_LDADD = $(top_builddir)/src/libassh.la
kex_CFLAGS = -I$(top_srcdir)/src
endif
endif

############################## bignum tests

noinst_PROGRAMS += bignum
TESTS += bignum
bignum_SOURCES = bignum.c
bignum_LDADD = $(top_builddir)/src/libassh.la
bignum_CFLAGS = -I$(top_srcdir)/src

noinst_PROGRAMS += gex_primes
#TESTS += gex_primes
gex_primes_SOURCES = gex_primes.c
gex_primes_LDADD = $(top_builddir)/src/libassh.la
gex_primes_CFLAGS = -I$(top_srcdir)/src

############################## signature tests

if COND_key_create
noinst_PROGRAMS += key_io
TESTS += key_io
key_io_SOURCES = key_io.c
key_io_LDADD = $(top_builddir)/src/libassh.la
key_io_CFLAGS = -I$(top_srcdir)/src

if COND_key_validate
noinst_PROGRAMS += signature
TESTS += signature
signature_SOURCES = signature.c
signature_LDADD = $(top_builddir)/src/libassh.la
signature_CFLAGS = -I$(top_srcdir)/src

noinst_PROGRAMS += signature2
TESTS += signature2
signature2_SOURCES = signature2.c
signature2_LDADD = $(top_builddir)/src/libassh.la
signature2_CFLAGS = -I$(top_srcdir)/src
endif
endif

noinst_PROGRAMS += algo_list
TESTS += algo_list
algo_list_SOURCES = algo_list.c
algo_list_LDADD = $(top_builddir)/src/libassh.la
algo_list_CFLAGS = -I$(top_srcdir)/src

noinst_PROGRAMS += fail
fail_SOURCES = fail.c
fail_LDADD = $(top_builddir)/src/libassh.la
fail_CFLAGS = -I$(top_srcdir)/src
TESTS += fail
XFAIL_TESTS = fail

EXTRA_DIST = \
fifo.h \
keys.h \
sign.h \
test.h \
leaks_check.h \
prng_weak.h \
cipher_fuzz.h \
*.ssh
