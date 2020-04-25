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

AUTOMAKE_OPTIONS = serial-tests

AM_CPPFLAGS = -I$(top_builddir)/src/assh

lib_LIBRARIES = libasshtest.a

libasshtest_a_SOURCES = test.c
libasshtest_a_CFLAGS = -I$(top_srcdir)/src

noinst_PROGRAMS =
TESTS =

noinst_PROGRAMS += buffer
TESTS += buffer
buffer_SOURCES = buffer.c
buffer_LDADD = $(top_builddir)/src/libassh.la libasshtest.a
buffer_CFLAGS = -I$(top_srcdir)/src

############################## crypto tests

noinst_PROGRAMS += hash
TESTS += hash
hash_SOURCES = hash.c
hash_LDADD = $(top_builddir)/src/libassh.la libasshtest.a
hash_CFLAGS = -I$(top_srcdir)/src

noinst_PROGRAMS += cipher
TESTS += cipher
cipher_SOURCES = cipher.c
cipher_LDADD = $(top_builddir)/src/libassh.la libasshtest.a
cipher_CFLAGS = -I$(top_srcdir)/src

noinst_PROGRAMS += cipher_bench
cipher_bench_SOURCES = cipher_bench.c
cipher_bench_LDADD = $(top_builddir)/src/libassh.la libasshtest.a
cipher_bench_CFLAGS = -I$(top_srcdir)/src

noinst_PROGRAMS += mac
TESTS += mac
mac_SOURCES = mac.c
mac_LDADD = $(top_builddir)/src/libassh.la libasshtest.a
mac_CFLAGS = -I$(top_srcdir)/src

noinst_PROGRAMS += mac_bench
mac_bench_SOURCES = mac_bench.c
mac_bench_LDADD = $(top_builddir)/src/libassh.la libasshtest.a
mac_bench_CFLAGS = -I$(top_srcdir)/src

noinst_PROGRAMS += prng
prng_SOURCES = prng.c
prng_LDADD = $(top_builddir)/src/libassh.la libasshtest.a
prng_CFLAGS = -I$(top_srcdir)/src

############################## protocol tests

noinst_PROGRAMS += replay
TESTS += replay
replay_SOURCES = replay.c
replay_LDADD = $(top_builddir)/src/libassh.la libasshtest.a
replay_CFLAGS = -I$(top_srcdir)/src

if COND_server
if COND_client

if COND_key_create
noinst_PROGRAMS += userauth
TESTS += userauth
userauth_SOURCES = userauth.c
userauth_LDADD = $(top_builddir)/src/libassh.la libasshtest.a
userauth_CFLAGS = -I$(top_srcdir)/src

noinst_PROGRAMS += userauth_server
TESTS += userauth_server
userauth_server_SOURCES = userauth_server.c
userauth_server_LDADD = $(top_builddir)/src/libassh.la libasshtest.a
userauth_server_CFLAGS = -I$(top_srcdir)/src

noinst_PROGRAMS += kex_bench
kex_bench_SOURCES = kex_bench.c
kex_bench_LDADD = $(top_builddir)/src/libassh.la libasshtest.a
kex_bench_CFLAGS = -I$(top_srcdir)/src
endif

noinst_PROGRAMS += connection
TESTS += connection
connection_SOURCES = connection.c
connection_LDADD = $(top_builddir)/src/libassh.la libasshtest.a
connection_CFLAGS = -I$(top_srcdir)/src

noinst_PROGRAMS += connection2
TESTS += connection2
connection2_SOURCES = connection2.c
connection2_LDADD = $(top_builddir)/src/libassh.la libasshtest.a
connection2_CFLAGS = -I$(top_srcdir)/src

noinst_PROGRAMS += kex
TESTS += kex
kex_SOURCES = kex.c
kex_LDADD = $(top_builddir)/src/libassh.la libasshtest.a
kex_CFLAGS = -I$(top_srcdir)/src
endif
endif

############################## bignum tests

if COND_bignum_builtin
noinst_PROGRAMS += bignum
TESTS += bignum
bignum_SOURCES = bignum.c
bignum_LDADD = $(top_builddir)/src/libassh.la libasshtest.a
bignum_CFLAGS = -I$(top_srcdir)/src

noinst_PROGRAMS += gex_primes
#TESTS += gex_primes
gex_primes_SOURCES = gex_primes.c
gex_primes_LDADD = $(top_builddir)/src/libassh.la libasshtest.a
gex_primes_CFLAGS = -I$(top_srcdir)/src
endif

############################## signature tests

if COND_key_create
noinst_PROGRAMS += key_io
TESTS += key_io
key_io_SOURCES = key_io.c
key_io_LDADD = $(top_builddir)/src/libassh.la libasshtest.a
key_io_CFLAGS = -I$(top_srcdir)/src

noinst_PROGRAMS += sign_bench
sign_bench_SOURCES = sign_bench.c
sign_bench_LDADD = $(top_builddir)/src/libassh.la libasshtest.a
sign_bench_CFLAGS = -I$(top_srcdir)/src

if COND_key_validate
noinst_PROGRAMS += signature
TESTS += signature
signature_SOURCES = signature.c
signature_LDADD = $(top_builddir)/src/libassh.la libasshtest.a
signature_CFLAGS = -I$(top_srcdir)/src
endif
endif

noinst_PROGRAMS += signature2
TESTS += signature2
signature2_SOURCES = signature2.c
signature2_LDADD = $(top_builddir)/src/libassh.la libasshtest.a
signature2_CFLAGS = -I$(top_srcdir)/src

noinst_PROGRAMS += algo_list
TESTS += algo_list
algo_list_SOURCES = algo_list.c
algo_list_LDADD = $(top_builddir)/src/libassh.la libasshtest.a
algo_list_CFLAGS = -I$(top_srcdir)/src

if COND_key_create
if COND_libfuzzer
noinst_PROGRAMS += libfuzzer
libfuzzer_SOURCES = libfuzzer.c
libfuzzer_LDADD = $(top_builddir)/src/libassh.la libasshtest.a
libfuzzer_CFLAGS = -I$(top_srcdir)/src -fsanitize=fuzzer,address
endif
endif

noinst_PROGRAMS += fail
fail_SOURCES = fail.c
fail_LDADD = $(top_builddir)/src/libassh.la libasshtest.a
fail_CFLAGS = -I$(top_srcdir)/src
TESTS += fail
XFAIL_TESTS = fail

EXTRA_DIST = \
fifo.h \
keys.h \
sign.h \
test.h \
cl_OpenSSH_4_7_rsa_dsa_aes128cbc_sha1.ssh \
cl_OpenSSH_8_3_c25519_ed25519_aes128ctr_sha256_pwbad.ssh \
cl_OpenSSH_8_3_c25519_ed25519_aes128ctr_sha256_pwok.ssh \
cl_OpenSSH_8_3_c25519_ed25519_chachapoly_sha256_pubok.ssh \
cl_OpenSSH_8_3_c25519_rsa_aes128ctr_sha256_pwok.ssh \
cl_OpenSSH_8_3_gex256_rsa_aes128ctr_sha256_pwok.ssh \
cl_TinySSH_20190101_c25519_ed25519_chachapoly_pubok.ssh \
cl_TinySSH_20190101_c25519_ed25519_chachapoly_pwbad.ssh \
cl_libssh_0_9_5_c25519_rsa_aes128ctr_sha256_pwbad.ssh \
cl_libssh_0_9_5_c25519_rsasha256_aes128ctr_sha256_pwok.ssh \
cl_wolfSSH_1_4_5_nistp256_nistp256_aes128ctr_sha256_pwbad.ssh \
cl_wolfSSH_1_4_5_nistp256_nistp256_aes128ctr_sha256_pwok.ssh \
clsv_c25519.ssh \
clsv_dhgex.ssh \
clsv_dhgroup1.ssh \
clsv_nistp256.ssh \
clsv_none_hostbased_bad_ok.ssh \
clsv_none_keyboard_bad_ok.ssh \
clsv_none_multiauth_bad.ssh \
clsv_none_multifactor_ok.ssh \
clsv_none_pw_bad_ok.ssh \
clsv_none_userpub_bad_ok.ssh \
sv_OpenSSH_6_2_nistp384_dsa_rijndael_sha1_pw.ssh \
sv_OpenSSH_8_3_c25519_ed25519_chachapoly_sha256_pubok.ssh \
sv_OpenSSH_8_3_c25519_rsa_aes128ctr_sha256_pw.ssh \
sv_PuTTY_0_74_c25519_rsa_aes128ctr_sha256_pw.ssh \
sv_PuTTY_0_74_nistp384_ed25519_chachapoly_pw.ssh \
sv_dropbear_2020_80_25519_ed25519_chachapoly_sha256_pubok.ssh \
sv_dropbear_2020_80_c25519_rsa_aes128ctr_sha256_pw.ssh \
sv_libssh2_1_9_0_nistp256_rsa_3descbc_sha1_pubok.ssh \
sv_libssh2_1_9_0_nistp256_rsa_aes128ctr_ripemd_pwbad.ssh \
sv_libssh2_1_9_0_nistp256_rsa_aes128ctr_sha256_pwok.ssh \
sv_libssh_0_9_5_nistp256_rsa_3descbc_sha1_pubok.ssh \
sv_libssh_0_9_5_nistp256_rsa_aes128ctr_sha256_pwok.ssh \
sv_wolfSSH_1_4_5_gex256_nistp256_aes128gcm_sha256_pw.ssh \
sv_wolfSSH_1_4_5_nistp256_rsa_aes128ctr_sha256_pw.ssh
