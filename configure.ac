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

AC_INIT(libassh, 0.1)
AC_PREREQ(2.50)

AC_CONFIG_AUX_DIR(build)
AM_INIT_AUTOMAKE(libassh, 0.1)
AC_CONFIG_HEADERS(config.h)
AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CC

AM_PROG_LIBTOOL 

AC_LANG(C)

AC_STDC_HEADERS
AC_CHECK_HEADERS(assert.h, AC_DEFINE([HAVE_ASSERT_H]))

AC_C_CONST
AC_C_INLINE

AC_CHECK_SIZEOF(long)
AC_CHECK_TYPE(long long, [bnlong_size=8], [bnlong_size=$ac_cv_sizeof_long])
AC_CHECK_TYPE(__int128,  [bnlong_size=x])
AC_CHECK_LIB(c, qsort_r, AC_DEFINE(CONFIG_ASSH_QSORTR, 1, [qsort_r available]))

case "${ac_cv_sizeof_long}_${bnlong_size}" in
    8_x)
         AC_DEFINE(CONFIG_ASSH_BIGNUM_WORD, 64, [Using 64 bits words for bignum.])
    ;;
    8_8|4_8)
         AC_DEFINE(CONFIG_ASSH_BIGNUM_WORD, 32, [Using 32 bits words for bignum.])
    ;;
    *)
         AC_DEFINE(CONFIG_ASSH_BIGNUM_WORD, 16, [Using 16 bits words for bignum.])
    ;;
esac

AC_ARG_ENABLE(server, AC_HELP_STRING(--disable-server, [Disable SSH server support]),
		       enable_server=$enableval, enable_server=yes)

AC_ARG_ENABLE(client, AC_HELP_STRING(--disable-client, [Disable SSH client support]),
		       enable_client=$enableval, enable_client=yes)

AC_ARG_ENABLE(gcrypt, AC_HELP_STRING(--disable-gcrypt, [Disable use of gcrypt support]),
		       enable_gcrypt=$enableval, enable_gcrypt=yes)

AC_ARG_ENABLE(gcrypt_hash, AC_HELP_STRING(--disable-gcrypt-hash, [Disable use of gcrypt hash algorithms]),
		       enable_gcrypt_hash=$enableval, enable_gcrypt_hash=yes)

AC_ARG_ENABLE(gcrypt_bignum, AC_HELP_STRING(--enable-gcrypt-bignum, [Enable use of gcrypt big number functions]),
		       enable_gcrypt_bignum=$enableval, enable_gcrypt_bignum=no)

AC_ARG_ENABLE(gcrypt_prng, AC_HELP_STRING(--enable-gcrypt-prng, [Enable use of gcrypt random number generation]),
		       enable_gcrypt_prng=$enableval, enable_gcrypt_prng=no)

AC_ARG_ENABLE(gcrypt_alloc, AC_HELP_STRING(--disable-gcrypt-alloc, [Disable use of gcrypt secur memory allocation]),
		       enable_gcrypt_alloc=$enableval, enable_gcrypt_alloc=yes)

AC_ARG_ENABLE(gcrypt_ciphers, AC_HELP_STRING(--disable-gcrypt-ciphers, [Disable use of gcrypt ciphers]),
		       enable_gcrypt_ciphers=$enableval, enable_gcrypt_ciphers=yes)

if test x$enable_gcrypt = xyes ; then
  AC_CHECK_LIB(gcrypt, gcry_check_version, [
    AC_CHECK_HEADERS(gcrypt.h, [
      LIBS="$LIBS -lgcrypt"
      AC_DEFINE([CONFIG_ASSH_USE_GCRYPT], [], [Libgcrypt support])

      if test x$enable_gcrypt_hash = xyes ; then
	AC_DEFINE([CONFIG_ASSH_USE_GCRYPT_HASH], [], [use of gcrypt hash algorithms])
        AC_DEFINE([CONFIG_ASSH_HASH_RIPEMD160], [], [RIPE-MD-160 message digest available])
      fi

      if test x$enable_gcrypt_bignum = xyes ; then
	AC_DEFINE([CONFIG_ASSH_USE_GCRYPT_BIGNUM], [], [use of gcrypt big number functions])
      fi

      if test x$enable_gcrypt_prng = xyes ; then
	AC_DEFINE([CONFIG_ASSH_USE_GCRYPT_PRNG], [], [use of gcrypt random number generation])
      fi

      if test x$enable_gcrypt_alloc = xyes ; then
	AC_DEFINE([CONFIG_ASSH_USE_GCRYPT_ALLOC], [], [use of gcrypt secur memory allocation])
      fi

      if test x$enable_gcrypt_ciphers = xyes ; then
	AC_DEFINE([CONFIG_ASSH_USE_GCRYPT_CIPHERS], [], [use of gcrypt cipherss])
        AC_DEFINE([CONFIG_ASSH_CIPHER_TDES], [], [Triple-DES cipher available])
        AC_DEFINE([CONFIG_ASSH_CIPHER_BLOWFISH], [], [Blowfish cipher available])
        AC_DEFINE([CONFIG_ASSH_CIPHER_TWOFISH], [], [Twofish cipher available])
        AC_DEFINE([CONFIG_ASSH_CIPHER_SERPENT], [], [Serpent cipher available])
        AC_DEFINE([CONFIG_ASSH_CIPHER_CAST128], [], [CAST128 cipher available])
        AC_DEFINE([CONFIG_ASSH_CIPHER_IDEA], [], [IDEA cipher available])
        AC_DEFINE([CONFIG_ASSH_CIPHER_CAMELLIA], [], [Camellia cipher available])
        AC_DEFINE([CONFIG_ASSH_MODE_GCM], [], [GCM cipher mode available])
        AC_DEFINE([CONFIG_ASSH_HASH_RIPEMD160], [], [RIPE-MD-160 message digest available])
      fi

    ], [
      enable_gcrypt=no
    ])
  ], [
    enable_gcrypt=no
  ])
   AC_DEFINE([CONFIG_ASSH_MAX_ALGORITHMS], 96, [Maximum number of registered algorithms])
fi

if test x$enable_gcrypt = xno ; then
   enable_gcrypt_hash=no
   enable_gcrypt_bignum=no
   enable_gcrypt_prng=no
   enable_gcrypt_alloc=no
   enable_gcrypt_ciphers=no
   AC_DEFINE([CONFIG_ASSH_MAX_ALGORITHMS], 64, [Maximum number of registered algorithms])
fi

if test -e /dev/random ; then
  AC_DEFINE([CONFIG_ASSH_USE_DEV_RANDOM], [], [use of unix /dev/u?random])
  enable_dev_random=yes
fi

AC_DEFINE([CONFIG_ASSH_CIPHER_AES], [], [AES cipher available])
AC_DEFINE([CONFIG_ASSH_CIPHER_ARCFOUR], [], [Arcfour cipher available])
AC_DEFINE([CONFIG_ASSH_CIPHER_CHACHAPOLY], [], [Chacha20-Poly1305 cipher available])
AC_DEFINE([CONFIG_ASSH_MODE_CTR], [], [Counter cipher mode available])
AC_DEFINE([CONFIG_ASSH_HASH_MD5], [], [MD5 message digest available])
AC_DEFINE([CONFIG_ASSH_HASH_SHA1], [], [SHA1 message digest available])
AC_DEFINE([CONFIG_ASSH_HASH_SHA2], [], [SHA2 message digest available])
AC_DEFINE([CONFIG_ASSH_HASH_SHA3], [], [SHA3 message digest available])

AM_CONDITIONAL(COND_server,  [test x$enable_server = xyes])
AM_CONDITIONAL(COND_client,  [test x$enable_client = xyes])

AM_CONDITIONAL(COND_gcrypt_hash,    [test x$enable_gcrypt_hash = xyes])
AM_CONDITIONAL(COND_gcrypt_bignum,  [test x$enable_gcrypt_bignum = xyes])
AM_CONDITIONAL(COND_gcrypt_prng,    [test x$enable_gcrypt_prng = xyes])
AM_CONDITIONAL(COND_gcrypt_alloc,   [test x$enable_gcrypt_alloc = xyes])
AM_CONDITIONAL(COND_gcrypt_ciphers, [test x$enable_gcrypt_ciphers = xyes])

AM_CONDITIONAL(COND_dev_random,  [test x$enable_dev_random = xyes])

if test x$enable_server = xyes ; then
   AC_DEFINE([CONFIG_ASSH_SERVER], [], [SSH server support])
   AC_DEFINE([CONFIG_ASSH_SERVER_AUTH_PUBLICKEY], [], [SSH server authentication: public key support])
   AC_DEFINE([CONFIG_ASSH_SERVER_AUTH_PASSWORD], [], [SSH server authentication: password support])
   #AC_DEFINE([CONFIG_ASSH_SERVER_AUTH_NONE], [], [SSH server authentication: bypassed, grant access directly])
fi

if test x$enable_client = xyes ; then
   AC_DEFINE([CONFIG_ASSH_CLIENT], [], [SSH client support])
   AC_DEFINE([CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY], [], [SSH client authentication: public key support])
   AC_DEFINE([CONFIG_ASSH_CLIENT_AUTH_PASSWORD], [], [SSH client authentication: password support])
   AC_DEFINE([CONFIG_ASSH_CLIENT_AUTH_USE_PKOK], [], [SSH client authentication: public key signature is not sent directly])
fi

AC_DEFINE([CONFIG_ASSH_AUTH_USERNAME_LEN], [32], [SSH authentication max username length])
AC_DEFINE([CONFIG_ASSH_AUTH_PASSWORD_LEN], [32], [SSH authentication max password length])

AC_DEFINE([CONFIG_ASSH_MAX_SERVICES], [4], [Maximum number of registered services])

AC_DEFINE([CONFIG_ASSH_PACKET_POOL], [], [Use a packet allocation pool])
#AC_DEFINE([CONFIG_ASSH_ALLOCA], [], [Enable storing key related material on stack])

if test "$GCC" = "yes" ; then
    CFLAGS="-Wall $CFLAGS"
fi

AC_OUTPUT([
  Makefile
  src/Makefile
  src/assh/Makefile
  examples/Makefile
  test/Makefile
  doc/Makefile
])

