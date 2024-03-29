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

AC_INIT(libassh, 1.1)
AC_PREREQ(2.50)

AC_DEFINE(CONFIG_ASSH_SRC_VERSION, 00010001, [Version of the source package.])
#                               Major ^   ^ minor

# https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html#Updating-version-info

ASSH_ABI_VERSION=1:0:0
AC_SUBST(ASSH_ABI_VERSION)

AC_DEFINE(CONFIG_ASSH_ABI_VERSION, 001001001, [Version of the shared library.])
#                                  cccrrraaa

AC_CONFIG_AUX_DIR(build)
AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS(config.h)
AC_CONFIG_MACRO_DIR([m4])

AC_ARG_ENABLE(libfuzzer, AC_HELP_STRING(--enable-libfuzzer, [Enable LLVM libFuzzer build]),
		       enable_libfuzzer=$enableval, enable_libfuzzer=no)

if test x$enable_libfuzzer = xyes ; then
    CFLAGS="-fsanitize=fuzzer-no-link,address -O2 -g"
    CC=clang
fi

AC_PROG_CC
AC_LANG(C)

AC_USE_SYSTEM_EXTENSIONS
AM_PROG_LIBTOOL

AC_GNU_SOURCE
AC_STDC_HEADERS

AC_C_CONST
AC_C_INLINE

AC_CHECK_SIZEOF(long)
AC_CHECK_TYPE(long long, [bnlong_size=8], [bnlong_size=$ac_cv_sizeof_long])
AC_CHECK_TYPE(__int128,  [bnlong_size=x])
AC_CHECK_LIB(c, malloc_usable_size, AC_DEFINE(CONFIG_ASSH_MALLOC_USABLE_SIZE, 1, [Use malloc_usable_size from C lbirary when defined.]))

AC_COMPILE_IFELSE([
  #include <sys/ioctl.h>
  struct winsize ws;
  int i = TIOCGWINSZ;
], AC_DEFINE(HAVE_TIOCGWINSZ, 1, [Use GNU TIOCGWINSZ ioctl]) )

AC_CHECK_LIB(c, posix_openpt,
  AC_DEFINE(HAVE_POSIX_OPENPT, 1, [Use posix_openpt when defined.])
)

AC_CHECK_LIB(c, setgroups,
  AC_DEFINE(CONFIG_ASSH_POSIX_SETGROUPS, 1, [Use setgroups when defined.])
)

AC_CHECK_LIB(c, getpwnam_r, AC_DEFINE(CONFIG_ASSH_GETPWNAM_R, 1, [Use getpwnam_r when defined.]))
AC_CHECK_LIB(c, getspnam_r, AC_DEFINE(CONFIG_ASSH_GETSPNAM_R, 1, [Use getspnam_r when defined.]))

AC_CHECK_LIB(crypt, crypt_r,
  LIBS="$LIBS -lcrypt"
  AC_DEFINE(CONFIG_ASSH_CRYPT_R, 1, [Use crypt_r when defined.])
  AC_CHECK_HEADERS(crypt.h,
    AC_DEFINE(HAVE_CRYPT_H, 1, [Have the crypt.h header.])
  )
)

AC_CHECK_HEADERS(stdio.h,
  AC_DEFINE([CONFIG_ASSH_STDIO], 1, [Use POSIX standard buffered streams])
  CONFIG_ASSH_STDIO=yes
)

AC_ARG_ENABLE(server, AC_HELP_STRING(--disable-server, [Disable SSH server support]),
		       enable_server=$enableval, enable_server=yes)

AC_ARG_ENABLE(client, AC_HELP_STRING(--disable-client, [Disable SSH client support]),
		       enable_client=$enableval, enable_client=yes)

AC_ARG_ENABLE(examples, AC_HELP_STRING(--disable-examples, [Disable building of example applications]),
		       enable_examples=$enableval, enable_examples=yes)

AC_ARG_ENABLE(none_userauth, AC_HELP_STRING(--disable-none-userauth, [Disable none authentication]),
		       enable_none_userauth=$enableval, enable_none_userauth=yes)

AC_ARG_ENABLE(publickey_userauth, AC_HELP_STRING(--disable-publickey-userauth, [Disable public key user authentication]),
		       enable_publickey_userauth=$enableval, enable_publickey_userauth=yes)

AC_ARG_ENABLE(password_userauth, AC_HELP_STRING(--disable-password-userauth, [Disable public key user authentication]),
		       enable_password_userauth=$enableval, enable_password_userauth=yes)

AC_ARG_ENABLE(hostbased_userauth, AC_HELP_STRING(--disable-hostbased-userauth, [Disable host based user authentication]),
		       enable_hostbased_userauth=$enableval, enable_hostbased_userauth=yes)

AC_ARG_ENABLE(keyboard_userauth, AC_HELP_STRING(--disable-keyboard-userauth, [Disable host based user authentication]),
		       enable_keyboard_userauth=$enableval, enable_keyboard_userauth=yes)

AC_ARG_ENABLE(key_validate, AC_HELP_STRING(--disable-key-validate, [Disable key validation code]),
		       enable_key_validate=$enableval, enable_key_validate=yes)

AC_ARG_ENABLE(key_create, AC_HELP_STRING(--disable-key-create, [Disable key creation code]),
		       enable_key_create=$enableval, enable_key_create=yes)

AC_ARG_WITH(hashes, AC_HELP_STRING(--with-hashes, [Specifies backend to use for hash algorithms (builtin, external, gcrypt, openssl)]),
		       [with_hashes=$withval], with_hashes=builtin)

AC_ARG_WITH(kex, AC_HELP_STRING(--with-kex, [Specifies backend to use for key-exchange algorithms (builtin, sodium, all)]),
		       [with_kex=$withval], with_kex=all)

AC_ARG_WITH(sign, AC_HELP_STRING(--with-sign, [Specifies backend to use for signature algorithms (builtin, sodium, all)]),
		       [with_sign=$withval], with_sign=all)

AC_ARG_WITH(ciphers, AC_HELP_STRING(--with-ciphers, [Specifies backend to use for cipher algorithms (builtin, external, gcrypt, openssl, all)]),
		       [with_ciphers=$withval], with_ciphers=all)

AC_ARG_WITH(macs, AC_HELP_STRING(--with-macs, [Specifies backend to use for MAC algorithms (builtin, external, gcrypt, openssl, all)]),
		       [with_macs=$withval], with_macs=all)

AC_ARG_WITH(prng, AC_HELP_STRING(--with-prng, [Specifies backend to use for random source (builtin, external, devrandom, gcrypt, openssl, sodium, all)]),
		       [with_prng=$withval], with_prng=all)

AC_ARG_WITH(alloc, AC_HELP_STRING(--with-alloc, [Specifies backend to use for secure memory allocation (none, libc, external, gcrypt, openssl)]),
		       [with_alloc=$withval], with_alloc=external)

AC_ARG_WITH(gcrypt, AC_HELP_STRING(--without-gcrypt, [Disable use of gcrypt support]),
		       with_gcrypt=$withval, with_gcrypt=yes)

AC_ARG_WITH(openssl, AC_HELP_STRING(--without-openssl, [Disable use of openssl support]),
		       with_openssl=$withval, with_openssl=yes)

AC_ARG_WITH(sodium, AC_HELP_STRING(--without-sodium, [Disable use of libsodium support]),
		       with_sodium=$withval, with_sodium=yes)

AC_ARG_WITH(zlib, AC_HELP_STRING(--without-zlib, [Disable use of the zlib library]),
		       with_zlib=$withval, with_zlib=yes)

AC_ARG_ENABLE(packet_pool, AC_HELP_STRING(--disable-packet-pool, [Disable use of packet allocation pool]),
		       enable_packet_pool=$enableval, enable_packet_pool=yes)

AC_ARG_ENABLE(alloca, AC_HELP_STRING(--enable-alloca, [Store key related material on stack]),
		       enable_alloca=$enableval, enable_alloca=no)

AC_ARG_ENABLE(assert, AC_HELP_STRING(--disable-assert, [Disable assert() by defining the NDEBUG macro]),
		       enable_assert=$enableval, enable_assert=yes)

CONFIG_ASSH_USE_BUILTIN_MD5=yes
CONFIG_ASSH_USE_BUILTIN_SHA1=yes
CONFIG_ASSH_USE_BUILTIN_SHA2=yes
CONFIG_ASSH_USE_BUILTIN_SHA3=yes

if test -e /dev/random ; then
  case "$with_prng" in
    *external*)
      with_prng=devrandom
      CONFIG_ASSH_USE_DEV_RANDOM=yes
      ;;
    *devrandom*|*all*)
      CONFIG_ASSH_USE_DEV_RANDOM=yes
  esac
  if test x$CONFIG_ASSH_USE_DEV_RANDOM = xyes ; then
    AC_DEFINE([CONFIG_ASSH_USE_DEV_RANDOM], [], [Enable support for unix @tt {/dev/u?random} random generator when defined.])
  fi
fi

case "$with_kex" in
  *builtin*|*all*)
    AC_DEFINE([CONFIG_ASSH_USE_BUILTIN_KEX], [], [Enable builtin key-exchange algorithms when defined.])
    CONFIG_ASSH_USE_BUILTIN_KEX=yes
esac

case "$with_sign" in
  *builtin*|*all*)
    AC_DEFINE([CONFIG_ASSH_USE_BUILTIN_SIGN], [], [Enable builtin signature algorithms when defined.])
    CONFIG_ASSH_USE_BUILTIN_SIGN=yes
esac

case "$with_ciphers" in
  *builtin*|*all*)
    AC_DEFINE([CONFIG_ASSH_USE_BUILTIN_CIPHERS], [], [Enable builtin cipher algorithms when defined.])
    CONFIG_ASSH_USE_BUILTIN_CIPHERS=yes

    AC_COMPILE_IFELSE([
    #include <wmmintrin.h>
    #include <tmmintrin.h>
    #include <smmintrin.h>
    __attribute__ ((target("aes,sse2,ssse3,sse4.1,pclmul")))
    int main() {
      __m128i a = _mm_aesenc_si128(a, a);
      return __builtin_cpu_supports("aes") &&
             __builtin_cpu_supports("pclmul");
    }
    ], [
      AC_DEFINE([CONFIG_ASSH_AES_NI], [], [Allow use of x86 AES-NI instructions])
      CONFIG_ASSH_AES_NI=yes
    ])
esac

case "$with_macs" in
  *builtin*|*all*)
    AC_DEFINE([CONFIG_ASSH_USE_BUILTIN_MACS], [], [Enable builtin MAC algorithms when defined.])
    CONFIG_ASSH_USE_BUILTIN_MACS=yes
esac

case "$with_prng" in
  *builtin*|*all*)
  AC_DEFINE([CONFIG_ASSH_USE_BUILTIN_PRNG], [], [Enable support for builtin PRNG.])
  CONFIG_ASSH_USE_BUILTIN_PRNG=yes
esac

CONFIG_ASSH_USE_GCRYPT=no
if test x$with_gcrypt = xyes ; then
  AC_CHECK_LIB(gcrypt, gcry_check_version, [
    AC_CHECK_HEADERS(gcrypt.h, [

      case "$with_hashes" in
        *external*|*gcrypt*)
      	  with_hashes=gcrypt
      	  AC_DEFINE([CONFIG_ASSH_USE_GCRYPT_HASH], [], [Use Libgcrypt hash algorithms implementations when defined.])
	  CONFIG_ASSH_USE_GCRYPT_HASH=yes
          CONFIG_ASSH_USE_BUILTIN_MD5=no
          CONFIG_ASSH_USE_BUILTIN_SHA1=no
          CONFIG_ASSH_USE_BUILTIN_SHA2=no
          AC_TRY_COMPILE([#include <gcrypt.h>], [return GCRY_MD_SHA3_256;], [
            CONFIG_ASSH_USE_BUILTIN_SHA3=no
          ])
      esac

      case "$with_prng" in
        *external*)
          with_prng=gcrypt
	  CONFIG_ASSH_USE_GCRYPT_PRNG=yes
	  ;;
        *gcrypt*|*all*)
	  CONFIG_ASSH_USE_GCRYPT_PRNG=yes
      esac
      if test x$CONFIG_ASSH_USE_GCRYPT_PRNG = xyes ; then
	  AC_DEFINE([CONFIG_ASSH_USE_GCRYPT_PRNG], [], [Enable Libgcrypt random number generator when defined.])
      fi

      case "$with_alloc" in
        *external*)
          with_alloc=gcrypt
	  CONFIG_ASSH_USE_GCRYPT_ALLOC=yes
	  ;;
        *gcrypt*|*all*)
	  CONFIG_ASSH_USE_GCRYPT_ALLOC=yes
      esac
      if test x$CONFIG_ASSH_USE_GCRYPT_ALLOC = xyes ; then
	  AC_DEFINE([CONFIG_ASSH_USE_GCRYPT_ALLOC], [], [Enable Libgcrypt secur memory allocator when defined.])
      fi

      case "$with_ciphers" in
        *external*)
          with_ciphers=gcrypt
	  CONFIG_ASSH_USE_GCRYPT_CIPHERS=yes
	  ;;
        *gcrypt*|*all*)
	  CONFIG_ASSH_USE_GCRYPT_CIPHERS=yes
      esac
      if test x$CONFIG_ASSH_USE_GCRYPT_CIPHERS = xyes ; then
	  AC_DEFINE([CONFIG_ASSH_USE_GCRYPT_CIPHERS], [], [Enable Libgcrypt cipher algorithms when defined.])
      fi

      case "$with_macs" in
        *external*)
          with_macs=gcrypt
	  CONFIG_ASSH_USE_GCRYPT_MACS=yes
	  ;;
        *gcrypt*|*all*)
	  CONFIG_ASSH_USE_GCRYPT_MACS=yes
      esac
      if test x$CONFIG_ASSH_USE_GCRYPT_MACS = xyes ; then
	  AC_DEFINE([CONFIG_ASSH_USE_GCRYPT_MACS], [], [Enable Libgcrypt MAC algorithms when defined.])
      fi

      if test x$CONFIG_ASSH_USE_GCRYPT_HASH = xyes ||
      	 test x$CONFIG_ASSH_USE_GCRYPT_CIPHERS = xyes ||
      	 test x$CONFIG_ASSH_USE_GCRYPT_ALLOC = xyes ||
      	 test x$CONFIG_ASSH_USE_GCRYPT_MACS = xyes ||
      	 test x$CONFIG_ASSH_USE_GCRYPT_PRNG = xyes ; then
        LIBS="$LIBS -lgcrypt"
        AC_DEFINE([CONFIG_ASSH_USE_GCRYPT], [], [Enable the Libgcrypt support when defined.])
	CONFIG_ASSH_USE_GCRYPT=yes
      fi
    ])
  ])
fi

CONFIG_ASSH_USE_OPENSSL=no
if test x$with_openssl = xyes ; then
  AC_CHECK_LIB(crypto, OpenSSL_version, [
    AC_CHECK_HEADERS(openssl/crypto.h, [
     AC_CHECK_HEADERS(openssl/opensslconf.h, [

      case "$with_hashes" in
        *external*|*openssl*)
	AC_CHECK_LIB(crypto, EVP_md5, [
	  AC_CHECK_LIB(crypto, EVP_sha1, [
            with_hashes=openssl
	    AC_DEFINE([CONFIG_ASSH_USE_OPENSSL_HASH], [], [Use openssl hash algorithms implementations when defined.])
	    CONFIG_ASSH_USE_OPENSSL_HASH=yes
            AC_TRY_COMPILE([#include <openssl/evp.h>], [return (int)EVP_md5();], [
              CONFIG_ASSH_USE_BUILTIN_MD5=no
            ])
            CONFIG_ASSH_USE_BUILTIN_SHA1=no
            CONFIG_ASSH_USE_BUILTIN_SHA2=no
	  ])
	 ])
      esac

      AC_CHECK_LIB(crypto, RAND_priv_bytes, [
        case "$with_prng" in
          *external*)
            with_prng=openssl
            CONFIG_ASSH_USE_OPENSSL_PRNG=yes
       	    ;;
          *openssl*|*all*)
            CONFIG_ASSH_USE_OPENSSL_PRNG=yes
        esac
        if test x$CONFIG_ASSH_USE_OPENSSL_PRNG = xyes ; then
       	  AC_DEFINE([CONFIG_ASSH_USE_OPENSSL_PRNG], [], [Enable openssl random number generator when defined.])
        fi
      ])

      case "$with_alloc" in
        *external*)
          with_alloc=openssl
	  CONFIG_ASSH_USE_OPENSSL_ALLOC=yes
	  ;;
        *openssl*|*all*)
	  CONFIG_ASSH_USE_OPENSSL_ALLOC=yes
      esac
      if test x$CONFIG_ASSH_USE_OPENSSL_ALLOC = xyes ; then
	  AC_DEFINE([CONFIG_ASSH_USE_OPENSSL_ALLOC], [], [Enable openssl secur memory allocator when defined.])
      fi

      case "$with_ciphers" in
        *external*)
          with_ciphers=openssl
	  CONFIG_ASSH_USE_OPENSSL_CIPHERS=yes
	  ;;
        *openssl*|*all*)
	  CONFIG_ASSH_USE_OPENSSL_CIPHERS=yes
      esac
      if test x$CONFIG_ASSH_USE_OPENSSL_CIPHERS = xyes ; then
	  AC_DEFINE([CONFIG_ASSH_USE_OPENSSL_CIPHERS], [], [Enable openssl cipher algorithms when defined.])
      fi

      case "$with_sign" in
        *external*)
          with_signs=openssl
	  CONFIG_ASSH_USE_OPENSSL_SIGN=yes
	  ;;
        *openssl*|*all*)
	  CONFIG_ASSH_USE_OPENSSL_SIGN=yes
      esac
      if test x$CONFIG_ASSH_USE_OPENSSL_SIGN = xyes ; then
	  AC_DEFINE([CONFIG_ASSH_USE_OPENSSL_SIGN], [], [Enable openssl signature algorithms when defined.])
      fi

      case "$with_macs" in
        *external*)
          with_macs=openssl
	  CONFIG_ASSH_USE_OPENSSL_MACS=yes
	  ;;
        *openssl*|*all*)
	  CONFIG_ASSH_USE_OPENSSL_MACS=yes
      esac
      if test x$CONFIG_ASSH_USE_OPENSSL_MACS = xyes ; then
	  AC_DEFINE([CONFIG_ASSH_USE_OPENSSL_MACS], [], [Enable openssl MAC algorithms when defined.])
      fi

      if test x$CONFIG_ASSH_USE_OPENSSL_HASH = xyes ||
      	 test x$CONFIG_ASSH_USE_OPENSSL_CIPHERS = xyes ||
      	 test x$CONFIG_ASSH_USE_OPENSSL_ALLOC = xyes ||
      	 test x$CONFIG_ASSH_USE_OPENSSL_MACS = xyes ||
      	 test x$CONFIG_ASSH_USE_OPENSSL_SIGN = xyes ||
      	 test x$CONFIG_ASSH_USE_OPENSSL_PRNG = xyes ; then
        LIBS="$LIBS -lcrypto"
        AC_DEFINE([CONFIG_ASSH_USE_OPENSSL], [], [Enable the openssl support when defined.])
	CONFIG_ASSH_USE_OPENSSL=yes
      fi
    ])
   ])
  ])
fi

CONFIG_ASSH_USE_SODIUM=no
if test x$with_sodium = xyes ; then
  AC_CHECK_LIB(sodium, crypto_scalarmult_curve25519, [
    AC_CHECK_HEADERS(sodium/crypto_scalarmult_curve25519.h, [
      case "$with_kex" in
        *external*)
          with_kex=sodium
	  CONFIG_ASSH_USE_SODIUM_KEX=yes
	  ;;
        *sodium*|*all*)
	  CONFIG_ASSH_USE_SODIUM_KEX=yes
      esac
      if test x$CONFIG_ASSH_USE_SODIUM_KEX = xyes ; then
	  AC_DEFINE([CONFIG_ASSH_USE_SODIUM_KEX], [], [Enable libsodium key-exchange algorithms when defined.])
      fi
   ])
  ])

  AC_CHECK_LIB(sodium, crypto_sign_ed25519_detached, [
    AC_CHECK_HEADERS(sodium/crypto_sign_ed25519.h, [
      case "$with_sign" in
        *external*)
          with_sign=sodium
	  CONFIG_ASSH_USE_SODIUM_SIGN=yes
	  ;;
        *sodium*|*all*)
	  CONFIG_ASSH_USE_SODIUM_SIGN=yes
      esac
      if test x$CONFIG_ASSH_USE_SODIUM_SIGN = xyes ; then
	  AC_DEFINE([CONFIG_ASSH_USE_SODIUM_SIGN], [], [Enable libsodium signature algorithms when defined.])
      fi
   ])
  ])

  AC_CHECK_LIB(sodium, randombytes_buf, [
    AC_CHECK_HEADERS(sodium/randombytes.h, [
      case "$with_prng" in
        *external*)
          with_prng=sodium
	  CONFIG_ASSH_USE_SODIUM_PRNG=yes
	  ;;
        *sodium*|*all*)
	  CONFIG_ASSH_USE_SODIUM_PRNG=yes
      esac
      if test x$CONFIG_ASSH_USE_SODIUM_PRNG = xyes ; then
	  AC_DEFINE([CONFIG_ASSH_USE_SODIUM_PRNG], [], [Enable libsodium based prng when defined.])
      fi
   ])
  ])

  if test x$CONFIG_ASSH_USE_SODIUM_KEX = xyes ||
     test x$CONFIG_ASSH_USE_SODIUM_KEX = xyes ||
     test x$CONFIG_ASSH_USE_SODIUM_PRNG = xyes; then
        LIBS="$LIBS -lsodium"
        AC_DEFINE([CONFIG_ASSH_USE_SODIUM], [], [Enable the libsodium support when defined.])
	CONFIG_ASSH_USE_SODIUM=yes
  fi
fi

CONFIG_ASSH_USE_ZLIB=no
if test x$with_zlib = xyes ; then
  AC_CHECK_LIB(z, zlibVersion, [
    AC_CHECK_HEADERS(zlib.h, [
      LIBS="$LIBS -lz"
      AC_DEFINE([CONFIG_ASSH_USE_ZLIB], [], [Enable the zlib library when defined.])
      CONFIG_ASSH_USE_ZLIB=yes
      AC_DEFINE([CONFIG_ASSH_ZLIB_ALLOC], [ASSH_ALLOC_INTERNAL], [Specifies the allocator storage type used for the zlib context.])
    ])
  ])
fi

AC_CHECK_HEADERS(valgrind/memcheck.h, [
  AC_DEFINE([CONFIG_ASSH_VALGRIND], [], [Use valgrind headers for better checking when defined.])
])

if test x$CONFIG_ASSH_USE_BUILTIN_KEX = xyes ||
   test x$CONFIG_ASSH_USE_BUILTIN_SIGN = xyes ; then

   AC_DEFINE(CONFIG_ASSH_BIGNUM_BUILTIN, 1, [Enable bignum engine when defined.])
   CONFIG_ASSH_BIGNUM_BUILTIN=yes

   case "${ac_cv_sizeof_long}_${bnlong_size}" in
       8_x)
            AC_DEFINE(CONFIG_ASSH_BIGNUM_WORD, 64, [Bignum uses 64 bits words when defined.])
       ;;
       8_8|4_8)
            AC_DEFINE(CONFIG_ASSH_BIGNUM_WORD, 32, [Bignum uses 64 bits words when defined.])
       ;;
       *)
            AC_DEFINE(CONFIG_ASSH_BIGNUM_WORD, 16, [Bignum uses 16 bits words when defined.])
       ;;
   esac

fi

case "$with_alloc" in
  *libc*|*all*|*external*)
  AC_DEFINE([CONFIG_ASSH_USE_LIBC_ALLOC], [], [Enable support for the C library allocator which is not secur on some platforms.])
  CONFIG_ASSH_USE_LIBC_ALLOC=yes
esac

if test x$CONFIG_ASSH_USE_BUILTIN_MD5 = xyes ; then
  AC_DEFINE([CONFIG_ASSH_BUILTIN_MD5], [], [Enable MD5 hash])
fi

if test x$CONFIG_ASSH_USE_BUILTIN_SHA1 = xyes ; then
  AC_DEFINE([CONFIG_ASSH_BUILTIN_SHA1], [], [Enable SHA1 hash])
fi

if test x$CONFIG_ASSH_USE_BUILTIN_SHA2 = xyes ; then
  AC_DEFINE([CONFIG_ASSH_BUILTIN_SHA2], [], [Enable SHA2 hash])
fi

if test x$CONFIG_ASSH_USE_BUILTIN_SHA3 = xyes ; then
  AC_DEFINE([CONFIG_ASSH_BUILTIN_SHA3], [], [Enable SHA3 hash])
fi

AM_CONDITIONAL(COND_server,  [test x$enable_server = xyes])
AM_CONDITIONAL(COND_client,  [test x$enable_client = xyes])

AM_CONDITIONAL(COND_libc_alloc,      [test x$CONFIG_ASSH_USE_LIBC_ALLOC = xyes])

AM_CONDITIONAL(COND_prng_devrandom,  [test x$CONFIG_ASSH_USE_DEV_RANDOM = xyes])

AM_CONDITIONAL(COND_kex_builtin,     [test x$CONFIG_ASSH_USE_BUILTIN_KEX = xyes])
AM_CONDITIONAL(COND_sign_builtin,    [test x$CONFIG_ASSH_USE_BUILTIN_SIGN = xyes])
AM_CONDITIONAL(COND_kex_sign_builtin, [test x$CONFIG_ASSH_USE_BUILTIN_KEX = xyes ||
				       test x$CONFIG_ASSH_USE_BUILTIN_SIGN = xyes])
AM_CONDITIONAL(COND_bignum_builtin,  [test x$CONFIG_ASSH_BIGNUM_BUILTIN = xyes])
AM_CONDITIONAL(COND_ciphers_builtin, [test x$CONFIG_ASSH_USE_BUILTIN_CIPHERS = xyes])
AM_CONDITIONAL(COND_macs_builtin,    [test x$CONFIG_ASSH_USE_BUILTIN_MACS = xyes])
AM_CONDITIONAL(COND_md5_builtin,     [test x$CONFIG_ASSH_USE_BUILTIN_MD5 = xyes])
AM_CONDITIONAL(COND_sha1_builtin,    [test x$CONFIG_ASSH_USE_BUILTIN_SHA1 = xyes])
AM_CONDITIONAL(COND_sha2_builtin,    [test x$CONFIG_ASSH_USE_BUILTIN_SHA2 = xyes])
AM_CONDITIONAL(COND_sha3_builtin,    [test x$CONFIG_ASSH_USE_BUILTIN_SHA3 = xyes])
AM_CONDITIONAL(COND_prng_builtin,    [test x$CONFIG_ASSH_USE_BUILTIN_PRNG = xyes])
AM_CONDITIONAL(COND_aes_ni,          [test x$CONFIG_ASSH_AES_NI = xyes])

AM_CONDITIONAL(COND_hash_gcrypt,     [test x$CONFIG_ASSH_USE_GCRYPT_HASH = xyes])
AM_CONDITIONAL(COND_alloc_gcrypt,    [test x$CONFIG_ASSH_USE_GCRYPT_ALLOC = xyes])
AM_CONDITIONAL(COND_ciphers_gcrypt,  [test x$CONFIG_ASSH_USE_GCRYPT_CIPHERS = xyes])
AM_CONDITIONAL(COND_macs_gcrypt,     [test x$CONFIG_ASSH_USE_GCRYPT_MACS = xyes])
AM_CONDITIONAL(COND_prng_gcrypt,     [test x$CONFIG_ASSH_USE_GCRYPT_PRNG = xyes])

AM_CONDITIONAL(COND_hash_openssl,    [test x$CONFIG_ASSH_USE_OPENSSL_HASH = xyes])
AM_CONDITIONAL(COND_alloc_openssl,   [test x$CONFIG_ASSH_USE_OPENSSL_ALLOC = xyes])
AM_CONDITIONAL(COND_ciphers_openssl, [test x$CONFIG_ASSH_USE_OPENSSL_CIPHERS = xyes])
AM_CONDITIONAL(COND_macs_openssl,    [test x$CONFIG_ASSH_USE_OPENSSL_MACS = xyes])
AM_CONDITIONAL(COND_sign_openssl,    [test x$CONFIG_ASSH_USE_OPENSSL_SIGN = xyes])
AM_CONDITIONAL(COND_prng_openssl,    [test x$CONFIG_ASSH_USE_OPENSSL_PRNG = xyes])

AM_CONDITIONAL(COND_kex_sodium,      [test x$CONFIG_ASSH_USE_SODIUM_KEX = xyes])
AM_CONDITIONAL(COND_sign_sodium,     [test x$CONFIG_ASSH_USE_SODIUM_SIGN = xyes])
AM_CONDITIONAL(COND_prng_sodium,     [test x$CONFIG_ASSH_USE_SODIUM_PRNG = xyes])

AM_CONDITIONAL(COND_zlib,            [test x$CONFIG_ASSH_USE_ZLIB = xyes])

AM_CONDITIONAL(COND_password_userauth, [test x$enable_password_userauth = xyes])
AM_CONDITIONAL(COND_hostbased_userauth, [test x$enable_hostbased_userauth = xyes])
AM_CONDITIONAL(COND_keyboard_userauth, [test x$enable_keyboard_userauth = xyes])
AM_CONDITIONAL(COND_publickey_userauth, [test x$enable_publickey_userauth = xyes])
AM_CONDITIONAL(COND_none_userauth, [test x$enable_none_userauth = xyes])

AM_CONDITIONAL(COND_key_validate, [test x$enable_key_validate = xyes])
AM_CONDITIONAL(COND_key_create, [test x$enable_key_create = xyes])

AM_CONDITIONAL(COND_libfuzzer, [test x$enable_libfuzzer = xyes])
AM_CONDITIONAL(COND_examples, [test x$enable_examples = xyes])

if test x$enable_server = xyes ; then
   AC_DEFINE([CONFIG_ASSH_SERVER], [], [Enable support for the server side of the SSH protocol when defined.])
   if test x$enable_publickey_userauth = xyes ; then
     AC_DEFINE([CONFIG_ASSH_SERVER_AUTH_PUBLICKEY], [], [Enable support for the @em{public key} user authentication method on server side when defined.])
   fi
   if test x$enable_password_userauth = xyes ; then
     AC_DEFINE([CONFIG_ASSH_SERVER_AUTH_PASSWORD], [], [Enable support for the @em{password} user authentication method on server side when defined.])
   fi
   if test x$enable_hostbased_userauth = xyes ; then
     AC_DEFINE([CONFIG_ASSH_SERVER_AUTH_HOSTBASED], [], [Enable support for the @em{host based} user authentication method on server side when defined.])
   fi
   if test x$enable_keyboard_userauth = xyes ; then
     AC_DEFINE([CONFIG_ASSH_SERVER_AUTH_KEYBOARD], [], [Enable support for the @em{keyboard interactive} user authentication method on server side when defined.])
   fi
   if test x$enable_none_userauth = xyes ; then
     AC_DEFINE([CONFIG_ASSH_SERVER_AUTH_NONE], [], [Enable support for the @em{none} user authentication method on server side when defined.])
   fi
fi

if test x$enable_client = xyes ; then
   AC_DEFINE([CONFIG_ASSH_CLIENT], [], [Enable support for the client side of the SSH protocol when defined.])
   if test x$enable_publickey_userauth = xyes ; then
     AC_DEFINE([CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY], [], [Enable support for the @em{public key support} user authentication method on server side when defined.])
     AC_DEFINE([CONFIG_ASSH_CLIENT_AUTH_USE_PKOK], [], [Send a public key lookup packet first before sending the signature during user authentication when defined.])
   fi
   if test x$enable_password_userauth = xyes ; then
     AC_DEFINE([CONFIG_ASSH_CLIENT_AUTH_PASSWORD], [], [Enable support for the @em{password support} user authentication method on server side when defined.])
   fi
   if test x$enable_hostbased_userauth = xyes ; then
     AC_DEFINE([CONFIG_ASSH_CLIENT_AUTH_HOSTBASED], [], [Enable support for the @em{host based} user authentication method on server side when defined.])
   fi
   if test x$enable_keyboard_userauth = xyes ; then
     AC_DEFINE([CONFIG_ASSH_CLIENT_AUTH_KEYBOARD], [], [Enable support for the @em{keyboard interactive} user authentication method on server side when defined.])
   fi
fi

if test x$enable_key_validate = xyes ; then
  AC_DEFINE([CONFIG_ASSH_KEY_VALIDATE], [], [Enable support for SSH key validation when defined.])
fi

if test x$enable_key_create = xyes ; then
  AC_DEFINE([CONFIG_ASSH_KEY_CREATE], [], [Enable support for SSH key creation when defined.])
fi

AC_DEFINE([CONFIG_ASSH_NO_REKEX_BEFORE_AUTH], [], [Disallow performing multiple key exchanges before user authentication.])

AC_DEFINE([CONFIG_ASSH_AUTH_USERNAME_LEN], [32], [Specifies maximum length of username for user authentication.])
AC_DEFINE([CONFIG_ASSH_AUTH_PASSWORD_LEN], [32], [Specifies maximum length of password for user authentication.])
AC_DEFINE([CONFIG_ASSH_AUTH_HOSTNAME_LEN], [128], [Specifies maximum length of hostname for user authentication.])

AC_DEFINE([CONFIG_ASSH_IDENT_SIZE], [255], [Specifies the maximum length of the remote software identification string.
				    rfc4253 section 4.2 requires 255 bytes which is almost never seen in practice.
				    Using a lower value on embedded targets will reduce the size of the
				    @ref assh_session_s structure.])

AC_DEFINE([CONFIG_ASSH_MAX_PAYLOAD_LEN], [32768], [Specifies the maximum size of the ssh packet payload.
				     rfc4253 section 6.1 requires 32768 bytes. Using a lower value on embedded
				     targets will reduce the memory usage and limit resources exhaustion attacks.])

AC_DEFINE([CONFIG_ASSH_MAX_PACKET_LEN], [35000], [Specifies the maximum size of the ssh transport packet.])

AC_DEFINE([CONFIG_ASSH_MAX_SERVICES], [4], [Specifies the maximum number of registered services.])
AC_DEFINE([CONFIG_ASSH_ABI_WARN], [], [Enable warning at compile time for use of functions which are not ABI stable.])

#AC_DEFINE([NDEBUG], [], [Disable asserts and some aborts])
AC_DEFINE([CONFIG_ASSH_OPENSSH_PREFIX], ["/etc/ssh/"], [Specifies the path to OpenSSH key files for use by helpers.])

AC_DEFINE([CONFIG_ASSH_SECMEM_SIZE], [0x10000], [Value passed to the CRYPTO_secure_malloc_init function.])

if test x$enable_packet_pool = xyes ; then
  AC_DEFINE([CONFIG_ASSH_PACKET_POOL], [], [Enable the packet pool allocator when defined.])
  AC_DEFINE([CONFIG_ASSH_PACKET_POOL_SIZE], [1048576], [Specifies the maximum byte amount of spare packets in the pool.])
fi

if test x$enable_alloca = xyes ; then
  AC_DEFINE([CONFIG_ASSH_ALLOCA], [], [Enable storage of temporary buffers on stack.
  				  This is not secur on platforms with memory swapping.])
fi

if test x$enable_assert = xno ; then
  AC_DEFINE([NDEBUG], [], [Enable assert()])
fi

AC_DEFINE([CONFIG_ASSH_VERBOSE_ERROR], [], [Include error strings in the library])

if test "$GCC" = "yes" ; then
    CFLAGS="-Wall -Wno-enum-compare $CFLAGS"
fi

AC_OUTPUT([
  libassh.pc
  Makefile
  src/Makefile
  src/assh/Makefile
  examples/Makefile
  test/Makefile
  doc/Makefile
])

