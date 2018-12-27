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

AC_GNU_SOURCE

AC_STDC_HEADERS
AC_CHECK_HEADERS(assert.h, AC_DEFINE([HAVE_ASSERT_H]))

AC_C_CONST
AC_C_INLINE

AC_CHECK_SIZEOF(long)
AC_CHECK_TYPE(long long, [bnlong_size=8], [bnlong_size=$ac_cv_sizeof_long])
AC_CHECK_TYPE(__int128,  [bnlong_size=x])
AC_CHECK_LIB(c, qsort_r, AC_DEFINE(CONFIG_ASSH_QSORTR, 1, [Use qsort_r from C lbirary when defined.]))
AC_CHECK_LIB(c, malloc_usable_size, AC_DEFINE(CONFIG_ASSH_MALLOC_USABLE_SIZE, 1, [Use malloc_usable_size from C lbirary when defined.]))

AC_CHECK_LIB(c, posix_openpt,
  AC_DEFINE(CONFIG_ASSH_POSIX_OPENPT, 1, [Use posix_openpt when defined.])
  AC_DEFINE(_XOPEN_SOURCE, 600, [_XOPEN_SOURCE])
)

AC_CHECK_LIB(c, getpwnam_r, AC_DEFINE(CONFIG_ASSH_GETPWNAM_R, 1, [Use getpwnam_r when defined.]))
AC_CHECK_LIB(c, getspnam_r, AC_DEFINE(CONFIG_ASSH_GETSPNAM_R, 1, [Use getspnam_r when defined.]))

AC_CHECK_LIB(crypt, crypt_r,
  LIBS="$LIBS -lcrypt"
  AC_DEFINE(CONFIG_ASSH_CRYPT_R, 1, [Use crypt_r when defined.])
)

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

AC_ARG_ENABLE(server, AC_HELP_STRING(--disable-server, [Disable SSH server support]),
		       enable_server=$enableval, enable_server=yes)

AC_ARG_ENABLE(client, AC_HELP_STRING(--disable-client, [Disable SSH client support]),
		       enable_client=$enableval, enable_client=yes)

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
		       [with_hashes=$withval], with_hashes=external)

AC_ARG_WITH(ciphers, AC_HELP_STRING(--with-ciphers, [Specifies backend to use for cipher algorithms (builtin, external, gcrypt, openssl)]),
		       [with_ciphers=$withval], with_ciphers=external)

AC_ARG_WITH(prng, AC_HELP_STRING(--with-prng, [Specifies backend to use for random source (builtin, external, gcrypt, openssl)]),
		       [with_prng=$withval], with_prng=external)

AC_ARG_WITH(alloc, AC_HELP_STRING(--with-alloc, [Specifies backend to use for secure memory allocation (none, libc, external, gcrypt, openssl)]),
		       [with_alloc=$withval], with_alloc=external)

AC_ARG_WITH(gcrypt, AC_HELP_STRING(--without-gcrypt, [Disable use of gcrypt support]),
		       with_gcrypt=$withval, with_gcrypt=yes)

AC_ARG_WITH(openssl, AC_HELP_STRING(--without-openssl, [Disable use of openssl support]),
		       with_openssl=$withval, with_openssl=yes)

AC_ARG_WITH(zlib, AC_HELP_STRING(--without-zlib, [Disable use of the zlib library]),
		       with_zlib=$withval, with_zlib=yes)

AC_ARG_ENABLE(packet_pool, AC_HELP_STRING(--disable-packet-pool, [Disable use of packet allocation pool]),
		       enable_packet_pool=$enableval, enable_packet_pool=yes)

AC_ARG_ENABLE(alloca, AC_HELP_STRING(--enable-alloca, [Store key related material on stack]),
		       enable_alloca=$enableval, enable_alloca=no)

AC_ARG_ENABLE(assert, AC_HELP_STRING(--disable-assert, [Disable assert() by defining the NDEBUG macro]),
		       enable_assert=$enableval, enable_assert=yes)

if test -e /dev/random ; then
  if test x$with_prng = xdevrandom || test x$with_prng = xexternal ; then
    AC_DEFINE([CONFIG_ASSH_USE_DEV_RANDOM], [], [Enable support for unix @tt {/dev/u?random} random generator when defined.])
    with_prng=devrandom
  fi
else
  with_devrandom=no
fi

if test x$with_gcrypt = xyes ; then
  AC_CHECK_LIB(gcrypt, gcry_check_version, [
    AC_CHECK_HEADERS(gcrypt.h, [

      if test x$with_hashes = xgcrypt || test x$with_hashes = xexternal ; then
      	with_hashes=gcrypt
      	AC_DEFINE([CONFIG_ASSH_USE_GCRYPT_HASH], [], [Use Libgcrypt hash algorithms implementations when defined.])
        AC_DEFINE([CONFIG_ASSH_HASH_RIPEMD160], [], [Enable the RIPE-MD-160 MAC algorithm when defined.])
      fi

      if test x$with_prng = xgcrypt || test x$with_prng = xexternal ; then
        with_prng=gcrypt
	AC_DEFINE([CONFIG_ASSH_USE_GCRYPT_PRNG], [], [Enable Libgcrypt random number generator when defined.])
      fi

      if test x$with_alloc = xgcrypt || test x$with_alloc = xexternal ; then
        with_alloc=gcrypt
	AC_DEFINE([CONFIG_ASSH_USE_GCRYPT_ALLOC], [], [Enable Libgcrypt secur memory allocator when defined.])
      fi

      if test x$with_ciphers = xgcrypt || test x$with_ciphers = xexternal ; then
        with_ciphers=gcrypt
	AC_DEFINE([CONFIG_ASSH_USE_GCRYPT_CIPHERS], [], [Enable Libgcrypt cipher algorithms when defined.])
	AC_DEFINE([CONFIG_ASSH_CIPHER_ARCFOUR], [], [Enable the Arcfour cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_TDES_CBC], [], [Enable the Triple-DES cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_TDES_CTR], [], [Enable the Triple-DES cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_CAST128_CBC], [], [Enable the CAST128 cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_CAST128_CTR], [], [Enable the CAST128 cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_IDEA_CBC], [], [Enable the IDEA cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_IDEA_CTR], [], [Enable the IDEA cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_BLOWFISH_CBC], [], [Enable the Blowfish cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_BLOWFISH_CTR], [], [Enable the Blowfish cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_AES128_CBC], [], [Enable the AES cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_AES192_CBC], [], [Enable the AES cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_AES256_CBC], [], [Enable the AES cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_AES128_CTR], [], [Enable the AES cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_AES192_CTR], [], [Enable the AES cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_AES256_CTR], [], [Enable the AES cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_AES128_GCM], [], [Enable the AES cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_AES256_GCM], [], [Enable the AES cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_TWOFISH128_CBC], [], [Enable the Twofish cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_TWOFISH256_CBC], [], [Enable the Twofish cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_TWOFISH128_CTR], [], [Enable the Twofish cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_TWOFISH256_CTR], [], [Enable the Twofish cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_TWOFISH128_GCM], [], [Enable the Twofish cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_TWOFISH256_GCM], [], [Enable the Twofish cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_SERPENT128_CBC], [], [Enable the Serpent cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_SERPENT192_CBC], [], [Enable the Serpent cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_SERPENT256_CBC], [], [Enable the Serpent cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_SERPENT128_CTR], [], [Enable the Serpent cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_SERPENT192_CTR], [], [Enable the Serpent cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_SERPENT256_CTR], [], [Enable the Serpent cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_SERPENT128_GCM], [], [Enable the Serpent cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_SERPENT256_GCM], [], [Enable the Serpent cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_CAMELLIA128_CBC], [], [Enable the Camellia cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_CAMELLIA192_CBC], [], [Enable the Camellia cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_CAMELLIA256_CBC], [], [Enable the Camellia cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_CAMELLIA128_CTR], [], [Enable the Camellia cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_CAMELLIA192_CTR], [], [Enable the Camellia cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_CAMELLIA256_CTR], [], [Enable the Camellia cipher when defined.])
      fi

      if test x$with_hashes = xgcrypt ||
      	 test x$with_alloc = xgcrypt ||
      	 test x$with_ciphers = xgcrypt ||
      	 test x$with_prng = xgcrypt ; then
        LIBS="$LIBS -lgcrypt"
        AC_DEFINE([CONFIG_ASSH_USE_GCRYPT], [], [Enable the Libgcrypt support when defined.])
      fi

    ], [
      with_gcrypt=no
    ])
  ], [
    with_gcrypt=no
  ])
fi

if test x$with_openssl = xyes ; then
  AC_CHECK_LIB(crypto, OpenSSL_version, [
    AC_CHECK_HEADERS(openssl/crypto.h, [

      if test x$with_hashes = xopenssl || test x$with_hashes = xexternal ; then
	AC_CHECK_LIB(crypto, EVP_md5, [
	  AC_CHECK_LIB(crypto, EVP_sha1, [
            with_hashes=openssl
	    AC_DEFINE([CONFIG_ASSH_USE_OPENSSL_HASH], [], [Use openssl hash algorithms implementations when defined.])
	    AC_CHECK_LIB(crypto, EVP_ripemd160, [
              AC_DEFINE([CONFIG_ASSH_HASH_RIPEMD160], [], [Enable the RIPE-MD-160 MAC algorithm when defined.])
	    ])
	  ])
	 ])
      fi

      if test x$with_prng = xopenssl || test x$with_prng = xexternal ; then
	AC_DEFINE([CONFIG_ASSH_USE_OPENSSL_PRNG], [], [Enable openssl random number generator when defined.])
      fi

      if test x$with_alloc = xopenssl || test x$with_alloc = xexternal ; then
        with_alloc=openssl
	AC_DEFINE([CONFIG_ASSH_USE_OPENSSL_ALLOC], [], [Enable openssl secur memory allocator when defined.])
	AC_DEFINE([CONFIG_ASSH_USE_OPENSSL_HEAP_SIZE], [0x10000], [Value passed to the CRYPTO_secure_malloc_init function.])
      fi

      if test x$with_ciphers = xopenssl || test x$with_ciphers = xexternal ; then
        with_ciphers=openssl
	AC_DEFINE([CONFIG_ASSH_USE_OPENSSL_CIPHERS], [], [Enable openssl cipher algorithms when defined.])
	AC_CHECK_LIB(crypto, EVP_rc4, [
	  AC_DEFINE([CONFIG_ASSH_CIPHER_ARCFOUR], [], [Enable the Arcfour cipher when defined.])
	])
	AC_CHECK_LIB(crypto, EVP_des_ede3_cbc, [
          AC_DEFINE([CONFIG_ASSH_CIPHER_TDES_CBC], [], [Enable the Triple-DES cipher when defined.])
	])
	AC_CHECK_LIB(crypto, EVP_bf_cbc, [
          AC_DEFINE([CONFIG_ASSH_CIPHER_BLOWFISH_CBC], [], [Enable the Blowfish cipher when defined.])
	])
	AC_CHECK_LIB(crypto, EVP_cast5_cbc, [
          AC_DEFINE([CONFIG_ASSH_CIPHER_CAST128_CBC], [], [Enable the CAST128 cipher when defined.])
	])
	AC_CHECK_LIB(crypto, EVP_idea_cbc, [
          AC_DEFINE([CONFIG_ASSH_CIPHER_IDEA_CBC], [], [Enable the IDEA cipher when defined.])
	])
        AC_DEFINE([CONFIG_ASSH_CIPHER_AES128_CBC], [], [Enable the AES cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_AES192_CBC], [], [Enable the AES cipher when defined.])
        AC_DEFINE([CONFIG_ASSH_CIPHER_AES256_CBC], [], [Enable the AES cipher when defined.])
	AC_CHECK_LIB(crypto, EVP_aes_128_ctr, [
          AC_DEFINE([CONFIG_ASSH_CIPHER_AES128_CTR], [], [Enable the AES cipher when defined.])
          AC_DEFINE([CONFIG_ASSH_CIPHER_AES192_CTR], [], [Enable the AES cipher when defined.])
          AC_DEFINE([CONFIG_ASSH_CIPHER_AES256_CTR], [], [Enable the AES cipher when defined.])
	])
	AC_CHECK_LIB(crypto, EVP_aes_128_gcm, [
          AC_DEFINE([CONFIG_ASSH_CIPHER_AES128_GCM], [], [Enable the AES-GCM cipher when defined.])
          AC_DEFINE([CONFIG_ASSH_CIPHER_AES256_GCM], [], [Enable the AES-GCM cipher when defined.])
	])
	AC_CHECK_LIB(crypto, EVP_camellia_128_cbc, [
          AC_DEFINE([CONFIG_ASSH_CIPHER_CAMELLIA128_CBC], [], [Enable the Camellia cipher when defined.])
          AC_DEFINE([CONFIG_ASSH_CIPHER_CAMELLIA192_CBC], [], [Enable the Camellia cipher when defined.])
          AC_DEFINE([CONFIG_ASSH_CIPHER_CAMELLIA256_CBC], [], [Enable the Camellia cipher when defined.])
	])
	AC_CHECK_LIB(crypto, EVP_camellia_128_ctr, [
          AC_DEFINE([CONFIG_ASSH_CIPHER_CAMELLIA128_CTR], [], [Enable the Camellia cipher when defined.])
          AC_DEFINE([CONFIG_ASSH_CIPHER_CAMELLIA192_CTR], [], [Enable the Camellia cipher when defined.])
          AC_DEFINE([CONFIG_ASSH_CIPHER_CAMELLIA256_CTR], [], [Enable the Camellia cipher when defined.])
	])
      fi

      if test x$with_hashes = xopenssl ||
      	 test x$with_alloc = xopenssl ||
      	 test x$with_ciphers = xopenssl ||
      	 test x$with_prng = xopenssl ; then
        LIBS="$LIBS -lcrypto"
        AC_DEFINE([CONFIG_ASSH_USE_OPENSSL], [], [Enable the openssl support when defined.])
      fi

    ], [
      with_openssl=no
    ])
  ], [
    with_openssl=no
  ])
fi

if test x$with_gcrypt = xno && test x$with_openssl = xno ; then
  with_hashes=builtin
  with_alloc=libc
  with_ciphers=builtin
  if test x$with_devrandom = xno ; then
    with_prng=builtin
  fi
fi

if test x$with_ciphers = xbuiltin ; then
  AC_DEFINE([CONFIG_ASSH_CIPHER_ARCFOUR], [], [Enable the Arcfour cipher when defined.])
  AC_DEFINE([CONFIG_ASSH_CIPHER_AES128_CBC], [], [Enable the AES cipher when defined.])
  AC_DEFINE([CONFIG_ASSH_CIPHER_AES192_CBC], [], [Enable the AES cipher when defined.])
  AC_DEFINE([CONFIG_ASSH_CIPHER_AES256_CBC], [], [Enable the AES cipher when defined.])
  AC_DEFINE([CONFIG_ASSH_CIPHER_AES128_CTR], [], [Enable the AES cipher when defined.])
  AC_DEFINE([CONFIG_ASSH_CIPHER_AES192_CTR], [], [Enable the AES cipher when defined.])
  AC_DEFINE([CONFIG_ASSH_CIPHER_AES256_CTR], [], [Enable the AES cipher when defined.])
fi

if test x$with_alloc = xlibc ; then
  AC_DEFINE([CONFIG_ASSH_USE_LIBC_ALLOC], [], [Enable support for the C library allocator which is not secur on some platforms.])
fi

AC_DEFINE([CONFIG_ASSH_CIPHER_CHACHAPOLY], [], [Enable the Chacha20-Poly1305 cipher when defined.])
AC_DEFINE([CONFIG_ASSH_HASH_MD5], [], [Enable the MD5 message digest when defined.])
AC_DEFINE([CONFIG_ASSH_HASH_SHA1], [], [Enable the SHA1 message digest when defined.])
AC_DEFINE([CONFIG_ASSH_HASH_SHA2], [], [Enable the SHA2 message digest when defined.])
AC_DEFINE([CONFIG_ASSH_HASH_SHA3], [], [Enable the SHA3 message digest when defined.])

if test x$with_zlib = xyes ; then
  AC_CHECK_LIB(z, zlibVersion, [
    AC_CHECK_HEADERS(zlib.h, [
      LIBS="$LIBS -lz"
      AC_DEFINE([CONFIG_ASSH_USE_ZLIB], [], [Enable the zlib library when defined.])
      AC_DEFINE([CONFIG_ASSH_ZLIB_ALLOC], [ASSH_ALLOC_INTERNAL], [Specifies the allocator storage type used for the zlib context.])
    ], [
      with_zlib=no
    ])
  ], [
    with_zlib=no
  ])
fi

AC_CHECK_HEADERS(valgrind/memcheck.h, [
  AC_DEFINE([CONFIG_ASSH_VALGRIND], [], [Use valgrind headers for better checking when defined.])
])

AM_CONDITIONAL(COND_server,  [test x$enable_server = xyes])
AM_CONDITIONAL(COND_client,  [test x$enable_client = xyes])

AM_CONDITIONAL(COND_libc_alloc,      [test x$with_alloc = xlibc])

AM_CONDITIONAL(COND_builtin_hash,    [test x$with_hashes = xbuiltin])
AM_CONDITIONAL(COND_builtin_ciphers, [test x$with_ciphers = xbuiltin])
AM_CONDITIONAL(COND_builtin_prng,    [test x$with_prng = xbuiltin])
AM_CONDITIONAL(COND_dev_random,      [test x$with_prng = xdevrandom])

AM_CONDITIONAL(COND_gcrypt_hash,     [test x$with_hashes = xgcrypt])
AM_CONDITIONAL(COND_gcrypt_alloc,    [test x$with_alloc = xgcrypt])
AM_CONDITIONAL(COND_gcrypt_ciphers,  [test x$with_ciphers = xgcrypt])
AM_CONDITIONAL(COND_gcrypt_prng,     [test x$with_prng = xgcrypt])

AM_CONDITIONAL(COND_openssl_hash,    [test x$with_hashes = xopenssl])
AM_CONDITIONAL(COND_openssl_alloc,   [test x$with_alloc = xopenssl])
AM_CONDITIONAL(COND_openssl_ciphers, [test x$with_ciphers = xopenssl])
AM_CONDITIONAL(COND_openssl_prng,    [test x$with_prng = xopenssl])

AM_CONDITIONAL(COND_zlib,            [test x$with_zlib = xyes])

AM_CONDITIONAL(COND_password_userauth, [test x$enable_password_userauth = xyes])
AM_CONDITIONAL(COND_hostbased_userauth, [test x$enable_hostbased_userauth = xyes])
AM_CONDITIONAL(COND_keyboard_userauth, [test x$enable_keyboard_userauth = xyes])
AM_CONDITIONAL(COND_publickey_userauth, [test x$enable_publickey_userauth = xyes])
AM_CONDITIONAL(COND_none_userauth, [test x$enable_none_userauth = xyes])

AM_CONDITIONAL(COND_key_validate, [test x$enable_key_validate = xyes])
AM_CONDITIONAL(COND_key_create, [test x$enable_key_create = xyes])

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

AC_DEFINE([CONFIG_ASSH_MAX_PAYLOAD], [32768], [Specifies the maximum size of the ssh packet payload.
				     rfc4253 section 6.1 requires 32768 bytes. Using a lower value on embedded
				     targets will reduce the memory usage and limit resources exhaustion attacks.])

AC_DEFINE([CONFIG_ASSH_MAX_SERVICES], [4], [Specifies the maximum number of registered services.])
AC_DEFINE([CONFIG_ASSH_ABI_WARN], [], [Enable warning at compile time for use of functions which are not ABI stable.])

#AC_DEFINE([NDEBUG], [], [Disable asserts and some aborts])
AC_DEFINE([CONFIG_ASSH_OPENSSH_PREFIX], ["/etc/ssh/"], [Specifies the path to OpenSSH key files for use by helpers.])

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
  Makefile
  src/Makefile
  src/assh/Makefile
  examples/Makefile
  test/Makefile
  doc/Makefile
])

