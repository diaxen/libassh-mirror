/*

  libassh - asynchronous ssh2 client/server library.

  Copyright (C) 2013-2020 Alexandre Becoulet <alexandre.becoulet@free.fr>

  This library is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of the
  License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
  02110-1301 USA

*/

/**
   @file
   @short Descriptors for algorithms and modules based on OpenSSL
*/

#ifndef ASSH_MOD_OPENSSL_H_
#define ASSH_MOD_OPENSSL_H_

#include <assh/assh_alloc.h>
#include <assh/assh_prng.h>
#include <assh/assh_cipher.h>
#include <assh/assh_mac.h>
#include <assh/assh_sign.h>

#ifdef CONFIG_ASSH_USE_OPENSSL
# include <openssl/opensslconf.h>
#endif

# ifdef CONFIG_ASSH_USE_OPENSSL_CIPHERS
/** @multiple @This is a cipher algorithm implementation descriptor
    for the Arc4 implementation. @xsee {cipheralgos} */
#  ifndef OPENSSL_NO_RC4
extern const struct assh_algo_cipher_s assh_cipher_openssl_arc4;
extern const struct assh_algo_cipher_s assh_cipher_openssl_arc4_128;
extern const struct assh_algo_cipher_s assh_cipher_openssl_arc4_256;

/** @multiple @This is a cipher algorithm descriptor for the Triple
    DES implementation. @xsee {cipheralgos} */
extern const struct assh_algo_cipher_s assh_cipher_openssl_tdes_cbc;
#  endif

#  ifndef OPENSSL_NO_CAST
/** @multiple @This is a cipher algorithm descriptor for the CAST128
    implementation. @xsee {cipheralgos} */
extern const struct assh_algo_cipher_s assh_cipher_openssl_cast128_cbc;
#  endif

#  ifndef OPENSSL_NO_IDEA
/** @multiple @This is a cipher algorithm descriptor for the IDEA
    implementation. @xsee {cipheralgos} */
extern const struct assh_algo_cipher_s assh_cipher_openssl_idea_cbc;
#  endif

#  ifndef OPENSSL_NO_BF
/** @multiple @This is a cipher algorithm descriptor for the Blowfish
    implementation. @xsee {cipheralgos} */
extern const struct assh_algo_cipher_s assh_cipher_openssl_blowfish_cbc;
#  endif

#  ifndef OPENSSL_NO_DES
/** @multiple @This is a cipher algorithm descriptor for the 3 DES
    implementation. @xsee {cipheralgos} */
extern const struct assh_algo_cipher_s assh_cipher_openssl_tdes_cbc;
#  endif

/** @multiple @This is a cipher algorithm descriptor for the AES
    implementation. @xsee {cipheralgos} */
extern const struct assh_algo_cipher_s assh_cipher_openssl_aes128_cbc;
extern const struct assh_algo_cipher_s assh_cipher_openssl_aes192_cbc;
extern const struct assh_algo_cipher_s assh_cipher_openssl_aes256_cbc;
extern const struct assh_algo_cipher_s assh_cipher_openssl_aes128_ctr;
extern const struct assh_algo_cipher_s assh_cipher_openssl_aes192_ctr;
extern const struct assh_algo_cipher_s assh_cipher_openssl_aes256_ctr;
extern const struct assh_algo_cipher_s assh_cipher_openssl_aes128_gcm;
extern const struct assh_algo_cipher_s assh_cipher_openssl_aes256_gcm;

#  ifndef OPENSSL_NO_CAMELLIA
/** @multiple @This is a cipher algorithm descriptor for the Camellia
    implementation. @xsee {cipheralgos} */
extern const struct assh_algo_cipher_s assh_cipher_openssl_camellia128_cbc;
extern const struct assh_algo_cipher_s assh_cipher_openssl_camellia192_cbc;
extern const struct assh_algo_cipher_s assh_cipher_openssl_camellia256_cbc;
extern const struct assh_algo_cipher_s assh_cipher_openssl_camellia128_ctr;
extern const struct assh_algo_cipher_s assh_cipher_openssl_camellia192_ctr;
extern const struct assh_algo_cipher_s assh_cipher_openssl_camellia256_ctr;
#  endif
# endif

# ifdef CONFIG_ASSH_USE_OPENSSL_MACS
/** @multiple @This is a mac algorithm implementation descriptor.
    @xsee {macalgos} */
#  ifndef OPENSSL_NO_MD5
extern const struct assh_algo_mac_s assh_mac_openssl_md5;
extern const struct assh_algo_mac_s assh_mac_openssl_md5_96;
extern const struct assh_algo_mac_s assh_mac_openssl_md5_etm;
extern const struct assh_algo_mac_s assh_mac_openssl_md5_96_etm;
#  endif

extern const struct assh_algo_mac_s assh_mac_openssl_sha1;
extern const struct assh_algo_mac_s assh_mac_openssl_sha1_96;
extern const struct assh_algo_mac_s assh_mac_openssl_sha1_etm;
extern const struct assh_algo_mac_s assh_mac_openssl_sha1_96_etm;
extern const struct assh_algo_mac_s assh_mac_openssl_sha256;
extern const struct assh_algo_mac_s assh_mac_openssl_sha512;
extern const struct assh_algo_mac_s assh_mac_openssl_sha256_etm;
extern const struct assh_algo_mac_s assh_mac_openssl_sha512_etm;

#  ifndef OPENSSL_NO_RMD160
extern const struct assh_algo_mac_s assh_mac_openssl_ripemd160;
extern const struct assh_algo_mac_s assh_mac_openssl_ripemd160_etm;
#  endif
# endif

# ifdef CONFIG_ASSH_USE_OPENSSL_SIGN
#  ifndef OPENSSL_NO_RSA
/** Accept sha* and md5 RSA signatures, generate sha1 signatures.
    Reject keys with modulus size less than 768 bits. */
extern const struct assh_algo_sign_s assh_sign_openssl_rsa_sha1_md5;

/** Accept sha* RSA signatures, generate sha1 signatures,
    Reject keys with modulus size less than 1024 bits. */
extern const struct assh_algo_sign_s assh_sign_openssl_rsa_sha1;

/** Accept sha* RSA signatures, generate sha1 signatures. 
    Reject keys with modulus size less than 2048 bits. */
extern const struct assh_algo_sign_s assh_sign_openssl_rsa_sha1_2048;

/** Accept sha2, RSA signatures, generate sha256 signatures. 
    Reject keys with modulus size less than 2048 bits. */
extern const struct assh_algo_sign_s assh_sign_openssl_rsa_sha256;

/** Accept sha2 RSA signatures, generate sha512 signatures. 
    Reject keys with modulus size less than 2048 bits. */
extern const struct assh_algo_sign_s assh_sign_openssl_rsa_sha512;
#  endif
# endif

# ifdef CONFIG_ASSH_USE_OPENSSL_PRNG
/** @This is a descriptor for the @em OpenSSL random number
    generator module. */
extern const struct assh_prng_s assh_prng_openssl;
# endif

# ifdef CONFIG_ASSH_USE_OPENSSL_ALLOC
/** This allocator relies on the secur memory allocation functions
    provided by the openssl library.

    It does not requires private data; @tt NULL may be passed as @tt
    alloc_pv parameter of the initialization function.

    When this is enabled in the build, the @ref assh_deps_init
    function calls the openssl @tt CRYPTO_secure_malloc_init function
    unless the @tt CRYPTO_secure_malloc_initialized function indicates
    that it has already been performed.
*/
ASSH_ALLOCATOR(assh_openssl_allocator);
# endif

#endif
