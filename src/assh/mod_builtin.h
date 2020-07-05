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
   @short Descriptors for builtin algorithms and modules
*/

#ifndef ASSH_MOD_BUILTIN_H_
#define ASSH_MOD_BUILTIN_H_

#include <assh/assh_alloc.h>
#include <assh/assh_prng.h>
#include <assh/assh_cipher.h>
#include <assh/assh_mac.h>

# ifdef CONFIG_ASSH_USE_BUILTIN_KEX
/** Standard @tt diffie-hellman-group1-sha1 algorithm.
    @xsee {kexalgos} */
extern const struct assh_algo_kex_s assh_kex_builtin_dh_group1_sha1;

/** Standard @tt diffie-hellman-group14-sha1 algorithm.
    @xsee {Prime field Diffie-Hellman} */
extern const struct assh_algo_kex_s assh_kex_builtin_dh_group14_sha1;

/** Draft @tt @tt diffie-hellman-group14-sha256 algorithm.
    @xsee {Prime field Diffie-Hellman} */
extern const struct assh_algo_kex_s assh_kex_builtin_dh_group14_sha256;

/** Draft @tt @tt diffie-hellman-group15-sha512 algorithm.
    @xsee {Prime field Diffie-Hellman} */
extern const struct assh_algo_kex_s assh_kex_builtin_dh_group15_sha512;

/** Draft @tt @tt diffie-hellman-group16-sha512 algorithm.
    @xsee {Prime field Diffie-Hellman} */
extern const struct assh_algo_kex_s assh_kex_builtin_dh_group16_sha512;

/** Draft @tt @tt diffie-hellman-group17-sha512 algorithm.
    @xsee {Prime field Diffie-Hellman} */
extern const struct assh_algo_kex_s assh_kex_builtin_dh_group17_sha512;

/** Draft @tt @tt diffie-hellman-group18-sha512 algorithm.
    @xsee {Prime field Diffie-Hellman} */
extern const struct assh_algo_kex_s assh_kex_builtin_dh_group18_sha512;

/** The @tt curve25519-sha256 algorithm.
    @xsee {Montgomery curves Diffie-Hellman} */
extern const struct assh_algo_kex_s assh_kex_builtin_curve25519_sha256;

/** The @tt m383-sha384@libassh.org algorithm.
    @xsee {Montgomery curves Diffie-Hellman} */
extern const struct assh_algo_kex_s assh_kex_builtin_m383_sha384;

/** The @tt m511-sha512@libassh.org algorithm.
    @xsee {Montgomery curves Diffie-Hellman} */
extern const struct assh_algo_kex_s assh_kex_builtin_m511_sha512;

/** Standard @tt diffie-hellman-group-exchange-sha1 algorithm
    specified in rfc4419. The client requests group size in range
    [1024, 4096] depending on the length of the cipher key. The server
    accepts group size in range [1024, 8192].
    @xsee {Prime field Diffie-Hellman with group exchange} */
extern const struct assh_algo_kex_s assh_kex_builtin_dh_gex_sha1;

/** Standard @tt diffie-hellman-group-exchange-sha256 algorithm
    specified in rfc4419. The client requests group size in range
    [1024, 2048] depending on the length of the cipher key. The server
    accepts group size in range [1024, 8192].
    @see assh_kex_builtin_dh_gex_sha256_8
    @see assh_kex_builtin_dh_gex_sha256_4
    @xsee {Prime field Diffie-Hellman with group exchange} */
extern const struct assh_algo_kex_s assh_kex_builtin_dh_gex_sha256_12;

/** Standard @tt diffie-hellman-group-exchange-sha256 algorithm
    specified in rfc4419. The client requests group size in range
    [2048, 4096] depending on the length of the cipher key. The server
    accepts group size in range [2048, 8192].
    @see assh_kex_builtin_dh_gex_sha256_12
    @see assh_kex_builtin_dh_gex_sha256_4
    @xsee {Prime field Diffie-Hellman with group exchange} */
extern const struct assh_algo_kex_s assh_kex_builtin_dh_gex_sha256_8;

/** Standard @tt diffie-hellman-group-exchange-sha256 algorithm
    specified in rfc4419. The client requests group size in range
    [4096, 16384] depending on the length of the cipher key. The server
    accepts group size in range [4096, 16384].
    @see assh_kex_builtin_dh_gex_sha256_12
    @see assh_kex_builtin_dh_gex_sha256_8
    @xsee {Prime field Diffie-Hellman with group exchange} */
extern const struct assh_algo_kex_s assh_kex_builtin_dh_gex_sha256_4;

/** Standard @tt rsa1024-sha1 algorithm specified in rfc4432.
    @xsee {RSA encrypted secret} */
extern const struct assh_algo_kex_s assh_kex_builtin_rsa1024_sha1;

/** Standard @tt rsa2048-sha256 algorithm specified in rfc4432.
    @xsee {RSA encrypted secret} */
extern const struct assh_algo_kex_s assh_kex_builtin_rsa2048_sha256;

/** Standard @tt nist curves dh algorithm specified in rfc5656.
    @xsee {Weierstrass curves Diffie-Hellman} */
extern const struct assh_algo_kex_s assh_kex_builtin_sha2_nistp256;
extern const struct assh_algo_kex_s assh_kex_builtin_sha2_nistp384;
extern const struct assh_algo_kex_s assh_kex_builtin_sha2_nistp521;
# endif


# if defined(CONFIG_ASSH_USE_BUILTIN_SIGN) || \
     defined(CONFIG_ASSH_USE_BUILTIN_KEX)
/** Key operations descriptor for RSA keys */
extern const struct assh_key_algo_s assh_key_builtin_rsa;
# endif

# ifdef CONFIG_ASSH_USE_BUILTIN_SIGN
/** @multiple Key operations descriptor for EdDSA keys */
extern const struct assh_key_algo_s assh_key_builtin_ed25519;
extern const struct assh_key_algo_s assh_key_builtin_eddsa_e382;
extern const struct assh_key_algo_s assh_key_builtin_eddsa_e521;

/** @multiple Key operations descriptor for Ecdsa keys */
extern const struct assh_key_algo_s assh_key_builtin_ecdsa_nist;

/** Key operations descriptor for DSA keys */
extern const struct assh_key_algo_s assh_key_builtin_dsa;

/** Use SHA1 and a dsa key with L >= 768 and N = 160. */
extern const struct assh_algo_sign_s assh_sign_builtin_dsa768;

/** Use SHA1 and a dsa key with L >= 1024 and N = 160. */
extern const struct assh_algo_sign_s assh_sign_builtin_dsa1024;

/** Use SHA224 and a dsa key with L >= 2048 and N = 224. */
extern const struct assh_algo_sign_s assh_sign_builtin_dsa2048_sha224;

/** Use SHA256 and a dsa key with L >= 2048 and N = 256. */
extern const struct assh_algo_sign_s assh_sign_builtin_dsa2048_sha256;

/** Use SHA256 and a dsa key with L >= 3072 and N = 256. */
extern const struct assh_algo_sign_s assh_sign_builtin_dsa3072_sha256;

/** Accept sha* and md5 RSA signatures, generate sha1 signatures.
    Reject keys with modulus size less than 768 bits. */
extern const struct assh_algo_sign_s assh_sign_builtin_rsa_sha1_md5;

/** Accept sha* RSA signatures, generate sha1 signatures,
    Reject keys with modulus size less than 1024 bits. */
extern const struct assh_algo_sign_s assh_sign_builtin_rsa_sha1;

/** Accept sha* RSA signatures, generate sha1 signatures. 
    Reject keys with modulus size less than 2048 bits. */
extern const struct assh_algo_sign_s assh_sign_builtin_rsa_sha1_2048;

/** Accept sha2, RSA signatures, generate sha256 signatures. 
    Reject keys with modulus size less than 2048 bits. */
extern const struct assh_algo_sign_s assh_sign_builtin_rsa_sha256;

/** Accept sha2 RSA signatures, generate sha512 signatures. 
    Reject keys with modulus size less than 2048 bits. */
extern const struct assh_algo_sign_s assh_sign_builtin_rsa_sha512;

/** The ssh-ed25519 algorithm as implemented by openssh. This offerrs
    125 bits security and relies on an Edward elliptic curve. 

    See @url {http://safecurves.cr.yp.to/} */
extern const struct assh_algo_sign_s assh_sign_builtin_ed25519;

/** Same algorithm as @ref assh_sign_builtin_ed25519 with the stronger
    E382 edward curve and the shake256 hash function.

    See @url {http://safecurves.cr.yp.to/} */
extern const struct assh_algo_sign_s assh_sign_builtin_eddsa_e382;

/** Same algorithm as @ref assh_sign_builtin_ed25519 with the stronger
    E521 edward curve and the shake256 hash function.

    See @url {http://safecurves.cr.yp.to/} */
extern const struct assh_algo_sign_s assh_sign_builtin_eddsa_e521;

extern const struct assh_algo_sign_s assh_sign_builtin_nistp256;
extern const struct assh_algo_sign_s assh_sign_builtin_nistp384;
extern const struct assh_algo_sign_s assh_sign_builtin_nistp521;
# endif


# ifdef CONFIG_ASSH_USE_BUILTIN_CIPHERS
/** @multiple @This is a cipher algorithm descriptor for the openssh
    Chacha20-Poly1305 authenticated cipher implementation.
    @xsee {cipheralgos} */
extern const struct assh_algo_cipher_s assh_cipher_builtin_chachapoly;

/** @multiple @This is a cipher algorithm descriptor for the AES
    implementation. @xsee {cipheralgos} */
extern const struct assh_algo_cipher_s assh_cipher_builtin_aes128_cbc;
extern const struct assh_algo_cipher_s assh_cipher_builtin_aes192_cbc;
extern const struct assh_algo_cipher_s assh_cipher_builtin_aes256_cbc;
extern const struct assh_algo_cipher_s assh_cipher_builtin_aes128_ctr;
extern const struct assh_algo_cipher_s assh_cipher_builtin_aes192_ctr;
extern const struct assh_algo_cipher_s assh_cipher_builtin_aes256_ctr;

extern const struct assh_algo_cipher_s assh_cipher_builtin_arc4;
extern const struct assh_algo_cipher_s assh_cipher_builtin_arc4_128;
extern const struct assh_algo_cipher_s assh_cipher_builtin_arc4_256;
# endif

# ifdef CONFIG_ASSH_USE_BUILTIN_MACS
extern const struct assh_algo_mac_s assh_mac_builtin_md5;
extern const struct assh_algo_mac_s assh_mac_builtin_md5_96;
extern const struct assh_algo_mac_s assh_mac_builtin_sha1;
extern const struct assh_algo_mac_s assh_mac_builtin_sha1_96;
extern const struct assh_algo_mac_s assh_mac_builtin_sha256;
extern const struct assh_algo_mac_s assh_mac_builtin_sha512;

extern const struct assh_algo_mac_s assh_mac_builtin_md5_etm;
extern const struct assh_algo_mac_s assh_mac_builtin_md5_96_etm;
extern const struct assh_algo_mac_s assh_mac_builtin_sha1_etm;
extern const struct assh_algo_mac_s assh_mac_builtin_sha1_96_etm;
extern const struct assh_algo_mac_s assh_mac_builtin_sha256_etm;
extern const struct assh_algo_mac_s assh_mac_builtin_sha512_etm;
# endif


/** @This is a descriptor for the builtin xswap prng.

    When this prng is used, a seed of at least 16 bytes
    must be passed to the @ref assh_context_create function. */
extern const struct assh_prng_s assh_prng_xswap;

# ifdef CONFIG_ASSH_USE_DEV_RANDOM
/** @This is a descriptor for the @tt /dev/random random number
    generator module. */
extern const struct assh_prng_s assh_prng_dev_random;
# endif

# ifdef CONFIG_ASSH_USE_LIBC_ALLOC
/** This allocator relies on the libc @tt realloc function. This
    allocator @b{is not} able to provide secure memory.

    It does not requires private data; @tt NULL may be passed as @tt
    alloc_pv parameter of the initialization function.
*/
ASSH_ALLOCATOR(assh_libc_allocator);
# endif

#endif
