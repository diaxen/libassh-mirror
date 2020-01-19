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
   @short Descriptors for algorithms and modules based on Libgcrypt
*/

#ifndef ASSH_MOD_GCRYPT_H_
#define ASSH_MOD_GCRYPT_H_

#include <assh/assh_alloc.h>
#include <assh/assh_prng.h>
#include <assh/assh_cipher.h>
#include <assh/assh_mac.h>

# ifdef CONFIG_ASSH_USE_GCRYPT_CIPHERS
/** @multiple @This is a cipher algorithm implementation descriptor
    for the Arc4 implementation. @xsee {cipheralgos} */
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_arc4;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_arc4_128;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_arc4_256;

/** @multiple @This is a cipher algorithm descriptor for the Triple
    DES implementation. @xsee {cipheralgos} */
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_tdes_cbc;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_tdes_ctr;

/** @multiple @This is a cipher algorithm descriptor for the CAST128
    implementation. @xsee {cipheralgos} */
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_cast128_cbc;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_cast128_ctr;

/** @multiple @This is a cipher algorithm descriptor for the IDEA
    implementation. @xsee {cipheralgos} */
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_idea_cbc;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_idea_ctr;

/** @multiple @This is a cipher algorithm descriptor for the Blowfish
    implementation. @xsee {cipheralgos} */
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_blowfish_cbc;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_blowfish_ctr;

/** @multiple @This is a cipher algorithm descriptor for the Twofish
    implementation. @xsee {cipheralgos} */
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_twofish128_cbc;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_twofish256_cbc;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_twofish128_ctr;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_twofish256_ctr;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_twofish128_gcm;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_twofish256_gcm;

/** @multiple @This is a cipher algorithm descriptor for the Serpent
    implementation. @xsee {cipheralgos} */
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_serpent128_cbc;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_serpent192_cbc;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_serpent256_cbc;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_serpent128_ctr;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_serpent192_ctr;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_serpent256_ctr;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_serpent128_gcm;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_serpent256_gcm;

/** @multiple @This is a cipher algorithm descriptor for the AES
    implementation. @xsee {cipheralgos} */
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_aes128_cbc;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_aes192_cbc;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_aes256_cbc;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_aes128_ctr;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_aes192_ctr;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_aes256_ctr;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_aes128_gcm;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_aes256_gcm;

/** @multiple @This is a cipher algorithm descriptor for the Camellia
    implementation. @xsee {cipheralgos} */
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_camellia128_cbc;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_camellia192_cbc;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_camellia256_cbc;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_camellia128_ctr;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_camellia192_ctr;
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_camellia256_ctr;
# endif

# ifdef CONFIG_ASSH_USE_GCRYPT_MACS
/** @multiple @This is a mac algorithm implementation descriptor.
    @xsee {macalgos} */
extern const struct assh_algo_mac_s assh_mac_gcrypt_md5;
extern const struct assh_algo_mac_s assh_mac_gcrypt_md5_96;
extern const struct assh_algo_mac_s assh_mac_gcrypt_sha1;
extern const struct assh_algo_mac_s assh_mac_gcrypt_sha1_96;
extern const struct assh_algo_mac_s assh_mac_gcrypt_sha256;
extern const struct assh_algo_mac_s assh_mac_gcrypt_sha512;

extern const struct assh_algo_mac_s assh_mac_gcrypt_md5_etm;
extern const struct assh_algo_mac_s assh_mac_gcrypt_md5_96_etm;
extern const struct assh_algo_mac_s assh_mac_gcrypt_sha1_etm;
extern const struct assh_algo_mac_s assh_mac_gcrypt_sha1_96_etm;
extern const struct assh_algo_mac_s assh_mac_gcrypt_sha256_etm;
extern const struct assh_algo_mac_s assh_mac_gcrypt_sha512_etm;

extern const struct assh_algo_mac_s assh_mac_gcrypt_ripemd160;
extern const struct assh_algo_mac_s assh_mac_gcrypt_ripemd160_etm;
# endif

# ifdef CONFIG_ASSH_USE_GCRYPT_PRNG
/** @This is a descriptor for the @em Libgcrypt random number
    generator module. */
extern const struct assh_prng_s assh_prng_gcrypt;
# endif

# ifdef CONFIG_ASSH_USE_GCRYPT_ALLOC
/** This allocator relies on the secur memory allocation functions
    provided by libgcrypt.

    It does not requires private data; @tt NULL may be passed as @tt
    alloc_pv parameter of the initialization function.
*/
ASSH_ALLOCATOR(assh_gcrypt_allocator);
# endif

#endif
