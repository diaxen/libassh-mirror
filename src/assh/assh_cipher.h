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
   @short SSH cipher module interface

   This header file contains API descriptors for cipher
   @hl algorithm modules implemented in the library.

   @xsee{cipheralgos}
   @xsee{coremod}
*/

#ifndef ASSH_CIPHER_H_
#define ASSH_CIPHER_H_

#include "assh_algo.h"

/** @internal @see assh_cipher_init_t */
#define ASSH_CIPHER_INIT_FCN(n) \
  ASSH_WARN_UNUSED_RESULT assh_status_t (n)(struct assh_context_s *c, void *ctx_, \
                                           const uint8_t *key, const uint8_t *iv, \
                                           assh_bool_t encrypt)

/** @internal @This defines the function type for the cipher
    initialization operation of the cipher module interface. The @tt
    ctx_ argument must points to a buffer allocated in secure memory
    of size given by @ref assh_algo_cipher_s::ctx_size. */
typedef ASSH_CIPHER_INIT_FCN(assh_cipher_init_t);

/** @internal @This specifies the packet cipher processing phases. */
enum assh_cipher_op_e
{
  /** Process packet head data containing the packet length word */
  ASSH_CIPHER_PCK_HEAD,
  /** Process remaining packet data */
  ASSH_CIPHER_PCK_TAIL,
  /** Process key blob */
  ASSH_CIPHER_KEY,
};

/** @internal @see assh_cipher_process_t */
#define ASSH_CIPHER_PROCESS_FCN(n) \
  ASSH_WARN_UNUSED_RESULT assh_status_t (n)(void *ctx_, uint8_t *data, size_t len, \
                                           enum assh_cipher_op_e op, uint32_t seq)

/** @internal @This defines the function type for the data processing
    operation of the cipher module interface. */
typedef ASSH_CIPHER_PROCESS_FCN(assh_cipher_process_t);

/** @internal @see assh_cipher_cleanup_t */
#define ASSH_CIPHER_CLEANUP_FCN(n) \
  void (n)(struct assh_context_s *c, void *ctx_)

/** @internal @This defines the function type for the context cleanup
    operation of the cipher module interface. */
typedef ASSH_CIPHER_CLEANUP_FCN(assh_cipher_cleanup_t);


/** @internalmembers @This is the cipher algorithm descriptor. It can
    be casted to the @ref assh_algo_s type. @xsee{coremod} */
struct assh_algo_cipher_s
{
  struct assh_algo_s algo;
  assh_cipher_init_t *f_init;
  assh_cipher_process_t *f_process;
  assh_cipher_cleanup_t *f_cleanup;
  /** Size of the context structure needed to initialize the algorithm. */
  uint16_t ctx_size;
  /** Cipher block size in bytes, not less than 8. */
  uint8_t block_size;
  /** Cipher IV size, may be 0. */
  uint8_t iv_size;
  /** Cipher key size in bytes. */
  uint8_t key_size;
  /** Cipher authentication tag size in bytes, may be 0. */
  uint8_t auth_size;
  /** Number of packet bytes which must be fetched in order to
      decipher the packet length word. greater or equal to 4. */
  uint8_t head_size;
};

ASSH_FIRST_FIELD_ASSERT(assh_algo_cipher_s, algo);

/** @multiple @This is a cipher algorithm implementation descriptor
    for the dummy @tt none algorithm. */
extern const struct assh_algo_cipher_s assh_cipher_none;

# ifdef CONFIG_ASSH_CIPHER_ARCFOUR
/** @multiple @This is a cipher algorithm implementation descriptor
    for the Arc4 implementation. @xsee {cipheralgos} */
extern const struct assh_algo_cipher_s assh_cipher_arc4;
extern const struct assh_algo_cipher_s assh_cipher_arc4_128;
extern const struct assh_algo_cipher_s assh_cipher_arc4_256;
# endif

/** @multiple @This is a cipher algorithm descriptor for the AES
    implementation. @xsee {cipheralgos} */
# ifdef CONFIG_ASSH_CIPHER_AES128_CBC
extern const struct assh_algo_cipher_s assh_cipher_aes128_cbc;
# endif
# ifdef CONFIG_ASSH_CIPHER_AES192_CBC
extern const struct assh_algo_cipher_s assh_cipher_aes192_cbc;
# endif
# ifdef CONFIG_ASSH_CIPHER_AES256_CBC
extern const struct assh_algo_cipher_s assh_cipher_aes256_cbc;
# endif
# ifdef CONFIG_ASSH_CIPHER_AES128_CTR
extern const struct assh_algo_cipher_s assh_cipher_aes128_ctr;
# endif
# ifdef CONFIG_ASSH_CIPHER_AES192_CTR
extern const struct assh_algo_cipher_s assh_cipher_aes192_ctr;
# endif
# ifdef CONFIG_ASSH_CIPHER_AES256_CTR
extern const struct assh_algo_cipher_s assh_cipher_aes256_ctr;
# endif
# ifdef CONFIG_ASSH_CIPHER_AES128_GCM
extern const struct assh_algo_cipher_s assh_cipher_aes128_gcm;
# endif
# ifdef CONFIG_ASSH_CIPHER_AES256_GCM
extern const struct assh_algo_cipher_s assh_cipher_aes256_gcm;
# endif

/** @multiple @This is a cipher algorithm descriptor for the Triple
    DES implementation. @xsee {cipheralgos} */
# ifdef CONFIG_ASSH_CIPHER_TDES_CBC
extern const struct assh_algo_cipher_s assh_cipher_tdes_cbc;
# endif
# ifdef CONFIG_ASSH_CIPHER_TDES_CTR
extern const struct assh_algo_cipher_s assh_cipher_tdes_ctr;
# endif

/** @multiple @This is a cipher algorithm descriptor for the CAST128
    implementation. @xsee {cipheralgos} */
# ifdef CONFIG_ASSH_CIPHER_CAST128_CBC
extern const struct assh_algo_cipher_s assh_cipher_cast128_cbc;
# endif
# ifdef CONFIG_ASSH_CIPHER_CAST128_CTR
extern const struct assh_algo_cipher_s assh_cipher_cast128_ctr;
# endif

/** @multiple @This is a cipher algorithm descriptor for the IDEA
    implementation. @xsee {cipheralgos} */
# ifdef CONFIG_ASSH_CIPHER_IDEA_CBC
extern const struct assh_algo_cipher_s assh_cipher_idea_cbc;
# endif
# ifdef CONFIG_ASSH_CIPHER_IDEA_CTR
extern const struct assh_algo_cipher_s assh_cipher_idea_ctr;
# endif

/** @multiple @This is a cipher algorithm descriptor for the Blowfish
    implementation. @xsee {cipheralgos} */
# ifdef CONFIG_ASSH_CIPHER_BLOWFISH_CBC
extern const struct assh_algo_cipher_s assh_cipher_blowfish_cbc;
# endif
# ifdef CONFIG_ASSH_CIPHER_BLOWFISH_CTR
extern const struct assh_algo_cipher_s assh_cipher_blowfish_ctr;
# endif

/** @multiple @This is a cipher algorithm descriptor for the Twofish
    implementation. @xsee {cipheralgos} */
# ifdef CONFIG_ASSH_CIPHER_TWOFISH128_CBC
extern const struct assh_algo_cipher_s assh_cipher_twofish128_cbc;
# endif
# ifdef CONFIG_ASSH_CIPHER_TWOFISH192_CBC
extern const struct assh_algo_cipher_s assh_cipher_twofish192_cbc;
# endif
# ifdef CONFIG_ASSH_CIPHER_TWOFISH256_CBC
extern const struct assh_algo_cipher_s assh_cipher_twofish256_cbc;
# endif
# ifdef CONFIG_ASSH_CIPHER_TWOFISH128_CTR
extern const struct assh_algo_cipher_s assh_cipher_twofish128_ctr;
# endif
# ifdef CONFIG_ASSH_CIPHER_TWOFISH192_CTR
extern const struct assh_algo_cipher_s assh_cipher_twofish192_ctr;
# endif
# ifdef CONFIG_ASSH_CIPHER_TWOFISH256_CTR
extern const struct assh_algo_cipher_s assh_cipher_twofish256_ctr;
# endif
# ifdef CONFIG_ASSH_CIPHER_TWOFISH128_GCM
extern const struct assh_algo_cipher_s assh_cipher_twofish128_gcm;
# endif
# ifdef CONFIG_ASSH_CIPHER_TWOFISH256_GCM
extern const struct assh_algo_cipher_s assh_cipher_twofish256_gcm;
# endif

/** @multiple @This is a cipher algorithm descriptor for the Serpent
    implementation. @xsee {cipheralgos} */
# ifdef CONFIG_ASSH_CIPHER_SERPENT128_CBC
extern const struct assh_algo_cipher_s assh_cipher_serpent128_cbc;
# endif
# ifdef CONFIG_ASSH_CIPHER_SERPENT192_CBC
extern const struct assh_algo_cipher_s assh_cipher_serpent192_cbc;
# endif
# ifdef CONFIG_ASSH_CIPHER_SERPENT256_CBC
extern const struct assh_algo_cipher_s assh_cipher_serpent256_cbc;
# endif
# ifdef CONFIG_ASSH_CIPHER_SERPENT128_CTR
extern const struct assh_algo_cipher_s assh_cipher_serpent128_ctr;
# endif
# ifdef CONFIG_ASSH_CIPHER_SERPENT192_CTR
extern const struct assh_algo_cipher_s assh_cipher_serpent192_ctr;
# endif
# ifdef CONFIG_ASSH_CIPHER_SERPENT256_CTR
extern const struct assh_algo_cipher_s assh_cipher_serpent256_ctr;
# endif
# ifdef CONFIG_ASSH_CIPHER_SERPENT128_GCM
extern const struct assh_algo_cipher_s assh_cipher_serpent128_gcm;
# endif
# ifdef CONFIG_ASSH_CIPHER_SERPENT256_GCM
extern const struct assh_algo_cipher_s assh_cipher_serpent256_gcm;
# endif

/** @multiple @This is a cipher algorithm descriptor for the Camellia
    implementation. @xsee {cipheralgos} */
# ifdef CONFIG_ASSH_CIPHER_CAMELLIA128_CBC
extern const struct assh_algo_cipher_s assh_cipher_camellia128_cbc;
# endif
# ifdef CONFIG_ASSH_CIPHER_CAMELLIA192_CBC
extern const struct assh_algo_cipher_s assh_cipher_camellia192_cbc;
# endif
# ifdef CONFIG_ASSH_CIPHER_CAMELLIA256_CBC
extern const struct assh_algo_cipher_s assh_cipher_camellia256_cbc;
# endif
# ifdef CONFIG_ASSH_CIPHER_CAMELLIA128_CTR
extern const struct assh_algo_cipher_s assh_cipher_camellia128_ctr;
# endif
# ifdef CONFIG_ASSH_CIPHER_CAMELLIA192_CTR
extern const struct assh_algo_cipher_s assh_cipher_camellia192_ctr;
# endif
# ifdef CONFIG_ASSH_CIPHER_CAMELLIA256_CTR
extern const struct assh_algo_cipher_s assh_cipher_camellia256_ctr;
# endif

# ifdef CONFIG_ASSH_CIPHER_CHACHAPOLY
/** @multiple @This is a cipher algorithm descriptor for the openssh
    Chacha20-Poly1305 authenticated cipher implementation.
    @xsee {cipheralgos} */
extern const struct assh_algo_cipher_s assh_cipher_chachapoly;
# endif

#endif


