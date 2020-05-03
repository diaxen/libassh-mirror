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

/** @This casts and returns the passed pointer if the
    algorithm class is @ref ASSH_ALGO_CIPHER. In
    other cases, @tt NULL is returned. */
ASSH_INLINE const struct assh_algo_cipher_s *
assh_algo_cipher(const struct assh_algo_s *algo)
{
  return algo->class_ == ASSH_ALGO_CIPHER
    ? (const struct assh_algo_cipher_s *)algo
    : NULL;
}

/** @This finds a cipher @hl algorithm in a @tt NULL terminated array of
    pointers to algorithm descriptors. @see assh_algo_by_name_static */
ASSH_INLINE ASSH_WARN_UNUSED_RESULT assh_status_t
assh_algo_cipher_by_name_static(const struct assh_algo_s **table,
				const char *name, size_t name_len,
				const struct assh_algo_cipher_s **ca,
				const struct assh_algo_name_s **namep)
{
 return assh_algo_by_name_static(table, ASSH_ALGO_CIPHER, name, name_len,
				 (const struct assh_algo_s **)ca, namep);
}

/** @internal @This finds a registered cipher @hl algorithm.
    @see assh_algo_by_name */
ASSH_INLINE ASSH_WARN_UNUSED_RESULT assh_status_t
assh_algo_cipher_by_name(struct assh_context_s *c, const char *name,
			 size_t name_len, const struct assh_algo_cipher_s **ca,
			 const struct assh_algo_name_s **namep)
{
  return assh_algo_by_name(c, ASSH_ALGO_CIPHER, name, name_len,
			   (const struct assh_algo_s **)ca, namep);
}


/** @multiple @This is a cipher algorithm implementation descriptor
    for the dummy @tt none algorithm. */
extern const struct assh_algo_cipher_s assh_cipher_none;

#endif


