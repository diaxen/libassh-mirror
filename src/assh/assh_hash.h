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
   @short Hashing module interface
   @internal

   This header file contains descriptors for cryptographic hash
   function modules implemented and used in the library.

   @xsee{coremod}
*/

#ifndef ASSH_HASH_H_
#define ASSH_HASH_H_

#include "assh_algo.h"

struct assh_hash_algo_s;

/** @internal @This is the base structure for hash contexts */
struct assh_hash_ctx_s
{
  const struct assh_hash_algo_s *algo;
};

/** @internal @see assh_hash_init_t */
#define ASSH_HASH_INIT_FCN(n) \
  ASSH_WARN_UNUSED_RESULT assh_status_t (n)(struct assh_context_s *c, \
                                           struct assh_hash_ctx_s *hctx, \
                                           const struct assh_hash_algo_s *algo)

/** @internal @This defines the function type for the hash initialization
    operation of the hash module interface. @see assh_hash_init */
typedef ASSH_HASH_INIT_FCN(assh_hash_init_t);

/** @internal @see assh_hash_copy_t */
#define ASSH_HASH_COPY_FCN(n) \
  ASSH_WARN_UNUSED_RESULT assh_status_t (n)(struct assh_hash_ctx_s *hctx_dst, \
                                           const struct assh_hash_ctx_s *hctx_src)

/** @internal @This defines the function type for the hash context copy
    operation of the hash module interface. @see assh_hash_copy. */
typedef ASSH_HASH_COPY_FCN(assh_hash_copy_t);

/** @internal @see assh_hash_update_t */
#define ASSH_HASH_UPDATE_FCN(n) \
  void (n)(struct assh_hash_ctx_s *hctx, const void *data, size_t len)

/** @internal @This defines the function type for the hash update
    operation of the hash module interface. @see assh_hash_update */
typedef ASSH_HASH_UPDATE_FCN(assh_hash_update_t);

/** @internal @see assh_hash_final_t */
#define ASSH_HASH_FINAL_FCN(n) \
  void (n)(struct assh_hash_ctx_s *hctx, uint8_t *hash, size_t len)

/** @internal @This defines the function type for the hash output
    operation of the hash module interface. @see assh_hash_final */
typedef ASSH_HASH_FINAL_FCN(assh_hash_final_t);

/** @internal @see assh_hash_cleanup_t */
#define ASSH_HASH_CLEANUP_FCN(n) \
  void (n)(struct assh_hash_ctx_s *hctx)

/** @internal @This defines the function type for the hash context cleanup
    operation of the hash module interface. @see assh_hash_cleanup */
typedef ASSH_HASH_CLEANUP_FCN(assh_hash_cleanup_t);

/** @internal @This is the hashing module interface structure. */
struct assh_hash_algo_s
{
  ASSH_PV const char *name;
  assh_hash_init_t *f_init;
  assh_hash_copy_t *f_copy;
  assh_hash_update_t *f_update;
  assh_hash_final_t *f_final;
  assh_hash_cleanup_t *f_cleanup;
  /** Size of the context structure needed to initialize the algorithm. */
  ASSH_PV uint16_t ctx_size;
  /** Hash function output size, 0 for variable size output. */
  ASSH_PV uint8_t hash_size;
  /** Hash algorithm block size. */
  ASSH_PV uint8_t block_size;
  /** This relates to the collision resistance of the hash
      function. It is mostly relevant when involved in signature
      algorithms and does not necessarily impact other constructions
      like HMAC and key derivation. */
  ASSH_PV assh_safety_t sign_safety:8;
};

/** @internal @This hashes a ssh string. The string must contain a
    valid 32 bits size header. No bound checking is performed by this
    function. */
ASSH_PV void assh_hash_string(struct assh_hash_ctx_s *hctx, const uint8_t *str);

/** @internal @This hashes an array of bytes as if it was stored as a
    ssh string. This means that a 32 bits headers with the array
    length is first generated and hashed. */
ASSH_PV void assh_hash_bytes_as_string(struct assh_hash_ctx_s *hctx,
				       const uint8_t *bytes, size_t len);

#ifdef CONFIG_ASSH_BIGNUM_BUILTIN
/** @internal @This convert the big number to the ssh mpint
    representation and hash the resulting buffer. */
ASSH_PV ASSH_WARN_UNUSED_RESULT assh_status_t
assh_hash_bignum(struct assh_context_s *ctx,
                 struct assh_hash_ctx_s *hctx,
                 const struct assh_bignum_s *bn);
#endif

/** @internal @This hash the packet payload. The packet must contain a
    valid 32 bits size header; not check is performed by this
    function. */
ASSH_PV void
assh_hash_payload_as_string(struct assh_hash_ctx_s *hctx,
			    const struct assh_packet_s *p);

/** @internal @This initializes an hash algorithm context. The @tt
    hctx argument must points to a buffer allocated in secure memory
    of size given by @ref assh_hash_algo_s::ctx_size. */
ASSH_PV ASSH_INLINE ASSH_WARN_UNUSED_RESULT assh_status_t
assh_hash_init(struct assh_context_s *c,
               struct assh_hash_ctx_s *hctx,
               const struct assh_hash_algo_s *algo)
{
  hctx->algo = algo;
  return algo->f_init(c, hctx, algo);
}

/** @internal @This creates a copy of the hash algorithm context. The
    new context must be released as if it was created by @ref
    assh_hash_init. */
ASSH_PV ASSH_INLINE ASSH_WARN_UNUSED_RESULT assh_status_t
assh_hash_copy(struct assh_hash_ctx_s *hctx_dst,
               struct assh_hash_ctx_s *hctx_src)
{
  return hctx_src->algo->f_copy(hctx_dst, hctx_src);  
}

/** @internal @This updates the hash context with new input data. */
ASSH_PV ASSH_INLINE void
assh_hash_update(struct assh_hash_ctx_s *hctx, const void *data, size_t len)
{
  hctx->algo->f_update(hctx, data, len);
}

/** @internal @This produce the hash output. It can be called multiple
    times when the hash algorithm has a variable length output. */
ASSH_PV ASSH_INLINE void
assh_hash_final(struct assh_hash_ctx_s *hctx, uint8_t *hash, size_t len)
{
  hctx->algo->f_final(hctx, hash, len);
}

/** @internal @This releases resources allocated by the @ref
    assh_hash_init and @ref assh_hash_copy functions.  @see
    assh_hash_cleanup. */
ASSH_PV ASSH_INLINE void
assh_hash_cleanup(struct assh_hash_ctx_s *hctx)
{
  hctx->algo->f_cleanup(hctx);
}

/** @multiple @internal safety factor of common hash functions.
    @see assh_hash_algo_s::sign_safety */
#define ASSH_SAFETY_MD5      10
#define ASSH_SAFETY_SHA1     20
#define ASSH_SAFETY_SHA2_224 43
#define ASSH_SAFETY_SHA2_256 50
#define ASSH_SAFETY_SHA2_384 75
#define ASSH_SAFETY_SHA2_512 99
#define ASSH_SAFETY_SHA3_224 43
#define ASSH_SAFETY_SHA3_256 50
#define ASSH_SAFETY_SHA3_384 75
#define ASSH_SAFETY_SHA3_512 99
#define ASSH_SAFETY_SHAKE128 50
#define ASSH_SAFETY_SHAKE256 99

/** @internal @This is the md5 hash algorithm implementation
    descriptor. */
ASSH_PV extern const struct assh_hash_algo_s assh_hash_md5;

/** @internal @This is the sha1 hash algorithm implementation
    descriptor. */
ASSH_PV extern const struct assh_hash_algo_s assh_hash_sha1;

/** @multiple @internal @This is a sha2 hash algorithm implementation
    descriptor. */
ASSH_PV extern const struct assh_hash_algo_s assh_hash_sha224;
ASSH_PV extern const struct assh_hash_algo_s assh_hash_sha256;
ASSH_PV extern const struct assh_hash_algo_s assh_hash_sha384;
ASSH_PV extern const struct assh_hash_algo_s assh_hash_sha512;

/** @multiple @internal @This is a sha3 hash algorithm implementation
    descriptor. */
ASSH_PV extern const struct assh_hash_algo_s assh_hash_sha3_224;
ASSH_PV extern const struct assh_hash_algo_s assh_hash_sha3_256;
ASSH_PV extern const struct assh_hash_algo_s assh_hash_sha3_384;
ASSH_PV extern const struct assh_hash_algo_s assh_hash_sha3_512;
ASSH_PV extern const struct assh_hash_algo_s assh_hash_shake_128;
ASSH_PV extern const struct assh_hash_algo_s assh_hash_shake_256;

#endif

