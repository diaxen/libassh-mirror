/*

  libassh - asynchronous ssh2 client/server library.

  Copyright (C) 2013 Alexandre Becoulet <alexandre.becoulet@free.fr>

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


#ifndef ASSH_HASH_H_
#define ASSH_HASH_H_

#include "assh.h"

struct assh_hash_algo_s;

struct assh_hash_ctx_s
{
  const struct assh_hash_algo_s *algo;
};

/** @internal @see assh_hash_init_t */
#define ASSH_HASH_INIT_FCN(n) \
  ASSH_WARN_UNUSED_RESULT assh_error_t (n)(struct assh_context_s *c, \
                                           struct assh_hash_ctx_s *hctx, \
                                           const struct assh_hash_algo_s *algo)
/** @internal This function initializes an hash algorithm context. A
    call to this function must be paired with a call to @ref assh_hash_final_t. */
typedef ASSH_HASH_INIT_FCN(assh_hash_init_t);

/** @internal @see assh_hash_copy_t */
#define ASSH_HASH_COPY_FCN(n) \
  ASSH_WARN_UNUSED_RESULT assh_error_t (n)(struct assh_hash_ctx_s *hctx_dst, \
                                           const struct assh_hash_ctx_s *hctx_src)
/** @internal This function creates a copy of the hash algorithm context. A
    call to this function must be paired with a call to @ref assh_hash_final_t. */
typedef ASSH_HASH_COPY_FCN(assh_hash_copy_t);

/** @internal @see assh_hash_update_t */
#define ASSH_HASH_UPDATE_FCN(n) \
  void (n)(struct assh_hash_ctx_s *hctx, const void *data, size_t len)
/** @internal This function updates the hash context with new input data. */
typedef ASSH_HASH_UPDATE_FCN(assh_hash_update_t);

/** @internal @see assh_hash_final_t */
#define ASSH_HASH_FINAL_FCN(n) \
  void (n)(struct assh_hash_ctx_s *hctx, uint8_t *hash, size_t len)
/** @internal This function writes the hash result. */
typedef ASSH_HASH_FINAL_FCN(assh_hash_final_t);

/** @internal @see assh_hash_cleanup_t */
#define ASSH_HASH_CLEANUP_FCN(n) \
  void (n)(struct assh_hash_ctx_s *hctx)
/** @internal This function releases resources allocated by the @ref
    assh_hash_init_t or assh_hash_copy_t function. */
typedef ASSH_HASH_CLEANUP_FCN(assh_hash_cleanup_t);

struct assh_hash_algo_s
{
  const char *name;
  assh_hash_init_t *f_init;
  assh_hash_copy_t *f_copy;
  assh_hash_update_t *f_update;
  assh_hash_final_t *f_final;
  assh_hash_cleanup_t *f_cleanup;
  /** size of hash function context structure */
  size_t ctx_size;
  /** hash function output size, 0 for variable size output */
  size_t hash_size;
  size_t block_size;
};

/** This function hashes a ssh string. The string must contain a valid
    32 bits size header; not check is performed by this function. */
void assh_hash_string(struct assh_hash_ctx_s *hctx, const uint8_t *str);

/** This function hashes an array of bytes as if it was stored as a
    ssh string. This means that a 32 bits headers with the array
    length is first generated and hashed. */
void assh_hash_bytes_as_string(struct assh_hash_ctx_s *hctx,
                               const uint8_t *bytes, size_t len);

/** This function convert the big number to the ssh mpint
    representation and hash the result. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_hash_bignum(struct assh_context_s *ctx,
                 struct assh_hash_ctx_s *hctx,
                 const struct assh_bignum_s *bn);

/** This function hash the packet payload. The packet must contain a valid
    32 bits size header; not check is performed by this function. */
void assh_hash_payload_as_string(struct assh_hash_ctx_s *hctx,
                                 const struct assh_packet_s *p);

static inline void
assh_hash_update(struct assh_hash_ctx_s *hctx, const void *data, size_t len)
{
  return hctx->algo->f_update(hctx, data, len);
}

/** @This can be called multiple times when the hash algorithm has a
    variable length output. */
static inline void
assh_hash_final(struct assh_hash_ctx_s *hctx, uint8_t *hash, size_t len)
{
  hctx->algo->f_final(hctx, hash, len);
}

static inline void
assh_hash_cleanup(struct assh_hash_ctx_s *hctx)
{
  hctx->algo->f_cleanup(hctx);
}

static inline ASSH_WARN_UNUSED_RESULT assh_error_t
assh_hash_copy(struct assh_hash_ctx_s *hctx_dst,
               struct assh_hash_ctx_s *hctx_src)
{
  return hctx_src->algo->f_copy(hctx_dst, hctx_src);  
}

/** @This initialize a hash algorithm context. */
static inline ASSH_WARN_UNUSED_RESULT assh_error_t
assh_hash_init(struct assh_context_s *c,
               struct assh_hash_ctx_s *hctx,
               const struct assh_hash_algo_s *algo)
{
  hctx->algo = algo;
  return algo->f_init(c, hctx, algo);
}

extern const struct assh_hash_algo_s assh_hash_md5;

extern const struct assh_hash_algo_s assh_hash_sha1;

extern const struct assh_hash_algo_s assh_hash_sha224;
extern const struct assh_hash_algo_s assh_hash_sha256;
extern const struct assh_hash_algo_s assh_hash_sha384;
extern const struct assh_hash_algo_s assh_hash_sha512;

extern const struct assh_hash_algo_s assh_hash_sha3_224;
extern const struct assh_hash_algo_s assh_hash_sha3_256;
extern const struct assh_hash_algo_s assh_hash_sha3_384;
extern const struct assh_hash_algo_s assh_hash_sha3_512;
extern const struct assh_hash_algo_s assh_hash_shake_128;
extern const struct assh_hash_algo_s assh_hash_shake_256;

#endif

