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

/** @internal @see assh_hash_init_t */
#define ASSH_HASH_INIT_FCN(n) \
  ASSH_WARN_UNUSED_RESULT assh_error_t (n)(void *ctx_)
/** @internal This function initializes an hash algorithm context. A
    call to this function must be paired with a call to @ref assh_hash_final_t. */
typedef ASSH_HASH_INIT_FCN(assh_hash_init_t);

/** @internal @see assh_hash_copy_t */
#define ASSH_HASH_COPY_FCN(n) \
  ASSH_WARN_UNUSED_RESULT assh_error_t (n)(void *ctx_dst_, const void *ctx_src_)
/** @internal This function creates a copy of the hash algorithm context. A
    call to this function must be paired with a call to @ref assh_hash_final_t. */
typedef ASSH_HASH_COPY_FCN(assh_hash_copy_t);

/** @internal @see assh_hash_update_t */
#define ASSH_HASH_UPDATE_FCN(n) \
  void (n)(void *ctx_, const void *data, size_t len)
/** @internal This function updates the hash context with new input data. */
typedef ASSH_HASH_UPDATE_FCN(assh_hash_update_t);

/** @internal @see assh_hash_final_t */
#define ASSH_HASH_FINAL_FCN(n) \
  void (n)(void *ctx_, uint8_t *hash)
/** @internal This function writes the hash result and releases
    resources allocated by the @ref assh_hash_init_t and
    assh_hash_copy_t functions. If the @tt hash parameter is NULL, the
    hash result is discarded. */
typedef ASSH_HASH_FINAL_FCN(assh_hash_final_t);

struct assh_hash_s
{
  const char *name;
  size_t ctx_size;
  size_t hash_size;
  size_t block_size;
  assh_hash_init_t *f_init;
  assh_hash_copy_t *f_copy;
  assh_hash_update_t *f_update;
  assh_hash_final_t *f_final;
};

/** This function hashes a ssh string. The string must contain a valid
    32 bits size header; not check is performed by this function. */
void assh_hash_string(void *ctx_, assh_hash_update_t *update, const uint8_t *str);

/** This function hashes an array of bytes as if it was stored as a
    ssh string. This means that a 32 bits headers with the array
    length is first generated and hashed. */
void assh_hash_bytes_as_string(void *ctx_, assh_hash_update_t *update, const uint8_t *bytes, size_t len);

/** This function convert the big number to the ssh mpint representation and hash the result. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_hash_bignum(struct assh_context_s *ctx, void *ctx_,
		 assh_hash_update_t *update, const struct assh_bignum_s *bn);

/** This function hash the packet payload. The packet must contain a valid
    32 bits size header; not check is performed by this function. */
void assh_hash_payload_as_string(void *ctx_, assh_hash_update_t *update, const struct assh_packet_s *p);

extern const struct assh_hash_s assh_hash_md5;
extern const struct assh_hash_s assh_hash_sha1;
extern const struct assh_hash_s assh_hash_sha224;
extern const struct assh_hash_s assh_hash_sha256;
extern const struct assh_hash_s assh_hash_sha384;
extern const struct assh_hash_s assh_hash_sha512;

#endif

