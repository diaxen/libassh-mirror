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

#define ASSH_HASH_INIT_FCN(n) \
  void (n)(void *ctx_)
typedef ASSH_HASH_INIT_FCN(assh_hash_init_t);

#define ASSH_HASH_UPDATE_FCN(n) \
  void (n)(void *ctx_, const void *data, size_t len)
typedef ASSH_HASH_UPDATE_FCN(assh_hash_update_t);

#define ASSH_HASH_FINAL_FCN(n) \
  void (n)(void *ctx_, uint8_t *hash)
typedef ASSH_HASH_FINAL_FCN(assh_hash_final_t);

struct assh_hash_s
{
  size_t ctx_size;
  size_t hash_size;
  assh_hash_init_t *f_init;
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
assh_hash_bignum(void *ctx_, assh_hash_update_t *update, const struct assh_bignum_s *bn);

/** This function hash the packet payload. The packet must contain a valid
    32 bits size header; not check is performed by this function. */
void assh_hash_payload_as_string(void *ctx_, assh_hash_update_t *update, const struct assh_packet_s *p);

#endif

