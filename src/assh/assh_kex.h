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


#ifndef ASSH_KEX_H_
#define ASSH_KEX_H_

#include "assh_algo.h"

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_algo_kex_send_init(struct assh_session_s *s);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_kex_got_init(struct assh_session_s *s, struct assh_packet_s *p);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_kex_new_keys(struct assh_session_s *s,
                  const struct assh_hash_s *hash_algo,
                  const uint8_t *ex_hash, struct assh_bignum_s *k);

void assh_kex_keys_cleanup(struct assh_session_s *ctx,
                           struct assh_kex_keys_s *keys);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_kex_end(struct assh_session_s *s, assh_bool_t accept);

/** This function is called when the key exchange is initiated. It may
    allocate a private context and store it in the @ref
    assh_session_s::kex_pv field. */
#define ASSH_KEX_INIT_FCN(n) assh_error_t (n)(struct assh_session_s *s)
typedef ASSH_KEX_INIT_FCN(assh_kex_init_t);

/** This function is called when the key exchange is over if the @ref
    assh_session_s::kex_pv field is not @tt NULL. It must free the
    key exchange private context and set this field back to @tt NULL. */
#define ASSH_KEX_CLEANUP_FCN(n) void (n)(struct assh_session_s *s)
typedef ASSH_KEX_CLEANUP_FCN(assh_kex_cleanup_t);

/** This function is called when the current transport state is @ref
    #ASSH_TR_KEX_RUNNING and an incoming key exchange packet is available.

    The function may initialize the passed event object, in this case
    the event will be propagated to the caller of the @ref
    assh_event_get function.
*/
#define ASSH_KEX_PROCESS_FCN(n) assh_error_t (n)(struct assh_session_s *s, \
                                                 struct assh_packet_s *p, \
                                                 struct assh_event_s *e)
typedef ASSH_KEX_PROCESS_FCN(assh_kex_process_t);

struct assh_kex_keys_s
{
  const struct assh_algo_cipher_s *cipher;
  void *cipher_ctx;
  const struct assh_algo_mac_s *mac;
  void *mac_ctx;
  const struct assh_algo_compress_s *cmp;
  void *cmp_ctx;
  uint8_t iv[ASSH_MAX_BLOCK_SIZE];
};

struct assh_algo_kex_s
{
  struct assh_algo_s algo;
  assh_kex_init_t *f_init;
  assh_kex_cleanup_t *f_cleanup;
  assh_kex_process_t *f_process;
};

extern struct assh_algo_kex_s assh_kex_dh_group1_sha1;
extern struct assh_algo_kex_s assh_kex_dh_group14_sha1;

#endif

