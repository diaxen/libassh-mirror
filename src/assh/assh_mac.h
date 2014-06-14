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


#ifndef ASSH_MAC_H_
#define ASSH_MAC_H_

#include "assh_algo.h"

#define ASSH_MAC_INIT_FCN(n) \
  ASSH_WARN_UNUSED_RESULT assh_error_t (n)(struct assh_context_s *c,\
                                           void *ctx_, const uint8_t *key)
typedef ASSH_MAC_INIT_FCN(assh_mac_init_t);

#define ASSH_MAC_COMPUTE_FCN(n) \
  ASSH_WARN_UNUSED_RESULT assh_error_t (n)(void *ctx_, uint32_t seq, \
                                           const uint8_t *data, size_t len, \
                                           uint8_t *mac)
typedef ASSH_MAC_COMPUTE_FCN(assh_mac_compute_t);

#define ASSH_MAC_VERIFY_FCN(n) \
  ASSH_WARN_UNUSED_RESULT assh_error_t (n)(void *ctx_, uint32_t seq, \
                                           const uint8_t *data, size_t len, \
                                           const uint8_t *mac)
typedef ASSH_MAC_VERIFY_FCN(assh_mac_verify_t);

#define ASSH_MAC_CLEANUP_FCN(n) void (n)(struct assh_context_s *c, void *ctx_)
typedef ASSH_MAC_CLEANUP_FCN(assh_mac_cleanup_t);

struct assh_algo_mac_s
{
  struct assh_algo_s algo;
  size_t ctx_size;
  size_t key_size;
  size_t mac_size;
  assh_mac_init_t *f_init;
  assh_mac_compute_t *f_compute;
  assh_mac_verify_t *f_verify;
  assh_mac_cleanup_t *f_cleanup;
};

void assh_mac_register(struct assh_algo_mac_s *m);

extern struct assh_algo_mac_s assh_hmac_none;
extern struct assh_algo_mac_s assh_hmac_md5;
extern struct assh_algo_mac_s assh_hmac_md5_96;
extern struct assh_algo_mac_s assh_hmac_sha1;
extern struct assh_algo_mac_s assh_hmac_sha1_96;
extern struct assh_algo_mac_s assh_hmac_sha256;
extern struct assh_algo_mac_s assh_hmac_sha512;

#endif

