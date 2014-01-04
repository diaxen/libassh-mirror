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


#include <assh/assh_mac.h>
#include <assh/hash_sha1.h>
#include <assh/assh_packet.h>

#include <string.h>

struct assh_hmac_sha1_context_s
{
  struct assh_hash_sha1_context_s co;
  struct assh_hash_sha1_context_s ci;
};

static ASSH_MAC_INIT_FCN(assh_hmac_sha1_init)
{
  struct assh_hmac_sha1_context_s *ctx = ctx_;
  uint8_t kx[64];
  unsigned int i;

  for (i = 0; i < 20; i++)
    kx[i] = key[i] ^ 0x36;
  for (; i < sizeof(kx); i++)
    kx[i] = 0x36;
  assh_sha1_init(&ctx->ci);
  assh_sha1_update(&ctx->ci, kx, sizeof(kx));

  for (i = 0; i < 20; i++)
    kx[i] = key[i] ^ 0x5c;
  for (; i < sizeof(kx); i++)
    kx[i] = 0x5c;
  assh_sha1_init(&ctx->co);
  assh_sha1_update(&ctx->co, kx, sizeof(kx));

  return ASSH_OK;
}

static ASSH_MAC_CLEANUP_FCN(assh_hmac_sha1_cleanup)
{
}

static ASSH_MAC_COMPUTE_FCN(assh_hmac_sha1_compute)
{
  struct assh_hmac_sha1_context_s *ctx = ctx_;
  struct assh_hash_sha1_context_s co, ci;
  uint8_t t[20];
  uint8_t be_seq[4];

  memcpy(&ci, &ctx->ci, sizeof(ci));
  assh_store_u32(be_seq, seq);
  assh_sha1_update(&ci, be_seq, 4);
  assh_sha1_update(&ci, data, len);
  assh_sha1_final(&ci, t);
  memcpy(&co, &ctx->co, sizeof(co));
  assh_sha1_update(&co, t, sizeof(t));
  assh_sha1_final(&co, mac);

  return ASSH_OK;
}

struct assh_algo_mac_s assh_hmac_sha1 = 
{
  .algo = { .name = "hmac-sha1", .class_ = ASSH_ALGO_MAC,
            .safety = 21, .speed = 50 },
  .ctx_size = sizeof(struct assh_hmac_sha1_context_s),
  .key_size = 20,
  .mac_size = 20,
  .f_init = assh_hmac_sha1_init,
  .f_compute = assh_hmac_sha1_compute,
  .f_cleanup = assh_hmac_sha1_cleanup,
};

static ASSH_MAC_COMPUTE_FCN(assh_hmac_sha1_96_compute)
{
  uint8_t t[20];
  assh_error_t err = assh_hmac_sha1_compute(ctx_, seq, data, len, t);
  memcpy(mac, t, 12);
  return err;
}

struct assh_algo_mac_s assh_hmac_sha1_96 = 
{
  .algo = { .name = "hmac-sha1-96", .class_ = ASSH_ALGO_MAC,
            .safety = 20, .speed = 50 },
  .ctx_size = sizeof(struct assh_hmac_sha1_context_s),
  .key_size = 20,
  .mac_size = 12,
  .f_init = assh_hmac_sha1_init,
  .f_compute = assh_hmac_sha1_96_compute,
  .f_cleanup = assh_hmac_sha1_cleanup,
};

