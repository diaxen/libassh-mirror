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


#include <assh/assh_prng.h>
#include <assh/assh_context.h>
#include <assh/assh_packet.h>
#include <assh/assh_alloc.h>
#include <assh/assh_buffer.h>
#include <assh/mod_builtin.h>

#include <string.h>
#include <stdlib.h>

  /*
   ______              ______
  /      \            /      \
  |      |            |      |
  |      v            v      |
  |  +---------|----------+  |
  |  |   256 bits state   |  |
  |  +---------|----------+  |
  |      |            |      |
 XOR<----+----.  .----+---->XOR
  ^      |     \/     |      ^
  |      v     /\     v      |
  |     TEA<--'  '-->TEA     |
  |      |            |      |
  \______/            |______/
                      |
                      v
                     Out
  */

struct assh_prng_pv_s
{
  uint32_t s[8];
  uint8_t buf[16];
};

static void xtea_cipher(const uint32_t key[4], uint32_t *v0_,
                        uint32_t *v1_, uint32_t delta)
{
  uint32_t v0 = *v0_, v1 = *v1_;
  uint32_t sum = 0;
  uint_fast8_t i;

  for (i = 0; i < 32; i++)
    {
      v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
      sum += delta;
      v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
    }

  *v0_ = v0;
  *v1_ = v1;
}

static void assh_prng_xswap_round(struct assh_prng_pv_s *ctx)
{
  uint32_t *s = ctx->s;
  uint32_t s0 = s[0];
  uint32_t s1 = s[1];
  uint32_t s2 = s[2];
  uint32_t s3 = s[3];
  uint32_t s4 = s[4];
  uint32_t s5 = s[5];
  uint32_t s6 = s[6];
  uint32_t s7 = s[7];

  xtea_cipher(s + 4, &s0, &s1, 0x9e3779b9);
  xtea_cipher(s + 4, &s2, &s3, 0x71374491);
  xtea_cipher(s + 0, &s4, &s5, 0xb5c0fbcf);
  xtea_cipher(s + 0, &s6, &s7, 0xe9b5dba5);

  s[0] ^= s0;
  s[1] ^= s1;
  s[2] ^= s2;
  s[3] ^= s3;
  s[4] ^= s4;
  s[5] ^= s5;
  s[6] ^= s6;
  s[7] ^= s7;

  uint8_t *buf = ctx->buf;
  assh_store_u32le(buf + 0, s0);
  assh_store_u32le(buf + 4, s1);
  assh_store_u32le(buf + 8, s4);
  assh_store_u32le(buf + 12, s5);
}

static ASSH_PRNG_INIT_FCN(assh_prng_xswap_init)
{
  uint8_t *rdata = seed->data;
  size_t rdata_len = seed->len;
  assh_status_t err;

  ASSH_RET_IF_TRUE(rdata == NULL || rdata_len < 16, ASSH_ERR_BAD_ARG);

  ASSH_RET_ON_ERR(assh_alloc(c, sizeof(struct assh_prng_pv_s),
                          ASSH_ALLOC_SECUR, &c->prng_pv));
  struct assh_prng_pv_s *ctx = c->prng_pv;

  memset(ctx, 0, sizeof(*ctx));

  while (rdata_len >= 16)
    {
      ctx->s[4] ^= assh_load_u32le(rdata + 0);
      ctx->s[5] ^= assh_load_u32le(rdata + 4);
      ctx->s[6] ^= assh_load_u32le(rdata + 8);
      ctx->s[7] ^= assh_load_u32le(rdata + 12);

      assh_prng_xswap_round(ctx);
      rdata += 16;
      rdata_len -= 16;
    }

  if (rdata_len > 0)
    {
      uint8_t *buf = ctx->buf;
      memcpy(buf, rdata, rdata_len);

      ctx->s[4] ^= assh_load_u32le(buf + 0);
      ctx->s[5] ^= assh_load_u32le(buf + 4);
      ctx->s[6] ^= assh_load_u32le(buf + 8);
      ctx->s[7] ^= assh_load_u32le(buf + 12);

      assh_prng_xswap_round(ctx);
    }

  return ASSH_OK;
}

static ASSH_PRNG_GET_FCN(assh_prng_xswap_get)
{
  struct assh_prng_pv_s *ctx = c->prng_pv;

  if (quality == ASSH_PRNG_QUALITY_WEAK)
    {
      while (rdata_len--)
	*rdata++ = rand();
      return ASSH_OK;
    }

  while (rdata_len > 0)
    {
      uint_fast8_t l = assh_min_uint(16, rdata_len);
      assh_prng_xswap_round(ctx);
      memcpy(rdata, ctx->buf, l);
      rdata_len -= l;
      rdata += l;
    }

  return ASSH_OK;
}

static ASSH_PRNG_CLEANUP_FCN(assh_prng_xswap_cleanup)
{
  struct assh_prng_pv_s *ctx = c->prng_pv;
  assh_free(c, ctx);
}

const struct assh_prng_s assh_prng_xswap = 
{
  .f_init = assh_prng_xswap_init,
  .f_get = assh_prng_xswap_get,
  .f_cleanup = assh_prng_xswap_cleanup,  
};

