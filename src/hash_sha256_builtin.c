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

#include <assh/hash_sha256.h>
#include <assh/assh_packet.h>

/*
 *  FIPS-180-2 compliant SHA-256 implementation
 *  based on code written by Christophe Devine
 *
 *  This code has been distributed as PUBLIC DOMAIN.
 */

#include <string.h>

ASSH_HASH_INIT_FCN(assh_sha256_init)
{
  struct assh_hash_sha256_context_s *ctx = ctx_;

  ctx->count[0] = 0;
  ctx->count[1] = 0;

  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
}

static inline uint32_t ror(uint32_t value, unsigned int bits)
{
  return (((value) >> (bits)) | ((value) << (32 - (bits))));
}

static void sha256_process(struct assh_hash_sha256_context_s *ctx,
			   const uint8_t data[64])
{
  uint32_t temp1, temp2, w[64];
  uint_fast8_t i;

  for (i = 0; i < 16; i++)
    w[i] = assh_load_u32(data + i * 4);

#define S0(x) (ror(x,  7) ^ ror(x, 18) ^ (x >> 3))
#define S1(x) (ror(x, 17) ^ ror(x, 19) ^ (x >> 10))

#define S2(x) (ror(x,  2) ^ ror(x, 13) ^ ror(x, 22))
#define S3(x) (ror(x,  6) ^ ror(x, 11) ^ ror(x, 25))

#define F0(x,y,z) ((x & y) | (z & (x | y)))
#define F1(x,y,z) (z ^ (x & (y ^ z)))

#define R(t)                                    \
(                                               \
    w[t] = S1(w[t -  2]) + w[t -  7] +          \
           S0(w[t - 15]) + w[t - 16]            \
)

#define P(a, b, c, d, e, f, g, h, x, K)		\
{                                               \
    temp1 = h + S3(e) + F1(e,f,g) + K + x;      \
    temp2 = S2(a) + F0(a,b,c);                  \
    d += temp1; h = temp1 + temp2;              \
}

  uint32_t a = ctx->state[0];
  uint32_t b = ctx->state[1];
  uint32_t c = ctx->state[2];
  uint32_t d = ctx->state[3];
  uint32_t e = ctx->state[4];
  uint32_t f = ctx->state[5];
  uint32_t g = ctx->state[6];
  uint32_t h = ctx->state[7];

  static const uint32_t keys[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  };

  for (i = 0; i < 16; i++)
    {
      P(a, b, c, d, e, f, g, h, w[i], keys[i]);
      uint32_t x = h;
      (h = g), (g = f), (f = e), (e = d), (d = c), (c = b), (b = a), (a = x);      
    }

  for (; i < 64; i++)
    {
      P(a, b, c, d, e, f, g, h, R(i), keys[i]);
      uint32_t x = h;
      (h = g), (g = f), (f = e), (e = d), (d = c), (c = b), (b = a), (a = x);
    }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

ASSH_HASH_UPDATE_FCN(assh_sha256_update)
{
  struct assh_hash_sha256_context_s *ctx = ctx_;
  uint32_t left, fill;
  const uint8_t *input = data;

  if (len == 0)
    return;

  left = ctx->count[0] & 0x3f;
  fill = 64 - left;

  ctx->count[0] += len;
  if (ctx->count[0] < len)
    ctx->count[1]++;

  if (left && len >= fill)
    {
      memcpy((ctx->buffer + left), input, fill);
      sha256_process(ctx, ctx->buffer);
      len -= fill;
      input += fill;
      left = 0;
    }

  while (len >= 64)
    {
      sha256_process(ctx, input);
      len -= 64;
      input += 64;
    }

  if (len)
    memcpy((ctx->buffer + left), input, len);
}

ASSH_HASH_FINAL_FCN(assh_sha256_final)
{
  struct assh_hash_sha256_context_s *ctx = ctx_;
  uint32_t last, padn;
  uint32_t high, low;
  uint8_t msglen[8];
  uint_fast8_t i;

  high = (ctx->count[0] >> 29) | (ctx->count[1] << 3);
  low  = (ctx->count[0] << 3);

  assh_store_u32(msglen + 0, high);
  assh_store_u32(msglen + 4, low);

  last = ctx->count[0] & 0x3f;
  padn = (last < 56) ? (56 - last) : (120 - last);

  static const uint8_t sha256_padding[17] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  };

  const uint8_t *pad = sha256_padding;
  while (padn > 16)
    {
      assh_sha256_update(ctx, pad, 16);
      pad = sha256_padding + 1;
      padn -= 16;
    }
  assh_sha256_update(ctx, pad, padn);

  assh_sha256_update(ctx, msglen, 8);

  for (i = 0; i < 8; i++)
    assh_store_u32(hash + i * 4, ctx->state[i]);
}

const struct assh_hash_s assh_hash_sha256 = 
{
  .ctx_size = sizeof(struct assh_hash_sha256_context_s),
  .hash_size = 32,
  .f_init = assh_sha256_init,
  .f_update = assh_sha256_update,
  .f_final = assh_sha256_final,
};

