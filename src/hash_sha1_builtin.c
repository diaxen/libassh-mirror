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


#include <assh/hash_sha1.h>

/*
 based on SHA-1 in C
 By Steve Reid <steve@edmweb.com>
 100% Public Domain
*/

#include <string.h>
#include <arpa/inet.h>

static inline uint32_t rol(uint32_t value, unsigned int bits)
{
  return (((value) << (bits)) | ((value) >> (32 - (bits))));
}

/* BLK0() and BLK() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */

#define BLK0(i) (block->l[i] = htonl(block->l[i]))
#define BLK(i) (block->l[i&15] = rol(block->l[(i + 13)&15] ^ block->l[(i + 8)&15] \
                ^ block->l[(i + 2)&15] ^ block->l[i&15], 1))

/* (R0 + R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v, w, x, y, z, i) do { z += ((w&(x ^ y)) ^ y) + BLK0(i) + 0x5A827999 + rol(v, 5);w = rol(w, 30); } while (0)
#define R1(v, w, x, y, z, i) do { z += ((w&(x ^ y)) ^ y) + BLK(i) + 0x5A827999 + rol(v, 5);w = rol(w, 30); } while (0)
#define R2(v, w, x, y, z, i) do { z += (w ^ x ^ y) + BLK(i) + 0x6ED9EBA1 + rol(v, 5);w = rol(w, 30); } while (0)
#define R3(v, w, x, y, z, i) do { z += (((w|x)&y)|(w&x)) + BLK(i) + 0x8F1BBCDC + rol(v, 5);w = rol(w, 30); } while (0)
#define R4(v, w, x, y, z, i) do { z += (w ^ x ^ y) + BLK(i) + 0xCA62C1D6 + rol(v, 5);w = rol(w, 30); } while (0)


/* Hash a single 512-bit block. This is the core of the algorithm. */
static void assh_sha1_transform(uint32_t state[5], const uint8_t buffer[64])
{
  uint32_t a, b, c, d, e, x;
  typedef union {
    uint8_t c[64];
    uint32_t l[16];
  } CHAR64LONG16;

  CHAR64LONG16 block[1];
  memcpy(block, buffer, 64);

  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];

  /* 4 rounds of 20 operations each. */  
  unsigned int i;
  for (i = 0; i <= 15; i++)
    {
      R0(a, b, c, d, e, i);
      (x = a), (a = e), (e = d), (d = c), (c = b), (b = x);
    }
  for (; i <= 19; i++)
    {
      R1(a, b, c, d, e, i);
      (x = a), (a = e), (e = d), (d = c), (c = b), (b = x);
    }
  for (; i <= 39; i++)
    {
      R2(a, b, c, d, e, i);
      (x = a), (a = e), (e = d), (d = c), (c = b), (b = x);
    }
  for (; i <= 59; i++)
    {
      R3(a, b, c, d, e, i);
      (x = a), (a = e), (e = d), (d = c), (c = b), (b = x);
    }
  for (; i <= 79; i++)
    {
      R4(a, b, c, d, e, i);
      (x = a), (a = e), (e = d), (d = c), (c = b), (b = x);
    }

  /* Add the working vars back into context.state[] */
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
}


ASSH_HASH_INIT_FCN(assh_sha1_init)
{
  struct assh_hash_sha1_context_s *ctx = ctx_;

  /* SHA1 initialization constants */
  ctx->state[0] = 0x67452301;
  ctx->state[1] = 0xEFCDAB89;
  ctx->state[2] = 0x98BADCFE;
  ctx->state[3] = 0x10325476;
  ctx->state[4] = 0xC3D2E1F0;
  ctx->count[0] = ctx->count[1] = 0;
}


ASSH_HASH_UPDATE_FCN(assh_sha1_update)
{
  struct assh_hash_sha1_context_s *ctx = ctx_;
  const uint8_t *data_ = data;
  uint32_t i, j;

  j = ctx->count[0];

  if ((ctx->count[0] += len << 3) < j)
    ctx->count[1]++;

  ctx->count[1] += (len>>29);
  j = (j >> 3) & 63;

  if ((j + len) > 63)
    {
      i = 64 - j;
      memcpy(&ctx->buffer[j], data_, i);

      assh_sha1_transform(ctx->state, ctx->buffer);
      for ( ; i + 63 < len; i += 64)
	assh_sha1_transform(ctx->state, &data_[i]);

      j = 0;
    }
  else
    {
      i = 0;
    }

  memcpy(&ctx->buffer[j], &data_[i], len - i);
}


ASSH_HASH_FINAL_FCN(assh_sha1_final)
{
  struct assh_hash_sha1_context_s *ctx = ctx_;
  unsigned int i;
  uint8_t finalcount[8];
  uint8_t c;

  for (i = 0; i < 8; i++)
    finalcount[i] = (uint8_t)((ctx->count[(i >= 4 ? 0 : 1)]
			       >> ((3-(i & 3)) * 8) ) & 0xff);

  c = 0200;
  assh_sha1_update(ctx, &c, 1);
  while ((ctx->count[0] & 504) != 448)
    {
      c = 0000;
      assh_sha1_update(ctx, &c, 1);
    }

  assh_sha1_update(ctx, finalcount, 8);
  for (i = 0; i < 20; i++)
    hash[i] = (uint8_t)((ctx->state[i >> 2] >> ((3 - (i & 3)) * 8) ) & 0xff);
}

const struct assh_hash_s assh_hash_sha1 = 
{
  .ctx_size = sizeof(struct assh_hash_sha1_context_s),
  .hash_size = 20,
  .f_init = assh_sha1_init,
  .f_update = assh_sha1_update,
  .f_final = assh_sha1_final,
};

