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

#define ASSH_PV

#include <assh/assh_cipher.h>
#include <assh/assh_buffer.h>
#include <assh/mod_builtin.h>

/******************************************************* chacha20 */

/* This chacha implementation is somewhat ssh specific. */

struct assh_chacha20_ctx_s
{
  uint32_t w[12];
};

static void assh_chacha20_set_key(struct assh_chacha20_ctx_s *ctx,
                                  const uint8_t key[32])
{
  ctx->w[0] = assh_load_u32le(key);
  ctx->w[1] = assh_load_u32le(key + 4);
  ctx->w[2] = assh_load_u32le(key + 8);
  ctx->w[3] = assh_load_u32le(key + 12);

  ctx->w[4] = 0;                /* iv low */
  ctx->w[7] = 0;                /* ctr high */

  ctx->w[8] = assh_load_u32le(key + 16);
  ctx->w[9] = assh_load_u32le(key + 20);
  ctx->w[10] = assh_load_u32le(key + 24);
  ctx->w[11] = assh_load_u32le(key + 28);
}

static inline void assh_chacha20_set_iv(struct assh_chacha20_ctx_s *ctx,
                                        const uint32_t iv)
{
  ctx->w[5] = (iv >> 24) | (iv << 24) |  /* byte swap */
    ((iv << 8) & 0x00ff0000) | ((iv >> 8) & 0x0000ff00);
}

static inline void assh_chacha20_set_ctr(struct assh_chacha20_ctx_s *ctx,
                                         const uint32_t ctr)
{
  ctx->w[6] = ctr;
}

static inline uint32_t assh_chacha20_rotate(uint32_t x, uint_fast8_t i)
{
  return (x << i) | (x >> (32 - i));
}

static void assh_chacha20_block(struct assh_chacha20_ctx_s *ctx,
                                uint32_t out[16], size_t count)
{
  uint_fast8_t i;

  const uint32_t c0 =  0x61707865;
  const uint32_t c5 =  0x3320646e;
  const uint32_t c15 = 0x6b206574;
  const uint32_t c10 = 0x79622d32;

  uint32_t *in = ctx->w;

  uint32_t x0  = c0;
  uint32_t x1  = c5;
  uint32_t x2  = c10;
  uint32_t x3  = c15;
  uint32_t x4  = in[0];
  uint32_t x5  = in[1];
  uint32_t x6  = in[2];
  uint32_t x7  = in[3];
  uint32_t x8  = in[8];
  uint32_t x9  = in[9];
  uint32_t x10 = in[10];
  uint32_t x11 = in[11];
  uint32_t x12 = in[6];
  uint32_t x13 = in[7];
  uint32_t x14 = in[4];
  uint32_t x15 = in[5];

#define CHACHA_QUARTERROUND(a,b,c,d)            \
  x##a += x##b;                                 \
  x##d = assh_chacha20_rotate(x##d ^ x##a, 16); \
  x##c += x##d;                                 \
  x##b = assh_chacha20_rotate(x##b ^ x##c, 12); \
  x##a += x##b;                                 \
  x##d = assh_chacha20_rotate(x##d ^ x##a, 8);  \
  x##c += x##d;                                 \
  x##b = assh_chacha20_rotate(x##b ^ x##c, 7);

  for (i = 20; i > 0; i -= 2)
    {
      CHACHA_QUARTERROUND(0, 4,  8, 12);
      CHACHA_QUARTERROUND(1, 5,  9, 13);
      CHACHA_QUARTERROUND(2, 6, 10, 14);
      CHACHA_QUARTERROUND(3, 7, 11, 15);
      CHACHA_QUARTERROUND(0, 5, 10, 15);
      CHACHA_QUARTERROUND(1, 6, 11, 12);
      CHACHA_QUARTERROUND(2, 7,  8, 13);
      CHACHA_QUARTERROUND(3, 4,  9, 14);
    }

  out[0] = x0 + c0;
  if (count > 1)
    {
      out[1] = x1 + c5;
      out[2] = x2 + c10;
      out[3] = x3 + c15;
      out[4] = x4 + in[0];
      out[5] = x5 + in[1];
      out[6] = x6 + in[2];
      out[7] = x7 + in[3];
      if (count > 8)
        {
          out[8] = x8 + in[8];
          out[9] = x9 + in[9];
          out[10] = x10 + in[10];
          out[11] = x11 + in[11];
          out[12] = x12 + in[6];
          out[13] = x13 + in[7];
          out[14] = x14 + in[4];
          out[15] = x15 + in[5];
        }
    }

  in[6]++;
}

static void assh_chacha20_xor_buf(struct assh_chacha20_ctx_s *ctx, uint8_t *data, size_t len)
{
  uint32_t out[16];
  size_t i;

  do {
    assh_chacha20_block(ctx, out, 16);

    for (i = 0; i < 16 && (len >= 4); i++)
      {
        assh_store_u32le(data, assh_load_u32le(data) ^ out[i]);
        data += 4;
        len -= 4;
      }
  } while (len >= 4);

  if (len)
    {
      uint32_t x = out[i];
      while (len--)
        {
          *data++ ^= x;
          x >>= 8;
        }
    }
}

/******************************************************* poly1305 */

/*
  Based on poly1305 32 bits implementation by Andrew Moon
  modified for stateless oneshot authentication.
  https://github.com/floodyberry/poly1305-donna.git
*/

#define POLY1305_BLOCK_SIZE 16

#define ASSH_POLY1305_BLOCKS()                                          \
                                                                        \
  /* h += m[i] */                                                       \
  h0 += (assh_load_u32le(m +  0)     ) & 0x3ffffff;                     \
  h1 += (assh_load_u32le(m +  3) >> 2) & 0x3ffffff;                     \
  h2 += (assh_load_u32le(m +  6) >> 4) & 0x3ffffff;                     \
  h3 += (assh_load_u32le(m +  9) >> 6) & 0x3ffffff;                     \
  h4 += (assh_load_u32le(m + 12) >> 8) | hibit;                         \
                                                                        \
  /* h *= r */                                                          \
  d0 = ((uint64_t)h0 * r0) + ((uint64_t)h1 * s4) + ((uint64_t)h2 * s3)  \
    + ((uint64_t)h3 * s2) + ((uint64_t)h4 * s1);                        \
  d1 = ((uint64_t)h0 * r1) + ((uint64_t)h1 * r0) + ((uint64_t)h2 * s4)  \
    + ((uint64_t)h3 * s3) + ((uint64_t)h4 * s2);                        \
  d2 = ((uint64_t)h0 * r2) + ((uint64_t)h1 * r1) + ((uint64_t)h2 * r0)  \
    + ((uint64_t)h3 * s4) + ((uint64_t)h4 * s3);                        \
  d3 = ((uint64_t)h0 * r3) + ((uint64_t)h1 * r2) + ((uint64_t)h2 * r1)  \
    + ((uint64_t)h3 * r0) + ((uint64_t)h4 * s4);                        \
  d4 = ((uint64_t)h0 * r4) + ((uint64_t)h1 * r3) + ((uint64_t)h2 * r2)  \
    + ((uint64_t)h3 * r1) + ((uint64_t)h4 * r0);                        \
                                                                        \
  /* (partial) h %= p */                                                \
  c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;              \
  d1 += c;     c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff; \
  d2 += c;     c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff; \
  d3 += c;     c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff; \
  d4 += c;     c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff; \
  h0 += c * 5; c =           (h0 >> 26); h0 =           h0 & 0x3ffffff; \
  h1 += c;

#define ASSH_POLY1305_FINISH()                                     \
  /* fully carry h */                                              \
  c = h1 >> 26; h1 = h1 & 0x3ffffff;                               \
  h2 +=     c; c = h2 >> 26; h2 = h2 & 0x3ffffff;                  \
  h3 +=     c; c = h3 >> 26; h3 = h3 & 0x3ffffff;                  \
  h4 +=     c; c = h4 >> 26; h4 = h4 & 0x3ffffff;                  \
  h0 += c * 5; c = h0 >> 26; h0 = h0 & 0x3ffffff;                  \
  h1 +=     c;                                                     \
                                                                   \
  /* compute h + -p */                                             \
  g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;                      \
  g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;                      \
  g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;                      \
  g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;                      \
  g4 = h4 + c - (1 << 26);                                         \
                                                                   \
  /* select h if h < p, or h + -p if h >= p */                     \
  mask = (g4 >> ((sizeof(uint32_t) * 8) - 1)) - 1;                 \
  g0 &= mask;  g1 &= mask;  g2 &= mask;  g3 &= mask;  g4 &= mask;  \
  mask = ~mask;                                                    \
  h0 = (h0 & mask) | g0;  h1 = (h1 & mask) | g1;                   \
  h2 = (h2 & mask) | g2;  h3 = (h3 & mask) | g3;                   \
  h4 = (h4 & mask) | g4;                                           \
                                                                   \
  /* h = h % (2^128) */                                            \
  h0 = ((h0      ) | (h1 << 26)) & 0xffffffff;                     \
  h1 = ((h1 >>  6) | (h2 << 20)) & 0xffffffff;                     \
  h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;                     \
  h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffff;                     \
                                                                   \
  /* mac = (h + pad) % (2^128) */                                  \
  f = (uint64_t)h0 + pad0            ; h0 = (uint32_t)f;           \
  f = (uint64_t)h1 + pad1 + (f >> 32); h1 = (uint32_t)f;           \
  f = (uint64_t)h2 + pad2 + (f >> 32); h2 = (uint32_t)f;           \
  f = (uint64_t)h3 + pad3 + (f >> 32); h3 = (uint32_t)f;

static void
assh_poly1305_auth(uint8_t mac[16], const uint8_t *m,
              size_t bytes, const uint32_t key[8])
{
  /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
  uint32_t r0 = (key[0]                     ) & 0x03ffffff;
  uint32_t r1 = (key[1] << 6  | key[0] >> 26) & 0x03ffff03;
  uint32_t r2 = (key[2] << 12 | key[1] >> 20) & 0x03ffc0ff;
  uint32_t r3 = (key[3] << 18 | key[2] >> 14) & 0x03f03fff;
  uint32_t r4 = (key[3] >> 8                ) & 0x000fffff;

  uint32_t pad0 = key[4], pad1 = key[5], pad2 = key[6], pad3 = key[7];

  uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;

  uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;
  uint32_t hibit = 1 << 24; /* 1 << 128 */

  uint32_t g0, g1, g2, g3, g4;
  uint64_t d0, d1, d2, d3, d4;
  uint32_t c, mask;
  uint64_t f;

  while (bytes >= POLY1305_BLOCK_SIZE)
    {
      ASSH_POLY1305_BLOCKS();
      m += POLY1305_BLOCK_SIZE;
      bytes -= POLY1305_BLOCK_SIZE;
    }

  if (bytes)
    {
      uint8_t buffer[POLY1305_BLOCK_SIZE];
      memcpy(buffer, m, bytes);
      buffer[bytes] = 1;
      size_t i;
      for (i = bytes + 1; i < POLY1305_BLOCK_SIZE; i++)
        buffer[i] = 0;
      m = buffer;
      hibit = 0;
      ASSH_POLY1305_BLOCKS();
    }

  ASSH_POLY1305_FINISH();

  assh_store_u32le(mac +  0, h0);
  assh_store_u32le(mac +  4, h1);
  assh_store_u32le(mac +  8, h2);
  assh_store_u32le(mac + 12, h3);
}

/******************************************************* ssh cipher */

struct assh_cipher_chachapoly_context_s
{
  struct assh_chacha20_ctx_s chacha_sz; /* size header */
  struct assh_chacha20_ctx_s chacha_pl; /* payload */
  uint32_t poly_key[8];
  uint32_t enc_size;
  assh_bool_t encrypt;
};

static ASSH_CIPHER_INIT_FCN(assh_chachapoly_init)
{
  struct assh_cipher_chachapoly_context_s *ctx = ctx_;

  assh_chacha20_set_key(&ctx->chacha_sz, key + 32);
  assh_chacha20_set_key(&ctx->chacha_pl, key);
  ctx->encrypt = encrypt;

  return ASSH_OK;
}

static ASSH_CIPHER_PROCESS_FCN(assh_chachapoly_process)
{
  struct assh_cipher_chachapoly_context_s *ctx = ctx_;
  assh_status_t err;

  if (!ctx->encrypt)
    {
      if (op == ASSH_CIPHER_PCK_HEAD)
        {
          uint32_t x, l = assh_load_u32le(data);
          ctx->enc_size = l;
          /* decrypt size */
          assh_chacha20_set_ctr(&ctx->chacha_sz, 0);
          assh_chacha20_set_iv(&ctx->chacha_sz, seq);
          assh_chacha20_block(&ctx->chacha_sz, &x, 1);
          assh_store_u32le(data, x ^ l);
        }
      else
        {
          /* get auth key */
          assh_chacha20_set_ctr(&ctx->chacha_pl, 0);
          assh_chacha20_set_iv(&ctx->chacha_pl, seq);
          assh_chacha20_block(&ctx->chacha_pl, ctx->poly_key, 8);

          /* check auth tag */
          uint8_t poly_tag[16];
          uint32_t l = assh_load_u32le(data);
          assh_store_u32le(data, ctx->enc_size);
          assh_poly1305_auth(poly_tag, data, len - 16, ctx->poly_key);
          assh_store_u32le(data, l);
          ASSH_RET_IF_TRUE(assh_memcmp(data + len - 16, poly_tag, 16),
                       ASSH_ERR_CRYPTO);

          /* decrypt data */
          assh_chacha20_set_ctr(&ctx->chacha_pl, 1);
          assh_chacha20_xor_buf(&ctx->chacha_pl, data + 4, len - 4 - 16);
        }
    }
  else
    {
      /* encrypt size */
      uint32_t x, l = assh_load_u32le(data);
      assh_chacha20_set_ctr(&ctx->chacha_sz, 0);
      assh_chacha20_set_iv(&ctx->chacha_sz, seq);
      assh_chacha20_block(&ctx->chacha_sz, &x, 1);
      assh_store_u32le(data, x ^ l);

      /* encrypt data */
      assh_chacha20_set_ctr(&ctx->chacha_pl, 1);
      assh_chacha20_set_iv(&ctx->chacha_pl, seq);
      assh_chacha20_xor_buf(&ctx->chacha_pl, data + 4, len - 4 - 16);

      /* get auth key */
      assh_chacha20_set_ctr(&ctx->chacha_pl, 0);
      assh_chacha20_block(&ctx->chacha_pl, ctx->poly_key, 8);

      /* append auth tag */
      assh_poly1305_auth(data + len - 16, data, len - 16, ctx->poly_key);
    }

  return ASSH_OK;
}

static ASSH_CIPHER_CLEANUP_FCN(assh_chachapoly_cleanup)
{
}

const struct assh_algo_cipher_s assh_cipher_builtin_chachapoly =
{
  ASSH_ALGO_BASE(CIPHER, "assh-builtin", 80, 17,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_COMMON, "chacha20-poly1305@openssh.com" })
  ),
  .ctx_size = sizeof(struct assh_cipher_chachapoly_context_s),
  .block_size = 8,
  .head_size = 4,
  .iv_size = 0,
  .auth_size = 16,
  .key_size = 64,
  .f_init = assh_chachapoly_init,
  .f_process = assh_chachapoly_process,
  .f_cleanup = assh_chachapoly_cleanup,
};
