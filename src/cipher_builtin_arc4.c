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
#include <assh/mod_builtin.h>

struct assh_cipher_arc4_context_s
{
  uint8_t a, b;
  uint8_t s[256];
};

static void assh_arc4_set_key(struct assh_cipher_arc4_context_s *ctx,
			     const uint8_t *key, size_t klen)
{
  ctx->a = ctx->b = 0;
  uint_fast16_t i;
  for (i = 0; i < 256; i++)
    ctx->s[i] = i;

  uint_fast16_t a, b;
  for (a = b = 0; a < 256; a++)
    {
      uint8_t tmp = ctx->s[a];
      b = (uint8_t)(b + tmp + key[a % klen]);
      ctx->s[a] = ctx->s[b];
      ctx->s[b] = tmp;
    }
}

static void assh_arc4_run(struct assh_cipher_arc4_context_s *ctx,
			  uint8_t *data, size_t len)
{
  uint_fast8_t a = ctx->a, b = ctx->b;

  while (len--)
    {
      a = (uint8_t)(a + 1);
      b = (uint8_t)(b + ctx->s[a]);
      uint8_t tmp = ctx->s[b];
      ctx->s[b] = ctx->s[a];
      ctx->s[a] = tmp;
      if (data != NULL)
	*data++ ^= ctx->s[(uint8_t)(ctx->s[a] + ctx->s[b])];
    }

  ctx->a = a;
  ctx->b = b;
}

static ASSH_CIPHER_INIT_FCN(assh_arc4_init)
{
  struct assh_cipher_arc4_context_s *ctx = ctx_;  
  assh_arc4_set_key(ctx, key, 16);
  return ASSH_OK;
}

static ASSH_CIPHER_INIT_FCN(assh_arc4_128_init)
{
  struct assh_cipher_arc4_context_s *ctx = ctx_;
  assh_arc4_set_key(ctx, key, 16);
  assh_arc4_run(ctx, NULL, 1536);
  return ASSH_OK;
}

static ASSH_CIPHER_INIT_FCN(assh_arc4_256_init)
{
  struct assh_cipher_arc4_context_s *ctx = ctx_;
  assh_arc4_set_key(ctx, key, 32);
  assh_arc4_run(ctx, NULL, 1536);
  return ASSH_OK;
}

static ASSH_CIPHER_PROCESS_FCN(assh_arc4_process)
{
  struct assh_cipher_arc4_context_s *ctx = ctx_;
  assh_arc4_run(ctx, data, len);
  return ASSH_OK;
}

static ASSH_CIPHER_CLEANUP_FCN(assh_arc4_cleanup)
{
}

const struct assh_algo_cipher_s assh_cipher_builtin_arc4 =
{
  ASSH_ALGO_BASE(CIPHER, "assh-builtin", 5, 31,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
                      "arcfour" })
  ),
  .ctx_size = sizeof(struct assh_cipher_arc4_context_s),
  .block_size = 8,
  .head_size = 8,
  .key_size = 16,
  .f_init = assh_arc4_init,
  .f_process = assh_arc4_process,
  .f_cleanup = assh_arc4_cleanup,
};

const struct assh_algo_cipher_s assh_cipher_builtin_arc4_128 =
{
  ASSH_ALGO_BASE(CIPHER, "assh-builtin", 10, 31,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
                      "arcfour128" })
  ),
  .ctx_size = sizeof(struct assh_cipher_arc4_context_s),
  .block_size = 8,
  .head_size = 8,
  .key_size = 16,
  .f_init = assh_arc4_128_init,
  .f_process = assh_arc4_process,
  .f_cleanup = assh_arc4_cleanup,
};

const struct assh_algo_cipher_s assh_cipher_builtin_arc4_256 =
{
  ASSH_ALGO_BASE(CIPHER, "assh-builtin", 15, 31,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
                      "arcfour256" })
  ),
  .ctx_size = sizeof(struct assh_cipher_arc4_context_s),
  .block_size = 8,
  .head_size = 8,
  .key_size = 32,
  .f_init = assh_arc4_256_init,
  .f_process = assh_arc4_process,
  .f_cleanup = assh_arc4_cleanup,
};

