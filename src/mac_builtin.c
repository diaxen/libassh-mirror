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

#include <assh/assh_mac.h>
#include <assh/mod_builtin.h>
#include <assh/assh_hash.h>
#include <assh/assh_buffer.h>
#include <assh/assh_alloc.h>

#include <string.h>

struct assh_hmac_context_s
{
  const struct assh_hash_algo_s *hash;
  const struct assh_algo_mac_s *ma;
  void *hash_co;
  void *hash_ci;
  void *hash_co_t;
  void *hash_ci_t;
  uint8_t *buf;
  assh_bool_t generate;
};

static assh_status_t
assh_hmac_init(struct assh_context_s *c, const struct assh_algo_mac_s *ma,
               struct assh_hmac_context_s *ctx, assh_bool_t generate,
               const uint8_t *key, const struct assh_hash_algo_s *hash)
{
  assh_status_t err;
  uint_fast16_t i;

  assert(hash->hash_size != 0);
  assert(ma->mac_size <= hash->hash_size);
  assert(ma->key_size <= hash->block_size);

  ASSH_RET_ON_ERR(assh_alloc(c, sizeof(struct assh_hmac_context_s)
                          + hash->ctx_size * 4 + /* buf */ hash->hash_size,
                          ASSH_ALLOC_SECUR, &ctx->hash_co));

  ctx->hash = hash;
  ctx->ma = ma;
  ctx->generate = generate;

  ctx->hash_ci = (uint8_t*)ctx->hash_co + hash->ctx_size;
  ctx->hash_co_t = (uint8_t*)ctx->hash_co + hash->ctx_size * 2;
  ctx->hash_ci_t = (uint8_t*)ctx->hash_co + hash->ctx_size * 3;
  ctx->buf = (uint8_t*)ctx->hash_co + hash->ctx_size * 4;

  ASSH_SCRATCH_ALLOC(c, uint8_t, kx, hash->block_size, ASSH_ERRSV_CONTINUE, err_ctx);

  for (i = 0; i < ma->key_size; i++)
    kx[i] = key[i] ^ 0x36;
  for (; i < hash->block_size; i++)
    kx[i] = 0x36;
  ASSH_JMP_ON_ERR(assh_hash_init(c, ctx->hash_ci, hash), err_sc);
  assh_hash_update(ctx->hash_ci, kx, hash->block_size);

  for (i = 0; i < ma->key_size; i++)
    kx[i] = key[i] ^ 0x5c;
  for (; i < hash->block_size; i++)
    kx[i] = 0x5c;
  ASSH_JMP_ON_ERR(assh_hash_init(c, ctx->hash_co, hash), err_ci);
  assh_hash_update(ctx->hash_co, kx, hash->block_size);

  ASSH_SCRATCH_FREE(c, kx);

  return ASSH_OK;

 err_ci:
  assh_hash_cleanup(ctx->hash_ci);
 err_sc:
  ASSH_SCRATCH_FREE(c, kx);  
 err_ctx:
  assh_free(c, ctx->hash_co);
  return err;
}

static ASSH_MAC_CLEANUP_FCN(assh_hmac_cleanup)
{
  struct assh_hmac_context_s *ctx = ctx_;

  assh_hash_cleanup(ctx->hash_ci);
  assh_hash_cleanup(ctx->hash_co);

  assh_free(c, ctx->hash_co);
}

static ASSH_MAC_PROCESS_FCN(assh_hmac_process)
{
  struct assh_hmac_context_s *ctx = ctx_;
  uint8_t be_seq[4];
  assh_status_t err;

  ASSH_RET_ON_ERR(assh_hash_copy(ctx->hash_ci_t, ctx->hash_ci));
  assh_store_u32(be_seq, seq);
  assh_hash_update(ctx->hash_ci_t, be_seq, 4);
  assh_hash_update(ctx->hash_ci_t, data, len);
  assh_hash_final(ctx->hash_ci_t, ctx->buf, ctx->hash->hash_size);
  assh_hash_cleanup(ctx->hash_ci_t);

  ASSH_RET_ON_ERR(ctx->hash->f_copy(ctx->hash_co_t, ctx->hash_co));
  assh_hash_update(ctx->hash_co_t, ctx->buf, ctx->hash->hash_size);

  if (ctx->generate)
    {
      if (ctx->ma->mac_size < ctx->hash->hash_size)
	{
	  assh_hash_final(ctx->hash_co_t, ctx->buf, ctx->hash->hash_size);
	  memcpy(mac, ctx->buf, ctx->ma->mac_size);
	}
      else
	{
	  assh_hash_final(ctx->hash_co_t, mac, ctx->hash->hash_size);
	}
      assh_hash_cleanup(ctx->hash_co_t);
    }
  else
    {
      uint8_t buf[ctx->hash->hash_size];
      assh_hash_final(ctx->hash_co_t, buf, ctx->hash->hash_size);
      assh_hash_cleanup(ctx->hash_co_t);
      ASSH_RET_IF_TRUE(assh_memcmp(mac, buf, ctx->ma->mac_size), ASSH_ERR_MAC);
    }

  return ASSH_OK;
}

static ASSH_MAC_INIT_FCN(assh_hmac_md5_init)
{
  return assh_hmac_init(c, &assh_mac_builtin_md5, ctx_,
			generate, key, &assh_hash_md5);
}

const struct assh_algo_mac_s assh_mac_builtin_md5 = 
{
  ASSH_ALGO_BASE(MAC, "assh-builtin", 30, 10,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
                      "hmac-md5" })
  ),
  .ctx_size = sizeof(struct assh_hmac_context_s),
  .key_size = 16,
  .mac_size = 16,
  .f_init = assh_hmac_md5_init,
  .f_process = assh_hmac_process,
  .f_cleanup = assh_hmac_cleanup,
};

const struct assh_algo_mac_s assh_mac_builtin_md5_etm = 
{
  ASSH_ALGO_BASE(MAC, "assh-builtin", 31, 10,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_COMMON,
                      "hmac-md5-etm@openssh.com" })
  ),
  .ctx_size = sizeof(struct assh_hmac_context_s),
  .key_size = 16,
  .mac_size = 16,
  .etm = 1,
  .f_init = assh_hmac_md5_init,
  .f_process = assh_hmac_process,
  .f_cleanup = assh_hmac_cleanup,
};


static ASSH_MAC_INIT_FCN(assh_hmac_md5_96_init)
{
  return assh_hmac_init(c, &assh_mac_builtin_md5_96, ctx_,
			generate, key, &assh_hash_md5);
}

const struct assh_algo_mac_s assh_mac_builtin_md5_96 = 
{
  ASSH_ALGO_BASE(MAC, "assh-builtin", 20, 10,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
                      "hmac-md5-96" })
  ),
  .ctx_size = sizeof(struct assh_hmac_context_s),
  .key_size = 16,
  .mac_size = 12,
  .f_init = assh_hmac_md5_96_init,
  .f_process = assh_hmac_process,
  .f_cleanup = assh_hmac_cleanup,
};

const struct assh_algo_mac_s assh_mac_builtin_md5_96_etm = 
{
  ASSH_ALGO_BASE(MAC, "assh-builtin", 21, 10,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_COMMON,
                      "hmac-md5-96-etm@openssh.com" })
  ),
  .ctx_size = sizeof(struct assh_hmac_context_s),
  .key_size = 16,
  .mac_size = 12,
  .etm = 1,
  .f_init = assh_hmac_md5_96_init,
  .f_process = assh_hmac_process,
  .f_cleanup = assh_hmac_cleanup,
};

static ASSH_MAC_INIT_FCN(assh_hmac_sha1_init)
{
  return assh_hmac_init(c, &assh_mac_builtin_sha1, ctx_,
			generate, key, &assh_hash_sha1);
}

const struct assh_algo_mac_s assh_mac_builtin_sha1 = 
{
  ASSH_ALGO_BASE(MAC, "assh-builtin", 35, 9,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
                      "hmac-sha1" })
  ),
  .ctx_size = sizeof(struct assh_hmac_context_s),
  .key_size = 20,
  .mac_size = 20,
  .f_init = assh_hmac_sha1_init,
  .f_process = assh_hmac_process,
  .f_cleanup = assh_hmac_cleanup,
};

const struct assh_algo_mac_s assh_mac_builtin_sha1_etm = 
{
  ASSH_ALGO_BASE(MAC, "assh-builtin", 36, 9,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_COMMON,
                      "hmac-sha1-etm@openssh.com" })
  ),
  .ctx_size = sizeof(struct assh_hmac_context_s),
  .key_size = 20,
  .mac_size = 20,
  .etm = 1,
  .f_init = assh_hmac_sha1_init,
  .f_process = assh_hmac_process,
  .f_cleanup = assh_hmac_cleanup,
};


static ASSH_MAC_INIT_FCN(assh_hmac_sha1_96_init)
{
  return assh_hmac_init(c, &assh_mac_builtin_sha1_96, ctx_,
			generate, key, &assh_hash_sha1);
}

const struct assh_algo_mac_s assh_mac_builtin_sha1_96 = 
{
  ASSH_ALGO_BASE(MAC, "assh-builtin", 25, 9,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
                      "hmac-sha1-96" })
  ),
  .ctx_size = sizeof(struct assh_hmac_context_s),
  .key_size = 20,
  .mac_size = 12,
  .f_init = assh_hmac_sha1_96_init,
  .f_process = assh_hmac_process,
  .f_cleanup = assh_hmac_cleanup,
};

const struct assh_algo_mac_s assh_mac_builtin_sha1_96_etm = 
{
  ASSH_ALGO_BASE(MAC, "assh-builtin", 26, 9,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_COMMON,
                      "hmac-sha1-96-etm@openssh.com" })
  ),
  .ctx_size = sizeof(struct assh_hmac_context_s),
  .key_size = 20,
  .mac_size = 12,
  .etm = 1,
  .f_init = assh_hmac_sha1_96_init,
  .f_process = assh_hmac_process,
  .f_cleanup = assh_hmac_cleanup,
};

static ASSH_MAC_INIT_FCN(assh_hmac_sha256_init)
{
  return assh_hmac_init(c, &assh_mac_builtin_sha256, ctx_,
			generate, key, &assh_hash_sha256);
}

const struct assh_algo_mac_s assh_mac_builtin_sha256 = 
{
  ASSH_ALGO_BASE(MAC, "assh-builtin", 40, 5,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
                      "hmac-sha2-256" })
  ),
  .ctx_size = sizeof(struct assh_hmac_context_s),
  .key_size = 32,
  .mac_size = 32,
  .f_init = assh_hmac_sha256_init,
  .f_process = assh_hmac_process,
  .f_cleanup = assh_hmac_cleanup,
};

const struct assh_algo_mac_s assh_mac_builtin_sha256_etm = 
{
  ASSH_ALGO_BASE(MAC, "assh-builtin", 41, 5,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_COMMON,
                      "hmac-sha2-256-etm@openssh.com" })
  ),
  .ctx_size = sizeof(struct assh_hmac_context_s),
  .key_size = 32,
  .mac_size = 32,
  .etm = 1,
  .f_init = assh_hmac_sha256_init,
  .f_process = assh_hmac_process,
  .f_cleanup = assh_hmac_cleanup,
};


static ASSH_MAC_INIT_FCN(assh_hmac_sha512_init)
{
  return assh_hmac_init(c, &assh_mac_builtin_sha512, ctx_,
			generate, key, &assh_hash_sha512);
}

const struct assh_algo_mac_s assh_mac_builtin_sha512 = 
{
  ASSH_ALGO_BASE(MAC, "assh-builtin", 50, 8,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
                      "hmac-sha2-512" })
  ),
  .ctx_size = sizeof(struct assh_hmac_context_s),
  .key_size = 64,
  .mac_size = 64,
  .f_init = assh_hmac_sha512_init,
  .f_process = assh_hmac_process,
  .f_cleanup = assh_hmac_cleanup,
};

const struct assh_algo_mac_s assh_mac_builtin_sha512_etm =
{
  ASSH_ALGO_BASE(MAC, "assh-builtin", 51, 8,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_COMMON,
                      "hmac-sha2-512-etm@openssh.com" })
  ),
  .ctx_size = sizeof(struct assh_hmac_context_s),
  .key_size = 64,
  .mac_size = 64,
  .etm = 1,
  .f_init = assh_hmac_sha512_init,
  .f_process = assh_hmac_process,
  .f_cleanup = assh_hmac_cleanup,
};
