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
#define ASSH_ABI_UNSAFE  /* do not warn */

#include <assh/assh_context.h>
#include <assh/assh_packet.h>
#include <assh/assh_algo.h>
#include <assh/assh_key.h>
#include <assh/assh_kex.h>
#include <assh/assh_prng.h>
#include <assh/assh_alloc.h>

#include <stdlib.h>

ASSH_WARN_UNUSED_RESULT assh_status_t
assh_context_init(struct assh_context_s *c,
                  enum assh_context_type_e type,
                  assh_allocator_t *alloc, void *alloc_pv,
                  const struct assh_prng_s *prng,
                  const struct assh_buffer_s *prng_seed)
{
  assh_status_t err;

  c->session_count = 0;

  switch (type)
    {
    case ASSH_CLIENT:
#ifndef CONFIG_ASSH_CLIENT
      ASSH_RETURN(ASSH_ERR_NOTSUP);
#endif
      break;
    case ASSH_SERVER:
#ifndef CONFIG_ASSH_SERVER
      ASSH_RETURN(ASSH_ERR_NOTSUP);
#endif
      break;
    case ASSH_CLIENT_SERVER:
#ifdef CONFIG_ASSH_SERVER
      type = ASSH_SERVER;
#else
      type = ASSH_CLIENT;
#endif
      break;
    default:
      ASSH_UNREACHABLE();
    }

  c->type = type;

  if (alloc == NULL)
    {
      alloc = assh_default_alloc();
      alloc_pv = NULL;
    }

  ASSH_RET_IF_TRUE(alloc == NULL,
                   ASSH_ERR_MISSING_ALGO);

  c->f_alloc = alloc;
  c->alloc_pv = alloc_pv;

  if (prng == NULL)
    prng = assh_default_prng();

  ASSH_RET_IF_TRUE(prng == NULL,
                   ASSH_ERR_MISSING_ALGO);

  c->prng = prng;
  ASSH_RET_ON_ERR(prng->f_init(c, prng_seed));

  c->keys = NULL;
  c->kex_init_size = 0;

  c->algo_cnt = c->algo_max = 0;
  c->algo_realloc = 0;
  c->algos = NULL;

#ifdef CONFIG_ASSH_PACKET_POOL
  size_t i;
  for (i = 0; i < ASSH_PCK_POOL_SIZE; i++)
    {
      c->pool[i].pck = NULL;
      c->pool[i].count = 0;
      c->pool[i].size = 0;
    }

  c->pck_pool_max_size = CONFIG_ASSH_PACKET_POOL_SIZE;
  c->pck_pool_max_bsize = CONFIG_ASSH_PACKET_POOL_SIZE / ASSH_PCK_POOL_SIZE;
  c->pck_pool_size = 0;
#endif

  c->srvs_count = 0;
  c->safety_weight = 50;
  c->timeout_transport = 10 - 1;
  c->timeout_kex = 30 - 1;
  c->timeout_userauth = 60 - 1;
  c->timeout_rekex = 3600 - 1;
  c->timeout_keepalive = 300;

  return ASSH_OK;
}

ASSH_WARN_UNUSED_RESULT assh_status_t
assh_context_create(struct assh_context_s **ctx,
		    enum assh_context_type_e type,
		    assh_allocator_t *alloc, void *alloc_pv,
                    const struct assh_prng_s *prng,
                    const struct assh_buffer_s *prng_seed)
{
  assh_status_t err;

  if (alloc == NULL)
    {
      alloc = assh_default_alloc();
      alloc_pv = NULL;
    }

  ASSH_RET_IF_TRUE(alloc == NULL, ASSH_ERR_MISSING_ALGO);

  *ctx = NULL;
  ASSH_RET_ON_ERR(alloc(alloc_pv, (void**)ctx, sizeof(**ctx),
                     ASSH_ALLOC_INTERNAL));

  ASSH_JMP_ON_ERR(assh_context_init(*ctx, type, alloc, alloc_pv,
                                  prng, prng_seed), err);

  return ASSH_OK;

 err:
  alloc(alloc_pv, (void**)ctx, 0, ASSH_ALLOC_INTERNAL);
  return err;
}

void assh_context_release(struct assh_context_s *ctx)
{
  assh_context_cleanup(ctx);
  assh_free(ctx, ctx);
}

void assh_context_cleanup(struct assh_context_s *c)
{
  assert(c->session_count == 0);

#ifdef CONFIG_ASSH_PACKET_POOL
  assh_packet_collect(c);
#endif

  assh_key_flush(c, &c->keys);

  if (c->algo_realloc)
    assh_free(c, c->algos);

  c->prng->f_cleanup(c);
}

void assh_context_set_pv(struct assh_context_s *ctx,
                    void *private)
{
  ctx->user_pv = private;
}

void * assh_context_get_pv(const struct assh_context_s *ctx)
{
  return ctx->user_pv;
}

struct assh_key_s **
assh_context_keys(struct assh_context_s *ctx)
{
  return &ctx->keys;
}

void
assh_context_set_timeouts(struct assh_context_s *c,
                      uint_fast8_t transport, uint_fast8_t kex,
                      uint_fast16_t rekex, uint_fast16_t userauth)
{
  if (transport)
    c->timeout_transport = transport - 1;
  if (kex)
    c->timeout_kex = kex - 1;
  if (rekex)
    c->timeout_rekex = rekex - 1;
  if (userauth)
    c->timeout_userauth = userauth - 1;
}

void
assh_context_set_keepalive(struct assh_context_s *c, uint_fast16_t keepalive)
{
  c->timeout_keepalive = keepalive;
}

size_t
assh_context_refcount(const struct assh_context_s *ctx)
{
  return ctx->session_count;
}
