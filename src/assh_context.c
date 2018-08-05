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


#include <assh/assh_context.h>
#include <assh/assh_packet.h>
#include <assh/assh_algo.h>
#include <assh/assh_key.h>
#include <assh/assh_kex.h>
#include <assh/assh_prng.h>
#include <assh/assh_alloc.h>

#include <stdlib.h>

#ifdef CONFIG_ASSH_USE_GCRYPT
# include <gcrypt.h>
#endif

assh_error_t
assh_deps_init()
{
  assh_error_t err;

#ifdef CONFIG_ASSH_USE_GCRYPT
  ASSH_RET_IF_TRUE(!gcry_check_version(GCRYPT_VERSION),
               ASSH_ERR_CRYPTO);

  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
#endif

  return ASSH_OK;
}

#ifdef CONFIG_ASSH_USE_GCRYPT_ALLOC

# define ASSH_DEFAULT_ALLOCATOR assh_gcrypt_allocator
ASSH_ALLOCATOR(assh_gcrypt_allocator)
{
  assh_error_t err;

  if (size == 0)
    {
      gcry_free(*ptr);
      return ASSH_OK;
    }
  else if (*ptr == NULL)
    {
      switch (type)
	{
        case ASSH_ALLOC_NONE:
          ASSH_UNREACHABLE();
	case ASSH_ALLOC_INTERNAL:
	case ASSH_ALLOC_PACKET:
	  *ptr = gcry_malloc(size);
	  break;
	case ASSH_ALLOC_SECUR:
	case ASSH_ALLOC_SCRATCH:
	  *ptr = gcry_malloc_secure(size);
	  break;
	}
      ASSH_RET_IF_TRUE(*ptr == NULL, ASSH_ERR_MEM);
      return ASSH_OK;
    }
  else
    {
      *ptr = gcry_realloc(*ptr, size);
      ASSH_RET_IF_TRUE(*ptr == NULL, ASSH_ERR_MEM);
      return ASSH_OK;
    }

  return ASSH_OK;
}

#endif

#ifdef CONFIG_ASSH_LIBC_REALLOC

# ifndef ASSH_DEFAULT_ALLOCATOR
#  warning The default allocator relies on the standard non-secur realloc function
#  define ASSH_DEFAULT_ALLOCATOR assh_libc_allocator
# endif

ASSH_ALLOCATOR(assh_libc_allocator)
{
  assh_error_t err;

  *ptr = realloc(*ptr, size);
  ASSH_RET_IF_TRUE(size != 0 && *ptr == NULL, ASSH_ERR_MEM);
  return ASSH_OK;
}
#endif

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_context_init(struct assh_context_s *c,
                  enum assh_context_type_e type,
                  assh_allocator_t *alloc, void *alloc_pv,
                  const struct assh_prng_s *prng,
                  const struct assh_buffer_s *prng_seed)
{
  assh_error_t err;

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

#ifdef ASSH_DEFAULT_ALLOCATOR
  if (alloc == NULL)
    alloc = ASSH_DEFAULT_ALLOCATOR;
#else
  ASSH_RET_IF_TRUE(alloc == NULL,
               ASSH_ERR_MISSING_ALGO | ASSH_ERRSV_FATAL);
#endif

#ifdef CONFIG_ASSH_USE_GCRYPT_ALLOC
  ASSH_RET_IF_TRUE(alloc == &assh_gcrypt_allocator &&
               !gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P),
               ASSH_ERR_CRYPTO | ASSH_ERRSV_FATAL);
#endif

  c->f_alloc = alloc;
  c->alloc_pv = alloc_pv;

  if (prng == NULL)
    {
#ifdef CONFIG_ASSH_USE_GCRYPT_PRNG
      prng = &assh_prng_gcrypt;
#elif defined(CONFIG_ASSH_USE_DEV_RANDOM)
      prng = &assh_prng_dev_random;
#else
      prng = &assh_prng_xswap;
#endif
    }
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

  return ASSH_OK;
}

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_context_create(struct assh_context_s **ctx,
		    enum assh_context_type_e type,
		    assh_allocator_t *alloc, void *alloc_pv,
                    const struct assh_prng_s *prng,
                    const struct assh_buffer_s *prng_seed)
{
  assh_error_t err;

#ifdef ASSH_DEFAULT_ALLOCATOR
  if (alloc == NULL)
    {
      alloc = ASSH_DEFAULT_ALLOCATOR;
      alloc_pv = NULL;
    }
#else
  ASSH_RET_IF_TRUE(alloc == NULL, ASSH_ERR_MISSING_ALGO | ASSH_ERRSV_FATAL);
#endif

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

void * assh_context_get_pv(struct assh_context_s *ctx)
{
  return ctx->user_pv;
}
