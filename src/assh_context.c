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

#include <stdlib.h>

static ASSH_ALLOCATOR(assh_default_allocator)
{
  *ptr = realloc(*ptr, size);
  return (size == 0 || *ptr != NULL) ? ASSH_OK : ASSH_ERR_MEM;
}

void assh_context_init(struct assh_context_s *c,
                       enum assh_context_type_e type)
{
  c->session_count = 0;
  c->type = type;

  c->f_alloc = assh_default_allocator;

  c->prng = NULL;
#ifdef CONFIG_ASSH_SERVER
  c->host_keys = NULL;
#endif

  c->algos_count = 0;

  int i;
  for (i = 0; i < ASSH_PCK_POOL_SIZE; i++)
    c->pck_pool[i] = NULL;

#ifdef CONFIG_ASSH_SERVER
  c->srvs_count = 0;
#endif
}

static void assh_pck_pool_cleanup(struct assh_context_s *c)
{
  int i;
  for (i = 0; i < ASSH_PCK_POOL_SIZE; i++)
    {
      struct assh_packet_s *n, *p;
      for (p = c->pck_pool[i]; p != NULL; p = n)
        {
          n = p->pool_next;
          assh_free(c, p, ASSH_ALLOC_PACKET);
        }
      c->pck_pool[i] = NULL;
    }
}

void assh_context_cleanup(struct assh_context_s *c)
{
  assert(c->session_count == 0);

  assh_pck_pool_cleanup(c);

#ifdef CONFIG_ASSH_SERVER
  assh_key_flush(c, &c->host_keys);
#endif

  if (c->prng != NULL)
    c->prng->f_cleanup(c);
}

void assh_context_allocator(struct assh_context_s *c,
			    assh_allocator_t *alloc,
			    void *alloc_pv)
{
  c->f_alloc = alloc ? alloc : assh_default_allocator;
  c->alloc_pv = alloc_pv;
}

assh_error_t assh_context_prng(struct assh_context_s *c,
			       const struct assh_prng_s *prng)
{
  assh_error_t err;
  c->prng = prng;
  ASSH_ERR_RET(prng->f_init(c));
  return ASSH_OK;
}

assh_error_t assh_context_hostkeys(struct assh_context_s *c, const char *algo,
				   const uint8_t *blob, size_t blob_len,
				   enum assh_key_format_e format)
{
  assh_error_t err;
#ifdef CONFIG_ASSH_SERVER
  ASSH_ERR_RET(assh_key_add(c, &c->host_keys, algo, blob, blob_len, format));
  return ASSH_OK;
#else
  ASSH_ERR_RET(ASSH_ERR_NOTSUP);
#endif
}

