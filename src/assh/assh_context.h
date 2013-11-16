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


#ifndef ASSH_CONTEXT_H_
#define ASSH_CONTEXT_H_

#include "assh.h"

/** This specifies the type of ssh session. */
enum assh_context_type_e
{
  ASSH_SERVER,
  ASSH_CLIENT,
};

struct assh_packet_pool_s
{
  struct assh_packet_s *pck;
  size_t count;
  size_t size;
};

struct assh_context_s
{
  unsigned int session_count;

  /** Client/server context type. */
  enum assh_context_type_e type;

  /** Memory allocator */
  assh_allocator_t *f_alloc;
  /** Memory allocator private data */
  void *alloc_pv;

  /** Pseudo random number generator */
  const struct assh_prng_s *prng;
  /** Pseudo random number generator private data, allocated by the
      @ref assh_prng_s::f_init function and freed by @ref
      assh_prng_s::f_cleanup. */
  void *prng_ctx;
  /** Current amount of entropy in the prng pool. a negative value
      will make the @ref assh_event_get function return an @ref
      ASSH_EVENT_RANDOM event.  */
  int prng_entropy;

#ifdef CONFIG_ASSH_SERVER
  /** head of host keys list */
  struct assh_key_s *host_keys;
#endif

  /** maximum allocated size in a single bucket. */
  size_t pck_pool_max_bsize;
  /** maximum allocated size. */
  size_t pck_pool_max_size;
  /** allocated size. */
  size_t pck_pool_size;

  /** Pool of spare packets by size. */
  struct assh_packet_pool_s pool[ASSH_PCK_POOL_SIZE];

  /** Registered algorithms */
  const struct assh_algo_s *algos[ASSH_MAX_ALGORITHMS];
  /** Number of registered algorithms */
  unsigned int algos_count;

  /** Registered services supported by the server. */
  const struct assh_service_s *srvs[ASSH_MAX_SERVICES];
  /** Number of registered services */
  unsigned int srvs_count;
};

/** This specifies the type of data to be stored in the allocated memory. */
enum assh_alloc_type_e
{
  /** General purpose allocation. */
  ASSH_ALLOC_INTERNAL,
  /** Cryptographic buffer allocation. */
  ASSH_ALLOC_KEY,
  /** SSH packet allocation. */
  ASSH_ALLOC_PACKET,
};

static inline ASSH_WARN_UNUSED_RESULT assh_error_t
assh_alloc(struct assh_context_s *c, size_t size,
	   enum assh_alloc_type_e type, void **result)
{
  *result = NULL;
  return c->f_alloc(c, result, size, type);
}

static inline ASSH_WARN_UNUSED_RESULT assh_error_t
assh_realloc(struct assh_context_s *c, void **ptr, size_t size,
	     enum assh_alloc_type_e type)
{
  return c->f_alloc(c, ptr, size, type);
}

static inline void assh_free(struct assh_context_s *c, void *ptr,
			     enum assh_alloc_type_e type)
{
  if (ptr != NULL)
    (void)c->f_alloc(c, &ptr, 0, type);
}

void assh_context_init(struct assh_context_s *ctx,
                       enum assh_context_type_e type);

void assh_context_cleanup(struct assh_context_s *ctx);

/** This function setups the memory allocator to use for this
    session. The default memory allocator uses the libc realloc
    function. */
void assh_context_allocator(struct assh_context_s *c,
			    assh_allocator_t *alloc,
			    void *alloc_pv);

/** This function setups the pseudo-random number generator to use for
    this context. No default generator is initialy setup. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_context_prng(struct assh_context_s *s,
		  const struct assh_prng_s *prng);

/** This function registers new host keys. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_context_hostkeys(struct assh_context_s *c, const char *algo,
                      const uint8_t *blob, size_t blob_len,
                      enum assh_key_format_e format);

#endif

