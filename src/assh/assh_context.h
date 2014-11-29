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
  ASSH_CLIENT_SERVER,
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
      ASSH_EVENT_PRNG_FEED event.  */
  int prng_entropy;

  /** head of keys list */
  const struct assh_key_s *keys;

  /** estimated size of the kex init packet, computed when new
      algorithm are registered. */
  size_t kex_init_size;

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
  size_t algos_count;

  /** Registered services supported by the server. */
  const struct assh_service_s *srvs[ASSH_MAX_SERVICES];
  /** Number of registered services */
  size_t srvs_count;

  const struct assh_bignum_algo_s *bignum;
};

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
    this context. If an other prng has already been setup, it will be
    properly released.

    If this function is called with @tt NULL as @tt prng parameter and
    no prng has already been registered, a default prng is setup.
    This is performed when calling the @ref assh_session_init function.
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_context_prng(struct assh_context_s *s,
		  const struct assh_prng_s *prng);

#endif

