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

/**
   @file
   @short Main context structure and related functions

   The library main context structure hold stuff common to multiple
   sessions. This includes registered algorithms and host keys.
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

/** @internal @This is the packet pool allocator bucket
    structure. Freed packets are inserted in the linked list of the
    bucket associated with their size. */
struct assh_packet_pool_s
{
  struct assh_packet_s *pck;
  size_t count;
  size_t size;
};

/** @internalmembers @This is the library main context structure. */
struct assh_context_s
{
  /** User private data */
  void *user_pv;

  /** Memory allocator function */
  assh_allocator_t *f_alloc;
  /** Memory allocator private data */
  void *alloc_pv;

  /** Pseudo random number generator */
  const struct assh_prng_s *prng;
  /** Pseudo random number generator private data, allocated by the
      @ref assh_prng_init_t function and freed by @ref
      assh_prng_cleanup_t. */
  union {
    void *prng_pv;
    intptr_t prng_pvl;
  };

  /** Big number engine */
  const struct assh_bignum_algo_s *bignum;

  /** Head of loaded keys list */
  struct assh_key_s *keys;

#ifdef CONFIG_ASSH_PACKET_POOL
  /** Packet pool maximum allocated size in a single bucket. */
  uint32_t pck_pool_max_bsize;
  /** Packet pool maximum allocated size. */
  uint32_t pck_pool_max_size;
  /** Packet pool current allocated size. */
  uint32_t pck_pool_size;

  /** Packet pool buckets of spare packets by size. */
  struct assh_packet_pool_s pool[ASSH_PCK_POOL_SIZE];
#endif

  /** Registered services. */
  const struct assh_service_s *srvs[CONFIG_ASSH_MAX_SERVICES];

  /** Client/server context type. */
  enum assh_context_type_e type:2;

  /** Number of registered services */
  size_t srvs_count:6;

  /** Number of initialized sessions attached to this context. */
  size_t session_count:8;

  /** Number of algorithm slots */
  size_t algo_max:16;

  /** Number of registered algorithms */
  size_t algo_cnt:16;

  /** Estimated size of the kex init packet, computed when new
      algorithms are registered. */
  size_t kex_init_size:16;

  /** Registered algorithms */
  const struct assh_algo_s *algos[CONFIG_ASSH_MAX_ALGORITHMS];
};

#ifdef CONFIG_ASSH_LIBC_REALLOC
/** This allocator relies on the libc @tt realloc function. This
    allocator @b{is not} able to provide secure memory.

    It does not requires private data; @tt NULL may be passed as @tt
    alloc_pv parameter of the initialization function.
*/
ASSH_ALLOCATOR(assh_libc_allocator);
#endif

#ifdef CONFIG_ASSH_USE_GCRYPT_ALLOC
/** This allocator relies on the various memory allocation functions
    provided by libgcrypt.

    It does not requires private data; @tt NULL may be passed as @tt
    alloc_pv parameter of the initialization function.
*/
ASSH_ALLOCATOR(assh_gcrypt_allocator);
#endif

/** @This allocates and initializes a context.

    If the @tt alloc parameter is @tt NULL, a default memory allocator
    will be used provided that one have been compiled in the
    library. If the @tt prng parameter is @tt NULL, a default random
    generator will be used. Some random number generator require a
    seed.

    @see assh_context_release */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_context_create(struct assh_context_s **ctx,
		    enum assh_context_type_e type, size_t algo_max,
		    assh_allocator_t *alloc, void *alloc_pv,
                    const struct assh_prng_s *prng,
                    const struct assh_buffer_s *prng_seed);

/** @This cleanups and releases a context created by the @ref
    assh_context_create function. All existing @ref assh_session_s
    objects must have been released when calling this function.

    @see assh_context_create */
void assh_context_release(struct assh_context_s *ctx);

/** @This initializes a context for use as a client or server. This
    can be used to initialize a statically allocated context
    object.

    If the @tt alloc parameter is @tt NULL, a default memory allocator
    will be used provided that one have been compiled in the
    library. If the @tt prng parameter is @tt NULL, a default random
    generator will be used. Some random number generator require a
    seed.

    When a stable ABI is needed, use the @ref assh_context_create
    function instead.

    @see assh_context_cleanup
*/
ASSH_ABI_UNSAFE ASSH_WARN_UNUSED_RESULT assh_error_t
assh_context_init(struct assh_context_s *ctx,
                  enum assh_context_type_e type,
                  assh_allocator_t *alloc, void *alloc_pv,
                  const struct assh_prng_s *prng,
                  const struct assh_buffer_s *prng_seed);

/** @This releases resources associated with a context. All existing
    @ref assh_session_s objects must have been released when calling
    this function. @see assh_context_init */
ASSH_ABI_UNSAFE void
assh_context_cleanup(struct assh_context_s *ctx);

/** @This set the user private pointer of the context. */
void assh_context_set_pv(struct assh_context_s *ctx,
                         void *private);

/** @This get the user private pointer of the context. */
void * assh_context_get_pv(struct assh_context_s *ctx);

#endif

