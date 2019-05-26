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

   The library uses a context structure to store stuff common to
   multiple @hl sessions. This header file provides declaration of
   the @ref assh_context_s structure and related functions.
*/

#ifndef ASSH_CONTEXT_H_
#define ASSH_CONTEXT_H_

#include "assh.h"

/** This specifies the type of ssh sessions that will be created. */
enum assh_context_type_e
{
  /** Sessions associated to the context will be server side. */
  ASSH_SERVER,
  /** Sessions associated to the context will be client side. */
  ASSH_CLIENT,
  /** No session can be associated to the context. The context may
      still be used to perform key management operations. */
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

/** @internalmembers @This is the library main context structure. It
    is designed to store resources shared between multiple @ref
    assh_session_s instances.

    It stores the following resources:
    @list
    @item the set of registered @hl algorithms,
    @item the memory allocator context,
    @item the random generator context,
    @item the user configurable protocol timeouts,
    @item the list of server host keys.
    @end list
*/
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

  /** Head of loaded keys list */
  struct assh_key_s *keys;

  /** Registered algorithms */
  const struct assh_algo_s **algos;

  /** Set if @tt algos is not a static array */
  size_t algo_realloc:1;

  /** Number of algorithm slots */
  size_t algo_max:15;

  /** Number of registered algorithms */
  size_t algo_cnt:16;

#ifdef CONFIG_ASSH_PACKET_POOL
  /** Packet pool: maximum allocated size in a single bucket. */
  uint32_t pck_pool_max_bsize;
  /** Packet pool: maximum byte amount of spare packets before
      releasing to the memory allocator. */
  uint32_t pck_pool_max_size;
  /** Packet pool: current byte amount of spare packets not yet
      released to the memory allocator. */
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

  /** Timeout waiting for reply to the version string and service
      start requests. Expressed in seconds minus 1. */
  uint8_t timeout_transport;
  /** Maximum duration of a key exchange, in seconds minus 1. */
  uint8_t timeout_kex;
  /** Duration before initiating a new key exchanges, in seconds minus 1. */
  uint16_t timeout_rekex;
  /** Maximum duration of the user authentication process, in
      seconds minus 1. */
  uint16_t timeout_userauth;
  /** Delay between transmission of the @ref SSH_MSG_IGNORE packets by
      the running service for keepalive purpose, in seconds. Disabled
      when 0. */
  uint16_t timeout_keepalive;

  /** Estimated size of the kex init packet, computed when new
      algorithms are registered. */
  size_t kex_init_size:16;
};

/** @This sets various timeout delays related to the transport
    layer. Values are expressed in second unit. When passing 0, the
    delay is not changed. */
void
assh_context_timeouts(struct assh_context_s *c,
                      uint_fast8_t transport, uint_fast8_t kex,
                      uint_fast16_t rekex, uint_fast16_t userauth);

/** @This sets the idle delay before transmission of a keep-alive
    message by the running service. No keep-alive messages are
    transmitted when 0. */
void
assh_context_keepalive(struct assh_context_s *c, uint_fast16_t keepalive);

/** @This takes care of performing the external libraries global
    initialization.

    The assh library does not use global variables and does not
    require global initialization. You do not need to call this
    function if you know that you use a standalone build of assh or if
    you already perform the initialization of the required third party
    libraries in your application code. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_deps_init(void);

/** @This allocates and initializes an @ref assh_context_s instance.

    If the @tt alloc parameter is @tt NULL, a default memory allocator
    will be used provided that one have been compiled in the library.

    If the @tt prng parameter is @tt NULL, a default random generator
    will be used. Some random number generator require the seed
    argument to be not @tt {NULL}.

    @see assh_context_release */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_context_create(struct assh_context_s **ctx,
		    enum assh_context_type_e type,
		    assh_allocator_t *alloc, void *alloc_pv,
                    const struct assh_prng_s *prng,
                    const struct assh_buffer_s *prng_seed);

/** @This releases an @ref assh_context_s instance created by the @ref
    assh_context_create function as well as associated resources.

    All existing @ref assh_session_s objects must have been released
    when this function is called.

    @see assh_context_create */
void assh_context_release(struct assh_context_s *ctx);

/** @This initializes an user allocated @ref assh_context_s
    instance.  When a stable ABI is needed, the @ref
    assh_context_create function must be used instead.

    This requires the same arguments as the @ref assh_context_create
    function.

    @see assh_context_cleanup
*/
ASSH_ABI_UNSAFE ASSH_WARN_UNUSED_RESULT assh_error_t
assh_context_init(struct assh_context_s *ctx,
                  enum assh_context_type_e type,
                  assh_allocator_t *alloc, void *alloc_pv,
                  const struct assh_prng_s *prng,
                  const struct assh_buffer_s *prng_seed);

/** @This releases resources associated with an user allocated @ref
    assh_context_s instance.

    Any associated @ref assh_session_s objects must have been released
    when this function is called.

    @see assh_context_init */
ASSH_ABI_UNSAFE void
assh_context_cleanup(struct assh_context_s *ctx);

/** @This sets the user private pointer of the context.
    @see assh_context_get_pv */
void assh_context_set_pv(struct assh_context_s *ctx,
                         void *private);

/** @This retrieves the user private pointer attached to the context.
    @see assh_context_set_pv */
void * assh_context_get_pv(struct assh_context_s *ctx);

/** @This returns the list head of keys attached to the context.  It
    can be used to attach more keys. The @ref assh_key_flush
    function will be called on this list on context cleanup.

    @see asshh_load_hostkey_file
    @see asshh_load_hostkey_filename
 */
struct assh_key_s **
assh_context_keys(struct assh_context_s *ctx);

#endif

