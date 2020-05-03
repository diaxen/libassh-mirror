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

/**
   @file
   @short SSH message authentication code module interface

   This header file contains API descriptors for message
   authentication @hl algorithm modules implemented in the library.

   @xsee{macalgos}
   @xsee{coremod}
*/

#ifndef ASSH_MAC_H_
#define ASSH_MAC_H_

#include "assh_algo.h"

/** @internal @see assh_mac_init_t */
#define ASSH_MAC_INIT_FCN(n)                                            \
  ASSH_WARN_UNUSED_RESULT assh_status_t (n)(struct assh_context_s *c,    \
					    void *ctx_, const uint8_t *key, \
					    assh_bool_t generate)

/** @internal @This defines the function type for the mac
    initialization operation of the mac module interface. The @tt
    ctx_ argument must points to a buffer allocated in secure memory
    of size given by @ref assh_algo_mac_s::ctx_size. */
typedef ASSH_MAC_INIT_FCN(assh_mac_init_t);

/** @internal @see assh_mac_process_t */
#define ASSH_MAC_PROCESS_FCN(n)                                         \
  ASSH_WARN_UNUSED_RESULT assh_status_t (n)(void *ctx_,    \
                                           const uint8_t *data, size_t len, \
                                           uint8_t *mac, uint32_t seq)

/** @internal @This defines the function type for the mac computation
    operation of the mac module interface. */
typedef ASSH_MAC_PROCESS_FCN(assh_mac_process_t);


/** @internal @see assh_mac_cleanup_t */
#define ASSH_MAC_CLEANUP_FCN(n) void (n)(struct assh_context_s *c, void *ctx_)

/** @internal @This defines the function type for the cleanup
    operation of the mac module interface. */
typedef ASSH_MAC_CLEANUP_FCN(assh_mac_cleanup_t);

/** @internalmembers @This is the mac algorithm descriptor
    structure. It can be casted to the @ref assh_algo_s type.
    @xsee{coremod} */
struct assh_algo_mac_s
{
  struct assh_algo_s algo;
  assh_mac_init_t    *f_init;
  assh_mac_process_t *f_process;
  assh_mac_cleanup_t *f_cleanup;
  /** Size of the context structure needed to initialize the algorithm. */
  uint16_t ctx_size;
  /** Mac key size in bytes. */
  uint8_t key_size:7;
  /** This is set if encrypt must be performed before mac */
  assh_bool_t etm:1;
  /** Authentication tag size. */
  uint8_t mac_size;
};

/** @This casts and returns the passed pointer if the
    algorithm class is @ref ASSH_ALGO_MAC. In
    other cases, @tt NULL is returned. */
ASSH_INLINE const struct assh_algo_mac_s *
assh_algo_mac(const struct assh_algo_s *algo)
{
  return algo->class_ == ASSH_ALGO_MAC
    ? (const struct assh_algo_mac_s *)algo
    : NULL;
}

/** @This finds a mac @hl algorithm in a @tt NULL terminated array of
    pointers to algorithm descriptors. @see assh_algo_by_name_static */
ASSH_INLINE ASSH_WARN_UNUSED_RESULT assh_status_t
assh_algo_mac_by_name_static(const struct assh_algo_s **table,
			     const char *name, size_t name_len,
			     const struct assh_algo_mac_s **ma,
			     const struct assh_algo_name_s **namep)
{
 return assh_algo_by_name_static(table, ASSH_ALGO_MAC, name, name_len,
				 (const struct assh_algo_s **)ma, namep);
}

/** @internal @This finds a registered mac @hl algorithm.
    @see assh_algo_by_name */
ASSH_INLINE ASSH_WARN_UNUSED_RESULT assh_status_t
assh_algo_mac_by_name(struct assh_context_s *c, const char *name,
		      size_t name_len, const struct assh_algo_mac_s **ma,
		      const struct assh_algo_name_s **namep)
{
  return assh_algo_by_name(c, ASSH_ALGO_MAC, name, name_len,
			   (const struct assh_algo_s **)ma, namep);
}

/** @multiple @This is a mac algorithm implementation descriptor.
    @xsee {macalgos} */
extern const struct assh_algo_mac_s assh_mac_none;

#endif

