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
   @short SSH compression module interface

   This header file contains API descriptors for compression
   @hl algorithm modules implemented in the library.

   @xsee{compalgos}
   @xsee{coremod}
*/

#ifndef ASSH_COMPRESS_H_
#define ASSH_COMPRESS_H_

#include "assh_algo.h"

/** @internal @see assh_compress_init_t */
#define ASSH_COMPRESS_INIT_FCN(n) \
  ASSH_WARN_UNUSED_RESULT assh_status_t (n)(struct assh_context_s *c,	\
					   void *ctx_, assh_bool_t compress)

/** @internal @This defines the function type for the
    initialization operation of the compression module interface. */
typedef ASSH_COMPRESS_INIT_FCN(assh_compress_init_t);

/** @internal @see assh_compress_process_t */
#define ASSH_COMPRESS_PROCESS_FCN(n) \
  ASSH_WARN_UNUSED_RESULT assh_status_t (n)(struct assh_context_s *c, \
                                           void *ctx_, struct assh_packet_s **p_, \
                                           assh_bool_t auth_done)

/** @internal @This defines the function type for the data processing
    operation of the compression module interface. This function
    should rely on the @ref assh_packet_realloc_raw function. */
typedef ASSH_COMPRESS_PROCESS_FCN(assh_compress_process_t);

/** @internal @see assh_compress_cleanup_t */
#define ASSH_COMPRESS_CLEANUP_FCN(n) \
  void (n)(struct assh_context_s *c, void *ctx_)

/** @internal @This defines the function type for the hash context
    cleanup operation of the hash module interface. */
typedef ASSH_COMPRESS_CLEANUP_FCN(assh_compress_cleanup_t);

/** @internalmembers @This is the compression algorithm descriptor
    structure. It can be casted to the @ref assh_algo_s type.
    @xsee{coremod} */
struct assh_algo_compress_s
{
  struct assh_algo_s algo;
  /** Size of the context structure needed to initialize the algorithm. */
  size_t ctx_size;
  assh_compress_init_t *f_init;
  assh_compress_process_t *f_process;
  assh_compress_cleanup_t *f_cleanup;
};

/** @This casts and returns the passed pointer if the
    algorithm class is @ref ASSH_ALGO_COMPRESS. In
    other cases, @tt NULL is returned. */
ASSH_INLINE const struct assh_algo_compress_s *
assh_algo_compress(const struct assh_algo_s *algo)
{
  return algo->class_ == ASSH_ALGO_COMPRESS
    ? (const struct assh_algo_compress_s *)algo
    : NULL;
}

/** @This finds a compression @hl algorithm in a @tt NULL terminated
    array of pointers to algorithm descriptors. @see
    assh_algo_by_name_static */
ASSH_INLINE ASSH_WARN_UNUSED_RESULT assh_status_t
assh_algo_compress_by_name_static(const struct assh_algo_s **table,
				  const char *name, size_t name_len,
				  const struct assh_algo_compress_s **cpa,
				  const struct assh_algo_name_s **namep)
{
 return assh_algo_by_name_static(table, ASSH_ALGO_COMPRESS, name, name_len,
				 (const struct assh_algo_s **)cpa, namep);
}

/** @internal @This finds a registered compression @hl algorithm.
    @see assh_algo_by_name */
ASSH_INLINE ASSH_WARN_UNUSED_RESULT assh_status_t
assh_algo_compress_by_name(struct assh_context_s *c, const char *name,
			   size_t name_len, const struct assh_algo_compress_s **cpa,
			   const struct assh_algo_name_s **namep)
{
  return assh_algo_by_name(c, ASSH_ALGO_COMPRESS, name, name_len,
			   (const struct assh_algo_s **)cpa, namep);
}


ASSH_FIRST_FIELD_ASSERT(assh_algo_compress_s, algo);

extern const struct assh_algo_compress_s assh_compress_none;

#endif

