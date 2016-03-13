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
   @short Random generator module interface
*/

#ifndef ASSH_PRNG_H_
#define ASSH_PRNG_H_

#include "assh_algo.h"
#include "assh_context.h"

/** @This specifies quality of randomly generated data. */
enum assh_prng_quality_e
{
  /** weak random data for use in the testsuite */
  ASSH_PRNG_QUALITY_WEAK,
  /** random data for use as public parameter */
  ASSH_PRNG_QUALITY_PUBLIC,
  /** random data for use as nonce in signature algorithms */
  ASSH_PRNG_QUALITY_NONCE,
  /** random data for use in ephemeral key generation */
  ASSH_PRNG_QUALITY_EPHEMERAL_KEY,
  /** random data for use in long term key generation */
  ASSH_PRNG_QUALITY_LONGTERM_KEY,
};

/** @internal @see assh_prng_init_t */
#define ASSH_PRNG_INIT_FCN(n) \
  ASSH_WARN_UNUSED_RESULT assh_error_t (n)(struct assh_context_s *c, \
                                const struct assh_buffer_s *seed)

/** @internal @This defines the function type for the initialization
    operation of the prng module interface. The prng can store its private
    data in @ref assh_context_s::prng_pv. */
typedef ASSH_PRNG_INIT_FCN(assh_prng_init_t);

/** @internal @see assh_prng_get_t */
#define ASSH_PRNG_GET_FCN(n) \
  ASSH_WARN_UNUSED_RESULT assh_error_t (n)(struct assh_context_s *c,    \
                                           uint8_t *rdata, size_t rdata_len, \
					   enum assh_prng_quality_e quality)
/** @internal @This defines the function type for the random generation
    operation of the prng module interface. @see assh_prng_get */
typedef ASSH_PRNG_GET_FCN(assh_prng_get_t);

/** @internal @see assh_prng_cleanup_t */
#define ASSH_PRNG_CLEANUP_FCN(n) void (n)(struct assh_context_s *c)

/** @internal @This defines the function type for the cleanup
    operation of the prng module interface. */
typedef ASSH_PRNG_CLEANUP_FCN(assh_prng_cleanup_t);

/** @internalmembers @This is the prng module interface descriptor
    structure. */
struct assh_prng_s
{
  assh_prng_init_t    *f_init;
  assh_prng_get_t     *f_get;
  assh_prng_cleanup_t *f_cleanup;
};

/** @internal @This fills the buffer with random data. */
ASSH_INLINE ASSH_WARN_UNUSED_RESULT assh_error_t
assh_prng_get(struct assh_context_s *c,
              uint8_t *rdata, size_t rdata_len,
              enum assh_prng_quality_e quality)
{
  return c->prng->f_get(c, rdata, rdata_len, quality);
}

/** @multiple @This is a prng algorithm implementation descriptor. */
extern const struct assh_prng_s assh_prng_xswap;

#ifdef CONFIG_ASSH_USE_GCRYPT_PRNG
extern const struct assh_prng_s assh_prng_gcrypt;
#endif

#ifdef CONFIG_ASSH_USE_DEV_RANDOM
extern const struct assh_prng_s assh_prng_dev_random;
#endif

#endif
