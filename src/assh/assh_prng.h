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


#ifndef ASSH_PRNG_H_
#define ASSH_PRNG_H_

#ifdef ASSH_EVENT_H_
# warning The assh/assh_prng.h header should be included after assh_transport.h
#endif

#include "assh_algo.h"

enum assh_prng_quality_e
{
  ASSH_PRNG_QUALITY_WEAK,          //< weak random data for use in the testsuite
  ASSH_PRNG_QUALITY_NONCE,         //< random data for use as nonce in signature algorithms
  ASSH_PRNG_QUALITY_EPHEMERAL_KEY, //< random data for use in ephemeral key generation
  ASSH_PRNG_QUALITY_LONGTERM_KEY,  //< random data for use in long term key generation
};

/**
   The @ref ASSH_EVENT_PRNG_FEED event is returned when the pluggable
   prng needs some entropy input. The @ref buf buffer must be updated
   to point to random data before calling the @ref assh_event_done
   function. The @ref size field gives the prefered amount of random
   data.
*/
struct assh_event_prng_feed_s
{
  size_t       size;       //< input/output
  uint8_t      buf[32];    //< output
};

/** @internal */
union assh_event_prng_u
{
  struct assh_event_prng_feed_s feed;  
};

#define ASSH_PRNG_INIT_FCN(n) \
  ASSH_WARN_UNUSED_RESULT assh_error_t (n)(struct assh_context_s *c)
typedef ASSH_PRNG_INIT_FCN(assh_prng_init_t);

#define ASSH_PRNG_GET_FCN(n) \
  ASSH_WARN_UNUSED_RESULT assh_error_t (n)(struct assh_context_s *c,    \
                                           uint8_t *rdata, size_t rdata_len, \
					   enum assh_prng_quality_e quality)
typedef ASSH_PRNG_GET_FCN(assh_prng_get_t);

#define ASSH_PRNG_FEED_FCN(n) \
  ASSH_WARN_UNUSED_RESULT assh_error_t (n)(struct assh_context_s *c,    \
                                           const uint8_t *rdata, size_t rdata_len)
typedef ASSH_PRNG_FEED_FCN(assh_prng_feed_t);

#define ASSH_PRNG_CLEANUP_FCN(n) void (n)(struct assh_context_s *c)
typedef ASSH_PRNG_CLEANUP_FCN(assh_prng_cleanup_t);

struct assh_prng_s
{
  assh_prng_init_t    *f_init;
  assh_prng_get_t     *f_get;
  assh_prng_feed_t    *f_feed;
  assh_prng_cleanup_t *f_cleanup;
};

extern const struct assh_prng_s assh_prng_xswap;

#ifdef CONFIG_ASSH_USE_GCRYPT_PRNG
extern const struct assh_prng_s assh_prng_gcrypt;
#endif

#endif
