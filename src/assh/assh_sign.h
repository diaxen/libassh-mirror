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
   @short SSH signature module interface

   This header file contains API descriptors for signature
   @hl algorithm modules implemented in the library.

   @xsee{authalgos}
   @xsee{coremod}
*/

#ifndef ASSH_SIGN_H_
#define ASSH_SIGN_H_

#include "assh_algo.h"
#include "assh_key.h"
#include "assh_buffer.h"

/** @internal @see assh_sign_generate_t */
#define ASSH_SIGN_GENERATE_FCN(n) ASSH_WARN_UNUSED_RESULT assh_status_t(n) \
  (struct assh_context_s *c,						\
   const struct assh_key_s *key, size_t data_count,			\
   const struct assh_cbuffer_s data[], uint8_t *sign, size_t *sign_len)

/** @internal @This defines the function type for the signature
    generation operation of the signature module interface.
    @see assh_sign_generate */
typedef ASSH_SIGN_GENERATE_FCN(assh_sign_generate_t);

/** @internal @see assh_sign_check_t */
#define ASSH_SIGN_CHECK_FCN(n) ASSH_WARN_UNUSED_RESULT assh_status_t (n) \
  (struct assh_context_s *c,						\
   const struct assh_key_s *key, size_t data_count,			\
   const struct assh_cbuffer_s data[],                                  \
   const uint8_t *sign, size_t sign_len, assh_safety_t *safety)

/** @internal @This defines the function type for the signature
    checking operation of the signature module interface.
    @see assh_sign_check */
typedef ASSH_SIGN_CHECK_FCN(assh_sign_check_t);

/** @internalmembers @This is the signature algorithm descriptor
    structure. It can be casted to the @ref assh_algo_s type.
    @xsee{coremod} */
struct assh_algo_sign_s
{
  struct assh_algo_s algo;

  /** Bit mask used to define groups in a set of algorithms which can
      use the same type of key. This used to reduce the number of
      authentication retries with the same key. */
  uint16_t groups;

  assh_sign_generate_t *f_generate;
  assh_sign_check_t *f_check;
};

/** @internal @This computes the signature of the passed data using
    the provided private key then writes it to the @tt sign buffer. The @tt
    sign_len parameter indicates the size of the buffer and is updated
    with the actual size of the signature blob.

    The data to sign can be split into multiple buffers. The @tt
    data_count parameter must specify the number of data buffers to use.

    If the @tt sign parameter is @tt NULL, the function updates the
    @tt sign_len parmeter with a size value which is greater or equal
    to what is needed to hold the signature blob. In this case, the
    @tt data_* parameters are not used and the key need not be private. */
ASSH_INLINE ASSH_WARN_UNUSED_RESULT assh_status_t
assh_sign_generate(struct assh_context_s *c, const struct assh_algo_sign_s *algo,
                   const struct assh_key_s *key, size_t data_count,
                   const struct assh_cbuffer_s data[],
                   uint8_t *sign, size_t *sign_len)
{
  return algo->f_generate(c, key, data_count, data, sign, sign_len);
}

/** @internal @This checks the signature of the passed data using the
    provided key. The data can be split into multiple buffers. The @tt
    data_count parameter must specify the number of data buffers used. */
ASSH_INLINE ASSH_WARN_UNUSED_RESULT assh_status_t
assh_sign_check(struct assh_context_s *c, const struct assh_algo_sign_s *algo,
                const struct assh_key_s *key, size_t data_count,
                const struct assh_cbuffer_s data[],
                const uint8_t *sign, size_t sign_len, assh_safety_t *safety)
{
  *safety = assh_min_uint(algo->algo.safety, key->safety);
  return algo->f_check(c, key, data_count, data, sign, sign_len, safety);
}

/** Dummy signature algorithm */
extern const struct assh_algo_sign_s assh_sign_none;

#endif

