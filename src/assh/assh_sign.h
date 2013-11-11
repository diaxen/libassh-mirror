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


#ifndef ASSH_SIGN_H_
#define ASSH_SIGN_H_

#include "assh_algo.h"
#include "assh_key.h"

/** This function must compute the signature of the passed data using
    the provided key and writes it to the @tt sign buffer. The @tt
    sign_len parameter indicates the size of the buffer and is updated
    with the actual size of the signature blob.

    The data to sign can be split into multiple buffers. The @tt
    data_count parameter must specify the number of data buffers to use.

    If the @tt sign parameter is @tt NULL, the function updates the
    @tt sign_len parmeter with a size value which is greater or equal
    to what is needed to hold the signature blob. In this case, the
    @tt data_* parameters are not used.
 */
#define ASSH_SIGN_GENERATE_FCN(n) assh_error_t (n)(struct assh_context_s *c, \
                                                   const struct assh_key_s *key, size_t data_count, \
                                                   const uint8_t * const data[], size_t const data_len[], \
                                                   uint8_t *sign, size_t *sign_len)
typedef ASSH_SIGN_GENERATE_FCN(assh_sign_generate_t);

/** This function must verify the signature of the passed data using
    the provided key and update the @tt ok parameter accordingly.

    The data can be split into multiple buffers. The @tt data_count
    parameter must specify the number of data buffers used.
 */
#define ASSH_SIGN_VERIFY_FCN(n) assh_error_t (n)(struct assh_context_s *c, \
                                                 const struct assh_key_s *key, size_t data_count, \
                                                 const uint8_t * const data[], size_t const data_len[], \
                                                 const uint8_t *sign, size_t sign_len, assh_bool_t *ok)
typedef ASSH_SIGN_VERIFY_FCN(assh_sign_verify_t);


struct assh_algo_sign_s
{
  struct assh_algo_s algo;
  assh_key_load_t *f_key_load;
  assh_sign_generate_t *f_generate;
  assh_sign_verify_t *f_verify;
};

extern struct assh_algo_sign_s assh_sign_dss;
extern struct assh_algo_sign_s assh_sign_rsa;
extern struct assh_algo_sign_s assh_sign_ecdsa;

#endif

