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
    provided keys and append it to the given packet payload. */
#define ASSH_SIGN_ADD_SIGN_FCN(n) assh_error_t (n)(struct assh_context_s *c, \
                                                   const struct assh_key_s *key, size_t data_count, \
                                                   const uint8_t * const data[], size_t const data_len[], \
                                                   struct assh_packet_s *pout)
typedef ASSH_SIGN_ADD_SIGN_FCN(assh_sign_add_sign_t);


#define ASSH_SIGN_CHECK_FCN(n) assh_error_t (n)(struct assh_context_s *c, \
                                                const struct assh_key_s *key, size_t data_count, \
                                                const uint8_t * const data[], size_t const data_len[], \
                                                const uint8_t *sign_str, assh_bool_t *ok)
typedef ASSH_SIGN_CHECK_FCN(assh_sign_check_t);


/** This function must append the public key blob to the given packet payload. */
#define ASSH_SIGN_ADD_PUB_FCN(n) assh_error_t (n)(struct assh_context_s *c, \
                                                 const struct assh_key_s *key, \
                                                 struct assh_packet_s *pout)
typedef ASSH_SIGN_ADD_PUB_FCN(assh_sign_add_pub_t);

struct assh_algo_sign_s
{
  struct assh_algo_s algo;
  assh_key_load_t *f_key_load;
  assh_sign_add_sign_t *f_add_sign;
  assh_sign_check_t *f_verify;
  assh_sign_add_pub_t *f_add_pub;
};

extern struct assh_algo_sign_s assh_sign_dss;
extern struct assh_algo_sign_s assh_sign_rsa;
extern struct assh_algo_sign_s assh_sign_ecdsa;

#endif

