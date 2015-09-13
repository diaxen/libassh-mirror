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
   @short Key support for the ECDSA signature algorithm
   @internal
*/

#ifndef ASSH_KEY_ECDSA_H_
#define ASSH_KEY_ECDSA_H_

#include <assh/assh_key.h>
#include <assh/assh_bignum.h>

struct assh_weierstrass_curve_s;

struct assh_key_ecdsa_id_s
{
  const char *name;
  const uint8_t *oid;           /* len in oid[0] */
  const struct assh_weierstrass_curve_s *curve;
  const struct assh_hash_algo_s *hash;
};

/** @internal ECDSA key storage */
struct assh_key_ecdsa_s
{
  struct assh_key_s key;

  const struct assh_key_ecdsa_id_s *id;

  /* public key ec point */
  struct assh_bignum_s xn;
  struct assh_bignum_s yn;
  /* private key scalar */
  struct assh_bignum_s sn;
};

ASSH_FIRST_FIELD_ASSERT(assh_key_ecdsa_s, key);

/** @multiple @internal Key operations descriptor for Ecdsa keys */
extern const struct assh_key_ops_s assh_key_ecdsa_nistp;

#endif

