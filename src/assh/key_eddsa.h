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
   @short Key support for the EdDSA signature algorithm
   @internal
*/

#ifndef ASSH_KEY_EDDSA_H_
#define ASSH_KEY_EDDSA_H_

#include <assh/assh_key.h>
#include <assh/assh_bignum.h>

/** @internal Edward elliptic curve parameters decriptor.
    @em {a*x^2+y^2 = 1+d*x^2y^2} */
struct assh_edward_curve_s
{
  const uint8_t *p;
  const uint8_t *l; /* order */
  const uint8_t *bx; /* basepoint x */
  const uint8_t *by; /* basepoint y */
  const uint8_t *a;
  const uint8_t *d;
  const uint8_t *i; /* sqrt(-1), used when p%8 == 5 */
  size_t bits;
  uint_fast8_t cofactor;
};

/** @internal EdDSA key storage */
struct assh_key_eddsa_s
{
  struct assh_key_s key;

  const struct assh_edward_curve_s *curve;
  const struct assh_hash_algo_s *hash;

  assh_bool_t private;

  /** public + secret key data */
  uint8_t data[0];
};

ASSH_FIRST_FIELD_ASSERT(assh_key_eddsa_s, key);

/** @multiple @internal Key operations descriptor for EdDSA keys */
extern const struct assh_key_ops_s assh_key_ed25519;
extern const struct assh_key_ops_s assh_key_eddsa_e382;
extern const struct assh_key_ops_s assh_key_eddsa_e521;

/** @multiple @internal Edward curve parameters */
extern const struct assh_edward_curve_s assh_ed25519_curve;
extern const struct assh_edward_curve_s assh_e382_curve;
extern const struct assh_edward_curve_s assh_e521_curve;

/** @internal Adjust blob for use with edward curvre */
ASSH_INLINE void
assh_edward_adjust(const struct assh_edward_curve_s *curve, uint8_t *blob)
{
  uint_fast8_t i = (8 - curve->bits) & 7;
  uint_fast8_t j = (curve->bits - 1) / 8;

  blob[0] -= blob[0] % curve->cofactor;
  blob[j] &= 0xff >> i;
  blob[j] |= 0x80 >> i;
}

/** @internal Edward curve point encoding */
ASSH_INLINE void 
assh_edward_encode(const struct assh_edward_curve_s *curve,
                   uint8_t y[], const uint8_t x[])
{
  uint_fast8_t j = (curve->bits - 1) / 8;
  y[j] |= ((x[0] & 1) << 7);
}

#endif

