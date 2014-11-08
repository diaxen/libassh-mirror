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

#ifndef ASSH_KEY_ED25519_H_
#define ASSH_KEY_ED25519_H_

#include <assh/assh_key.h>
#include <assh/assh_bignum.h>

struct assh_edward_curve_s
{
  const uint8_t *p;
  const uint8_t *l;
  const uint8_t *bx;
  const uint8_t *by;
  const uint8_t *a;
  const uint8_t *d;
  const uint8_t *i;
  size_t bits;
  uint_fast8_t cofactor;
};

struct assh_key_ed25519_s
{
  struct assh_key_s key;

  assh_bool_t private;
  uint8_t s[32];
  uint8_t p[32];
};

ASSH_FIRST_FIELD_ASSERT(assh_key_ed25519_s, key);

extern const struct assh_algo_key_s assh_key_ed25519;

extern const struct assh_edward_curve_s assh_ed25519_curve;

static const char *assh_ed25519_id = "\x00\x00\x00\x0bssh-ed25519";
static const size_t assh_ed25519_id_len = 4 + 11;

static inline void
assh_edward_adjust(const struct assh_edward_curve_s *curve, uint8_t *blob)
{
  uint_fast8_t i = (8 - curve->bits) & 7;
  uint_fast8_t j = (curve->bits - 1) / 8;

  blob[0] -= blob[0] % curve->cofactor;
  blob[j] &= 0xff >> i;
  blob[j] |= 0x80 >> i;
}

static inline void 
assh_edward_encode(const struct assh_edward_curve_s *curve,
                   uint8_t y[], const uint8_t x[])
{
  uint_fast8_t j = (curve->bits - 1) / 8;
  y[j] |= ((x[0] & 1) << 7);
}

#endif

