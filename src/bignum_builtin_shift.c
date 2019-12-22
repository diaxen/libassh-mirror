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

#include "bignum_builtin.h"

assh_status_t
assh_bignum_rshift(struct assh_bignum_s *dst,
                   const struct assh_bignum_s *src,
                   uint_fast32_t n)
{
  assert(src->bits == dst->bits);
  assert(n < src->bits);

  size_t i, l = assh_bignum_words(src->bits);

  if (dst == src && n == 0)
    return ASSH_OK;

  assh_bnword_t *dn = dst->n, *sn = src->n;

  assh_bnword_t o = sn[n / ASSH_BIGNUM_W];
  for (i = 0; i < l - n / ASSH_BIGNUM_W - 1; i++)
    {
      assh_bnword_t x = sn[i + n / ASSH_BIGNUM_W + 1];
      dn[i] = ((assh_bnlong_t)o >> (n % ASSH_BIGNUM_W))
        | ((assh_bnlong_t)x << (ASSH_BIGNUM_W - n % ASSH_BIGNUM_W));
      o = x;
    }
  for (; i < l; i++)
    {
      dn[i] = ((assh_bnlong_t)o >> (n % ASSH_BIGNUM_W));
      o = 0;
    }

  return ASSH_OK;
}

assh_status_t
assh_bignum_lshift(struct assh_bignum_s *dst,
                   const struct assh_bignum_s *src,
                   uint_fast32_t n)
{
  assert(src->bits == dst->bits);
  assert(n < src->bits);

  ssize_t i, l = assh_bignum_words(src->bits);

  if (dst == src && n == 0)
    return ASSH_OK;

  assh_bnword_t *dn = dst->n, *sn = src->n;

  assh_bnword_t o = sn[l - 1 - n / ASSH_BIGNUM_W];
  for (i = 0; i < l - n / ASSH_BIGNUM_W - 1; i++)
    {
      assh_bnword_t x = sn[l - 2 - i - n / ASSH_BIGNUM_W];
      dn[l - 1 - i] = ((assh_bnlong_t)o << (n % ASSH_BIGNUM_W))
        | ((assh_bnlong_t)x >> (ASSH_BIGNUM_W - n % ASSH_BIGNUM_W));
      o = x;
    }
  for (; i < l; i++)
    {
      dn[l - 1 - i] = ((assh_bnlong_t)o << (n % ASSH_BIGNUM_W));
      o = 0;
    }

  return ASSH_OK;
}

