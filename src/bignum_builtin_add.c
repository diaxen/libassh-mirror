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

#include "bignum_builtin.h"

assh_status_t
assh_bignum_addsub(struct assh_bignum_s *dst,
                   const struct assh_bignum_s *a,
                   const struct assh_bignum_s *b,
                   assh_bnword_t smask)
{
  assh_status_t err;
  assh_bnword_t amask = 0;

  /* make A the largest bits length */
  if (a->bits < b->bits)
    {
      ASSH_SWAP(a, b);
      amask ^= smask;
    }

  size_t dl = assh_bignum_words(dst->bits);
  size_t al = assh_bignum_words(a->bits);
  size_t bl = assh_bignum_words(b->bits);
  assert(dl >= al);

  const assh_bnword_t *an = a->n;
  const assh_bnword_t *bn = b->n;
  assh_bnword_t *dn = dst->n;
  assh_bnword_t bmask = amask ^ smask;
  size_t i;

  assh_bnlong_t t = (assh_bnlong_t)(smask & 1) << ASSH_BIGNUM_W;

  /* add/sub numbers */
  for (i = 0; i < bl; i++)
    dn[i] = t = (assh_bnlong_t)(an[i] ^ amask) + (bn[i] ^ bmask) + (t >> ASSH_BIGNUM_W);
  for (; i < al; i++)
    dn[i] = t = (assh_bnlong_t)(an[i] ^ amask) + bmask + (t >> ASSH_BIGNUM_W);
  for (; i < dl; i++)
    dn[i] = t = smask + (t >> ASSH_BIGNUM_W);

  /* handle overflow condition */
  t ^= (assh_bnlong_t)(smask & 1) << ASSH_BIGNUM_W;

  size_t l = dst->bits % ASSH_BIGNUM_W;
  if (!l)
    l = ASSH_BIGNUM_W;
  ASSH_RET_IF_TRUE(t >> l != 0, ASSH_ERR_NUM_OVERFLOW);

  return ASSH_OK;
}

