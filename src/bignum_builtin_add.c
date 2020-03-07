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
      ASSH_SWAP(const struct assh_bignum_s *, a, b);
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

void
assh_bignum_mt_add(struct assh_bignum_s *dst,
                   const struct assh_bignum_s *a,
                   const struct assh_bignum_s *b,
                   const struct assh_bignum_s *mod)
{
  struct assh_bignum_mt_s *mt = (void*)mod;

  assert(dst->bits == a->bits);
  assert(dst->bits == b->bits);
  assert(dst->bits == mod->bits);

  size_t i, dl = assh_bignum_words(dst->bits);
  if (dl)
    {
      /* We want to add two numbers in montgomery representation. When
         an overflow is detected, we need to add 1 in montgomery
         representation. Since we use a redundant montgomery
         representation, accounting for the first overflow may
         generate a second overflow. At most two overflows can be
         generated which would require 3 loops in order to perform the
         whole operation in constant time: a + b; +1?; +1?.

         Instead we merge the first two loops: a + b + 1?; +1?.
         This is achieved by predicting the first overflow by only
         summing the most significant word of each number. In case of
         misprediction, we correct the result thanks to the second
         loop. This works because misprediction and double overflow
         conditions can't occur at the same time. */
      const assh_bnword_t *an = a->n;
      const assh_bnword_t *bn = b->n;
      const assh_bnword_t *r1 = (assh_bnword_t*)mt->mod.n + 2 * dl;
      assh_bnword_t *dn = dst->n;

      /* compute the 1st mask by predicting the first overflow */
      assh_bnword_t q = ((assh_bnlong_t)an[dl - 1] + bn[dl - 1]) >> ASSH_BIGNUM_W;
      q = (q ^ 1) - 1;

      /* add the numbers and conditionally add montgomery(1) */
      assh_bnlong_t t = 0;
      for (i = 0; i < dl; i++)
        dn[i] = t = (assh_bnlong_t)an[i] + bn[i] + (q & r1[i]) + (t >> ASSH_BIGNUM_W);

      /* compute 2nd mask:
         1st mask   carry    2nd mask
         0          0        0       no overflow
         1          0                not possible
         0          1        1       mispredicted single overflow
         1          1        0       single overflow
         0          2                not possible
         1          2        1       double overflow
      */
      q = (assh_bnword_t)(1 & ((t >> ASSH_BIGNUM_W) ^ q ^ 1)) - 1;

      /* conditionally add montgomery(1) */
      t = 0;
      for (t = i = 0; i < dl; i++)
        dn[i] = t = (assh_bnlong_t)dn[i] + (q & r1[i]) + (t >> ASSH_BIGNUM_W);
    }
}

void
assh_bignum_mt_sub(struct assh_bignum_s *dst,
                   const struct assh_bignum_s *a,
                   const struct assh_bignum_s *b,
                   const struct assh_bignum_s *mod)
{
  struct assh_bignum_mt_s *mt = (void*)mod;

  assert(dst->bits == a->bits);
  assert(dst->bits == b->bits);
  assert(dst->bits == mod->bits);

  size_t i, dl = assh_bignum_words(dst->bits);
  if (dl)
    {
      /* see assh_bignum_mt_add for explanations */
      const assh_bnword_t *an = a->n;
      const assh_bnword_t *bn = b->n;
      const assh_bnword_t *r1 = (assh_bnword_t*)mt->mod.n + 2 * dl;
      assh_bnword_t *dn = dst->n;

      /* compute the 1st mask by predicting the first overflow */
      assh_bnword_t q = ((assh_bnlong_t)an[dl - 1] - bn[dl - 1]) >> ASSH_BIGNUM_W;
      q = ((q & 1) ^ 1) - 1;

      /* subtract numbers and conditionally subtract montgomery(1) */
      assh_bnslong_t t = 0;
      for (i = 0; i < dl; i++)
        dn[i] = t = (assh_bnlong_t)an[i] - bn[i] - (q & r1[i]) + (t >> ASSH_BIGNUM_W);

      /* compute 2nd mask */
      q = (assh_bnword_t)(1 & ((t >> ASSH_BIGNUM_W) ^ q ^ 1)) - 1;

      /* conditionally subtract montgomery(1) */
      t = 0;
      for (i = 0; i < dl; i++)
        dn[i] = t = (assh_bnlong_t)dn[i] - (q & r1[i]) + (t >> ASSH_BIGNUM_W);
    }
}

