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

static void
assh_bignum_school_mul(assh_bnword_t * __restrict__ r,
                       const assh_bnword_t *a, uint_fast32_t alen,
                       const assh_bnword_t *b, uint_fast32_t blen)
{
  memset(r, 0, alen * sizeof(assh_bnword_t));

  uint_fast32_t j, i;
  assh_bnlong_t t;

  for (j = 0; j < blen; j++)
    {
      for (t = i = 0; i < alen; i++)
	r[i + j] = t = (assh_bnlong_t)a[i] * b[j] + r[i + j] + (t >> ASSH_BIGNUM_W);
      r[i + j] = (t >> ASSH_BIGNUM_W);
    }
}

#if !defined(__OPTIMIZE_SIZE__)
static void
assh_bignum_karatsuba(assh_bnword_t * __restrict__ r,
                      const assh_bnword_t *a, const assh_bnword_t *b,
                      assh_bnword_t *scratch, uint_fast32_t l)
{
  if (l < ASSH_BIGNUM_KARATSUBA_THRESHOLD || (l & 1))
    {
      assh_bignum_school_mul(r, a, l, b, l);
      return;
    }

  /*
    scratch buffer:
      layout: x[h], y_[h], z1[l+1]
      size: 2*l+1        per stack frame
            4*l+log2(l)  on initial call
  */

#define ASSH_KARA_SCRATCH(len) (len * 4)
          /* + log2(len) - ASSH_KARA_SCRATCH(ASSH_BIGNUM_KARATSUBA_THRESHOLD) */

  uint_fast32_t i, h = l / 2;
  assh_bnlong_t tx = 0, ty = 0;
  assh_bnword_t cx, cy;

  assh_bnword_t *x = scratch;
  assh_bnword_t *y_ = scratch + h;
  assh_bnword_t *y = x;

  /* compute high/low parts sums */
  for (i = 0; i < h; i++)
    x[i] = tx = (assh_bnlong_t)a[i + h] + a[i] + (tx >> ASSH_BIGNUM_W);
  cy = cx = (assh_bnsword_t)(tx >> 1) >> (ASSH_BIGNUM_W - 1);

  if (a != b)
    {
      y = y_;
      for (i = 0; i < h; i++)
	y[i] = ty = (assh_bnlong_t)b[i + h] + b[i] + (ty >> ASSH_BIGNUM_W);
      cy = (assh_bnsword_t)(ty >> 1) >> (ASSH_BIGNUM_W - 1);
    }

  /* recusive calls */
  assh_bnword_t *z1 = scratch + l;

  scratch += 2 * l + 1;
  assh_bignum_karatsuba(r + l, a + h, b + h, scratch, h); /* z0 */
  assh_bignum_karatsuba(z1   , x    , y    , scratch, h); /* z1 */
  assh_bignum_karatsuba(r    , a    , b    , scratch, h); /* z2 */

  /* z1 = z1 - z0 - z2 */
  assh_bnlong_t t = (assh_bnlong_t)2 << ASSH_BIGNUM_W;
  for (i = 0; i < h; i++)
    z1[i] = t = (assh_bnlong_t)z1[i] + (assh_bnword_t)~r[i]
              + (assh_bnword_t)~r[i + l] + (t >> ASSH_BIGNUM_W);
  for (; i < l; i++)
    z1[i] = t = (assh_bnlong_t)z1[i] + (assh_bnword_t)~r[i]
              + (assh_bnword_t)~r[i + l] + (t >> ASSH_BIGNUM_W)
              + (x[i-h] & cy) + (y[i-h] & cx);
  z1[i] = (t >> ASSH_BIGNUM_W) - 2 - (cx & cy);

  /* add z1 to result */
  t = 0;
  for (i = h; i < l+h+1; i++)
    r[i] = t = (assh_bnlong_t)r[i] + z1[i - h] + (t >> ASSH_BIGNUM_W);
  for (; i < l*2; i++)
    r[i] = t = (assh_bnlong_t)r[i] + (t >> ASSH_BIGNUM_W);
}
#endif

size_t
assh_bignum_mul_sc_size(const struct assh_bignum_s *r,
                        const struct assh_bignum_s *a,
                        const struct assh_bignum_s *b)
{
  size_t rl = assh_bignum_words(r->bits);
  size_t al = assh_bignum_words(a->bits);
  size_t bl = assh_bignum_words(b->bits);
  size_t l = al + bl;
  size_t sl = rl < l ? l : 0;

#if !defined(__OPTIMIZE_SIZE__)
  if (al == bl && !(al & 1))
    sl += ASSH_KARA_SCRATCH(al);
#endif

  return sl;
}

assh_status_t
assh_bignum_mul(struct assh_context_s *ctx,
                assh_bnword_t *s,
                struct assh_bignum_s *r,
                const struct assh_bignum_s *a,
                const struct assh_bignum_s *b)
{
  assh_status_t err;

  assert(r != a && r != b);

  ASSH_RET_IF_TRUE(r->bits < a->bits + b->bits, ASSH_ERR_OUTPUT_OVERFLOW);

  size_t rl = assh_bignum_words(r->bits);
  size_t al = assh_bignum_words(a->bits);
  size_t bl = assh_bignum_words(b->bits);
  size_t l = al + bl;
  size_t sl = rl < l ? l : 0;
  assh_bnword_t *x = r->n;

#if !defined(__OPTIMIZE_SIZE__)
  if (al == bl && !(al & 1))
    {
      if (sl)
        x = s;
      assh_bignum_karatsuba(x, a->n, b->n, s + sl, al);
    }
  else
#endif
    {
      if (sl)
        x = s;
      assh_bignum_school_mul(x, a->n, al, b->n, bl);
    }

  if (sl)
    memcpy((assh_bnword_t*)r->n, s, rl * sizeof(assh_bnword_t));
  else
    memset((assh_bnword_t*)r->n + l, 0, (rl - l) * sizeof(assh_bnword_t));

  return ASSH_OK;
}

size_t
assh_bignum_mul_mod_sc_size(const struct assh_bignum_s *a,
                            const struct assh_bignum_s *b)
{
  size_t al = assh_bignum_words(a->bits);
  size_t bl = assh_bignum_words(b->bits);
  size_t l = al + bl; /* result size */

#if !defined(__OPTIMIZE_SIZE__)
  if (al == bl && !(al & 1))
    l += ASSH_KARA_SCRATCH(al);
#endif

  return l;
}

assh_status_t
assh_bignum_mul_mod(struct assh_context_s *ctx,
                    assh_bnword_t *x,
                    struct assh_bignum_s *r,
                    const struct assh_bignum_s *a,
                    const struct assh_bignum_s *b,
                    const struct assh_bignum_s *m)
{
  assh_status_t err;

  ASSH_RET_IF_TRUE(r->bits < m->bits, ASSH_ERR_OUTPUT_OVERFLOW);

  size_t al = assh_bignum_words(a->bits);
  size_t bl = assh_bignum_words(b->bits);
  size_t ml = assh_bignum_words(m->bits);
  size_t rl = assh_bignum_words(r->bits);

  size_t l = al + bl; /* result size */

#if !defined(__OPTIMIZE_SIZE__)
  if (al == bl && !(al & 1))
    assh_bignum_karatsuba(x, a->n, b->n, x + l, al);
  else
#endif
    assh_bignum_school_mul(x, a->n, al, b->n, bl);

  ASSH_RET_ON_ERR(assh_bignum_div_euclidean(x, l, NULL, 0, m->n, ml,
                                         a->secret | b->secret | m->secret,
                                         a->bits + b->bits - assh_bignum_bitlen(m)));

  memcpy(r->n, x, ml * sizeof(assh_bnword_t));
  memset(r->n + ml, 0, (rl - ml) * sizeof(assh_bnword_t));

  return ASSH_OK;
}

