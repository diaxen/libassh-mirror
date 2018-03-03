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

#include <assh/assh_alloc.h>

assh_error_t
assh_bignum_mt_init(struct assh_context_s *c,
                    struct assh_bignum_mt_s *mt,
                    const struct assh_bignum_s *mod)
{
  assh_error_t err;


  /* check modulus is odd */
  ASSH_RET_IF_TRUE(!(*(assh_bnword_t*)mod->n & 1), ASSH_ERR_NUM_OVERFLOW);

  assert(mod->bits <= mt->max_bits);

  size_t ml = assh_bignum_words(mod->bits);
  assh_bnword_t *m = mt->mod.n;

  /* copy the modulus */
  memcpy(m, mod->n, ml * sizeof(assh_bnword_t));

  mt->mod.bits = mod->bits;
  mt->mod.secret = 0;
  mt->mod.mt_mod = 1;
  mt->n0 = assh_bnword_mt_modinv(-m[0]);

  /* compute r**2 % n */
  assh_bnword_t *r2 = m + ml;

  size_t i;
  for (i = 0; i < ml * 2; i++)
    r2[i] = 0;
  r2[i] = 1;

  if (mod->secret)
    assh_bignum_div_euclidean_ct(r2, ml * 2 + 1, NULL, 0, m, ml,
                                 ml * ASSH_BIGNUM_W + 1);
  else
    assh_bignum_div_euclidean(r2, ml * 2 + 1, NULL, 0, m, ml);

  /* compute 1 in montgomery representation */
  assh_bnword_t *r1 = m + ml * 2;

  for (i = 0; i < ml; i++)
    r1[i] = 0;
  r1[i] = 1;

  if (mod->secret)
    assh_bignum_div_euclidean_ct(r1, ml + 1, NULL, 0, m, ml, 1);
  else
    assh_bignum_div_euclidean(r1, ml + 1, NULL, 0, m, ml);

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

void
assh_bignum_mt_mul(const struct assh_bignum_mt_s *mt,
                   assh_bnword_t * __restrict__ a,
                   const assh_bnword_t * __restrict__ x,
                   const assh_bnword_t * __restrict__ y)
{
  size_t i, j;
  size_t ml = assh_bignum_words(mt->mod.bits);
  assh_bnword_t *m = mt->mod.n;
  assh_bnword_t q, k = 0;
  assh_bnlong_t p, t, r;

  for (i = 0; i < ml; i++)
    a[i] = 0;

  for (i = 0; i < ml; i++)
    {
      p = a[0] + (assh_bnlong_t)x[i] * y[0];
      q = p * mt->n0;
      r = (assh_bnlong_t)m[0] * q;

      /* t = (p + r) >> ASSH_BIGNUM_W, do not drop carry */
      t = (assh_bnlong_t)(assh_bnword_t)r + (assh_bnword_t)p;
      t = (t >> ASSH_BIGNUM_W) + (r >> ASSH_BIGNUM_W) + (p >> ASSH_BIGNUM_W);

      for (j = 1; j < ml; j++)
        {
          p = a[j] + (assh_bnlong_t)x[i] * y[j];
          r = (assh_bnlong_t)m[j] * q + t;

          /* a[j-1] = p + r,  t = (p + r) >> ASSH_BIGNUM_W */
          t = (assh_bnlong_t)(assh_bnword_t)r + (assh_bnword_t)p;
          a[j-1] = t;
          t = (t >> ASSH_BIGNUM_W) + (r >> ASSH_BIGNUM_W) + (p >> ASSH_BIGNUM_W);
        }
      t += k;
      a[j-1] = t;
      k = t >> ASSH_BIGNUM_W;
    }

  /* Masked final subtraction */
  q = (k ^ 1) - 1;
  t = (assh_bnlong_t)(q & 1) << ASSH_BIGNUM_W;
  for (i = 0; i < ml; i++)
    a[i] = t = (assh_bnlong_t)a[i] + (q & ~m[i]) + (t >> ASSH_BIGNUM_W);
}

void
assh_bignum_mt_reduce(const struct assh_bignum_mt_s *mt,
                      assh_bnword_t * __restrict__ a,
                      const assh_bnword_t * __restrict__ x)
{
  size_t i, j;
  size_t ml = assh_bignum_words(mt->mod.bits);
  assh_bnword_t *m = mt->mod.n;
  assh_bnword_t e;

  for (i = 0; i < ml; i++)
    a[i] = 0;

  for (i = 0; i < ml; i++)
    {
      assh_bnlong_t p = a[0] + (assh_bnlong_t)x[i];
      assh_bnword_t q = p * mt->n0;
      assh_bnword_t pm = m[0];
      assh_bnlong_t r = (assh_bnlong_t)pm * q;
      assh_bnlong_t t = p + r;
      e = 0;

      for (j = 1; j < ml; j++)
        {
          assh_bnword_t cm = m[j];
          p = a[j];
          r = (assh_bnlong_t)cm * q + (t >> ASSH_BIGNUM_W);
          t = p + r;
          a[j-1] = t;
          e |= (t ^ pm);
          pm = cm;
        }
      q = (t >> ASSH_BIGNUM_W);
      a[j-1] = q;
      e |= (q ^ pm);
    }

  /* handle a == mod */
  e = assh_bignum_eqzero(e) - 1;
  for (i = 0; i < ml; i++)
    a[i] &= e;
}

size_t
assh_bignum_mt_to_sc_size(const struct assh_bignum_s *r,
                          const struct assh_bignum_s *a)
{
  if (r == a)
    return assh_bignum_words(a->bits);
  return 0;
}

void
assh_bignum_mt_to(struct assh_context_s *ctx,
                  assh_bnword_t *s,
                  const struct assh_bignum_mt_s *mt,
                  struct assh_bignum_s *r,
                  const struct assh_bignum_s *a)
{
  assert(mt->mod.bits == a->bits && mt->mod.bits == r->bits);
  size_t ml = assh_bignum_words(mt->mod.bits);
  assh_bnword_t *t = r->n;

  if (r == a)
    t = s;

  assh_bnword_t *r2 = (assh_bnword_t*)mt->mod.n + ml;
  assh_bignum_mt_mul(mt, t, r2, a->n);

  if (r == a)
    memcpy(r->n, t, ml * sizeof(assh_bnword_t));
}

size_t
assh_bignum_mt_from_sc_size(const struct assh_bignum_s *r,
                            const struct assh_bignum_s *a)
{
  if (r == a)
    return assh_bignum_words(a->bits);
  return 0;
}

void
assh_bignum_mt_from(struct assh_context_s *ctx,
                    assh_bnword_t *s,
                    const struct assh_bignum_mt_s *mt,
                    struct assh_bignum_s *r,
                    const struct assh_bignum_s *a)
{
  assert(mt->mod.bits == a->bits && mt->mod.bits == r->bits);
  size_t ml = assh_bignum_words(mt->mod.bits);
  assh_bnword_t *t = r->n;

  if (r == a)
    t = s;

  assh_bignum_mt_reduce(mt, t, a->n);

  if (r == a)
    memcpy(r->n, t, ml * sizeof(assh_bnword_t));
}

size_t
assh_bignum_mul_mod_mt_sc_size(const struct assh_bignum_s *r,
                               const struct assh_bignum_s *a,
                               const struct assh_bignum_s *b)
{
  if (r == a || r == b)
    return assh_bignum_words(r->bits);
  return 0;
}

assh_error_t
assh_bignum_mul_mod_mt(struct assh_context_s *ctx,
                       assh_bnword_t *s,
                       struct assh_bignum_s *r,
                       const struct assh_bignum_s *a,
                       const struct assh_bignum_s *b,
                       const struct assh_bignum_mt_s *mt)
{
  assh_error_t err = ASSH_OK;

  assert(mt->mod.bits == a->bits &&
         mt->mod.bits == b->bits &&
         mt->mod.bits == r->bits);

  size_t rl = assh_bignum_words(r->bits);

  if (r == a || r == b)
    {
      assh_bignum_mt_mul(mt, s, a->n, b->n);
      memcpy(r->n, s, rl * sizeof(assh_bnword_t));
    }
  else
    {
      assh_bignum_mt_mul(mt, r->n, a->n, b->n);
    }

  return err;
}

size_t
assh_bignum_expmod_mt_sc_size(const struct assh_bignum_mt_s *mt)
{
  return assh_bignum_words(mt->max_bits) * 2;
}

assh_error_t
assh_bignum_expmod_mt(struct assh_context_s *ctx,
                      assh_bnword_t *sq,
                      struct assh_bignum_s *r,
                      const struct assh_bignum_s *a,
                      const struct assh_bignum_s *b,
                      const struct assh_bignum_mt_s *mt)
{
  assh_error_t err;

  assert(r != b);
  assert(mt->mod.bits == a->bits &&
         mt->mod.bits == r->bits);

  size_t ml = assh_bignum_words(mt->mod.bits);


  assh_bnword_t *tmp = sq + ml;
  assh_bnword_t *bn = b->n;
  assh_bnword_t *rn = r->n;
  uint_fast32_t i = 0, j = assh_bignum_bitlen(b);

  memcpy(sq, a->n, ml * sizeof(assh_bnword_t));
  if (!j)
    return ASSH_OK;

  assh_bnword_t *r1 = (assh_bnword_t*)mt->mod.n + 2 * ml;
  memcpy(rn, r1, ml * sizeof(assh_bnword_t));

  while (1)
    {
      /* constant time when exponent is secret */
      assh_bool_t c = (bn[i / ASSH_BIGNUM_W] >> (i % ASSH_BIGNUM_W)) & 1;
      volatile assh_bool_t d = b->secret | c;

      if (d)
        {
          assh_bignum_mt_mul(mt, tmp, rn, sq);
          assh_bignum_cmove(rn, tmp, ml, c);
        }

      if (++i == j)
        break;

      assh_bignum_mt_mul(mt, tmp, sq, sq);
      memcpy(sq, tmp, ml * sizeof(assh_bnword_t));
    }

  return ASSH_OK;
}

size_t
assh_bignum_modinv_mt_sc_size(const struct assh_bignum_mt_s *mt)
{
  return assh_bignum_words(mt->max_bits) * 2;
}

/* compute inverse using the Fermat little theorem */
assh_error_t
assh_bignum_modinv_mt(struct assh_context_s *ctx,
                      assh_bnword_t *sq,
                      struct assh_bignum_s *r,
                      const struct assh_bignum_s *a,
                      const struct assh_bignum_mt_s *mt)
{
  assh_error_t err;

  assert(mt->mod.bits == a->bits &&
         mt->mod.bits == r->bits);

  size_t ml = assh_bignum_words(mt->mod.bits);

  assh_bnword_t *tmp = sq + ml;
  uint_fast32_t i = 0;
  assh_bnword_t *rn = r->n;

  /* prime modulus - 2 */
  assh_bnword_t p = 0, *pn = mt->mod.n;
  assh_bnslong_t t = (assh_bnslong_t)-2 << ASSH_BIGNUM_W;

  memcpy(sq, a->n, ml * sizeof(assh_bnword_t));

  assh_bnword_t *r1 = (assh_bnword_t*)mt->mod.n + 2 * ml;
  memcpy(rn, r1, ml * sizeof(assh_bnword_t));

  while (1)
    {
      if (i % ASSH_BIGNUM_W == 0)
        p = t = (assh_bnslong_t)pn[i / ASSH_BIGNUM_W] + (t >> ASSH_BIGNUM_W);

      assh_bool_t c = (p >> (i % ASSH_BIGNUM_W)) & 1;
      volatile assh_bool_t d = mt->mod.secret | c;

      if (d)
        {
          assh_bignum_mt_mul(mt, tmp, rn, sq);
          assh_bignum_cmove(rn, tmp, ml, c);
        }

      if (++i == mt->mod.bits)
        break;

      assh_bignum_mt_mul(mt, tmp, sq, sq);
      memcpy(sq, tmp, ml * sizeof(assh_bnword_t));
    }

  return ASSH_OK;
}

