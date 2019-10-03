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


static inline int_fast32_t
assh_bignum_div_cmp(const assh_bnword_t *a, uint_fast32_t alen,
                    const assh_bnword_t *b, uint_fast32_t blen)
{
  if (alen != blen)
    return blen - alen;

  int_fast32_t i;
  for (i = blen - 1; i >= 0; i--)
    {
      if (a[i] < b[i])
	return 1;
      if (a[i] > b[i])
	return -1;
    }

  return 0;
}

/** reduce size to strip leading nul words */
static inline assh_bool_t
assh_bignum_div_strip(uint_fast32_t *len, const assh_bnword_t *x)
{
  while (*len > 0 && x[*len - 1] == 0)
    (*len)--;
  return (*len == 0);
}

/** find number of leading zero bits and get a word full of msb significant bits */
static inline void
assh_bignum_div_clz(uint_fast32_t len, const assh_bnword_t *x,
                    uint_fast32_t *z, uint_fast32_t *l, assh_bnword_t *t)
{
  *z = assh_bn_clz(x[len - 1]);
  *l = ASSH_BIGNUM_W - *z + (len - 1) * ASSH_BIGNUM_W;

  *t = (x[len - 1] << *z);
  if (len > 1)
    *t |= ((assh_bnlong_t)x[len - 2] >> (ASSH_BIGNUM_W - *z));  
}

/** find suitable factor and left shift amount for subtraction of the divisor */
static inline assh_bnword_t
assh_bignum_div_factor(assh_bnword_t at, assh_bnword_t bt,
                       uint_fast32_t d, uint_fast32_t *sa, uint_fast32_t *da)
{
  assh_bnword_t bi = bt + 1;
  if (bi != 0)
    bt = bi;

  assh_bnword_t q = ((assh_bnlong_t)(at - 1) << (ASSH_BIGNUM_W - 1)) / bt;

  if (d < (ASSH_BIGNUM_W - 1))
    {
      q >>= (ASSH_BIGNUM_W - 1) - d;
      *da = *sa = 0;
    }
  else
    {
      *da = (d - (ASSH_BIGNUM_W - 1)) / ASSH_BIGNUM_W;
      *sa = (d - (ASSH_BIGNUM_W - 1)) % ASSH_BIGNUM_W;
    }

  return q ? q : 1;
}

/** compute r = r - (b << (sa + da * W)) * q */
static inline void
assh_bignum_div_update_r(uint_fast32_t b_len, const assh_bnword_t * __restrict__ b,
                         uint_fast32_t r_len, assh_bnword_t * __restrict__ r,
                         assh_bnword_t q, uint_fast32_t sa, uint_fast32_t da)
{
  assh_bnlong_t t = (assh_bnlong_t)1 << ASSH_BIGNUM_W;
  assh_bnlong_t m = 0;
  assh_bnword_t bo = 0;
  uint_fast32_t i;

  assert(b_len + da <= r_len);

  for (i = 0; i < b_len; i++)
    {
      assh_bnword_t bi = b[i];
      m = (assh_bnword_t)((bi << sa) | ((assh_bnlong_t)bo >> (ASSH_BIGNUM_W - sa)))
	* (assh_bnlong_t)q + (m >> ASSH_BIGNUM_W);
      r[i + da] = t = (assh_bnlong_t)r[i + da]
	+ (assh_bnword_t)~m + (t >> ASSH_BIGNUM_W);
      bo = bi;
    }
  for (; i < r_len - da; i++)
    {
      m = ((assh_bnlong_t)bo >> (ASSH_BIGNUM_W - sa)) * q + (m >> ASSH_BIGNUM_W);
      r[i + da] = t = (assh_bnlong_t)r[i + da]
	+ (assh_bnword_t)~m + (t >> ASSH_BIGNUM_W);
      bo = 0;
    }
}

/** compute d = d + q << (sa + da * W) */
static inline void
assh_bignum_div_update_q(uint_fast32_t d_len, assh_bnword_t * __restrict__ d,
                         assh_bnword_t q, uint_fast32_t sa, uint_fast32_t da)
{
  assh_bnlong_t t, carry = (assh_bnlong_t)q << sa;
  uint_fast32_t i;
  for (i = da; carry != 0 && i < d_len; i++)
    {
      d[i] = t = (assh_bnlong_t)d[i] + carry;
      carry = t >> ASSH_BIGNUM_W;
    }
}

static assh_status_t
assh_bignum_div_euclidean_vt(assh_bnword_t * __restrict__ r,
                             uint_fast32_t r_len,
                             assh_bnword_t * __restrict__ d,
                             uint_fast32_t d_len,
                             const assh_bnword_t * __restrict__ b,
                             uint_fast32_t b_len)
{
  assh_status_t err;
  uint_fast32_t az, al, bz, bl, da, sa;
  assh_bnword_t at, bt, q;

  /* div by zero */
  ASSH_RET_IF_TRUE(assh_bignum_div_strip(&b_len, b), ASSH_ERR_NUM_OVERFLOW);

  assh_bignum_div_clz(b_len, b, &bz, &bl, &bt);

  while (1)
    {
      /* skip leading zero words */
      if (assh_bignum_div_strip(&r_len, r))
	break;

      assh_bignum_div_clz(r_len, r, &az, &al, &at);

      /* test for termination by compairing the remainder and the divisor */
      if (assh_bignum_div_cmp(r, r_len, b, b_len) > 0)
	break;

      /* find factor */
      q = assh_bignum_div_factor(at, bt, al - bl, &sa, &da);

      /* update the remainder */
      assh_bignum_div_update_r(b_len, b, r_len, r, q, sa, da);

      /* update the quotient */
      if (d != NULL)
	assh_bignum_div_update_q(d_len, d, q, sa, da);
    }

  return ASSH_OK;
}

static void
assh_bignum_div_euclidean_ct(assh_bnword_t * __restrict__ rn,
                             uint_fast32_t r_len,
                             assh_bnword_t * __restrict__ dn,
                             uint_fast32_t d_len,
                             const assh_bnword_t * __restrict__ bn,
                             uint_fast32_t b_len, int_fast32_t bitlen_diff)
{
  assh_bnword_t s = 0;
  assh_bnlong_t t;
  uint_fast32_t i, k;

  if (bitlen_diff < 0)
    return;

  /* This is a constant time euclidean division algorithm which shifts
     the divisor by a single bit per iteration. It works by always
     subtracting the divisor then correcting the remainder on the next
     iteration if it became negative. */

  for (k = bitlen_diff + 1; k--; )
    {
      /* if r >= 0
          r = r - (b << k)
        else
          r = r + (b << k) */

      s = ~s;    /* chose add or sub depending on the sign of last result */

      t = (assh_bnlong_t)(s & 1) << ASSH_BIGNUM_W;
      uint_fast32_t j = k / ASSH_BIGNUM_W;
      assh_bnword_t o = 0;

      for (i = 0; i < b_len; i++, j++)
        {
          assh_bnword_t x = bn[i];
          assh_bnword_t b = ((assh_bnlong_t)x << (k % ASSH_BIGNUM_W)) |
                             (assh_bnlong_t)o >> (ASSH_BIGNUM_W - k % ASSH_BIGNUM_W);
          rn[j] = t = (assh_bnlong_t)rn[j] + (b ^ s) + (t >> ASSH_BIGNUM_W);
          o = x;
        }

      o = (assh_bnlong_t)o >> (ASSH_BIGNUM_W - k % ASSH_BIGNUM_W);
      for (; j < r_len; j++)
        {
          rn[j] = t = (assh_bnlong_t)rn[j] + (o ^ s) + (t >> ASSH_BIGNUM_W);
          o = 0;
        }

      /* sign of r */
      s = (t >> ASSH_BIGNUM_W) - 1;

      /* update the quotient */
      if (dn)
        dn[k / ASSH_BIGNUM_W] |= ((s + 1) << (k % ASSH_BIGNUM_W));
    }

  /* perform final correction
     if r < 0
       r = r + b */
  t = 0;
  for (i = 0; i < b_len; i++)
    rn[i] = t = (assh_bnlong_t)rn[i] + (bn[i] & s) + (t >> ASSH_BIGNUM_W);
  for (; i < r_len; i++)
    rn[i] = t = (assh_bnlong_t)rn[i] + (t >> ASSH_BIGNUM_W);
}

assh_status_t
assh_bignum_div_euclidean(assh_bnword_t * __restrict__ rn,
                          uint_fast32_t r_len,
                          assh_bnword_t * __restrict__ dn,
                          uint_fast32_t d_len,
                          const assh_bnword_t * __restrict__ bn,
                          uint_fast32_t b_len,
                          assh_bool_t secret, int_fast32_t bitlen_diff)
{
  assh_status_t err;

  if (!secret)
    ASSH_RET_ON_ERR(assh_bignum_div_euclidean_vt(rn, r_len, dn, d_len, bn, b_len));
  else
    assh_bignum_div_euclidean_ct(rn, r_len, dn, d_len, bn, b_len, bitlen_diff);

  return ASSH_OK;
}

size_t
assh_bignum_div_sc_size(const struct assh_bignum_s *r,
                        const struct assh_bignum_s *a)
{
  if (r != NULL && r->bits >= a->bits)
    return 0;
  return assh_bignum_words(a->bits);
}

assh_status_t
assh_bignum_div(struct assh_context_s *ctx,
                assh_bnword_t *s,
                struct assh_bignum_s *r,
                struct assh_bignum_s *d,
                const struct assh_bignum_s *a,
                const struct assh_bignum_s *b)
{
  assh_status_t err;

  assert(r != d && a != d && b != d && b != r);
  assert(a->bits >= b->bits);
  assert(d == NULL || d->bits >= a->bits);

  size_t al = assh_bignum_words(a->bits);
  size_t bl = assh_bignum_words(b->bits);
  assh_bnword_t *dn = NULL, *rn;
  size_t rl;

  if (r != NULL && r->bits >= a->bits)
    {
      rl = assh_bignum_words(r->bits);
      rn = r->n;
    }
  else
    {
      rl = al;
      rn = s;
    }

  if (a->n != rn)
    {
      memcpy(rn, a->n, al * sizeof(assh_bnword_t));
      memset((assh_bnword_t*)rn + al, 0, (rl - al) * sizeof(assh_bnword_t));
    }

  size_t dl = 0;
  if (d != NULL)
    {
      dl = assh_bignum_words(d->bits);
      dn = d->n;
      memset(dn, 0, dl * sizeof(assh_bnword_t));
    }

  ASSH_RET_ON_ERR(assh_bignum_div_euclidean(rn, rl, dn, dl, b->n, bl,
                                         a->secret || b->secret,
                                         a->bits - assh_bignum_bitlen(b)));

  if (r != NULL && r->bits < a->bits)
    memcpy(r->n, rn, assh_bignum_words(r->bits) * sizeof(assh_bnword_t));

  return ASSH_OK;
}

size_t
assh_bignum_modinv_sc_size(const struct assh_bignum_s *m)
{
  return assh_bignum_words(m->bits) * 3;
}

assh_status_t
assh_bignum_modinv(struct assh_context_s *ctx,
                   assh_bnword_t *r,
                   struct assh_bignum_s *u,
                   const struct assh_bignum_s *a,
                   const struct assh_bignum_s *m)
{
  assh_status_t err;

  assert(u != a && u != m);
  assert(!a->secret && !m->secret);
  assert(a->bits <= m->bits);
  assert(u->bits >= a->bits);

  size_t ul = assh_bignum_words(u->bits);
  size_t al = assh_bignum_words(a->bits);
  size_t ml = assh_bignum_words(m->bits);

  assh_bnword_t * __restrict__ un = u->n;
  const assh_bnword_t * __restrict__ an = a->n;
  const assh_bnword_t * __restrict__ mn = m->n;

  assh_bnword_t *p = r + ml;
  assh_bnword_t *v = r + ml * 2;

  memcpy(r, mn, ml * sizeof(assh_bnword_t));
  memcpy(p, an, al * sizeof(assh_bnword_t));
  memset(p + al, 0, (ml - al) * sizeof(assh_bnword_t));

  ASSH_RET_ON_ERR(assh_bignum_div_euclidean_vt(p, al, NULL, 0, r, ml));

  memset(v, 0, ml * sizeof(assh_bnword_t));
  memset(un + 1, 0, (ul - 1) * sizeof(assh_bnword_t));
  un[0] = 1;

  uint_fast32_t rl = ml, pl = ml;
  assh_bnword_t *xr = r, *xp = p, *xu = un, *xv = v;

  ASSH_RET_IF_TRUE(assh_bignum_div_strip(&rl, xr) ||
	       assh_bignum_div_strip(&pl, xp) ||
	       rl < pl, ASSH_ERR_NUM_OVERFLOW);

  while (1)
    {
      uint_fast32_t az, as, bz, bs, da, sa;
      assh_bnword_t at, bt, q;

      /* find factor */
      assh_bignum_div_clz(rl, xr, &az, &as, &at);
      assh_bignum_div_clz(pl, xp, &bz, &bs, &bt);
      ASSH_RET_IF_TRUE(as < bs, ASSH_ERR_NUM_OVERFLOW);

      q = assh_bignum_div_factor(at, bt, as - bs, &sa, &da);

      assh_bignum_div_update_r(pl, xp, rl, xr, q, sa, da);

      /* skip leading zero words */
      if (assh_bignum_div_strip(&rl, xr))
	break;

      assh_bignum_div_update_r(ml - da, xu, ml, xv, q, sa, da);

      if (assh_bignum_div_cmp(xr, rl, xp, pl) > 0)
	{
	  ASSH_SWAP(rl, pl);
	  ASSH_SWAP(xr, xp);
	  ASSH_SWAP(xu, xv);
	}
    }

  return ASSH_OK;
}

size_t
assh_bignum_gcd_sc_size(const struct assh_bignum_s *a,
                        const struct assh_bignum_s *b)
{
  size_t al = assh_bignum_words(a->bits);
  size_t bl = assh_bignum_words(b->bits);
  return al > bl ? al : bl;
}

assh_status_t
assh_bignum_gcd(struct assh_context_s *ctx,
                assh_bnword_t *s,
                struct assh_bignum_s *g,
                const struct assh_bignum_s *a,
                const struct assh_bignum_s *b)
{
  assh_status_t err;

  assert(g != a && g != b);
  assert(g->bits >= a->bits || g->bits >= b->bits);
  assert(!a->secret && !b->secret);

  size_t al = assh_bignum_words(a->bits);
  size_t bl = assh_bignum_words(b->bits);

  assh_bnword_t * __restrict__ gn = g->n;
  const assh_bnword_t * __restrict__ an = a->n;
  const assh_bnword_t * __restrict__ bn = b->n;

  assh_bnword_t *xr = s;
  assh_bnword_t *xp = gn;

  /* use largest buffer between scratch and result for the largest
     input number, the gcd value will be available in both buffers
     at the end */
  if (al < bl)
    ASSH_SWAP(xr, xp);

  memmove(xr, an, al * sizeof(assh_bnword_t));
  memmove(xp, bn, bl * sizeof(assh_bnword_t));

  uint_fast32_t rl = al, pl = al;

  ASSH_RET_IF_TRUE(assh_bignum_div_strip(&rl, xr) ||
	       assh_bignum_div_strip(&pl, xp),
               ASSH_ERR_NUM_OVERFLOW);

  while (1)
    {
      uint_fast32_t az, al, bz, bl, da, sa;
      assh_bnword_t at, bt, q;

      int8_t c = assh_bignum_div_cmp(xr, rl, xp, pl);
      if (c == 0)
        break;
      if (c > 0)
	{
	  ASSH_SWAP(rl, pl);
	  ASSH_SWAP(xr, xp);
	}

      assh_bignum_div_clz(rl, xr, &az, &al, &at);
      assh_bignum_div_clz(pl, xp, &bz, &bl, &bt);
      ASSH_RET_IF_TRUE(al < bl, ASSH_ERR_NUM_OVERFLOW);

      q = assh_bignum_div_factor(at, bt, al - bl, &sa, &da);

      assh_bignum_div_update_r(pl, xp, rl, xr, q, sa, da);

      ASSH_RET_IF_TRUE(assh_bignum_div_strip(&rl, xr),
                   ASSH_ERR_NUM_OVERFLOW);
    }

  return ASSH_OK;
}

