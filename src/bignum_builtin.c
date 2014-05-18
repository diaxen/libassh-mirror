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

#include <assh/assh_bignum.h>
#include <assh/assh_context.h>
#include <assh/assh_packet.h>
#include <assh/assh_prng.h>

#include <string.h>
#include <stdio.h>

static inline int assh_clz(assh_bnword_t x)
{
  if (sizeof(x) <= sizeof(unsigned int))
    return __builtin_clz(x) + ASSH_BIGNUM_W - sizeof(unsigned int) * 8;
  else if (sizeof(x) <= sizeof(unsigned long))
    return __builtin_clzl(x) + ASSH_BIGNUM_W - sizeof(unsigned long) * 8;
  else if (sizeof(x) <= sizeof(unsigned long long))
    return __builtin_clzll(x) + ASSH_BIGNUM_W - sizeof(unsigned long long) * 8;
}

/********************************************************* init and convert */

assh_error_t assh_bignum_from_uint(struct assh_bignum_s *n,
				   unsigned int x)
{
  unsigned int i;
  assh_error_t err;

  for (i = 0; i < n->l; i++)
    {
      n->n[i] = x;
      x = (ASSH_BIGNUM_W < sizeof(x) * 8) ? x >> ASSH_BIGNUM_W : 0;
    }

  ASSH_CHK_RET(x != 0, ASSH_ERR_NUM_OVERFLOW);
  return ASSH_OK;
}

assh_error_t assh_bignum_rand(struct assh_context_s *c,
			      struct assh_bignum_s *n,
			      enum assh_prng_quality_e quality)
{
  return c->prng->f_get(c, (uint8_t*)n->n, n->l * sizeof(assh_bnword_t), quality);
}

assh_error_t assh_bignum_from_data(struct assh_bignum_s *bn,
                                   const uint8_t * __restrict__ data, size_t data_len)
{
  assh_error_t err;
  int i, j;

  const uint8_t *e = data + data_len - 1;

  for (i = 0; i < bn->l; i++)
    {
      assh_bnword_t x = 0;
      for (j = 0; j < ASSH_BIGNUM_W && e >= data; j += 8)
	x |= (assh_bnword_t)*e-- << j;
      bn->n[i] = x;
    }

  ASSH_CHK_RET(e >= data, ASSH_ERR_OUTPUT_OVERFLOW);
  return ASSH_OK;
}

assh_error_t assh_bignum_msb_to_data(const struct assh_bignum_s *bn,
                                     uint8_t * __restrict__ data, size_t data_len)
{
  assh_error_t err;

  ASSH_CHK_RET(bn->l * sizeof(assh_bnword_t) < data_len, ASSH_ERR_OUTPUT_OVERFLOW);

  int i;
  for (i = 0; i < data_len; i++)
    data[i] = bn->n[bn->l - 1 - i / sizeof(assh_bnword_t)]
      >> ((sizeof(assh_bnword_t) - 1 - i % sizeof(assh_bnword_t)) * 8);

  return ASSH_OK;
}

assh_error_t assh_bignum_to_mpint(const struct assh_bignum_s *bn,
                                  uint8_t * __restrict__ mpint)
{
  int i, j;
  uint8_t *m = mpint + 4, *p = m;

  for (i = bn->l - 1; i >= 0; i--)
    for (j = ASSH_BIGNUM_W - 8; j >= 0; j -= 8)
      {
	uint8_t b = bn->n[i] >> j;
	if (p == m)
	  {
	    if (!b)
	      continue;
	    if (b & 0x80)
	      *p++ = 0;
	  }
	  *p++ = b;
      }

  assh_store_u32(mpint, p - m);
  return ASSH_OK;
}

size_t assh_bignum_mpint_size(const struct assh_bignum_s *bn)
{
  int l = bn->l;
  while (l > 1 && !bn->n[l - 1])
    l--;
  return 4 + l * sizeof(assh_bnword_t) /* extra zero byte */ + 1;
}

assh_error_t assh_bignum_copy(struct assh_bignum_s *a,
			      const struct assh_bignum_s *b)
{
  assh_error_t err;
  int i, l = ASSH_MIN(a->l, b->l);

  for (i = 0; i < l; i++)
    a->n[i] = b->n[i];
  for (; i < a->l; i++)
    a->n[i] = 0;
  for (; i < b->l; i++)
    ASSH_CHK_RET(b->n[i] != 0, ASSH_ERR_OUTPUT_OVERFLOW);

  return ASSH_OK;
}

static void assh_bignum_print_raw(FILE *out, const char *name,
				  const assh_bnword_t *n, unsigned int len)
{
  int i, j;

  if (name != NULL)
    fprintf(out, "%s: ", name);
  for (i = 0; i < len; i++)
    {
      assh_bnword_t x = n[len - i - 1];
      for (j = ASSH_BIGNUM_W - 4; j >= 0; j -= 4)
	fputc("0123456789ABCDEF"[(x >> j) & 0xf], out);
    }
  if (name != NULL)
    fputc('\n', out);
}

void assh_bignum_print(FILE *out, const char *name,
		       const struct assh_bignum_s *bn)
{
  assh_bignum_print_raw(out, name, bn->n, bn->l);
}

/************************************************************ cmp, add, sub */

static inline int assh_bignum_cmp_raw(const assh_bnword_t *a, unsigned int alen,
				      const assh_bnword_t *b, unsigned int blen)
{
  if (alen != blen)
    return blen - alen;

  int i;
  for (i = blen - 1; i >= 0; i--)
    {
      if (a[i] < b[i])
	return 1;
      if (a[i] > b[i])
	return -1;
    }

  return 0;
}

int assh_bignum_cmp(const struct assh_bignum_s *a,
		    const struct assh_bignum_s *b)
{
  unsigned int a_len = a->l;
  unsigned int b_len = b->l;

  /* skip leading nul words */
  while (a_len > 0 && a->n[a_len - 1] == 0)
    a_len--;
  while (b_len > 0 && b->n[b_len - 1] == 0)
    b_len--;

  return assh_bignum_cmp_raw(a->n, a_len, b->n, b_len);
}

assh_bool_t assh_bignum_cmpz(const struct assh_bignum_s *a)
{
  unsigned int a_len = a->l;
  assh_bnword_t r = 0;

  while (a_len--)
    r |= a->n[a_len];

  return r == 0;
}

int assh_bignum_cmp_uint(const struct assh_bignum_s *a,
                         unsigned int x)
{
  unsigned int a_len = a->l;

  while (a_len > 0 && a->n[a_len - 1] == 0)
    a_len--;

  unsigned int b_len = 0;
  assh_bnword_t b[sizeof(x) / sizeof(assh_bnword_t) + 1];

  while (x)
    {
      b[b_len++] = x;
      if (sizeof(x) <= sizeof(assh_bnword_t))
        break;
      x = (uint64_t)x >> ASSH_BIGNUM_W;
    }

  return assh_bignum_cmp_raw(a->n, a_len, b, b_len);
}

assh_error_t assh_bignum_add(struct assh_bignum_s *r,
			     const struct assh_bignum_s *a,
			     const struct assh_bignum_s *b)
{
  assh_error_t err;
  unsigned int i;
  assh_bnlong_t t = 0;

  ASSH_CHK_RET(r->l < ASSH_MAX(a->l, b->l), ASSH_ERR_OUTPUT_OVERFLOW);

  if (a->l < b->l)
    ASSH_SWAP(a, b);

  for (i = 0; i < b->l; i++)
    r->n[i] = t = (assh_bnlong_t)a->n[i] + b->n[i] + (t >> ASSH_BIGNUM_W);
  for (; i < a->l; i++)
    r->n[i] = t = (assh_bnlong_t)a->n[i] + (t >> ASSH_BIGNUM_W);
  for (; i < r->l; i++)
    r->n[i] = t = (t >> ASSH_BIGNUM_W);

  ASSH_CHK_RET(t >> ASSH_BIGNUM_W, ASSH_ERR_NUM_OVERFLOW);
  return ASSH_OK;
}

assh_error_t assh_bignum_sub(struct assh_bignum_s *r,
			     const struct assh_bignum_s *a,
			     const struct assh_bignum_s *b)
{
  assh_error_t err;
  unsigned int i;
  assh_bnlong_t t = (assh_bnlong_t)1 << ASSH_BIGNUM_W;
  assh_bnword_t bmask = (assh_bnword_t)(a->l < b->l) - 1;
  assh_bnword_t amask = ~bmask;

  ASSH_CHK_RET(r->l < ASSH_MAX(a->l, b->l), ASSH_ERR_OUTPUT_OVERFLOW);

  if (amask)
    ASSH_SWAP(a, b);

  for (i = 0; i < b->l; i++)
    r->n[i] = t = (assh_bnlong_t)(a->n[i] ^ amask) + (b->n[i] ^ bmask) + (t >> ASSH_BIGNUM_W);
  for (; i < a->l; i++)
    r->n[i] = t = (assh_bnlong_t)(a->n[i] ^ amask) + bmask + (t >> ASSH_BIGNUM_W);
  for (; i < r->l; i++)
    r->n[i] = t = (t >> ASSH_BIGNUM_W);

  ASSH_CHK_RET(t >> ASSH_BIGNUM_W != 1, ASSH_ERR_NUM_OVERFLOW);
  return ASSH_OK;
}

/*********************************************************************** div, modinv */

/** reduce size to strip leading nul words */
static inline assh_bool_t assh_bignum_div_strip(unsigned int *len, const assh_bnword_t *x)
{
  while (*len > 0 && x[*len - 1] == 0)
    (*len)--;
  return (*len == 0);
}

/** find number of leading zero bits and get a word full of msb significant bits */
static inline void assh_bignum_div_clz(unsigned int len, const assh_bnword_t *x,
				       unsigned int *z, unsigned int *l, assh_bnword_t *t)
{
  *z = assh_clz(x[len - 1]);
  *l = ASSH_BIGNUM_W - *z + (len - 1) * ASSH_BIGNUM_W;

  *t = (x[len - 1] << *z);
  if (len > 1)
    *t |= ((assh_bnlong_t)x[len - 2] >> (ASSH_BIGNUM_W - *z));  
}

/** find suitable factor and left shift amount for subtraction of the divisor */
static inline assh_bnword_t assh_bignum_div_factor(assh_bnword_t at, assh_bnword_t bt,
							unsigned int d, unsigned int *sa, unsigned int *da)
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
static inline void assh_bignum_div_update_r(unsigned int b_len, const assh_bnword_t * __restrict__ b,
					    unsigned int r_len, assh_bnword_t * __restrict__ r,
					    assh_bnword_t q, unsigned int sa, unsigned int da)
{
  assh_bnlong_t t = (assh_bnlong_t)1 << ASSH_BIGNUM_W;
  assh_bnlong_t m = 0;
  assh_bnword_t bo = 0;
  unsigned int i;

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
static inline void assh_bignum_div_update_q(unsigned int d_len, assh_bnword_t * __restrict__ d,
					    assh_bnword_t q, unsigned int sa, unsigned int da)
{
  assh_bnlong_t t, carry = (assh_bnlong_t)q << sa;
  unsigned int i;
  for (i = da; carry != 0 && i < d_len; i++)
    {
      d[i] = t = (assh_bnlong_t)d[i] + carry;
      carry = t >> ASSH_BIGNUM_W;
    }
}

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_div_euclidean(assh_bnword_t * __restrict__ r,
                          unsigned int r_len,
                          assh_bnword_t * __restrict__ d,
                          unsigned int d_len,
                          const assh_bnword_t * __restrict__ b,
                          unsigned int b_len)
{
  assh_error_t err;
  unsigned int az, al, bz, bl, da, sa;
  assh_bnword_t at, bt, q;

  /* div by zero */
  ASSH_CHK_RET(assh_bignum_div_strip(&b_len, b), ASSH_ERR_NUM_OVERFLOW);

  assh_bignum_div_clz(b_len, b, &bz, &bl, &bt);

#ifdef CONFIG_ASSH_DEBUG_BIGNUM_DIV
  fprintf(stderr, "\n");
  assh_bignum_print_raw(stderr, "b", b, b_len);
#endif

  while (1)
    {
      /* skip leading zero words */
      if (assh_bignum_div_strip(&r_len, r))
	break;

#ifdef CONFIG_ASSH_DEBUG_BIGNUM_DIV
      assh_bignum_print_raw(stderr, "r", r, r_len);
#endif

      assh_bignum_div_clz(r_len, r, &az, &al, &at);

      /* test for termination by compairing the remainder and the divisor */
      if (assh_bignum_cmp_raw(r, r_len, b, b_len) > 0)
	break;

      /* find factor */
      q = assh_bignum_div_factor(at, bt, al - bl, &sa, &da);

#ifdef CONFIG_ASSH_DEBUG_BIGNUM_DIV
      fprintf(stderr, "at=%X bt=%X d=%u sa=%u da=%u q=%X\n", at, bt, al - bl, sa, da, q);
#endif

      /* update the remainder */
      assh_bignum_div_update_r(b_len, b, r_len, r, q, sa, da);

      /* update the quotient */
      if (d != NULL)
	assh_bignum_div_update_q(d_len, d, q, sa, da);
    }

  return ASSH_OK;
}

assh_error_t assh_bignum_div(struct assh_bignum_s *r,
			     struct assh_bignum_s *d,
			     const struct assh_bignum_s *a,
			     const struct assh_bignum_s *b)
{
  assh_error_t err;

  assert(r != d && a != d && b != d && b != r);

  ASSH_CHK_RET(a->l < b->l, ASSH_ERR_OUTPUT_OVERFLOW);
  ASSH_CHK_RET(r->l < a->l, ASSH_ERR_OUTPUT_OVERFLOW);
  if (d != NULL)
    ASSH_CHK_RET(d->l < a->l, ASSH_ERR_OUTPUT_OVERFLOW);

  if (a != r)
    {
      memcpy(r->n, a->n, a->l * sizeof(assh_bnword_t));
      memset(r->n + a->l, 0, (r->l - a->l) * sizeof(assh_bnword_t));
    }

  assh_bnword_t *dn = NULL;
  unsigned int d_len = 0;
  if (d != NULL)
    memset(dn = d->n, 0, (d_len = d->l) * sizeof(assh_bnword_t));

  return assh_bignum_div_euclidean(r->n, r->l, dn, d_len, b->n, b->l);
}

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_modinv_euclidean(assh_bnword_t * __restrict__ u,
                             unsigned int u_len,
                             const assh_bnword_t * __restrict__ a,
                             unsigned int a_len,
                             const assh_bnword_t * __restrict__ b,
                             unsigned int b_len, assh_bnword_t *scratch)
{
  assh_error_t err;

#define ASSH_MODINV_SCRATCH(len) (len * 3)

  assh_bnword_t *r = scratch;
  assh_bnword_t *p = scratch + a_len;
  assh_bnword_t *v = scratch + a_len * 2;

  memcpy(r, a, a_len * sizeof(assh_bnword_t));
  memcpy(p, b, b_len * sizeof(assh_bnword_t));
  memset(p + b_len, 0, (a_len - b_len) * sizeof(assh_bnword_t));

  memset(v, 0, a_len * sizeof(assh_bnword_t));
  memset(u + 1, 0, (u_len - 1) * sizeof(assh_bnword_t));
  u[0] = 1;

  unsigned int r_len = a_len, p_len = a_len;
  assh_bnword_t *xr = r, *xp = p, *xu = u, *xv = v;

  ASSH_CHK_RET(assh_bignum_div_strip(&r_len, xr) ||
	       assh_bignum_div_strip(&p_len, xp) ||
	       r_len < p_len, ASSH_ERR_NUM_OVERFLOW);

  while (1)
    {
      unsigned int az, al, bz, bl, da, sa;
      assh_bnword_t at, bt, q;

#ifdef CONFIG_ASSH_DEBUG_BIGNUM_MODINV
      fprintf(stderr, "\n");
      assh_bignum_print_raw(stderr, "r", xr, r_len);
      assh_bignum_print_raw(stderr, "p", xp, p_len);
      assh_bignum_print_raw(stderr, "u", xu, u_len);
      assh_bignum_print_raw(stderr, "v", xv, u_len);
#endif

      /* find factor */
      assh_bignum_div_clz(r_len, xr, &az, &al, &at);
      assh_bignum_div_clz(p_len, xp, &bz, &bl, &bt);
      ASSH_CHK_RET(al < bl, ASSH_ERR_NUM_OVERFLOW);

      q = assh_bignum_div_factor(at, bt, al - bl, &sa, &da);

#ifdef CONFIG_ASSH_DEBUG_BIGNUM_MODINV
      fprintf(stderr, "plen=%u rlen=%u a_len=%u al=%u bl=%u da=%u sa=%u q=%X\n",
              p_len, r_len, a_len, al, bl, da, sa, q);
#endif

      assh_bignum_div_update_r(p_len, xp, r_len, xr, q, sa, da);

      /* skip leading zero words */
      if (assh_bignum_div_strip(&r_len, xr))
	break;

      assh_bignum_div_update_r(a_len - da, xu, a_len, xv, q, sa, da);

      if (assh_bignum_cmp_raw(xr, r_len, xp, p_len) > 0)
	{
#ifdef CONFIG_ASSH_DEBUG_BIGNUM_MODINV
	  fprintf(stderr, "swap\n");
#endif
	  ASSH_SWAP(r_len, p_len);
	  ASSH_SWAP(xr, xp);
	  ASSH_SWAP(xu, xv);
	}
    }

  return ASSH_OK;
}

assh_error_t assh_bignum_modinv(struct assh_bignum_s *u,
				const struct assh_bignum_s *a,
				const struct assh_bignum_s *m)
{
  assh_error_t err;

  assert(u != a && u != m);

  ASSH_CHK_RET(a->l > m->l, ASSH_ERR_OUTPUT_OVERFLOW);
  ASSH_CHK_RET(u->l < a->l, ASSH_ERR_OUTPUT_OVERFLOW);

  ASSH_SCRATCH_ALLOC(m->ctx, assh_bnword_t, scratch, ASSH_MODINV_SCRATCH(m->l),
		     ASSH_ERRSV_CONTINUE, err);

  ASSH_ERR_GTO(assh_bignum_modinv_euclidean(u->n, u->l, m->n, m->l,
		a->n, a->l, scratch), err_scratch);

  err = ASSH_OK;
 err_scratch:
  ASSH_SCRATCH_FREE(m->ctx, scratch);
 err:
  return err;
}

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_gcd_euclidean(assh_bnword_t * __restrict__ g,
                          const assh_bnword_t * __restrict__ a,
                          unsigned int a_len,
                          const assh_bnword_t * __restrict__ b,
                          unsigned int b_len, assh_bnword_t *scratch)
{
  assh_error_t err;

#define ASSH_GCD_SCRATCH(len) (len)

  assh_bnword_t *xr = scratch;
  assh_bnword_t *xp = g;

  /* use largest buffer between scratch and result for the largest
     input number, actual gcd value will be available in both buffers
     at the end */
  if (a_len < b_len)
    ASSH_SWAP(xr, xp);

  memmove(xr, a, a_len * sizeof(assh_bnword_t));
  memmove(xp, b, b_len * sizeof(assh_bnword_t));

  unsigned int r_len = a_len, p_len = a_len;

  ASSH_CHK_RET(assh_bignum_div_strip(&r_len, xr) ||
	       assh_bignum_div_strip(&p_len, xp), ASSH_ERR_NUM_OVERFLOW);

  while (1)
    {
      unsigned int az, al, bz, bl, da, sa;
      assh_bnword_t at, bt, q;

#ifdef CONFIG_ASSH_DEBUG_BIGNUM_GCD
      assh_bignum_print_raw(stderr, "r", xr, r_len);
      assh_bignum_print_raw(stderr, "p", xp, p_len);
#endif

      int c = assh_bignum_cmp_raw(xr, r_len, xp, p_len);
      if (c == 0)
        break;
      if (c > 0)
	{
#ifdef CONFIG_ASSH_DEBUG_BIGNUM_GCD
	  fprintf(stderr, "swap\n");
#endif
	  ASSH_SWAP(r_len, p_len);
	  ASSH_SWAP(xr, xp);
	}

      /* find factor */
      assh_bignum_div_clz(r_len, xr, &az, &al, &at);
      assh_bignum_div_clz(p_len, xp, &bz, &bl, &bt);
      ASSH_CHK_RET(al < bl, ASSH_ERR_NUM_OVERFLOW);

      q = assh_bignum_div_factor(at, bt, al - bl, &sa, &da);

#ifdef CONFIG_ASSH_DEBUG_BIGNUM_GCD
      fprintf(stderr, "plen=%u rlen=%u a_len=%u al=%u bl=%u da=%u sa=%u q=%X\n",
              p_len, r_len, a_len, al, bl, da, sa, q);
#endif

      assh_bignum_div_update_r(p_len, xp, r_len, xr, q, sa, da);

      ASSH_CHK_RET(assh_bignum_div_strip(&r_len, xr), ASSH_ERR_NUM_OVERFLOW);
    }

  return ASSH_OK;
}

assh_error_t assh_bignum_gcd(struct assh_bignum_s *g,
                             const struct assh_bignum_s *a,
                             const struct assh_bignum_s *b)
{
  assh_error_t err;

  ASSH_CHK_RET(g->l < a->l && g->l < b->l, ASSH_ERR_OUTPUT_OVERFLOW);

  unsigned int l = a->l > b->l ? a->l : b->l;

  ASSH_SCRATCH_ALLOC(a->ctx, assh_bnword_t, scratch, ASSH_GCD_SCRATCH(l),
		     ASSH_ERRSV_CONTINUE, err);

  ASSH_ERR_GTO(assh_bignum_gcd_euclidean(g->n, a->n, a->l,
                                         b->n, b->l, scratch), err_scratch);

  err = ASSH_OK;
 err_scratch:
  ASSH_SCRATCH_FREE(a->ctx, scratch);
 err:
  return err;
}

/*********************************************************************** mul */

static void assh_bignum_school_mul(assh_bnword_t * __restrict__ r,
				   const assh_bnword_t *a,
				   unsigned int alen,
				   const assh_bnword_t *b,
				   unsigned int blen)
{
  memset(r, 0, alen * sizeof(assh_bnword_t));

  unsigned int j, i;
  assh_bnlong_t t;

  for (j = 0; j < blen; j++)
    {
      for (t = i = 0; i < alen; i++)
	r[i + j] = t = (assh_bnlong_t)a[i] * b[j] + r[i + j] + (t >> ASSH_BIGNUM_W);
      r[i + j] = (t >> ASSH_BIGNUM_W);
    }
}

static void assh_bignum_karatsuba(assh_bnword_t * __restrict__ r,
				  const assh_bnword_t *a,
				  const assh_bnword_t *b,
				  assh_bnword_t *scratch,
				  unsigned int l)
{
  if (l < ASSH_BIGNUM_KARATSUBA_THRESHOLD || (l & 1))
    return assh_bignum_school_mul(r, a, l, b, l);

  /*
    scratch buffer:
      layout: x[h], y_[h], z1[l+1]
      size: 2*l+1        per stack frame
            4*l+log2(l)  on initial call
  */

#define ASSH_KARA_SCRATCH(len) (len * 4)
          /* + log2(len) - ASSH_KARA_SCRATCH(ASSH_BIGNUM_KARATSUBA_THRESHOLD) */

  unsigned int i, h = l / 2;
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
  for (; (t >> ASSH_BIGNUM_W) && i < l*2; i++)
    r[i] = t = (assh_bnlong_t)r[i] + (t >> ASSH_BIGNUM_W);
}

assh_error_t assh_bignum_mul(struct assh_bignum_s *r,
                             const struct assh_bignum_s *a,
                             const struct assh_bignum_s *b)
{
  assh_error_t err;

  assert(r != a && r != b);

  ASSH_CHK_RET(r->l < a->l + b->l, ASSH_ERR_OUTPUT_OVERFLOW);

  size_t l = a->l + b->l;

  if (a->l == b->l && !(a->l & 1))
    {
      ASSH_SCRATCH_ALLOC(a->ctx, assh_bnword_t, scratch,
			 ASSH_KARA_SCRATCH(a->l),
			 ASSH_ERRSV_CONTINUE, err);
      assh_bignum_karatsuba(r->n, a->n, b->n, scratch, a->l);
      ASSH_SCRATCH_FREE(a->ctx, scratch);
    }
  else
    assh_bignum_school_mul(r->n, a->n, a->l, b->n, b->l);

  memset(r->n + l, 0, l - r->l);

  err = ASSH_OK;
 err:
  return err;
}

assh_error_t assh_bignum_mulmod(struct assh_bignum_s *r,
                                const struct assh_bignum_s *a,
                                const struct assh_bignum_s *b,
                                const struct assh_bignum_s *m)
{
  assh_error_t err;

  assert(r != a && r != b && r != m);

  ASSH_CHK_RET(r->l < m->l, ASSH_ERR_OUTPUT_OVERFLOW);

  size_t l = a->l + b->l; /* result size */

  assh_bool_t use_kara = a->l == b->l && !(a->l & 1);
  size_t scratch_len = l;
  if (use_kara)
    scratch_len += ASSH_KARA_SCRATCH(a->l);

  ASSH_SCRATCH_ALLOC(a->ctx, assh_bnword_t, scratch, scratch_len,
		     ASSH_ERRSV_CONTINUE, err);

  assh_bnword_t *x = scratch;

  if (use_kara)
    assh_bignum_karatsuba(x, a->n, b->n, scratch + l, a->l);
  else
    assh_bignum_school_mul(x, a->n, a->l, b->n, b->l);

  ASSH_ERR_GTO(assh_bignum_div_euclidean(x, l, NULL, 0, m->n, m->l), err_scratch);

  memcpy(r->n, x, m->l * sizeof(assh_bnword_t));
  memset(r->n + m->l, 0, (r->l - m->l) * sizeof(assh_bnword_t));

  err = ASSH_OK;
 err_scratch:
  ASSH_SCRATCH_FREE(a->ctx, scratch);
 err:
  return err;
}

/*********************************************************************** shift */

assh_error_t assh_bignum_rshift(struct assh_bignum_s *r,
                                const struct assh_bignum_s *a,
                                unsigned int n)
{
  assh_error_t err;
  unsigned int i;

  ASSH_CHK_RET(r->l != a->l, ASSH_ERR_OUTPUT_OVERFLOW);
  ASSH_CHK_RET(n >= a->l * ASSH_BIGNUM_W, ASSH_ERR_OUTPUT_OVERFLOW);

  if (r == a && n == 0)
    return ASSH_OK;

  assh_bnword_t o = a->n[n / ASSH_BIGNUM_W];
  for (i = 0; i < r->l - n / ASSH_BIGNUM_W - 1; i++)
    {
      assh_bnword_t x = a->n[i + n / ASSH_BIGNUM_W + 1];
      r->n[i] = ((assh_bnlong_t)o >> (n % ASSH_BIGNUM_W))
        | ((assh_bnlong_t)x << (ASSH_BIGNUM_W - n % ASSH_BIGNUM_W));
      o = x;
    }
  for (; i < r->l; i++)
    {
      r->n[i] = ((assh_bnlong_t)o >> (n % ASSH_BIGNUM_W));
      o = 0;
    }

  return ASSH_OK;
}

/*********************************************************************** exp */

assh_error_t assh_bignum_expmod(struct assh_bignum_s *r,
				const struct assh_bignum_s *x,
				const struct assh_bignum_s *e,
				const struct assh_bignum_s *mod)
{
  assh_error_t err;

  ASSH_CHK_RET(r->l < mod->l, ASSH_ERR_OUTPUT_OVERFLOW);

  /* square length */
  unsigned int sql = ASSH_MAX(mod->l, x->l) * 2;

  ASSH_SCRATCH_ALLOC(x->ctx, assh_bnword_t, scratch,
		     + sql * 2  /* sq[2] */
		     + sql * 2  /* r[2] */
		     + ASSH_KARA_SCRATCH(sql / 2),
		     ASSH_ERRSV_CONTINUE, err);

  assh_bnword_t *sqa = scratch, *sqb = scratch + sql;
  assh_bnword_t *ra = NULL,     *rb = scratch + sql * 3;
  assh_bnword_t *kara_scratch = scratch + sql * 4;
  unsigned int i, j;

  memcpy(sqa, x->n, x->l * sizeof(assh_bnword_t));
  memset(sqa + x->l, 0, (sql - x->l) * sizeof(assh_bnword_t));

  for (i = 0; i < e->l; i++)
    {
      for (j = 0; j < ASSH_BIGNUM_W; j++)
	{
	  if ((e->n[i] >> j) & 1)
	    {
	      if (ra == NULL)
		{
		  memcpy(rb, sqa, sql * sizeof(assh_bnword_t));
		  ra = scratch + sql * 2;
		}
	      else
		{
		  assh_bignum_karatsuba(rb, ra, sqa, kara_scratch, sql / 2);
		  ASSH_ERR_GTO(assh_bignum_div_euclidean(rb, sql, NULL, 0,
					       mod->n, mod->l), err_scratch);
		}

	      ASSH_SWAP(ra, rb);
	    }

	  assh_bignum_karatsuba(sqb, sqa, sqa, kara_scratch, sql / 2);
	  ASSH_ERR_GTO(assh_bignum_div_euclidean(sqb, sql, NULL, 0,
					 mod->n, mod->l), err_scratch);
	  ASSH_SWAP(sqa, sqb);
	}
    }

  /* zero exponent case */
  ASSH_CHK_GTO(ra == NULL, ASSH_ERR_NUM_OVERFLOW, err_scratch);

  memcpy(r->n, ra, mod->l * sizeof(assh_bnword_t));
  memset(r->n + mod->l, 0, (r->l - mod->l) * sizeof(assh_bnword_t));

  err = ASSH_OK;
 err_scratch:
  ASSH_SCRATCH_FREE(x->ctx, scratch);
 err:
  return err;
}

