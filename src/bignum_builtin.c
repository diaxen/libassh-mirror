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
#include <assh/assh_alloc.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#if 0
typedef uint64_t assh_bnword_t;
typedef int64_t assh_bnsword_t;
typedef unsigned __int128 assh_bnlong_t;
#define ASSH_BN_FMT "%016llx"

#elif 1
typedef uint32_t assh_bnword_t;
typedef int32_t assh_bnsword_t;
typedef uint64_t assh_bnlong_t;
typedef int64_t assh_bnslong_t;
#define ASSH_BN_FMT "%08x"

#elif 0
typedef uint16_t assh_bnword_t;
typedef int16_t assh_bnsword_t;
typedef uint32_t assh_bnlong_t;
#define ASSH_BN_FMT "%04x"

#else

/* 8 bits big number word is useful for testing bignum algorithms
   because there are fewer possible word values, it will test more
   corner cases quickly. */
typedef uint8_t assh_bnword_t;
typedef int8_t assh_bnsword_t;
typedef uint16_t assh_bnlong_t;
#define ASSH_BN_FMT "%02x"

#endif

/** Minimum number of words for karatsuba to switch to school mul. */
#define ASSH_BIGNUM_KARATSUBA_THRESHOLD 32

/** @This specifies the number of bits in a big number word. */
#define ASSH_BIGNUM_W (sizeof(assh_bnword_t) * 8)

struct assh_bignum_mt_s
{
  assh_bnword_t *r2;
  assh_bnword_t n0;
  size_t bits;
};

#ifdef CONFIG_ASSH_DEBUG
static void
assh_bignum_dump(const assh_bnword_t *x, size_t l)
{
  size_t i;
  fprintf(stderr, "0x");  
  for (i = l; i-- > 0; )
    fprintf(stderr, ASSH_BN_FMT, x[i]);
  fprintf(stderr, "\n");  
}
#endif

static inline size_t
assh_bignum_words(size_t bits)
{
  return (((bits - 1) | (ASSH_BIGNUM_W - 1)) + 1) / ASSH_BIGNUM_W;
}

static inline uint_fast8_t
assh_bn_clz(assh_bnword_t x)
{
  switch (sizeof(x))
    {
    case 1:
      return ASSH_CLZ8(x);
    case 2:
      return ASSH_CLZ16(x);
    case 4:
      return ASSH_CLZ32(x);
    case 8:
      return ASSH_CLZ64(x);
    }

  abort();
}

static void
assh_bignum_cswap(assh_bnword_t *a, assh_bnword_t *b,
                  size_t l, assh_bool_t c)
{
  assh_bnword_t m = ~((assh_bnword_t)c - 1);
  size_t i;

  for (i = 0; i < l; i++)
    {
      a[i] ^= b[i] & m;
      b[i] ^= a[i] & m;
      a[i] ^= b[i] & m;
    }
}

static void
assh_bignum_cmov(assh_bnword_t *a, const assh_bnword_t *b,
                 size_t l, assh_bool_t c)
{
  assh_bnword_t m = ~((assh_bnword_t)c - 1);
  size_t i;

  for (i = 0; i < l; i++)
    a[i] = (b[i] & m) | (a[i] & ~m);
}

/* This function copies a value between two big number objects. */
static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_copy(struct assh_bignum_s *dst,
                 const struct assh_bignum_s *src)
{
  assh_error_t err;
  size_t al = assh_bignum_words(dst->bits);
  size_t bl = assh_bignum_words(src->bits);
  size_t i, l = ASSH_MIN(al, bl);
  assh_bnword_t x = 0;
  assh_bnword_t *dn = dst->n, *sn = src->n;

  dst->secret = src->secret;

  for (i = 0; i < l; i++)
    x = dn[i] = sn[i];

  for (; i < al; i++)
    x = dn[i] = 0;

  if (dst->bits % ASSH_BIGNUM_W)
    x >>= (dst->bits % ASSH_BIGNUM_W);
  else
    x = 0;

  for (; i < bl; i++)
    x |= sn[i];
  ASSH_CHK_RET(x != 0, ASSH_ERR_OUTPUT_OVERFLOW);

  return ASSH_OK;
}

/* This function stores the value of a big number into a buffer. The
   destination format can be: ASSH_BIGNUM_MPINT, ASSH_BIGNUM_STRING,
   ASSH_BIGNUM_LSB_RAW, ASSH_BIGNUM_MSB_RAW. The buffer must be large
   enough to hold the value. */
static void
assh_bignum_to_buffer(const struct assh_bignum_s *bn,
                      uint8_t * __restrict__ mpint,
                      enum assh_bignum_fmt_e format)
{
  size_t i, l = ASSH_ALIGN8(bn->bits) / 8;
  assh_bnword_t *n = bn->n;
  uint8_t *m = mpint;

  if (format == ASSH_BIGNUM_MPINT ||
      format == ASSH_BIGNUM_STRING)
    m += 4;

  uint8_t *p = m;

  if (format == ASSH_BIGNUM_LSB_RAW)
    for (i = 0; i < l; i++)
      *p++ = n[i / sizeof(assh_bnword_t)]
        >> ((i % sizeof(assh_bnword_t)) * 8);
  else
    for (i = l; i-- > 0; )
      {
        uint8_t b = n[i / sizeof(assh_bnword_t)]
          >> ((i % sizeof(assh_bnword_t)) * 8);
        if (p == m && format == ASSH_BIGNUM_MPINT)
          {
            if (!b)
              continue;
            if (b & 0x80)
              *p++ = 0;
          }
        *p++ = b;
      }

  if (mpint < m)
    assh_store_u32(mpint, p - m);
}

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_from_buffer(struct assh_bignum_s *bn,
                            const uint8_t * __restrict__ data,
                            size_t data_len, enum assh_bignum_fmt_e format)
{
  assh_error_t err;
  size_t i, j, l = assh_bignum_words(bn->bits);
  size_t k = 0;
  assh_bnword_t x, *n = bn->n;

  if (l > 0)
    {
      for (i = 0; i < l; i++)
        {
          x = 0;
          for (j = 0; j < ASSH_BIGNUM_W && k < data_len; j += 8)
            {
              size_t m = k++;
              if (format != ASSH_BIGNUM_LSB_RAW)
                m = data_len - m - 1;
              x |= (assh_bnword_t)data[m] << j;
            }
          n[i] = x;
        }

      if (bn->bits % ASSH_BIGNUM_W)
        {
          assh_bnword_t mask = (assh_bnword_t)-1
            >> ((ASSH_BIGNUM_W - bn->bits) & (ASSH_BIGNUM_W - 1));

          if (format == ASSH_BIGNUM_MSB_RAW || format == ASSH_BIGNUM_LSB_RAW)
            n[i - 1] &= mask;
          else
            ASSH_CHK_RET(x & ~mask, ASSH_ERR_OUTPUT_OVERFLOW);
        }
    }

  ASSH_CHK_RET(k < data_len, ASSH_ERR_OUTPUT_OVERFLOW);
  return ASSH_OK;
}

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_from_uint(struct assh_bignum_s *bn,
                      uintptr_t x)
{
  size_t i, l = assh_bignum_words(bn->bits);
  assh_bnword_t *n = bn->n;
  assh_error_t err;

  for (i = 0; i < l; i++)
    {
      n[i] = x;
      x = (ASSH_BIGNUM_W < sizeof(x) * 8) ? x >> ASSH_BIGNUM_W : 0;
    }

  ASSH_CHK_RET(x != 0, ASSH_ERR_NUM_OVERFLOW);
  return ASSH_OK;
}

static int_fast8_t assh_bignum_cmp(const struct assh_bignum_s *a,
                                   const struct assh_bignum_s *b)
{
  size_t al = assh_bignum_words(a->bits);
  size_t bl = assh_bignum_words(b->bits);
  size_t i, l = ASSH_MIN(al, bl);
  assh_bnword_t *an = a->n, *bn = b->n;
  int_fast8_t lt = 0, gt = 0, eq;

  for (i = 0; i < l; i++)
    {
      eq = (an[i] == bn[i]);
      lt = (an[i] < bn[i]) | (lt & eq);
      gt = (an[i] > bn[i]) | (gt & eq);
    }
  for (; i < bl; i++)
    {
      eq = (0 == bn[i]);
      lt = (0 != bn[i]) | (lt & eq);
      gt = (gt & eq);
    }
  for (; i < al; i++)
    {
      eq = (an[i] == 0);
      lt = (lt & eq);
      gt = (an[i] != 0) | (gt & eq);
    }

  return gt - lt;
}

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_rand(struct assh_context_s *c,
                 struct assh_bignum_s *bn,
                 const struct assh_bignum_s *min,
                 const struct assh_bignum_s *max,
                 enum assh_prng_quality_e quality)
{
  assh_error_t err;
  assh_bnword_t *n = bn->n;
  size_t i, l = assh_bignum_words(bn->bits);

  bn->secret |= quality != ASSH_PRNG_QUALITY_WEAK;

  if (l == 0)
    return ASSH_OK;

  ASSH_ERR_RET(c->prng->f_get(c, (uint8_t*)n,
                 l * sizeof(assh_bnword_t), quality));

  while (1)
    {
      if (bn->bits % ASSH_BIGNUM_W)
        n[l - 1] >>= (ASSH_BIGNUM_W - bn->bits) & (ASSH_BIGNUM_W - 1);

      if ((min == NULL || assh_bignum_cmp(bn, min) > 0) &&
          (max == NULL || assh_bignum_cmp(bn, max) < 0))
        break;

      for (i = 1; i < l; i++)
        n[l - 1] = n[l];

      ASSH_ERR_RET(c->prng->f_get(c, (uint8_t*)(n + l - 1),
                     sizeof(assh_bnword_t), quality));
    }

  return ASSH_OK;
}

/*********************************************************************** shift */

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_rshift(struct assh_bignum_s *dst,
                   const struct assh_bignum_s *src,
                   uint_fast16_t n)
{
  assh_error_t err;

  assert(src->bits == dst->bits);
  assert(n < src->bits);
  dst->secret = src->secret;

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
}

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_lshift(struct assh_bignum_s *dst,
                   const struct assh_bignum_s *src,
                   uint_fast16_t n)
{
  assh_error_t err;

  assert(src->bits == dst->bits);
  assert(n < src->bits);
  dst->secret = src->secret;

  size_t i, l = assh_bignum_words(src->bits);

  if (dst == src && n == 0)
    return ASSH_OK;

  assh_bnword_t *dn = dst->n, *sn = src->n;

  assh_bnword_t o = sn[l - 1 - n / ASSH_BIGNUM_W];
  for (i = l; i-- > n / ASSH_BIGNUM_W; )
    {
      assh_bnword_t x = sn[i - 1 - n / ASSH_BIGNUM_W];
      dn[i] = ((assh_bnlong_t)o << (n % ASSH_BIGNUM_W))
        | ((assh_bnlong_t)x >> (ASSH_BIGNUM_W - n % ASSH_BIGNUM_W));
      o = x;
    }
  for (i++; i-- > 0; )
    {
      dn[i] = ((assh_bnlong_t)o << (n % ASSH_BIGNUM_W));
      o = 0;
    }

  if (dst->bits % ASSH_BIGNUM_W)
    {
      assh_bnword_t mask = (assh_bnword_t)-1
        >> ((ASSH_BIGNUM_W - dst->bits) & (ASSH_BIGNUM_W - 1));
      ASSH_CHK_RET(dn[l - 1] & ~mask, ASSH_ERR_OUTPUT_OVERFLOW);
    }

  return ASSH_OK;
}

/*********************************************************************** add, sub */

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_addsub(struct assh_bignum_s *dst,
                   const struct assh_bignum_s *a,
                   const struct assh_bignum_s *b,
                   const struct assh_bignum_mt_s *mt,
                   assh_bnword_t smask /* 0:add, -1:sub */)
{
  assh_error_t err;
  assh_bnword_t amask = 0;

  dst->secret = a->secret | b->secret;

  /* make A the largest bits length */
  if (a->bits < b->bits)
    {
      ASSH_SWAP(a, b);
      amask ^= smask;
    }

  size_t dl = assh_bignum_words(dst->bits);
  size_t al = assh_bignum_words(a->bits);
  size_t bl = assh_bignum_words(b->bits);
  const assh_bnword_t *an = a->n;
  const assh_bnword_t *bn = b->n;
  assh_bnword_t *dn = dst->n;

  assert(dl >= al);

  assh_bnlong_t t = (assh_bnlong_t)(smask & 1) << ASSH_BIGNUM_W;
  assh_bnword_t bmask = amask ^ smask;
  size_t i;

  /* add/sub numbers */
  for (i = 0; i < bl; i++)
    dn[i] = t = (assh_bnlong_t)(an[i] ^ amask) + (bn[i] ^ bmask) + (t >> ASSH_BIGNUM_W);
  for (; i < al; i++)
    dn[i] = t = (assh_bnlong_t)(an[i] ^ amask) + bmask + (t >> ASSH_BIGNUM_W);
  for (; i < dl; i++)
    dn[i] = t = smask + (t >> ASSH_BIGNUM_W);

  t ^= (assh_bnlong_t)(smask & 1) << ASSH_BIGNUM_W;

  /* handle overflow condition */

  if (mt)
    {
      assert(dst->bits == mt->bits);
      if (a->bits == dst->bits)
        {
          /* We have to ensure the result fits in the buffer by
             subtracting/adding the modulus if a carry was generated. It ok
             if the result is actually larger than the modulus, provided
             that it fits. assh_bignum_mt_reduce will work this out. */
          assh_bnword_t q = ((t >> ASSH_BIGNUM_W) ^ 1) - 1;
          assh_bnword_t *m = mt->r2 + dl;
          /* masked reduce */
          t = (assh_bnlong_t)(q & 1 & ~smask) << ASSH_BIGNUM_W;
          for (i = 0; i < dl; i++)
            dn[i] = t = (assh_bnlong_t)dn[i] + (q & (m[i] ^ (assh_bnword_t)~smask))
              + (t >> ASSH_BIGNUM_W);
        }
    }
  else
    {
      size_t l = dst->bits % ASSH_BIGNUM_W;
      if (!l)
        l = ASSH_BIGNUM_W;
      ASSH_CHK_RET(t >> l != 0, ASSH_ERR_NUM_OVERFLOW);
    }

  return ASSH_OK;
}

/*********************************************************************** div, modinv */

static inline int assh_bignum_div_cmp(const assh_bnword_t *a, unsigned int alen,
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

/** reduce size to strip leading nul words */
static inline assh_bool_t
assh_bignum_div_strip(unsigned int *len, const assh_bnword_t *x)
{
  while (*len > 0 && x[*len - 1] == 0)
    (*len)--;
  return (*len == 0);
}

/** find number of leading zero bits and get a word full of msb significant bits */
static inline void
assh_bignum_div_clz(unsigned int len, const assh_bnword_t *x,
                    unsigned int *z, unsigned int *l, assh_bnword_t *t)
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
static inline void
assh_bignum_div_update_r(unsigned int b_len, const assh_bnword_t * __restrict__ b,
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
static inline void
assh_bignum_div_update_q(unsigned int d_len, assh_bnword_t * __restrict__ d,
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

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_div(struct assh_context_s *ctx,
                struct assh_bignum_s *r,
                struct assh_bignum_s *d,
                const struct assh_bignum_s *a,
                const struct assh_bignum_s *b)
{
  assh_error_t err;

  assert(r != d && a != d && b != d && b != r);
  assert(!a->secret && !b->secret);

  ASSH_CHK_RET(a->bits < b->bits, ASSH_ERR_OUTPUT_OVERFLOW);
  ASSH_CHK_RET(r->bits < a->bits, ASSH_ERR_OUTPUT_OVERFLOW);
  if (d != NULL)
    ASSH_CHK_RET(d->bits < a->bits, ASSH_ERR_OUTPUT_OVERFLOW);

  size_t al = assh_bignum_words(a->bits);
  size_t bl = assh_bignum_words(b->bits);
  assh_bnword_t *dn = NULL, *rn;
  size_t rl;

  if (r != NULL)
    {
      r->secret = 0;
      rl = assh_bignum_words(r->bits);
      rn = r->n;
      goto done;
    }

  rl = al;
  ASSH_SCRATCH_ALLOC(ctx, assh_bnword_t, scratch,
                     rl, ASSH_ERRSV_CONTINUE, err);
  rn = scratch;
 done:

  if (a != r)
    {
      memcpy(rn, a->n, al * sizeof(assh_bnword_t));
      memset((assh_bnword_t*)rn + al, 0, (rl - al) * sizeof(assh_bnword_t));
    }

  size_t dl = 0;
  if (d != NULL)
    {
      d->secret = 0;
      dl = assh_bignum_words(d->bits);
      dn = d->n;
      memset(dn, 0, dl * sizeof(assh_bnword_t));
    }

  err = assh_bignum_div_euclidean(rn, rl, dn, dl, b->n, bl);
  if (r == NULL)
    ASSH_SCRATCH_FREE(ctx, scratch);

 err:
  return err;
}

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_modinv(struct assh_context_s *ctx,
                   struct assh_bignum_s *u,
                   const struct assh_bignum_s *a,
                   const struct assh_bignum_s *m)
{
  assh_error_t err;

  assert(u != a && u != m);
  assert(!a->secret && !m->secret);
  u->secret = 0;

  ASSH_CHK_RET(a->bits > m->bits, ASSH_ERR_OUTPUT_OVERFLOW);
  ASSH_CHK_RET(u->bits < a->bits, ASSH_ERR_OUTPUT_OVERFLOW);

  size_t ul = assh_bignum_words(u->bits);
  size_t al = assh_bignum_words(a->bits);
  size_t ml = assh_bignum_words(m->bits);

  ASSH_SCRATCH_ALLOC(ctx, assh_bnword_t, scratch, ml * 3,
		     ASSH_ERRSV_CONTINUE, err);

  assh_bnword_t * __restrict__ un = u->n;
  const assh_bnword_t * __restrict__ an = a->n;
  const assh_bnword_t * __restrict__ mn = m->n;

  assh_bnword_t *r = scratch;
  assh_bnword_t *p = scratch + ml;
  assh_bnword_t *v = scratch + ml * 2;

  memcpy(r, mn, ml * sizeof(assh_bnword_t));
  memcpy(p, an, al * sizeof(assh_bnword_t));
  memset(p + al, 0, (ml - al) * sizeof(assh_bnword_t));

  memset(v, 0, ml * sizeof(assh_bnword_t));
  memset(un + 1, 0, (ul - 1) * sizeof(assh_bnword_t));
  un[0] = 1;

  unsigned int rl = ml, pl = ml;
  assh_bnword_t *xr = r, *xp = p, *xu = un, *xv = v;

  ASSH_CHK_GTO(assh_bignum_div_strip(&rl, xr) ||
	       assh_bignum_div_strip(&pl, xp) ||
	       rl < pl, ASSH_ERR_NUM_OVERFLOW, err_scratch);

  while (1)
    {
      unsigned int az, as, bz, bs, da, sa;
      assh_bnword_t at, bt, q;

      /* find factor */
      assh_bignum_div_clz(rl, xr, &az, &as, &at);
      assh_bignum_div_clz(pl, xp, &bz, &bs, &bt);
      ASSH_CHK_GTO(as < bs, ASSH_ERR_NUM_OVERFLOW, err_scratch);

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

  err = ASSH_OK;
 err_scratch:
  ASSH_SCRATCH_FREE(ctx, scratch);
 err:
  return err;
}

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_gcd(struct assh_context_s *ctx,
                struct assh_bignum_s *g,
                const struct assh_bignum_s *a,
                const struct assh_bignum_s *b)
{
  assh_error_t err;

  assert(g->bits >= a->bits || g->bits >= b->bits);
  assert(!a->secret && !b->secret);
  g->secret = 0;

  size_t gl = assh_bignum_words(g->bits);
  size_t al = assh_bignum_words(a->bits);
  size_t bl = assh_bignum_words(b->bits);

  unsigned int l = al > bl ? al : bl;

  ASSH_SCRATCH_ALLOC(ctx, assh_bnword_t, scratch, l,
		     ASSH_ERRSV_CONTINUE, err);

  assh_bnword_t * __restrict__ gn = g->n;
  const assh_bnword_t * __restrict__ an = a->n;
  const assh_bnword_t * __restrict__ bn = b->n;

  assh_bnword_t *xr = scratch;
  assh_bnword_t *xp = gn;

  /* use largest buffer between scratch and result for the largest
     input number, actual gcd value will be available in both buffers
     at the end */
  if (al < bl)
    ASSH_SWAP(xr, xp);

  memmove(xr, an, al * sizeof(assh_bnword_t));
  memmove(xp, bn, bl * sizeof(assh_bnword_t));

  unsigned int rl = al, pl = al;

  ASSH_CHK_GTO(assh_bignum_div_strip(&rl, xr) ||
	       assh_bignum_div_strip(&pl, xp),
               ASSH_ERR_NUM_OVERFLOW, err_scratch);

  while (1)
    {
      unsigned int az, al, bz, bl, da, sa;
      assh_bnword_t at, bt, q;

      int c = assh_bignum_div_cmp(xr, rl, xp, pl);
      if (c == 0)
        break;
      if (c > 0)
	{
	  ASSH_SWAP(rl, pl);
	  ASSH_SWAP(xr, xp);
	}

      /* find factor */
      assh_bignum_div_clz(rl, xr, &az, &al, &at);
      assh_bignum_div_clz(pl, xp, &bz, &bl, &bt);
      ASSH_CHK_GTO(al < bl, ASSH_ERR_NUM_OVERFLOW, err_scratch);

      q = assh_bignum_div_factor(at, bt, al - bl, &sa, &da);

      assh_bignum_div_update_r(pl, xp, rl, xr, q, sa, da);

      ASSH_CHK_GTO(assh_bignum_div_strip(&rl, xr),
                   ASSH_ERR_NUM_OVERFLOW, err_scratch);
    }

  err = ASSH_OK;
 err_scratch:
  ASSH_SCRATCH_FREE(ctx, scratch);
 err:
  return err;
}

/*********************************************************************** mul */

static void
assh_bignum_school_mul(assh_bnword_t * __restrict__ r,
                       const assh_bnword_t *a, unsigned int alen,
                       const assh_bnword_t *b, unsigned int blen)
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

#if !defined(__OPTIMIZE_SIZE__)
static void
assh_bignum_karatsuba(assh_bnword_t * __restrict__ r,
                      const assh_bnword_t *a, const assh_bnword_t *b,
                      assh_bnword_t *scratch, unsigned int l)
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
  for (; i < l*2; i++)
    r[i] = t = (assh_bnlong_t)r[i] + (t >> ASSH_BIGNUM_W);
}
#endif

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_mul(struct assh_context_s *ctx,
                struct assh_bignum_s *r,
                const struct assh_bignum_s *a,
                const struct assh_bignum_s *b)
{
  assh_error_t err;

  r->secret = a->secret | b->secret;
  assert(r != a && r != b);

  ASSH_CHK_RET(r->bits < a->bits + b->bits, ASSH_ERR_OUTPUT_OVERFLOW);

  size_t rl = assh_bignum_words(r->bits);
  size_t al = assh_bignum_words(a->bits);
  size_t bl = assh_bignum_words(b->bits);
  size_t l = al + bl;

#if !defined(__OPTIMIZE_SIZE__)
  if (al == bl && !(al & 1))
    {
      ASSH_SCRATCH_ALLOC(ctx, assh_bnword_t, scratch,
			 ASSH_KARA_SCRATCH(al),
			 ASSH_ERRSV_CONTINUE, err);
      assh_bignum_karatsuba(r->n, a->n, b->n, scratch, al);
      ASSH_SCRATCH_FREE(ctx, scratch);
    }
  else
#endif
    assh_bignum_school_mul(r->n, a->n, al, b->n, bl);

  memset((assh_bnword_t*)r->n + l, 0, (rl - l) * sizeof(assh_bnword_t));

  err = ASSH_OK;
 err:
  return err;
}

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_mul_mod(struct assh_context_s *ctx,
                   struct assh_bignum_s *r,
                   const struct assh_bignum_s *a,
                   const struct assh_bignum_s *b,
                   const struct assh_bignum_s *m)
{
  assh_error_t err;

  assert(!a->secret && !b->secret && !m->secret);
  assert(r != a && r != b && r != m);
  r->secret = 0;

  ASSH_CHK_RET(r->bits < m->bits, ASSH_ERR_OUTPUT_OVERFLOW);

  size_t al = assh_bignum_words(a->bits);
  size_t bl = assh_bignum_words(b->bits);
  size_t ml = assh_bignum_words(m->bits);
  size_t rl = assh_bignum_words(r->bits);

  size_t l = al + bl; /* result size */

  size_t scratch_len = l;
#if !defined(__OPTIMIZE_SIZE__)
  assh_bool_t use_kara = al == bl && !(al & 1);
  if (use_kara)
    scratch_len += ASSH_KARA_SCRATCH(al);
#endif

  ASSH_SCRATCH_ALLOC(ctx, assh_bnword_t, scratch, scratch_len,
		     ASSH_ERRSV_CONTINUE, err);

  assh_bnword_t *x = scratch;

#if !defined(__OPTIMIZE_SIZE__)
  if (use_kara)
    assh_bignum_karatsuba(x, a->n, b->n, scratch + l, al);
  else
#endif
    assh_bignum_school_mul(x, a->n, al, b->n, bl);

  ASSH_ERR_GTO(assh_bignum_div_euclidean(x, l, NULL, 0, m->n, ml), err_scratch);

  memcpy(r->n, x, ml * sizeof(assh_bnword_t));
  memset(r->n + ml, 0, (rl - ml) * sizeof(assh_bnword_t));

  err = ASSH_OK;
 err_scratch:
  ASSH_SCRATCH_FREE(ctx, scratch);
 err:
  return err;
}

/********************************************************* montgomery */

static assh_bnword_t assh_bnword_mt_modinv(assh_bnword_t a)
{
  uint_fast8_t i, sh = assh_bn_clz(a);
  assh_bnword_t b = -(a << sh);
  assh_bnword_t q = -((assh_bnword_t)1 << sh);
  assh_bnword_t c, r = 1;

  while (a)
    {
      if (a < b)
        {
          ASSH_SWAP(a, b);
          ASSH_SWAP(r, q);
        }
      sh = assh_bn_clz(b) - assh_bn_clz(a);
      c = b << sh;
      i = (c > a);
      a -= (c >> i);
      r -= q << (sh - i);
    }

  return q;
}

static void
assh_bignum_mt_release(struct assh_context_s *c,
                       struct assh_bignum_mt_s *mt)
{
  if (mt->r2 != NULL)
    assh_free(c, mt->r2, ASSH_ALLOC_INTERNAL);
}

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_mt_init(struct assh_context_s *c,
                    struct assh_bignum_mt_s *mt,
                    const struct assh_bignum_s *mod)
{
  assh_error_t err;

  assert(!mod->secret);

  /* check modulus is odd */
  ASSH_CHK_RET(!(m[0] & 1), ASSH_ERR_NUM_OVERFLOW);

  /* compute r^2 % n */
  size_t ml = assh_bignum_words(mod->bits);
  size_t rl = ml * 2 + 1;

  if (mt->r2 == NULL || mt->bits != mod->bits)
    {
      if (mt->r2 != NULL)
        assh_free(c, mt->r2, ASSH_ALLOC_INTERNAL);
      mt->r2 = NULL;
      ASSH_ERR_RET(assh_alloc(c, rl * sizeof(assh_bnword_t),
                              ASSH_ALLOC_INTERNAL, (void**)&mt->r2));
    }

  assh_bnword_t *r2 = mt->r2, *m = mod->n;

  unsigned int i;
  for (i = 0; i < ml * 2; i++)
    r2[i] = 0;
  r2[i] = 1;

  ASSH_ERR_GTO(assh_bignum_div_euclidean(r2, rl, NULL, 0,
                                         m, ml), err_);

  /* store the modulus in the higher half of the array */
  memcpy(r2 + ml, m, ml * sizeof(assh_bnword_t));

  mt->bits = mod->bits;
  mt->n0 = assh_bnword_mt_modinv(-m[0]);

  return ASSH_OK;

 err_:
  assh_free(c, r2, ASSH_ALLOC_INTERNAL);
  return err;
}

static void
assh_bignum_mt_mul(const struct assh_bignum_mt_s *mt,
                   assh_bnword_t * __restrict__ a,
                   const assh_bnword_t * __restrict__ x,
                   const assh_bnword_t * __restrict__ y)
{
  size_t i, j;
  size_t ml = assh_bignum_words(mt->bits);
  assh_bnword_t *m = mt->r2 + ml;
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

static void
assh_bignum_mt_reduce(const struct assh_bignum_mt_s *mt,
                      assh_bnword_t * __restrict__ a,
                      const assh_bnword_t * __restrict__ x)
{
  size_t i, j;
  size_t ml = assh_bignum_words(mt->bits);
  assh_bnword_t *m = mt->r2 + ml;
  assh_bnword_t q;
  assh_bnlong_t p, t, r;

  for (i = 0; i < ml; i++)
    a[i] = 0;

  for (i = 0; i < ml; i++)
    {
      p = a[0] + (assh_bnlong_t)x[i];
      q = p * mt->n0;
      r = (assh_bnlong_t)m[0] * q;
      t = p + r;

      for (j = 1; j < ml; j++)
        {
          p = a[j];
          r = (assh_bnlong_t)m[j] * q + (t >> ASSH_BIGNUM_W);
          t = p + r;
          a[j-1] = t;
        }
      a[j-1] = (t >> ASSH_BIGNUM_W);
    }
}

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_mt_convert(struct assh_context_s *c, assh_bool_t fwd,
                       const struct assh_bignum_mt_s *mt,
                       struct assh_bignum_s *r,
                       const struct assh_bignum_s *a)
{
  assh_error_t err;

  ASSH_CHK_RET(mt->bits != a->bits || mt->bits != r->bits,
               ASSH_ERR_NUM_OVERFLOW);
  size_t ml = assh_bignum_words(mt->bits);
  assh_bnword_t *t = r->n;

  r->secret = a->secret;

  if (r != a)
    goto done;

  ASSH_SCRATCH_ALLOC(c, assh_bnword_t, scratch,
                     ml, ASSH_ERRSV_CONTINUE, err);
  t = scratch;
 done:
  err = ASSH_OK;

  if (fwd)
    assh_bignum_mt_mul(mt, t, mt->r2, a->n);
  else
    assh_bignum_mt_reduce(mt, t, a->n);

  if (r == a)
    {
      memcpy(r->n, t, ml * sizeof(assh_bnword_t));
      ASSH_SCRATCH_FREE(c, scratch);
    }
 err:
  return err;
}

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_mul_mod_mt(struct assh_context_s *ctx,
                      struct assh_bignum_s *r,
                      const struct assh_bignum_s *a,
                      const struct assh_bignum_s *b,
                      const struct assh_bignum_mt_s *mt)
{
  assh_error_t err;
  assert(r != a && r != b);
  ASSH_CHK_RET(mt->bits != a->bits ||
               mt->bits != b->bits ||
               mt->bits != r->bits,
               ASSH_ERR_NUM_OVERFLOW);

  r->secret = a->secret | b->secret;

  assh_bignum_mt_mul(mt, r->n, a->n, b->n);

  return ASSH_OK;
}

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_expmod_mt(struct assh_context_s *ctx,
                      struct assh_bignum_s *r,
                      const struct assh_bignum_s *a,
                      const struct assh_bignum_s *b,
                      const struct assh_bignum_mt_s *mt)
{
  assh_error_t err;

  assert(r != a && r != b);
  ASSH_CHK_RET(mt->bits != a->bits ||
               mt->bits != r->bits,
               ASSH_ERR_NUM_OVERFLOW);

  r->secret = a->secret | b->secret;

  size_t ml = assh_bignum_words(mt->bits);

  ASSH_SCRATCH_ALLOC(ctx, assh_bnword_t, sq, ml * 2,
		     ASSH_ERRSV_CONTINUE, err);
  assh_bnword_t *tmp = sq + ml;
  assh_bnword_t *bn = b->n;
  uint_fast16_t i = 0;

  /* rn = 1 */
  assh_bignum_mt_reduce(mt, r->n, mt->r2);

#if !defined(__OPTIMIZE_SIZE__)
  if (b->secret)
#endif
    {
      assh_bnword_t *rn = r->n;

      memcpy(sq, a->n, ml * sizeof(assh_bnword_t));

      while (1)
        {
          assh_bignum_mt_mul(mt, tmp, rn, sq);

          assh_bignum_cmov(rn, tmp, ml,
                           (bn[i / ASSH_BIGNUM_W] >> (i % ASSH_BIGNUM_W)) & 1);

          if (++i == b->bits)
            break;

          assh_bignum_mt_mul(mt, tmp, sq, sq);
          memcpy(sq, tmp, ml * sizeof(assh_bnword_t));
        }
    }
#if !defined(__OPTIMIZE_SIZE__)
  else
    {
      assh_bnword_t *rn = NULL;

      memcpy(sq, a->n, ml * sizeof(assh_bnword_t));

      while (1)
        {
          if ((bn[i / ASSH_BIGNUM_W] >> (i % ASSH_BIGNUM_W)) & 1)
            {
              if (rn == NULL)
                {
                  rn = r->n;
                  memcpy(rn, sq, ml * sizeof(assh_bnword_t));
                }
              else
                {
                  assh_bignum_mt_mul(mt, tmp, rn, sq);
                  memcpy(rn, tmp, ml * sizeof(assh_bnword_t));
                }
            }

          if (++i == b->bits)
            break;

          assh_bignum_mt_mul(mt, tmp, sq, sq);
          memcpy(sq, tmp, ml * sizeof(assh_bnword_t));
        }
    }
#endif

  err = ASSH_OK;
 err_scratch:
  ASSH_SCRATCH_FREE(ctx, sq);
 err:
  return err;
}

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_modinv_mt(struct assh_context_s *ctx,
                      struct assh_bignum_s *r,
                      const struct assh_bignum_s *a,
                      const struct assh_bignum_mt_s *mt)
{
  assh_error_t err;

  r->secret = a->secret;

  assert(r != a);
  assert(mt->bits == a->bits &&
         mt->bits == r->bits);

  size_t ml = assh_bignum_words(mt->bits);

  ASSH_SCRATCH_ALLOC(ctx, assh_bnword_t, sq, ml * 2,
		     ASSH_ERRSV_CONTINUE, err);
  assh_bnword_t *tmp = sq + ml;
  uint_fast16_t i = 0;
  assh_bnword_t *rn = r->n;

  /* modulus - 2 */
  assh_bnword_t p, *pn = mt->r2 + ml;
  assh_bnslong_t t = (assh_bnslong_t)-2 << ASSH_BIGNUM_W;

  memcpy(sq, a->n, ml * sizeof(assh_bnword_t));

  /* rn = 1 */
  assh_bignum_mt_reduce(mt, rn, mt->r2);

  while (1)
    {
      assh_bignum_mt_mul(mt, tmp, rn, sq);

      if (i % ASSH_BIGNUM_W == 0)
        p = t = (assh_bnslong_t)pn[i / ASSH_BIGNUM_W] + (t >> ASSH_BIGNUM_W);

      assh_bignum_cmov(rn, tmp, ml, (p >> (i % ASSH_BIGNUM_W)) & 1);

      if (++i == mt->bits)
        break;

      assh_bignum_mt_mul(mt, tmp, sq, sq);
      memcpy(sq, tmp, ml * sizeof(assh_bnword_t));
    }

  err = ASSH_OK;
 err_scratch:
  ASSH_SCRATCH_FREE(ctx, sq);
 err:
  return err;
}

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_realloc(struct assh_context_s *c,
                    struct assh_bignum_s *bn)
{
  if (bn->n != NULL)
    return ASSH_OK;
  return assh_realloc(c, &bn->n, assh_bignum_words(bn->bits) *
                      sizeof(assh_bnword_t), ASSH_ALLOC_SECUR);
}

static ASSH_BIGNUM_CONVERT_FCN(assh_bignum_builtin_convert)
{
  assh_error_t err;

  const struct assh_bignum_s *srcn = src;
  struct assh_bignum_s *dstn = dst;

  if (srcfmt == ASSH_BIGNUM_NATIVE ||
      srcfmt == ASSH_BIGNUM_STEMP ||
      srcfmt == ASSH_BIGNUM_TEMP)
    {
      switch (dstfmt)
        {
        case ASSH_BIGNUM_NATIVE:
        case ASSH_BIGNUM_TEMP:
        case ASSH_BIGNUM_STEMP:
          ASSH_ERR_RET(assh_bignum_realloc(c, dstn));
          ASSH_ERR_RET(assh_bignum_copy(dstn, srcn));
          break;
        case ASSH_BIGNUM_MPINT:
        case ASSH_BIGNUM_STRING:
        case ASSH_BIGNUM_MSB_RAW:
        case ASSH_BIGNUM_LSB_RAW:
          assh_bignum_to_buffer(srcn, dst, dstfmt);
          break;

        default:
          ASSH_ERR_RET(ASSH_ERR_NOTSUP);
        }
    }
  else
    {
      size_t l, n, b;

      if (srcfmt == ASSH_BIGNUM_MSB_RAW ||
          srcfmt == ASSH_BIGNUM_LSB_RAW)
        {
          b = dstn->bits;
          n = l = ASSH_ALIGN8(b) / 8;
        }
      else
        {
          ASSH_ERR_RET(assh_bignum_size_of_data(srcfmt, src, &l, &n, &b));
          ASSH_CHK_RET(dstn->bits < b, ASSH_ERR_NUM_OVERFLOW);
        }

      switch (srcfmt)
        {
        case ASSH_BIGNUM_STRING:
        case ASSH_BIGNUM_MPINT:
        case ASSH_BIGNUM_ASN1:
          ASSH_ERR_RET(assh_bignum_realloc(c, dstn));
          ASSH_ERR_RET(assh_bignum_from_buffer(dstn, src + l - n, n, srcfmt));
          break;

        case ASSH_BIGNUM_MSB_RAW:
        case ASSH_BIGNUM_LSB_RAW:
          ASSH_ERR_RET(assh_bignum_realloc(c, dstn));
          ASSH_ASSERT(assh_bignum_from_buffer(dstn, src, n, srcfmt));
          break;

        case ASSH_BIGNUM_INT:
          ASSH_CHK_RET(dstn->bits < sizeof(uintptr_t) * 8, ASSH_ERR_NUM_OVERFLOW);
          ASSH_ERR_RET(assh_bignum_realloc(c, dstn));
          ASSH_ERR_RET(assh_bignum_from_uint(dstn, (uintptr_t)src));
          break;

        case ASSH_BIGNUM_SIZE:
          dstn->bits = b;
          break;

        default:
          ASSH_ERR_RET(ASSH_ERR_NOTSUP);
        }
    }

  return ASSH_OK;
}

static ASSH_BIGNUM_BYTECODE_FCN(assh_bignum_builtin_bytecode)
{
  uint_fast8_t flen, tlen, mlen;
  assh_error_t err;
  uint_fast8_t i, j, k, pc = 0;

  /* find number of arguments and temporaries */
  for (mlen = tlen = flen = 0; format[flen]; flen++)
    {
      switch (format[flen])
        {
        case ASSH_BIGNUM_TEMP:
        case ASSH_BIGNUM_STEMP:
          tlen++;
          break;
        case ASSH_BIGNUM_MT:
          mlen++;
          break;
        }
    }

  void *args[flen];
  struct assh_bignum_s tmp[tlen];
  struct assh_bignum_mt_s mt[mlen];

  memset(tmp, 0, sizeof(tmp));

  for (i = j = k = 0; i < flen; i++)
    switch (format[i])
      {
      case ASSH_BIGNUM_STEMP:
        tmp[j].secret = 1;
      case ASSH_BIGNUM_TEMP:
        args[i] = &tmp[j];
        j++;
        break;
      case ASSH_BIGNUM_MT:
        mt[k].bits = 0;
        mt[k].r2 = NULL;
        args[i] = &mt[k];
        k++;
        break;
      case ASSH_BIGNUM_SIZE:
        args[i] = (void*)va_arg(ap, size_t);
        break;
      default:
        args[i] = va_arg(ap, void *);
      }

  while (1)
    {
      uint32_t opc = ops[pc];
      enum assh_bignum_opcode_e op = opc >> 26;
      uint_fast8_t oa = (opc >> 20) & 0x3f;
      uint_fast8_t ob = (opc >> 14) & 0x3f;
      uint_fast8_t oc = (opc >> 6) & 0xff;
      uint_fast8_t od = opc & 0x3f;
      uint_fast32_t value = (opc >> 6) & 0xfffff;

#if defined(CONFIG_ASSH_DEBUG) && defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
      const char *opnames[] = ASSH_BIGNUM_OP_NAMES;
      ASSH_DEBUG("exec=%p, pc=%u, op=%s, a=%u, b=%u, c=%u, d=%u, value=%u\n",
                 ops, pc, opnames[op], oa, ob, oc, od, value);
#endif

      pc++;
      switch (op)
        {
        case ASSH_BIGNUM_OP_END:
          goto end;

        case ASSH_BIGNUM_OP_MOVE:
          ASSH_ERR_GTO(assh_bignum_builtin_convert(c,
                    format[od], format[oc], args[od], args[oc]), err_sc);
          break;

        case ASSH_BIGNUM_OP_SIZER:
        case ASSH_BIGNUM_OP_SIZE: {
          size_t b, i;
          ASSH_ERR_GTO(assh_bignum_size_of_data(format[ob], args[ob],
                                                NULL, NULL, &b), err_sc);
          if (op == ASSH_BIGNUM_OP_SIZE)
            {
              struct assh_bignum_s *dst = args[oa];
              dst->bits = ((od >= 32) ? (b << (od - 32))
                           : (b >> (32 - od))) + (intptr_t)(int8_t)oc;
            }
          else
            for (i = oa; i <= oc; i++) 
              {
                struct assh_bignum_s *dst = args[i];
                dst->bits = b;
              }
          break;
        }

        case ASSH_BIGNUM_OP_SUB:
        case ASSH_BIGNUM_OP_ADD: {
          struct assh_bignum_s *dst = args[oa];
          ASSH_ERR_GTO(assh_bignum_realloc(c, dst), err_sc);
          assh_bnword_t mask = (assh_bnword_t)(op == ASSH_BIGNUM_OP_ADD) - 1;
          if (od != ASSH_BOP_NOREG)
            ASSH_ERR_GTO(assh_bignum_addsub(dst, args[ob], args[oc], args[od], mask), err_sc);
          else
            ASSH_ERR_GTO(assh_bignum_addsub(dst, args[ob], args[oc], NULL, mask), err_sc);
          break;
        }

        case ASSH_BIGNUM_OP_MUL: {
          struct assh_bignum_s *dst = args[oa];
          struct assh_bignum_s *src1 = args[ob];
          struct assh_bignum_s *src2 = args[oc];
          ASSH_ERR_GTO(assh_bignum_realloc(c, dst), err_sc);
          if (od == ASSH_BOP_NOREG)
            ASSH_ERR_GTO(assh_bignum_mul(c, dst, src1, src2), err_sc);
          else if (format[od] == ASSH_BIGNUM_MT)
            ASSH_ERR_GTO(assh_bignum_mul_mod_mt(c, dst, src1, src2, args[od]), err_sc);
          else
            ASSH_ERR_GTO(assh_bignum_mul_mod(c, dst, src1, src2, args[od]), err_sc);
          break;
        }

        case ASSH_BIGNUM_OP_EXPM: {
          struct assh_bignum_s *dst = args[oa];
          struct assh_bignum_s *src1 = args[ob];
          struct assh_bignum_s *src2 = args[oc];
          assert(format[od] == ASSH_BIGNUM_MT);
          ASSH_ERR_GTO(assh_bignum_realloc(c, dst), err_sc);
          ASSH_ERR_GTO(assh_bignum_expmod_mt(c, dst, src1, src2, args[od]), err_sc);
          break;
        }

        case ASSH_BIGNUM_OP_MTINIT: {
          struct assh_bignum_s *mod = args[od];
          assert(format[oc] == ASSH_BIGNUM_MT);
          ASSH_ERR_GTO(assh_bignum_mt_init(c, args[oc], mod), err_sc);
          break;
        }

        case ASSH_BIGNUM_OP_MTFROM:
        case ASSH_BIGNUM_OP_MTTO: {
          uint_fast8_t i;
          for (i = 0; i < oa; i++)
            {
              struct assh_bignum_s *dst = args[ob + i];
              struct assh_bignum_s *src = args[oc + i];
              ASSH_ERR_GTO(assh_bignum_realloc(c, dst), err_sc);
              ASSH_ERR_GTO(assh_bignum_mt_convert(c, op == ASSH_BIGNUM_OP_MTTO,
                                                  args[od], dst, src), err_sc);
            }
          break;
        }

        case ASSH_BIGNUM_OP_DIV: {
          struct assh_bignum_s *dsta = NULL, *dstb = NULL;
          struct assh_bignum_s *src1 = args[oc], *src2 = args[od];
          if (oa != ASSH_BOP_NOREG)
            {
              dsta = args[oa];
              ASSH_ERR_GTO(assh_bignum_realloc(c, dsta), err_sc);
            }
          if (ob != ASSH_BOP_NOREG)
            {
              dstb = args[ob];
              ASSH_ERR_GTO(assh_bignum_realloc(c, dstb), err_sc);
            }
          ASSH_ERR_GTO(assh_bignum_div(c, dstb, dsta, src1, src2), err_sc);
          break;
        }

        case ASSH_BIGNUM_OP_INV: {
          struct assh_bignum_s *dst = args[ob];
          struct assh_bignum_s *src1 = args[oc];
          ASSH_ERR_GTO(assh_bignum_realloc(c, dst), err_sc);
          if (format[od] == ASSH_BIGNUM_MT)
            ASSH_ERR_GTO(assh_bignum_modinv_mt(c, dst, src1, args[od]), err_sc);
          else
            ASSH_ERR_GTO(assh_bignum_modinv(c, dst, src1, args[od]), err_sc);
          break;
        }

        case ASSH_BIGNUM_OP_GCD: {
          struct assh_bignum_s *dst = args[ob];
          struct assh_bignum_s *src1 = args[oc], *src2 = args[od];
          ASSH_ERR_GTO(assh_bignum_realloc(c, dst), err_sc);
          ASSH_ERR_GTO(assh_bignum_gcd(c, dst, src1, src2), err_sc);
          break;
        }

        case ASSH_BIGNUM_OP_SHR:
        case ASSH_BIGNUM_OP_SHL: {
          struct assh_bignum_s *dst = args[oa];
          struct assh_bignum_s *src = args[ob];
          size_t b = 0;
          ASSH_CHK_GTO(dst->bits != src->bits, ASSH_ERR_OUTPUT_OVERFLOW, err_sc);
          if (od != ASSH_BOP_NOREG)
            {
              /* FIXME constant time ? */
              ASSH_ERR_GTO(assh_bignum_size_of_data(format[od], args[od],
                                                    NULL, NULL, &b), err_sc);
            }
          ASSH_ERR_GTO(assh_bignum_realloc(c, dst), err_sc);
          switch (op)
            {
            case ASSH_BIGNUM_OP_SHR:
              ASSH_ERR_GTO(assh_bignum_rshift(dst, src, b + oc - 128), err_sc);
              break;
            case ASSH_BIGNUM_OP_SHL:
              ASSH_ERR_GTO(assh_bignum_lshift(dst, src, b + oc - 128), err_sc);
              break;
            default:
              abort();
            }
          break;
        }

        case ASSH_BIGNUM_OP_RAND: {
          struct assh_bignum_s *dst = args[oa];
          ASSH_ERR_GTO(assh_bignum_realloc(c, dst), err_sc);
          ASSH_ERR_GTO(assh_bignum_rand(c, dst,
                         ob == ASSH_BOP_NOREG ? NULL : args[ob],
                         oc == ASSH_BOP_NOREG ? NULL : args[oc],
                         od), err_sc);
          break;
        }

        case ASSH_BIGNUM_OP_CMP: {
          int r = 0;
          if (ob != oa)
            {
              struct assh_bignum_s *src1 = args[oa];
              struct assh_bignum_s *src2 = args[ob];
              r = assh_bignum_cmp(src1, src2);
            }
          switch (od)
            {
            case 0:             /* cmpeq */
              r = r != 0;
              break;
            case 1:             /* cmpne */
              r = r == 0;
              break;
            case 2:             /* cmplt */
              r = r >= 0;
              break;
            case 3:             /* cmplteq */
              r = r > 0;
              break;
            }
          if (r)
            ASSH_CHK_GTO(oc == 128, ASSH_ERR_NUM_COMPARE_FAILED, err_sc);
          else
            pc += oc - 128;
          break;
        }

        case ASSH_BIGNUM_OP_UINT: {
          struct assh_bignum_s *dst = args[od];
          ASSH_ERR_GTO(assh_bignum_realloc(c, dst), err_sc);
          ASSH_ERR_GTO(assh_bignum_from_uint(dst, value), err_sc);
          ASSH_CHK_GTO(dst->n == NULL, ASSH_ERR_MEM, err_sc);
          break;
        }

        case ASSH_BIGNUM_OP_PRINT: {
#ifdef CONFIG_ASSH_DEBUG
          struct assh_bignum_s *src = args[od];
          char id[5];
          size_t i;
          id[4] = 0;
          assh_store_u32le((uint8_t*)id, oc);
          fprintf(stderr, "[pc=%u, id=%s, type=%c] ", pc, id, format[od]);
          switch (format[od])
            {
            case ASSH_BIGNUM_NATIVE:
            case ASSH_BIGNUM_STEMP:
            case ASSH_BIGNUM_TEMP:
              fprintf(stderr, "[bits=%zu] ", src->bits);
              if (src->n != NULL)
                assh_bignum_dump(src->n, assh_bignum_words(src->bits));
              else
                fprintf(stderr, "NULL\n");
              break;
            case ASSH_BIGNUM_SIZE:
              fprintf(stderr, "%u\n", (unsigned)(uintptr_t)args[od]);
              break;
            }
#endif
          break;
        }

        }
    }

 end:
  err = ASSH_OK;
 err_sc:;

  /* release numbers */
  for (i = 0; i < tlen; i++)
    if (tmp[i].n != NULL)
      assh_free(c, tmp[i].n, ASSH_ALLOC_SECUR);

  for (i = 0; i < mlen; i++)
    if (mt[i].r2 != NULL)
      assh_free(c, mt[i].r2, ASSH_ALLOC_INTERNAL);

  return err;
}

static ASSH_BIGNUM_RELEASE_FCN(assh_bignum_builtin_release)
{
  assh_free(ctx, bn->n, ASSH_ALLOC_SECUR);
}

const struct assh_bignum_algo_s assh_bignum_builtin =
{
  .name = "builtin",
  .f_bytecode = assh_bignum_builtin_bytecode,
  .f_convert = assh_bignum_builtin_convert,
  .f_release = assh_bignum_builtin_release,
};

