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

#ifndef CONFIG_ASSH_BIGNUM_WORD
# define CONFIG_ASSH_BIGNUM_WORD 32
#endif

#if CONFIG_ASSH_BIGNUM_WORD == 8
/* 8 bits big number word is useful for testing bignum algorithms.
   Because there are fewer possible word values, it will test more
   corner cases in a short time. */
typedef uint8_t assh_bnword_t;
typedef int8_t assh_bnsword_t;
typedef uint16_t assh_bnlong_t;
typedef int16_t assh_bnslong_t;
#define ASSH_BN_FMT "%02x"
#define ASSH_BN_LFSR 0xb8
#define assh_bn_clz(x) assh_ct_clz8((assh_bnword_t)x)
#define assh_bn_ctz(x) assh_ct_ctz8((assh_bnword_t)x)

#elif CONFIG_ASSH_BIGNUM_WORD == 16
typedef uint16_t assh_bnword_t;
typedef int16_t assh_bnsword_t;
typedef uint32_t assh_bnlong_t;
typedef int32_t assh_bnslong_t;
#define ASSH_BN_FMT "%04x"
#define ASSH_BN_LFSR 0xb008
#define assh_bn_clz(x) assh_ct_clz16((assh_bnword_t)x)
#define assh_bn_ctz(x) assh_ct_ctz16((assh_bnword_t)x)

#elif CONFIG_ASSH_BIGNUM_WORD == 32
typedef uint32_t assh_bnword_t;
typedef int32_t assh_bnsword_t;
typedef uint64_t assh_bnlong_t;
typedef int64_t assh_bnslong_t;
#define ASSH_BN_FMT "%08x"
#define ASSH_BN_LFSR 0x80200003
#define assh_bn_clz(x) assh_ct_clz32((assh_bnword_t)x)
#define assh_bn_ctz(x) assh_ct_ctz32((assh_bnword_t)x)

#elif CONFIG_ASSH_BIGNUM_WORD == 64
typedef uint64_t assh_bnword_t;
typedef int64_t assh_bnsword_t;
typedef unsigned __int128 assh_bnlong_t;
typedef signed __int128 assh_bnslong_t;
#define ASSH_BN_FMT "%016llx"
#define ASSH_BN_LFSR 0xd800000000000000ULL
#define assh_bn_clz(x) assh_ct_clz64((assh_bnword_t)x)
#define assh_bn_ctz(x) assh_ct_ctz64((assh_bnword_t)x)

#endif

#define ASSH_BN_WORDMAX (assh_bnword_t)-1LL

/** Minimum number of words for karatsuba to switch to school mul. */
#define ASSH_BIGNUM_KARATSUBA_THRESHOLD 32

/** @This specifies the number of bits in a big number word. */
#define ASSH_BIGNUM_W (sizeof(assh_bnword_t) * 8)

struct assh_bignum_scratch_s
{
  uint16_t words;
  uint16_t words_s;
  assh_bnword_t *n;
  assh_bnword_t *n_s;
};

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_scratch_expand(struct assh_context_s *c, assh_bnword_t **r,
                           struct assh_bignum_scratch_s *sc,
                           size_t words, assh_bool_t secure)
{
  assh_error_t err;

  if (secure)
    {
      if (sc->words_s < words)
        {
          ASSH_ERR_RET(assh_realloc(c, (void**)&sc->n_s,
            words * sizeof(assh_bnword_t), ASSH_ALLOC_SECUR));
          sc->words_s = words;
        }
      *r = sc->n_s;
    }
  else
    {
      if (sc->words < words)
        {
          ASSH_ERR_RET(assh_realloc(c, (void**)&sc->n,
            words * sizeof(assh_bnword_t), ASSH_ALLOC_INTERNAL));
          sc->words = words;
        }
      *r = sc->n;
    }

  return ASSH_OK;
}

struct assh_bignum_mt_s
{
  struct assh_bignum_s mod;
  assh_bnword_t n0;
};

ASSH_FIRST_FIELD_ASSERT(assh_bignum_mt_s, mod);

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

static inline assh_bnword_t assh_bignum_eqzero(assh_bnword_t a)
{
  /* return !a in constant time */
  return ((assh_bnword_t)(~a & (a - 1)) >> (ASSH_BIGNUM_W - 1)) & 1;
}

static inline assh_bnword_t assh_bignum_lt(assh_bnword_t a, assh_bnword_t b)
{
  /* return a < b in constant time */
  return (((assh_bnlong_t)a - (assh_bnlong_t)b) >> ASSH_BIGNUM_W) & 1;
}

static assh_bnword_t assh_bnword_egcd(assh_bnword_t a, assh_bnword_t b,
                                      assh_bnword_t q)
{
  uint_fast8_t sh, i;
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

static inline assh_bnword_t assh_bnword_modinv(assh_bnword_t a, assh_bnword_t b)
{
  assh_bnword_t q = assh_bnword_egcd(a, b, 0);
  q += ((assh_bnsword_t)q >> 31) & b;
  return q;
}

static inline size_t
assh_bignum_words(size_t bits)
{
  return (((bits - 1) | (ASSH_BIGNUM_W - 1)) + 1) / ASSH_BIGNUM_W;
}

static void
assh_bignum_cmove(assh_bnword_t *a, const assh_bnword_t *b,
                  size_t l, assh_bool_t c)
{
  assh_bnword_t m = ~((assh_bnword_t)c - 1);
  size_t i;

  for (i = 0; i < l; i++)
    a[i] = (b[i] & m) | (a[i] & ~m);
}

static void
assh_bignum_cswap(assh_bnword_t *an, assh_bnword_t *bn,
                  size_t l, assh_bool_t c)
{
  assh_bnword_t m = ~((assh_bnword_t)c - 1);
  size_t i;

  for (i = 0; i < l; i++)
    {
      an[i] ^= bn[i] & m;
      bn[i] ^= an[i] & m;
      an[i] ^= bn[i] & m;
    }
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

  ASSH_CHK_RET(dst->bits != src->bits && x != 0,
               ASSH_ERR_OUTPUT_OVERFLOW);

  return ASSH_OK;
}

/* This function stores the value of a big number into a buffer. The
   destination format can be: ASSH_BIGNUM_MPINT, ASSH_BIGNUM_STRING,
   ASSH_BIGNUM_LSB_RAW, ASSH_BIGNUM_MSB_RAW. The buffer must be large
   enough to hold the value. */
static void
assh_bignum_to_buffer(const struct assh_bignum_s *bn,
                      uint8_t *in, uint8_t **end,
                      enum assh_bignum_fmt_e format)
{
  size_t i, l = ASSH_ALIGN8(bn->bits) / 8;
  assh_bnword_t *n = bn->n;
  uint8_t *m = in;
  assh_bool_t skip_zero = 0;

  switch (format)
    {
    case ASSH_BIGNUM_ASN1:
      m -= 2;
    case ASSH_BIGNUM_MPINT:
      skip_zero = 1;
    case ASSH_BIGNUM_STRING:
      m += 4;
    default:
      break;
    }

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
        if (skip_zero && p == m)
          {
            if (!b)
              continue;
            if (b & 0x80)
              *p++ = 0;
          }
        *p++ = b;
      }

  switch (format)
    {
    case ASSH_BIGNUM_STRING:
    case ASSH_BIGNUM_MPINT:
      assh_store_u32(in, p - m);
      break;
    case ASSH_BIGNUM_ASN1: {
      uint8_t h_[4], *h = h_;
      if (p == m)
        *p++ = 0;
      l = p - m;
      assh_append_asn1(&h, 0x02, l);
      i = h - h_;
      if (i > 2)
        memmove(m + i - 2, m, l);
      memcpy(in, h_, i);
      p = in + i + l;
    }
    default:
      break;
    }

  if (end)
    *end = p;
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
          assh_bnword_t mask = ASSH_BN_WORDMAX
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

static assh_bool_t assh_bignum_eq_uint(const assh_bnword_t a,
                                       const assh_bnword_t *b, size_t bl)
{
  size_t i;
  assh_bnword_t r = b[0] ^ a;

  for (i = 1; i < bl; i++)
    r |= b[i];

  return assh_bignum_eqzero(r);
}

static assh_bool_t assh_bignum_eq(const assh_bnword_t *a, size_t al,
                                  const assh_bnword_t *b, size_t bl)
{
  size_t i;
  assh_bnword_t r = 0;

  for (i = 0; i < al && i < bl; i++)
    r |= a[i] ^ b[i];
  for (; i < al; i++)
    r |= a[i];
  for (; i < bl; i++)
    r |= b[i];

  return assh_bignum_eqzero(r);
}

enum assh_bignum_cmp_result_e {
  ASSH_BIGNUM_CMP_GT = 1,
  ASSH_BIGNUM_CMP_LT = 2,
};

static enum assh_bignum_cmp_result_e
assh_bignum_cmp(const struct assh_bignum_s *a,
                const struct assh_bignum_s *b)
{
  size_t al = assh_bignum_words(a->bits);
  size_t bl = assh_bignum_words(b->bits);
  size_t i, l = ASSH_MIN(al, bl);
  assh_bnword_t *an = a->n, *bn = b->n;
  int_fast8_t lt = 0, gt = 0, eq;

  for (i = 0; i < l; i++)
    {
      assh_bnword_t ax = an[i];
      assh_bnword_t bx = bn[i];
      eq = assh_bignum_eqzero(ax ^ bx);
      lt = assh_bignum_lt(ax, bx) | (lt & eq);
      gt = assh_bignum_lt(bx, ax) | (gt & eq);
    }
  for (; i < bl; i++)
    {
      assh_bnword_t bx = bn[i];
      eq = assh_bignum_eqzero(bx);
      lt = (eq ^ 1) | (lt & eq);
      gt = (gt & eq);
    }
  for (; i < al; i++)
    {
      assh_bnword_t ax = an[i];
      eq = assh_bignum_eqzero(ax);
      lt = (lt & eq);
      gt = (eq ^ 1) | (gt & eq);
    }

  return gt | (lt << 1);
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

  if (l == 0)
    return ASSH_OK;

  ASSH_ERR_RET(c->prng->f_get(c, (uint8_t*)n,
                 l * sizeof(assh_bnword_t), quality));

  while (1)
    {
      if (bn->bits % ASSH_BIGNUM_W)
        n[l - 1] &= ASSH_BN_WORDMAX >> (ASSH_BIGNUM_W - bn->bits % ASSH_BIGNUM_W);

      if ((min == NULL || (assh_bignum_cmp(bn, min) & ASSH_BIGNUM_CMP_GT)) &&
          (max == NULL || (assh_bignum_cmp(bn, max) & ASSH_BIGNUM_CMP_LT)))
        break;

      for (i = l; --i != 0; )
        n[i] = n[i - 1];

      ASSH_ERR_RET(c->prng->f_get(c, (uint8_t*)n,
                     sizeof(assh_bnword_t), quality));
    }

  return ASSH_OK;
}

/*********************************************************************** shift */

static assh_error_t ASSH_WARN_UNUSED_RESULT
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

static assh_error_t ASSH_WARN_UNUSED_RESULT
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

/*********************************************************************** add, sub */

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_addsub(struct assh_bignum_s *dst,
                   const struct assh_bignum_s *a,
                   const struct assh_bignum_s *b,
                   assh_bnword_t smask /* 0:add, -1:sub */)
{
  assh_error_t err;
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
  ASSH_CHK_RET(t >> l != 0, ASSH_ERR_NUM_OVERFLOW);

  return ASSH_OK;
}

/*********************************************************************** div, modinv */

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

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_div_euclidean(assh_bnword_t * __restrict__ r,
                          uint_fast32_t r_len,
                          assh_bnword_t * __restrict__ d,
                          uint_fast32_t d_len,
                          const assh_bnword_t * __restrict__ b,
                          uint_fast32_t b_len)
{
  assh_error_t err;
  uint_fast32_t az, al, bz, bl, da, sa;
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
                struct assh_bignum_scratch_s *sc,
                struct assh_bignum_s *r,
                struct assh_bignum_s *d,
                const struct assh_bignum_s *a,
                const struct assh_bignum_s *b)
{
  assh_error_t err;

  assert(r != d && a != d && b != d && b != r);
  assert(!a->secret && !b->secret);
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
      ASSH_ERR_RET(assh_bignum_scratch_expand(ctx, &rn, sc, rl,
                                              a->secure | b->secure));
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

  ASSH_ERR_RET(assh_bignum_div_euclidean(rn, rl, dn, dl, b->n, bl));

  if (r != NULL && r->bits < a->bits)
    memcpy(r->n, rn, assh_bignum_words(r->bits) * sizeof(assh_bnword_t));

  return ASSH_OK;
}

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_modinv(struct assh_context_s *ctx,
                   struct assh_bignum_scratch_s *sc,
                   struct assh_bignum_s *u,
                   const struct assh_bignum_s *a,
                   const struct assh_bignum_s *m)
{
  assh_error_t err;

  assert(u != a && u != m);
  assert(!a->secret && !m->secret);
  assert(a->bits <= m->bits);
  assert(u->bits >= a->bits);

  size_t ul = assh_bignum_words(u->bits);
  size_t al = assh_bignum_words(a->bits);
  size_t ml = assh_bignum_words(m->bits);

  assh_bnword_t *r;
  ASSH_ERR_RET(assh_bignum_scratch_expand(ctx, &r, sc, ml * 3,
                                          a->secure | m->secure));

  assh_bnword_t * __restrict__ un = u->n;
  const assh_bnword_t * __restrict__ an = a->n;
  const assh_bnword_t * __restrict__ mn = m->n;

  assh_bnword_t *p = r + ml;
  assh_bnword_t *v = r + ml * 2;

  memcpy(r, mn, ml * sizeof(assh_bnword_t));
  memcpy(p, an, al * sizeof(assh_bnword_t));
  memset(p + al, 0, (ml - al) * sizeof(assh_bnword_t));

  ASSH_ERR_RET(assh_bignum_div_euclidean(p, al, NULL, 0, r, ml));

  memset(v, 0, ml * sizeof(assh_bnword_t));
  memset(un + 1, 0, (ul - 1) * sizeof(assh_bnword_t));
  un[0] = 1;

  uint_fast32_t rl = ml, pl = ml;
  assh_bnword_t *xr = r, *xp = p, *xu = un, *xv = v;

  ASSH_CHK_RET(assh_bignum_div_strip(&rl, xr) ||
	       assh_bignum_div_strip(&pl, xp) ||
	       rl < pl, ASSH_ERR_NUM_OVERFLOW);

  while (1)
    {
      uint_fast32_t az, as, bz, bs, da, sa;
      assh_bnword_t at, bt, q;

      /* find factor */
      assh_bignum_div_clz(rl, xr, &az, &as, &at);
      assh_bignum_div_clz(pl, xp, &bz, &bs, &bt);
      ASSH_CHK_RET(as < bs, ASSH_ERR_NUM_OVERFLOW);

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

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_gcd(struct assh_context_s *ctx,
                struct assh_bignum_scratch_s *sc,
                struct assh_bignum_s *g,
                const struct assh_bignum_s *a,
                const struct assh_bignum_s *b)
{
  assh_error_t err;

  assert(g != a && g != b);
  assert(g->bits >= a->bits || g->bits >= b->bits);
  assert(!a->secret && !b->secret);

  size_t al = assh_bignum_words(a->bits);
  size_t bl = assh_bignum_words(b->bits);

  size_t l = al > bl ? al : bl;
  assh_bnword_t *xr;

  ASSH_ERR_RET(assh_bignum_scratch_expand(ctx, &xr, sc, l,
                                          a->secure | b->secure));

  assh_bnword_t * __restrict__ gn = g->n;
  const assh_bnword_t * __restrict__ an = a->n;
  const assh_bnword_t * __restrict__ bn = b->n;

  assh_bnword_t *xp = gn;

  /* use largest buffer between scratch and result for the largest
     input number, the gcd value will be available in both buffers
     at the end */
  if (al < bl)
    ASSH_SWAP(xr, xp);

  memmove(xr, an, al * sizeof(assh_bnword_t));
  memmove(xp, bn, bl * sizeof(assh_bnword_t));

  uint_fast32_t rl = al, pl = al;

  ASSH_CHK_RET(assh_bignum_div_strip(&rl, xr) ||
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
      ASSH_CHK_RET(al < bl, ASSH_ERR_NUM_OVERFLOW);

      q = assh_bignum_div_factor(at, bt, al - bl, &sa, &da);

      assh_bignum_div_update_r(pl, xp, rl, xr, q, sa, da);

      ASSH_CHK_RET(assh_bignum_div_strip(&rl, xr),
                   ASSH_ERR_NUM_OVERFLOW);
    }

  return ASSH_OK;
}

/*********************************************************************** mul */

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

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_mul(struct assh_context_s *ctx,
                struct assh_bignum_scratch_s *sc,
                struct assh_bignum_s *r,
                const struct assh_bignum_s *a,
                const struct assh_bignum_s *b)
{
  assh_error_t err;

  assert(r != a && r != b);

  ASSH_CHK_RET(r->bits < a->bits + b->bits, ASSH_ERR_OUTPUT_OVERFLOW);

  size_t rl = assh_bignum_words(r->bits);
  size_t al = assh_bignum_words(a->bits);
  size_t bl = assh_bignum_words(b->bits);
  size_t l = al + bl;
  size_t sl = rl < l ? l : 0;
  assh_bnword_t *s, *x = r->n;

#if !defined(__OPTIMIZE_SIZE__)
  if (al == bl && !(al & 1))
    {
      ASSH_ERR_RET(assh_bignum_scratch_expand(ctx, &s, sc, sl
                     + ASSH_KARA_SCRATCH(al), r->secret | a->secure | b->secure));
      if (sl)
        x = s;
      assh_bignum_karatsuba(x, a->n, b->n, s + sl, al);
    }
  else
#endif
    {
      if (sl)
        {
          ASSH_ERR_RET(assh_bignum_scratch_expand(ctx, &s, sc, sl,
                                                  r->secret | a->secure | b->secure));
          x = s;
        }
      assh_bignum_school_mul(x, a->n, al, b->n, bl);
    }

  if (sl)
    memcpy((assh_bnword_t*)r->n, s, rl * sizeof(assh_bnword_t));
  else
    memset((assh_bnword_t*)r->n + l, 0, (rl - l) * sizeof(assh_bnword_t));

  return ASSH_OK;
}

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_mul_mod(struct assh_context_s *ctx,
                    struct assh_bignum_scratch_s *sc,
                    struct assh_bignum_s *r,
                    const struct assh_bignum_s *a,
                    const struct assh_bignum_s *b,
                    const struct assh_bignum_s *m)
{
  assh_error_t err;

  assert(!a->secret && !b->secret && !m->secret);

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

  assh_bnword_t *x;
  ASSH_ERR_RET(assh_bignum_scratch_expand(ctx, &x, sc, scratch_len,
                                          a->secure | b->secure | m->secure));

#if !defined(__OPTIMIZE_SIZE__)
  if (use_kara)
    assh_bignum_karatsuba(x, a->n, b->n, x + l, al);
  else
#endif
    assh_bignum_school_mul(x, a->n, al, b->n, bl);

  ASSH_ERR_RET(assh_bignum_div_euclidean(x, l, NULL, 0, m->n, ml));

  memcpy(r->n, x, ml * sizeof(assh_bnword_t));
  memset(r->n + ml, 0, (rl - ml) * sizeof(assh_bnword_t));

  return ASSH_OK;
}

/********************************************************* montgomery */

static void
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

static void
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

static inline assh_bnword_t assh_bnword_mt_modinv(assh_bnword_t a)
{
  uint_fast8_t sh = assh_bn_clz(a);
  return assh_bnword_egcd(a, -(a << sh), -((assh_bnword_t)1 << sh));
}

static void
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

static void
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

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_mt_init(struct assh_context_s *c,
                    struct assh_bignum_mt_s *mt,
                    const struct assh_bignum_s *mod)
{
  assh_error_t err;

  assert(!mod->secret);

  /* check modulus is odd */
  ASSH_CHK_RET(!(*(assh_bnword_t*)mod->n & 1), ASSH_ERR_NUM_OVERFLOW);

  size_t ml = assh_bignum_words(mod->bits);

  assh_bnword_t *m = mt->mod.n;

  if (m == NULL || mt->mod.bits < mod->bits)
    {
      if (m != NULL)
        assh_free(c, m);
      mt->mod.n = NULL;
      ASSH_ERR_RET(assh_alloc(c, (ml * 3 + 1) * sizeof(assh_bnword_t),
                              ASSH_ALLOC_INTERNAL, (void**)&m));
      mt->mod.n = m;
    }

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

  ASSH_ERR_GTO(assh_bignum_div_euclidean(r2, ml * 2 + 1, NULL, 0, m, ml), err_);

  /* compute 1 in montgomery representation */
  assh_bnword_t *r1 = m + ml * 2;

  for (i = 0; i < ml; i++)
    r1[i] = 0;
  r1[i] = 1;

  ASSH_ERR_GTO(assh_bignum_div_euclidean(r1, ml + 1, NULL, 0, m, ml), err_);

  //  assh_hexdump("one", one, ml * sizeof(assh_bnword_t));

  return ASSH_OK;

 err_:
  mt->mod.n = NULL;
  assh_free(c, m);
  return err;
}

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_mt_convert(struct assh_context_s *ctx,
                       struct assh_bignum_scratch_s *sc,
                       assh_bool_t fwd,
                       const struct assh_bignum_mt_s *mt,
                       struct assh_bignum_s *r,
                       const struct assh_bignum_s *a)
{
  assh_error_t err;

  assert(mt->mod.bits == a->bits && mt->mod.bits == r->bits);
  size_t ml = assh_bignum_words(mt->mod.bits);
  assh_bnword_t *t = r->n;

  if (r == a)
    ASSH_ERR_RET(assh_bignum_scratch_expand(ctx, &t, sc, ml, r->secret | a->secure));

  if (fwd)
    {
      assh_bnword_t *r2 = (assh_bnword_t*)mt->mod.n + ml;
      assh_bignum_mt_mul(mt, t, r2, a->n);
    }
  else
    assh_bignum_mt_reduce(mt, t, a->n);

  if (r == a)
    memcpy(r->n, t, ml * sizeof(assh_bnword_t));

  return ASSH_OK;
}

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_mul_mod_mt(struct assh_context_s *ctx,
                       struct assh_bignum_scratch_s *sc,
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
      assh_bnword_t *rn;
      ASSH_ERR_RET(assh_bignum_scratch_expand(ctx, &rn, sc, rl,
                     r->secret | a->secure | b->secure));
      assh_bignum_mt_mul(mt, rn, a->n, b->n);
      memcpy(r->n, rn, rl * sizeof(assh_bnword_t));
    }
  else
    {
      assh_bignum_mt_mul(mt, r->n, a->n, b->n);
    }

  return err;
}

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_expmod_mt(struct assh_context_s *ctx,
                      struct assh_bignum_scratch_s *sc,
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

  assh_bnword_t *sq;
  ASSH_ERR_RET(assh_bignum_scratch_expand(ctx, &sq, sc, ml * 2,
                 r->secret | a->secure | b->secure));

  assh_bnword_t *tmp = sq + ml;
  assh_bnword_t *bn = b->n;
  assh_bnword_t *rn = r->n;
  uint_fast32_t i = 0, j = b->bits;

  memcpy(sq, a->n, ml * sizeof(assh_bnword_t));

  assh_bnword_t *r1 = (assh_bnword_t*)mt->mod.n + 2 * ml;
  memcpy(rn, r1, ml * sizeof(assh_bnword_t));

  if (!b->secret)
    {
      assh_bnword_t t;
      j = assh_bignum_words(b->bits);
      while (j && !(t = bn[j - 1]))
        j--;
      if (!j)
        return ASSH_OK;
      j = j * ASSH_BIGNUM_W - assh_bn_clz(t);
    }

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

/* compute inverse using the Fermat little theorem */
static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_modinv_mt(struct assh_context_s *ctx,
                      struct assh_bignum_scratch_s *sc,
                      struct assh_bignum_s *r,
                      const struct assh_bignum_s *a,
                      const struct assh_bignum_mt_s *mt)
{
  assh_error_t err;

  assert(mt->mod.bits == a->bits &&
         mt->mod.bits == r->bits);

  /* prime modulus as been checked as non-secret in mt_init */

  size_t ml = assh_bignum_words(mt->mod.bits);

  assh_bnword_t *sq;
  ASSH_ERR_RET(assh_bignum_scratch_expand(ctx, &sq, sc, ml * 2, r->secret | a->secure));

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

      if ((p >> (i % ASSH_BIGNUM_W)) & 1)
        {
          assh_bignum_mt_mul(mt, tmp, rn, sq);
          memcpy(rn, tmp, ml * sizeof(assh_bnword_t));
        }

      if (++i == mt->mod.bits)
        break;

      assh_bignum_mt_mul(mt, tmp, sq, sq);
      memcpy(sq, tmp, ml * sizeof(assh_bnword_t));
    }

  return ASSH_OK;
}

#include "bignum_builtin_primes.h"

struct assh_bignum_sieve_s
{
  uint16_t offsets[ASSH_SIEVE_PRIMES];
};

/* compute bignum modulo a small prime */
static uint16_t ASSH_WARN_UNUSED_RESULT
assh_bignum_sieve_mod(const assh_bnword_t *n, size_t l, uint16_t p)
{
  uint32_t o = n[0] % p;
  uint16_t m = ASSH_BN_WORDMAX % p + 1;
  uint16_t p2m = m;
  size_t i;

  for (i = 1; i < l; i++)
    {
      /* prevent overflow */
      if ((i & 63) == 0)
        o %= p;

      /* update with the next big number word */
      o += (uint32_t)m * (n[i] % p);
      m = ((uint32_t)m * p2m) % p;
    }

  return o % p;
}

/* compute offsets of prime number sieve */
static void
assh_bignum_sieve_init(struct assh_bignum_sieve_s * __restrict__ s,
                       const struct assh_bignum_s *bn,
                       const struct assh_bignum_s *step)
{
  size_t nl = assh_bignum_words(bn->bits);
  assh_bnword_t *n = bn->n;
  size_t i;

  for (i = 0; i < ASSH_SIEVE_PRIMES; i++)
    {
      uint16_t p = assh_primes[i];
      uint16_t o = assh_bignum_sieve_mod(bn->n, nl, p);
      uint16_t v = 1;

      /* compute offset so that (bn + step * offset) % p == 0 */

      if (step != NULL)         /* step != 1 */
        {
          /* solve linear congruence */
          size_t sl = assh_bignum_words(step->bits);
          uint16_t m = assh_bignum_sieve_mod(step->n, sl, p);
          v = assh_bnword_modinv(m, p);
        }

      o = (v * (p - o)) % p;

      /* keep offset + bignum odd */
      o += p * ((o ^ n[0] ^ 1) & 1);

      s->offsets[i] = o;
    }
}

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_miller_rabin(struct assh_context_s *c,
                         struct assh_bignum_scratch_s *sc,
                         assh_bnword_t *rn,
                         const struct assh_bignum_s *bn,
                         size_t rounds, assh_bool_t *result)
{
  assh_error_t err;
  size_t l = assh_bignum_words(bn->bits);
  assh_bnword_t *n = bn->n;  
  size_t i;

  assert(bn->bits > 0 && (n[0] & 1));
  *result = 0;

  assh_bnword_t *an;
  ASSH_ERR_RET(assh_bignum_scratch_expand(c, &an, sc, l * 4, bn->secret | bn->secure));

  assh_bnword_t *cn = an + l;
  assh_bnword_t *zn = an + l * 2;
  assh_bnword_t *tn = an + l * 3;

  /* compute c = n - 1 */
  assh_bnlong_t t = 0;
  for (i = 0; i < l; i++)
    cn[i] = t = (assh_bnlong_t)n[i] + ASSH_BN_WORDMAX + (t >> ASSH_BIGNUM_W);

  /* b = ctz(c) */
  size_t b = 0;
  while (1)
    {
      ASSH_CHK_RET(b >= l, ASSH_ERR_NUM_OVERFLOW);
      if (cn[b])
        break;
      b++;
    }
  b = b * ASSH_BIGNUM_W + assh_bn_ctz(cn[b]);
  assert(b > 0);

  /* Initialize a temporary montgomery context. We do not need to
     compute r2 for conversion to montgomery representation because
     the random base a is assumed to be in montgomery representation.
     We do not need to compute r1 because the LSB of the exponent
     is always set so we can skip the first multiply_by_one operation. */
  struct assh_bignum_mt_s mt;
  mt.mod.bits = l * ASSH_BIGNUM_W;
  mt.n0 = assh_bnword_mt_modinv(-n[0]);
  mt.mod.n = n;

  while (1)
    {
      memcpy(an, rn, l * sizeof(assh_bnword_t));

      /* compute z = a**(c >> b) % n */
      memcpy(zn, an, l * sizeof(assh_bnword_t)); /* LSB(c >> b) is always set */

      for (i = b + 1; i < bn->bits; i++)
        {
          assh_bool_t c = (cn[i / ASSH_BIGNUM_W]
                           >> (i % ASSH_BIGNUM_W)) & 1;
          volatile assh_bool_t d = bn->secret | c;

          assh_bignum_mt_mul(&mt, tn, an, an);
          memcpy(an, tn, l * sizeof(assh_bnword_t));

          if (d)
            {
              /* constant time exp */
              assh_bignum_mt_mul(&mt, tn, zn, an);
              assh_bignum_cmove(zn, tn, l, c);
            }
        }

      /* probable prime if z == 1 */
      assh_bignum_mt_reduce(&mt, tn, zn);
      if (!assh_bignum_eq_uint(1, tn, l))
        {
          i = b - 1;
          while (1)
            {
              /* probable prime if z == p - 1 */
              assh_bignum_mt_reduce(&mt, tn, zn);
              if (assh_bignum_eq(tn, l, cn, l))
                break;

              if (!i--)
                return ASSH_OK;

              /* z = z**2 % p */
              assh_bignum_mt_mul(&mt, tn, zn, zn);
              memcpy(zn, tn, l * sizeof(assh_bnword_t));

              /* composite if z == 1 */
              assh_bignum_mt_reduce(&mt, tn, zn);
              if (assh_bignum_eq_uint(1, tn, l))
                return ASSH_OK;
            }
        }

      if (!--rounds)
        break;

      /* shuffle random base words using a lfsr */
      for (i = 0; i < l; i++)
        rn[i] = (~((rn[i] & 1) - 1) & ASSH_BN_LFSR) ^ (rn[i] >> 1);
    }

  *result = 1;
  return ASSH_OK;
}

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_check_prime(struct assh_context_s *ctx,
                        struct assh_bignum_scratch_s *sc,
                        const struct assh_bignum_s *bn,
                        size_t rounds, assh_bool_t *result)
{
  assh_error_t err;
  size_t l = assh_bignum_words(bn->bits);
  assh_bnword_t *n = bn->n;
  size_t i;

  *result = 0;

  if (l == 0 || !(n[0] & 1))
    return ASSH_OK;

  /* test bn % small primes */
  assh_bool_t composite = 0;

  if (!bn->secret)
    {
      for (i = 0; i < ASSH_SIEVE_PRIMES; i++)
        {
          uint16_t p = assh_primes[i];
          uint16_t o = assh_bignum_sieve_mod(n, l, p);
          composite |= assh_bignum_eqzero(o);
        }
    }

  if (!composite)
    {
      assh_bnword_t rn[l];

      /* generate random base for mr algorithm */
      ASSH_ERR_RET(ctx->prng->f_get(ctx, (uint8_t*)rn,
                 sizeof(rn), ASSH_PRNG_QUALITY_NONCE));

      ASSH_ERR_RET(assh_bignum_miller_rabin(ctx, sc, rn, bn, rounds, result));
    }

  return ASSH_OK;
}

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_next_prime(struct assh_context_s *ctx,
                       struct assh_bignum_scratch_s *sc,
                       struct assh_bignum_s *bn,
                       struct assh_bignum_s *step)
{
  assh_error_t err;
  const size_t l = assh_bignum_words(bn->bits);
  assh_bnword_t *n = bn->n;  
  uint32_t sieve_bits[8];
  uint32_t k, offset = 0;
  size_t i, j;

  /* generate random base for mr algorithm */
  assh_bnword_t rn[l];
  ASSH_ERR_RET(ctx->prng->f_get(ctx, (uint8_t*)rn,
                 sizeof(rn), ASSH_PRNG_QUALITY_NONCE));

  /* simple formula for upper bound of max prime gap */
  const uint32_t max_prime_gap = (bn->bits * bn->bits) / 2;

  struct assh_bignum_sieve_s * __restrict__ sieve;
  ASSH_ERR_RET(assh_alloc(ctx, sizeof(*sieve),
                 bn->secret ? ASSH_ALLOC_SECUR : ASSH_ALLOC_INTERNAL,
                 (void**)&sieve));

  assh_bignum_sieve_init(sieve, bn, step);

  for (k = 0; k < max_prime_gap; k += 512)
    {
      /* update sieve bitmap */
      memset(sieve_bits, 0, sizeof(sieve_bits));
      for (i = 0; i < ASSH_SIEVE_PRIMES; i++)
        {
          uint32_t s = sieve->offsets[i];
          while (s - k < 512)
            {
              uint32_t x = (s - k) >> 1;
              sieve_bits[x / 32] |= 1 << (x % 32);
              s += assh_primes[i] * 2;
            }
          sieve->offsets[i] = s;
        }

      /* test remaining candidate primes */
      for (i = 0; i < 8; i++)
        {
          uint32_t x;
          for (x = ~sieve_bits[i]; x; x &= (x - 1))
            {
              uint32_t o = k + (i * 32 + assh_ct_ctz32(x)) * 2 + (sieve->offsets[0] & 1);
              // ASSH_DEBUG("candidate prime at offset %u, mask is %x\n", o, x);

              /* advance big number to candidate prime */
              assh_bnword_t c = o - offset;
              ASSH_CHK_GTO(c != o - offset, ASSH_ERR_NUM_OVERFLOW, err_);
              offset = o;
              assh_bnlong_t t = 0;
              j = 0;
              if (step != NULL)
                {
                  assh_bnword_t *in = step->n;
                  const size_t il = assh_bignum_words(step->bits);
                  for (; j < il; j++)
                    n[j] = t = n[j] + (assh_bnlong_t)in[j] * c + (t >> ASSH_BIGNUM_W);
                }
              else              /* step is 1 */
                {
                  t = (assh_bnlong_t)c << ASSH_BIGNUM_W;
                }
              for (; j < l; j++)
                n[j] = t = (assh_bnlong_t)n[j] + (t >> ASSH_BIGNUM_W);
              ASSH_CHK_GTO((t >> ASSH_BIGNUM_W) != 0, ASSH_ERR_NUM_OVERFLOW, err_);

              /* test prime candidate. number of rounds estimate for a
                 randomly generated number taken from: "Average case
                 error estimates for the strong probable prime test,
                 Mathematics of Computation 61" */
              assh_bool_t r;
              ASSH_ERR_GTO(assh_bignum_miller_rabin(ctx, sc, rn, bn, 7, &r), err_);
              if (r)
                goto err_;
            }
        }
    }

  /* give up */
  ASSH_ERR_GTO(ASSH_ERR_NUM_OVERFLOW, err_);

 err_:
  assh_free(ctx, sieve);
  return err;
}

static assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_gen_prime(struct assh_context_s *c,
                      struct assh_bignum_scratch_s *sc,
                      struct assh_bignum_s *bn,
                      const struct assh_bignum_s *min,
                      const struct assh_bignum_s *max,
                      enum assh_prng_quality_e quality)
{
  assh_error_t err;

  ASSH_ERR_RET(assh_bignum_rand(c, bn, min, max, quality));
  ASSH_ERR_RET(assh_bignum_next_prime(c, sc, bn, NULL));

  ASSH_CHK_RET(max != NULL && (assh_bignum_cmp(bn, max) & ASSH_BIGNUM_CMP_GT),
               ASSH_ERR_NUM_OVERFLOW);

  return ASSH_OK;
}

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_realloc(struct assh_context_s *c,
                    struct assh_bignum_s *bn,
                    assh_bool_t secret, assh_bool_t perserve)
{
  assh_error_t err;

  bn->secret = secret;
  secret |= bn->secure;

  enum assh_alloc_type_e type = secret
    ? ASSH_ALLOC_SECUR : ASSH_ALLOC_INTERNAL;
  size_t size = assh_bignum_words(bn->bits) * sizeof(assh_bnword_t);

  if (bn->n != NULL && bn->storage != secret)
    {
      void *new;
      ASSH_ERR_RET(assh_alloc(c, size, type, &new));
      if (perserve)
        memcpy(new, bn->n, size);
      assh_free(c, bn->n);
      bn->n = new;
    }
  else if (bn->n == NULL)
    {
      ASSH_ERR_RET(assh_realloc(c, &bn->n, size, type));
    }

  bn->storage = secret;
  return ASSH_OK;
}

static ASSH_BIGNUM_CONVERT_FCN(assh_bignum_builtin_convert)
{
  assh_error_t err;

  const struct assh_bignum_s *srcn = src;
  struct assh_bignum_s *dstn = dst;

  if (srcfmt == ASSH_BIGNUM_NATIVE ||
      srcfmt == ASSH_BIGNUM_TEMP)
    {
      switch (dstfmt)
        {
        case ASSH_BIGNUM_NATIVE:
        case ASSH_BIGNUM_TEMP:
          ASSH_ERR_RET(assh_bignum_realloc(c, dstn, srcn->secret | secret, 0));
          ASSH_ERR_RET(assh_bignum_copy(dstn, srcn));
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
          dstn->mt_num = srcn->mt_num;
          dstn->mt_id = srcn->mt_id;
#endif
          break;
        case ASSH_BIGNUM_MPINT:
        case ASSH_BIGNUM_STRING:
        case ASSH_BIGNUM_MSB_RAW:
        case ASSH_BIGNUM_LSB_RAW:
        case ASSH_BIGNUM_ASN1:
          assert(!srcn->mt_num);
          assh_bignum_to_buffer(srcn, dst, next, dstfmt);
          break;

        default:
          ASSH_TAIL_CALL(ASSH_ERR_NOTSUP);
        }
    }
  else
    {
      size_t l, n, b;

      assert(dstfmt == ASSH_BIGNUM_NATIVE ||
             dstfmt == ASSH_BIGNUM_TEMP);
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
      dstn->mt_num = 0;
#endif

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
          ASSH_ERR_RET(assh_bignum_realloc(c, dstn, secret, 0));
          ASSH_ERR_RET(assh_bignum_from_buffer(dstn, src + l - n, n, srcfmt));
          break;

        case ASSH_BIGNUM_MSB_RAW:
        case ASSH_BIGNUM_LSB_RAW:
          ASSH_ERR_RET(assh_bignum_realloc(c, dstn, secret, 0));
          ASSH_ASSERT(assh_bignum_from_buffer(dstn, src, n, srcfmt));
          break;

        case ASSH_BIGNUM_INT:
          ASSH_CHK_RET(dstn->bits < sizeof(uintptr_t) * 8, ASSH_ERR_NUM_OVERFLOW);
          ASSH_ERR_RET(assh_bignum_realloc(c, dstn, secret, 0));
          ASSH_ERR_RET(assh_bignum_from_uint(dstn, (uintptr_t)src));
          break;

        case ASSH_BIGNUM_SIZE:
          dstn->bits = b;
          break;

        default:
          ASSH_TAIL_CALL(ASSH_ERR_NOTSUP);
        }
    }

  return ASSH_OK;
}

static void
assh_bignum_builtin_print(void *arg, enum assh_bignum_fmt_e fmt,
                          uint32_t id, uint_fast16_t pc,
                          const struct assh_bignum_mt_s mt[])
{
#ifdef CONFIG_ASSH_DEBUG
  struct assh_bignum_s *src = arg;
  char idstr[5];
  size_t i;

  idstr[4] = 0;
  assh_store_u32le((uint8_t*)idstr, id);
  fprintf(stderr, "[pc=%u, id=%s, type=%c] ", pc, idstr, fmt);
  switch (fmt)
    {
    case ASSH_BIGNUM_NATIVE:
    case ASSH_BIGNUM_TEMP:
      fprintf(stderr, "[bits=%zu] ", src->bits);
      if (src->secret)
        fprintf(stderr, "secret ");
      if (src->n == NULL)
        {
          fprintf(stderr, "NULL\n");
          break;
        }
      size_t l = assh_bignum_words(src->bits);
      if (src->mt_num)
        {
          assh_bnword_t t[l];
          assh_bignum_mt_reduce(mt + src->mt_id, t, src->n);
          assh_bignum_dump(t, l);
        }
      else
        {
          assh_bignum_dump(src->n, l);
        }
      break;
    case ASSH_BIGNUM_SIZE:
      fprintf(stderr, "%u\n", (unsigned)(uintptr_t)arg);
      break;
    }
#endif
}

static ASSH_BIGNUM_BYTECODE_FCN(assh_bignum_builtin_bytecode)
{
  uint_fast8_t flen, tlen, mlen;
  assh_error_t err;
  uint_fast8_t i, j, k;
  uint_fast16_t pc = 0;
  uint_fast32_t lad_index = 0;
  uint8_t cond_secret = 0;
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
  uint8_t trace = 0;
#endif

  struct assh_bignum_scratch_s sc
    = { .words = 0, .words_s = 0, .n = NULL, .n_s = NULL };

  /* find number of arguments and temporaries */
  for (mlen = tlen = flen = 0; format[flen]; flen++)
    {
      switch (format[flen])
        {
        case ASSH_BIGNUM_TEMP:
          tlen++;
          break;
        case ASSH_BIGNUM_MT:
          mlen++;
          break;
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
        case ASSH_BIGNUM_NATIVE:
        case ASSH_BIGNUM_MPINT:
        case ASSH_BIGNUM_ASN1:
        case ASSH_BIGNUM_STRING:
        case ASSH_BIGNUM_MSB_RAW:
        case ASSH_BIGNUM_LSB_RAW:
        case ASSH_BIGNUM_HEX:
        case ASSH_BIGNUM_INT:
        case ASSH_BIGNUM_SIZE:
          break;
        default:
          ASSH_UNREACHABLE();
#endif
        }
    }

  void *args[flen];
  struct assh_bignum_s tmp[tlen];
  struct assh_bignum_mt_s mt[mlen];

  memset(tmp, 0, sizeof(tmp));

  for (i = j = k = 0; i < flen; i++)
    switch (format[i])
      {
      case ASSH_BIGNUM_TEMP:
        args[i] = &tmp[j];
        j++;
        break;
      case ASSH_BIGNUM_MT:
        mt[k].mod.n = NULL;
        args[i] = &mt[k];
        k++;
        break;
      case ASSH_BIGNUM_SIZE:
        args[i] = (void*)va_arg(ap, size_t);
        break;
      case ASSH_BIGNUM_NATIVE: {
        struct assh_bignum_s *bn = va_arg(ap, void *);
        args[i] = bn;
        break;
      }
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

#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
      if (trace & 1)
        {
          const char *opnames[] = ASSH_BIGNUM_OP_NAMES;
          ASSH_DEBUG("pc=%u, op=%s, a=%u, b=%u, c=%u, d=%u cond=0x%02x\n",
                     pc, opnames[op], oa, ob, oc, od, cond);
        }
#endif

      pc++;

      switch (op)
        {
        case ASSH_BIGNUM_OP_END:
          goto end;

        case ASSH_BIGNUM_OP_MOVE: {
          void *dst = args[oc];
          uint8_t *next;
          ASSH_ERR_GTO(assh_bignum_builtin_convert(c,
                    format[od], format[oc], args[od], dst, &next, ob), err_sc);

          /* deduce pointer of next buffer arg */
          if (oc + 1 < flen && args[oc + 1] == NULL)
            args[oc + 1] = next;

#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          switch (format[oc])
            {
            case ASSH_BIGNUM_NATIVE:
            case ASSH_BIGNUM_TEMP:
              if (trace & 2)
                assh_bignum_builtin_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc, mt);
            }
#endif
          break;
        }

        case ASSH_BIGNUM_OP_SIZE: {
          size_t b;
          ASSH_ERR_GTO(assh_bignum_size_of_data(format[ob], args[ob],
                                                NULL, NULL, &b), err_sc);
          struct assh_bignum_s *dst = args[oa];
          dst->bits = ((od >= 32) ? (b << (od - 32))
                       : (b >> (32 - od))) + (intptr_t)(int8_t)oc;

          if (dst->n != NULL)
            {
              assh_free(c, dst->n);
              dst->n = NULL;
            }
          break;
        }

        case ASSH_BIGNUM_OP_SIZER: {
          size_t b, i;
          ASSH_ERR_GTO(assh_bignum_size_of_data(format[ob], args[ob],
                                                NULL, NULL, &b), err_sc);
          for (i = oa; i <= oc; i++) 
            {
              struct assh_bignum_s *dst = args[i];
              dst->bits = b;

              if (dst->n != NULL)
                {
                  assh_free(c, dst->n);
                  dst->n = NULL;
                }
            }
          break;
        }

        case ASSH_BIGNUM_OP_SUB:
        case ASSH_BIGNUM_OP_ADD: {
          struct assh_bignum_s *dst = args[oa];
          struct assh_bignum_s *src1 = args[ob];
          struct assh_bignum_s *src2 = args[oc];
          ASSH_ERR_GTO(assh_bignum_realloc(c, dst, src1->secret | src2->secret, 1), err_sc);
          if (od != ASSH_BOP_NOREG)
            {
              struct assh_bignum_s *mod = args[od];
              assert(mod->mt_mod && src1->mt_num && src2->mt_num);
              if (op == ASSH_BIGNUM_OP_ADD)
                assh_bignum_mt_add(dst, src1, src2, mod);
              else
                assh_bignum_mt_sub(dst, src1, src2, mod);
            }
          else
            {
              assert(!src1->mt_num && !src2->mt_num);
              assh_bnword_t mask = (assh_bnword_t)(op == ASSH_BIGNUM_OP_ADD) - 1;
              ASSH_ERR_GTO(assh_bignum_addsub(dst, src1, src2, mask), err_sc);
            }
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
          dst->mt_num = src1->mt_num;
          dst->mt_id = src1->mt_id;
#endif
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_builtin_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc, mt);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_MUL: {
          struct assh_bignum_s *dst = args[oa];
          struct assh_bignum_s *src1 = args[ob];
          struct assh_bignum_s *src2 = args[oc];
          ASSH_ERR_GTO(assh_bignum_realloc(c, dst, src1->secret | src2->secret, 0), err_sc);
          if (od == ASSH_BOP_NOREG)
            {
              assert(!src1->mt_num && !src2->mt_num);
              ASSH_ERR_GTO(assh_bignum_mul(c, &sc, dst, src1, src2), err_sc);
            }
          else
            {
              struct assh_bignum_mt_s *mod = args[od];
              if (format[od] == ASSH_BIGNUM_MT)
                {
                  assert(mod->mod.mt_mod && src1->mt_num);
                  ASSH_ERR_GTO(assh_bignum_mul_mod_mt(c, &sc, dst, src1, src2, args[od]), err_sc);
                }
              else
                {
                  assert(!mod->mod.mt_mod && !src1->mt_num);
                  ASSH_ERR_GTO(assh_bignum_mul_mod(c, &sc, dst, src1, src2, args[od]), err_sc);
                }
            }
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
          dst->mt_num = src1->mt_num;
          dst->mt_id = src1->mt_id;
#endif
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_builtin_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc, mt);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_EXPM: {
          struct assh_bignum_s *dst = args[oa];
          struct assh_bignum_s *src1 = args[ob];
          struct assh_bignum_s *src2 = args[oc];
          struct assh_bignum_mt_s *mod = args[od]; 
          assert(format[od] == ASSH_BIGNUM_MT);
          assert(mod->mod.mt_mod);
          assert(src1->mt_num);
          assert(!src2->mt_num);
          ASSH_ERR_GTO(assh_bignum_realloc(c, dst, src1->secret | src2->secret, 1), err_sc);
          ASSH_ERR_GTO(assh_bignum_expmod_mt(c, &sc, dst, src1, src2, mod), err_sc);
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
          dst->mt_num = src1->mt_num;
          dst->mt_id = src1->mt_id;
#endif
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_builtin_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc, mt);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_MTINIT: {
          struct assh_bignum_s *mod = args[od];
          struct assh_bignum_mt_s *dst = args[oc];
          assert(!mod->mt_num);
          assert(format[oc] == ASSH_BIGNUM_MT);
          ASSH_ERR_GTO(assh_bignum_mt_init(c, dst, mod), err_sc);
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
          dst->mod.mt_mod = 1;
          dst->mod.mt_num = 0;
#endif
          break;
        }

        case ASSH_BIGNUM_OP_MTFROM:
        case ASSH_BIGNUM_OP_MTTO: {
          uint_fast8_t i;
          for (i = 0; i < oa; i++)
            {
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
              if (ob == oc)
                ASSH_DEBUG("MT convert: may optimize with src != dst\n");
#endif
              struct assh_bignum_s *dst = args[ob + i];
              struct assh_bignum_s *src = args[oc + i];
              assert(src->mt_num != (op == ASSH_BIGNUM_OP_MTTO));
              ASSH_ERR_GTO(assh_bignum_realloc(c, dst, src->secret, 1), err_sc);
              ASSH_ERR_GTO(assh_bignum_mt_convert(c, &sc, op == ASSH_BIGNUM_OP_MTTO,
                                                  args[od], dst, src), err_sc);
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
              dst->mt_num = (op == ASSH_BIGNUM_OP_MTTO);
              dst->mt_id = (struct assh_bignum_mt_s*)args[od] - mt;
#endif
            }
          break;
        }

        case ASSH_BIGNUM_OP_DIV: {
          struct assh_bignum_s *dsta = NULL, *dstb = NULL;
          struct assh_bignum_s *src1 = args[oc], *src2 = args[od];
          assert(!src2->mt_num);
          assert(src1->mt_num == src2->mt_mod);
          assert(src2->mt_mod || (!src1->secret && !src2->secret));
          if (oa != ASSH_BOP_NOREG)
            {
              assert(!src2->mt_mod);
              dsta = args[oa];
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
              dsta->mt_num = 0;
#endif
              ASSH_ERR_GTO(assh_bignum_realloc(c, dsta, 0, 0), err_sc);
            }
          if (ob != ASSH_BOP_NOREG)
            {
              dstb = args[ob];
              if (dstb != src1)
                {
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
                  dstb->mt_num = src2->mt_mod;
                  dstb->mt_id = src2->mt_id;
#endif
                  ASSH_ERR_GTO(assh_bignum_realloc(c, dstb, src1->secret, 1), err_sc);
                }
              if (src2->mt_mod)
                {
                  if (dstb != src1)
                    ASSH_ERR_GTO(assh_bignum_copy(dstb, src1), err_sc);
                  goto div_done;
                }
            }
          ASSH_ERR_GTO(assh_bignum_div(c, &sc, dstb, dsta, src1, src2), err_sc);
          div_done:
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            {
              if (dsta)
                assh_bignum_builtin_print(dsta, ASSH_BIGNUM_NATIVE, 'A', pc, mt);
              if (dstb)
                assh_bignum_builtin_print(dstb, ASSH_BIGNUM_NATIVE, 'B', pc, mt);
            }
#endif
          break;
        }

        case ASSH_BIGNUM_OP_INV: {
          struct assh_bignum_s *dst = args[ob];
          struct assh_bignum_s *src1 = args[oc];
          ASSH_ERR_GTO(assh_bignum_realloc(c, dst, src1->secret, 0), err_sc);
          if (format[od] == ASSH_BIGNUM_MT)
            {
              assert(src1->mt_num);
              ASSH_ERR_GTO(assh_bignum_modinv_mt(c, &sc, dst, src1, args[od]), err_sc);
            }
          else
            {
              assert(!src1->mt_num);
              ASSH_ERR_GTO(assh_bignum_modinv(c, &sc, dst, src1, args[od]), err_sc);
            }
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
          dst->mt_num = src1->mt_num;
          dst->mt_id = src1->mt_id;
#endif
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_builtin_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc, mt);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_GCD: {
          struct assh_bignum_s *dst = args[ob];
          struct assh_bignum_s *src1 = args[oc], *src2 = args[od];
          assert(!src1->mt_num && !src2->mt_num);
          ASSH_ERR_GTO(assh_bignum_realloc(c, dst, src1->secret, 0), err_sc);
          ASSH_ERR_GTO(assh_bignum_gcd(c, &sc, dst, src1, src2), err_sc);
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
          dst->mt_num = 0;
#endif
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_builtin_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc, mt);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_SHR:
        case ASSH_BIGNUM_OP_SHL: {
          struct assh_bignum_s *dst = args[oa];
          struct assh_bignum_s *src = args[ob];
          assert(!src->mt_num);
          size_t b = 0;
          ASSH_CHK_GTO(dst->bits != src->bits, ASSH_ERR_OUTPUT_OVERFLOW, err_sc);
          if (od != ASSH_BOP_NOREG)
            {
#warning FIXME constant time ?
              ASSH_ERR_GTO(assh_bignum_size_of_data(format[od], args[od],
                                                    NULL, NULL, &b), err_sc);
            }
          ASSH_ERR_GTO(assh_bignum_realloc(c, dst, src->secret, 1), err_sc);
          switch (op)
            {
            case ASSH_BIGNUM_OP_SHR:
              ASSH_ERR_GTO(assh_bignum_rshift(dst, src, b + oc - 128), err_sc);
              break;
            case ASSH_BIGNUM_OP_SHL:
              ASSH_ERR_GTO(assh_bignum_lshift(dst, src, b + oc - 128), err_sc);
              break;
            default:
              ASSH_UNREACHABLE();
            }
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
          dst->mt_num = 0;
#endif
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_builtin_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc, mt);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_RAND: {
          struct assh_bignum_s *dst = args[oa];
          ASSH_ERR_GTO(assh_bignum_realloc(c, dst, od > ASSH_PRNG_QUALITY_PUBLIC, 0), err_sc);
          ASSH_ERR_GTO(assh_bignum_rand(c, dst,
                         ob == ASSH_BOP_NOREG ? NULL : args[ob],
                         oc == ASSH_BOP_NOREG ? NULL : args[oc],
                         od), err_sc);
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
          dst->mt_num = 0;
#endif
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_builtin_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc, mt);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_CMP: {
          uint8_t r = 0;
          struct assh_bignum_s *src1 = args[ob];
          struct assh_bignum_s *src2 = args[oc];
          uint8_t cond_mask = 1 << oa;
          cond &= ~cond_mask;
          cond_secret &= ~cond_mask;
          if (oc == ASSH_BOP_NOREG)
            {
              r = src1->n != NULL;
            }
          else
            {
              cond_secret |= (src1->secret | src2->secret) << oa;
              assert(!src2->mt_num);
              if (oc != ob)
                {
                  assert(!src1->mt_num);
                  r = assh_bignum_cmp(src1, src2);
                }
            }
          /* shift lookup table for assh_bignum_cmp result against
             CMPEQ, CMPLT and CMPLTEQ opcodes

                  r
                 0  0    ==
                 0  1    >
                 1  0    <

                 cmplteq  cmplt    cmpeq
                 0101     0100     0001
                 5        4        1
          */
          r = (0x541 >> (od * 4 + r)) & 1;
          cond |= r << oa;
          break;
        }

        case ASSH_BIGNUM_OP_JMP:
          assert(!((cond_secret >> oa) & 1));
          if (ob | (((cond >> oa) ^ od) & 1))
            pc += oc - 128;
          break;

        case ASSH_BIGNUM_OP_CSWAP: {
          struct assh_bignum_s *a = args[ob], *b = args[oc];
          assert(a->bits == b->bits);
          a->secret = b->secret = a->secret |
            b->secret | ((cond_secret >> oa) & 1);
          assh_bignum_cswap(a->n, b->n, assh_bignum_words(a->bits),
                            ((cond >> oa) ^ od) & 1);
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            {
              assh_bignum_builtin_print(a, ASSH_BIGNUM_NATIVE, 'A', pc, mt);
              assh_bignum_builtin_print(b, ASSH_BIGNUM_NATIVE, 'B', pc, mt);
            }
#endif
          break;
        }

        case ASSH_BIGNUM_OP_CMOVE: {
          struct assh_bignum_s *dst = args[ob], *src = args[oc];
          assert(dst->bits == src->bits);
          dst->secret |= src->secret | ((cond_secret >> oa) & 1);
          assh_bignum_cmove(dst->n, src->n, assh_bignum_words(dst->bits),
                            ((cond >> oa) ^ od) & 1);
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_builtin_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc, mt);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_CFAIL:
          ASSH_CHK_GTO(((cond >> oc) ^ od) & 1, ASSH_ERR_NUM_COMPARE_FAILED, err_sc);
          break;

        case ASSH_BIGNUM_OP_LADINIT: {
          struct assh_bignum_s *src = args[od];
          lad_index = src->bits - 1;
          ASSH_CHK_GTO(lad_index == 0, ASSH_ERR_NUM_OVERFLOW, err_sc);
          break;
        }

        case ASSH_BIGNUM_OP_LADTEST: {
          struct assh_bignum_s *src = args[od];
          uint8_t cond_mask = (1 << oc);
          assert(!src->mt_num);
          cond &= ~cond_mask;
          assh_bnword_t *n = src->n;
          cond |= ((n[lad_index / ASSH_BIGNUM_W]
                    >> (lad_index % ASSH_BIGNUM_W)) & 1) << oc;
          cond_secret &= cond_mask;
          cond_secret |= src->secret << oc;
          break;
        }

        case ASSH_BIGNUM_OP_LADNEXT: {
          uint8_t cond_mask = (1 << od);
          cond &= ~cond_mask;
          if (lad_index--)
            cond |= cond_mask;
          cond_secret &= ~cond_mask;
          break;
        }

        case ASSH_BIGNUM_OP_TEST: {
          struct assh_bignum_s *src1 = args[ob];
          uint8_t cond_mask = (1 << oa);
          cond &= ~cond_mask;
          size_t b = oc;
          assert(!src1->mt_num);
          if (od != ASSH_BOP_NOREG)
            {
              ASSH_ERR_GTO(assh_bignum_size_of_data(format[od], args[od],
                                                    NULL, NULL, &b), err_sc);
              b -= oc;
            }
          assert(b < src1->bits);
          assh_bnword_t *n = src1->n;
          cond |= ((n[b / ASSH_BIGNUM_W] >> (b % ASSH_BIGNUM_W)) & 1) << oa;
          cond_secret &= ~cond_mask;
          cond_secret |= src1->secret << oa;
          break;
        }

        case ASSH_BIGNUM_OP_MTUINT: {
          uint_fast32_t value = (opc >> 14) & 0xfff;
          struct assh_bignum_s *dst = args[od];
          struct assh_bignum_mt_s *mt = args[oc];
          assert(dst->bits == mt->mod.bits);
          size_t ml = assh_bignum_words(mt->mod.bits);
          ASSH_ERR_GTO(assh_bignum_realloc(c, dst, 0, 0), err_sc);
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
          dst->mt_num = 1;
          dst->mt_id = (struct assh_bignum_mt_s*)args[oc] - mt;
#endif
          switch (value)
            {
            case 0:
              memset(dst->n, 0, ml * sizeof(assh_bnword_t));
              break;
            case 1:
              memcpy(dst->n, (assh_bnword_t*)mt->mod.n + 2 * ml, ml * sizeof(assh_bnword_t));
              break;
            default:
              ASSH_ERR_GTO(assh_bignum_from_uint(dst, value), err_sc);
              ASSH_ERR_GTO(assh_bignum_mt_convert(c, &sc, 1, mt, dst, dst), err_sc);
              break;
            }
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_builtin_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc, mt);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_UINT: {
          uint_fast32_t value = (opc >> 6) & 0xfffff;
          struct assh_bignum_s *dst = args[od];
          ASSH_ERR_GTO(assh_bignum_realloc(c, dst, 0, 0), err_sc);
          ASSH_ERR_GTO(assh_bignum_from_uint(dst, value), err_sc);
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
          dst->mt_num = 0;
#endif
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_builtin_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc, mt);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_ISPRIME: {
          struct assh_bignum_s *src = args[od];
          assert(!src->mt_num);
          assert(!src->secret);
          assert(oc > 0);
          uint8_t cond_mask = (1 << ob);
          assh_bool_t r;
          ASSH_ERR_GTO(assh_bignum_check_prime(c, &sc, src, oc, &r), err_sc);
          cond &= ~cond_mask;
          cond |= r << ob;
          cond_secret &= ~cond_mask;
          break;
        }

        case ASSH_BIGNUM_OP_PRIME: {
          struct assh_bignum_s *dst = args[oa];
          ASSH_ERR_GTO(assh_bignum_realloc(c, dst, od > ASSH_PRNG_QUALITY_PUBLIC, 0), err_sc);
          ASSH_ERR_GTO(assh_bignum_gen_prime(c, &sc, dst,
                         ob == ASSH_BOP_NOREG ? NULL : args[ob],
                         oc == ASSH_BOP_NOREG ? NULL : args[oc],
                         od), err_sc);
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
          dst->mt_num = 0;
#endif
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_builtin_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc, mt);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_NEXTPRIME: {
          struct assh_bignum_s *dst = args[oc];
          assert(!dst->mt_num);
          struct assh_bignum_s *step = NULL;
          if (od != ASSH_BOP_NOREG)
            {
              step = args[od];
              assert(step->bits <= dst->bits);
              assert(!step->mt_num);
              assert(!step->secret);
              assert(!dst->secret);
            }
          ASSH_ERR_GTO(assh_bignum_next_prime(c, &sc, dst, step), err_sc);
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_builtin_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc, mt);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_BOOL: {
          uint8_t src1 = (cond >> ob) & 1;
          uint8_t src2 = (cond >> oc) & 1;
          uint8_t dst_mask = (1 << oa);
          cond &= ~dst_mask;
          /* shift lookup table:
              op:       3     2     1     0
                       ANDN  XOR    OR   AND
            src1 src2  -------- dst --------
             0    0     0     0     0     0
             0    1     0     1     1     0
             1    0     1     1     1     0
             1    1     0     0     1     1
            --------------------------------
              hex:      4     6     E     8
             ~hex:      B     9     1     7
           */
          cond |= ((0xb91746e8 >> ((od << 2) | (src1 << 1) | src2)) & 1) << oa;
          cond_secret &= ~dst_mask;
          uint8_t src1_secret = (cond_secret >> ob) & 1;
          uint8_t src2_secret = (cond_secret >> oc) & 1;
          cond_secret |= (src1_secret | src2_secret) << oa;
          break;
        }

        case ASSH_BIGNUM_OP_PRIVACY: {
          struct assh_bignum_s *dst = args[od];
          dst->secure = oc;
          ASSH_ERR_GTO(assh_bignum_realloc(c, dst, ob, 1), err_sc);
          break;
        }

        case ASSH_BIGNUM_OP_PRINT: {
          assh_bignum_builtin_print(args[od], format[od], oc, pc, mt);
          break;
        }

        case ASSH_BIGNUM_OP_TRACE:
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          trace = od;
#endif
          break;

        }
    }

 end:
  err = ASSH_OK;
 err_sc:;

  if (sc.n != NULL)
    assh_free(c, sc.n);
  if (sc.n_s != NULL)
    assh_free(c, sc.n_s);

  /* release numbers */
  for (i = 0; i < tlen; i++)
    if (tmp[i].n != NULL)
      assh_free(c, tmp[i].n);

  for (i = 0; i < mlen; i++)
    if (mt[i].mod.n != NULL)
      assh_free(c, mt[i].mod.n);

  return err;
}

static ASSH_BIGNUM_RELEASE_FCN(assh_bignum_builtin_release)
{
  assh_free(ctx, bn->n);
}

const struct assh_bignum_algo_s assh_bignum_builtin =
{
  .name = "builtin",
  .f_bytecode = assh_bignum_builtin_bytecode,
  .f_convert = assh_bignum_builtin_convert,
  .f_release = assh_bignum_builtin_release,
};

