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

#include <assh/assh_context.h>
#include <assh/assh_packet.h>
#include <assh/assh_alloc.h>

#include <string.h>
#include <stdlib.h>

#ifdef CONFIG_ASSH_DEBUG
void
assh_bignum_dump(const assh_bnword_t *x, size_t l)
{
  size_t i;
  ASSH_DEBUG_("0x");  
  for (i = l; i-- > 0; )
    ASSH_DEBUG_(ASSH_BN_FMT, x[i]);
  ASSH_DEBUG_("\n");  
}
#endif

assh_bnword_t assh_bnword_egcd(assh_bnword_t a, assh_bnword_t b,
                               assh_bnword_t q)
{
  uint_fast8_t sh, i;
  assh_bnword_t c, r = 1;

  while (a)
    {
      if (a < b)
        {
          ASSH_SWAP(assh_bnword_t, a, b);
          ASSH_SWAP(assh_bnword_t, r, q);
        }
      sh = assh_bn_clz(b) - assh_bn_clz(a);
      c = b << sh;
      i = (c > a);
      a -= (c >> i);
      r -= q << (sh - i);
    }

  return q;
}

void
assh_bignum_cmove(assh_bnword_t *a, const assh_bnword_t *b,
                  size_t l, assh_bool_t c)
{
  assh_bnword_t m = ~((assh_bnword_t)c - 1);
  size_t i;

  for (i = 0; i < l; i++)
    a[i] = (b[i] & m) | (a[i] & ~m);
}

void
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
assh_status_t
assh_bignum_copy(struct assh_bignum_s *dst,
                 const struct assh_bignum_s *src)
{
  assh_status_t err;
  size_t al = assh_bignum_words(dst->bits);
  size_t bl = assh_bignum_words(src->bits);
  size_t i, l = assh_min_uint(al, bl);
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

  ASSH_RET_IF_TRUE(dst->bits != src->bits && x != 0,
               ASSH_ERR_OUTPUT_OVERFLOW);

  return ASSH_OK;
}

/* @This stores the value of a big number into a buffer. The
   destination format can be: ASSH_BIGNUM_MPINT, ASSH_BIGNUM_ASN1,
   ASSH_BIGNUM_STRING, ASSH_BIGNUM_LSB_RAW, ASSH_BIGNUM_MSB_RAW. The
   buffer must be large enough to hold the value. */
void
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

assh_status_t
assh_bignum_from_buffer(struct assh_bignum_s *bn,
                        const uint8_t * __restrict__ data,
                        size_t data_len, enum assh_bignum_fmt_e format)
{
  assh_status_t err;
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
            ASSH_RET_IF_TRUE(x & ~mask, ASSH_ERR_OUTPUT_OVERFLOW);
        }
    }

  ASSH_RET_IF_TRUE(k < data_len, ASSH_ERR_OUTPUT_OVERFLOW);
  return ASSH_OK;
}

assh_status_t
assh_bignum_from_uint(struct assh_bignum_s *bn,
                      uintptr_t x)
{
  size_t i, l = assh_bignum_words(bn->bits);
  assh_bnword_t *n = bn->n;
  assh_status_t err;

  for (i = 0; i < l; i++)
    {
      n[i] = x;
      x = (ASSH_BIGNUM_W < sizeof(x) * 8) ? x >> ASSH_BIGNUM_W : 0;
    }

  ASSH_RET_IF_TRUE(x != 0, ASSH_ERR_NUM_OVERFLOW);
  return ASSH_OK;
}

assh_bool_t assh_bignum_eq_uint(const assh_bnword_t a,
                                const assh_bnword_t *b, size_t bl)
{
  size_t i;
  assh_bnword_t r = b[0] ^ a;

  for (i = 1; i < bl; i++)
    r |= b[i];

  return assh_bignum_eqzero(r);
}

assh_bool_t assh_bignum_eq(const assh_bnword_t *a, size_t al,
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

enum assh_bignum_cmp_result_e
assh_bignum_cmp(const struct assh_bignum_s *a,
                const struct assh_bignum_s *b)
{
  size_t al = assh_bignum_words(a->bits);
  size_t bl = assh_bignum_words(b->bits);
  size_t i, l = assh_min_uint(al, bl);
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

assh_status_t
assh_bignum_rand(struct assh_context_s *c,
                 struct assh_bignum_s *bn,
                 const struct assh_bignum_s *min,
                 const struct assh_bignum_s *max,
                 enum assh_prng_quality_e quality)
{
  assh_status_t err;
  assh_bnword_t *n = bn->n;
  size_t l = assh_bignum_words(bn->bits);

  if (l == 0)
    return ASSH_OK;

  do {
      ASSH_RET_ON_ERR(assh_prng_get(c, (uint8_t*)n,
                 l * sizeof(assh_bnword_t), quality | ASSH_PRNG_BIGNUM_FLAG));

      if (bn->bits % ASSH_BIGNUM_W)
        n[l - 1] &= ASSH_BN_WORDMAX >> (ASSH_BIGNUM_W - bn->bits % ASSH_BIGNUM_W);

  } while (!(min == NULL || (assh_bignum_cmp(bn, min) & ASSH_BIGNUM_CMP_GT)) ||
	   !(max == NULL || (assh_bignum_cmp(bn, max) & ASSH_BIGNUM_CMP_LT)));

  return ASSH_OK;
}

uint_fast32_t assh_bignum_bitlen(const struct assh_bignum_s *a)
{
  if (a->secret)
    return a->bits;

  uint_fast32_t j = assh_bignum_words(a->bits);
  const assh_bnword_t *an = a->n;
  assh_bnword_t t;
  while (j && !(t = an[j - 1]))
    j--;

  return j ? j * ASSH_BIGNUM_W - assh_bn_clz(t) : 0;
}
