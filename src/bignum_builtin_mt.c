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

#define ASSH_PV

#include "bignum_builtin.h"

#include <assh/assh_alloc.h>

assh_status_t
assh_bignum_mt_init(struct assh_context_s *c,
                    struct assh_bignum_mt_s *mt,
                    const struct assh_bignum_s *mod)
{
  assh_status_t err;


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

  assh_bignum_div_euclidean(r2, ml * 2 + 1, NULL, 0, m, ml,
                    mod->secret, 2 * ml * ASSH_BIGNUM_W + 1 - mod->bits);

  /* compute 1 in montgomery representation */
  assh_bnword_t *r1 = m + ml * 2;

  for (i = 0; i < ml; i++)
    r1[i] = 0;
  r1[i] = 1;

  assh_bignum_div_euclidean(r1, ml + 1, NULL, 0, m, ml, mod->secret,
                             ml * ASSH_BIGNUM_W + 1 - mod->bits);

  return ASSH_OK;
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
assh_bignum_expmod_mt_sc_size(const struct assh_bignum_mt_s *mt)
{
  return assh_bignum_words(mt->max_bits) * 2;
}

assh_status_t
assh_bignum_expmod_mt(struct assh_context_s *ctx,
                      assh_bnword_t *sq,
                      struct assh_bignum_s *r,
                      const struct assh_bignum_s *a,
                      const struct assh_bignum_s *b,
                      const struct assh_bignum_mt_s *mt)
{
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
assh_status_t
assh_bignum_modinv_mt(struct assh_context_s *ctx,
                      assh_bnword_t *sq,
                      struct assh_bignum_s *r,
                      const struct assh_bignum_s *a,
                      const struct assh_bignum_mt_s *mt)
{
  assert(mt->mod.bits == a->bits &&
         mt->mod.bits == r->bits);

  size_t ml = assh_bignum_words(mt->mod.bits);

  assh_bnword_t *tmp = sq + ml;
  uint_fast32_t i = 0;
  assh_bnword_t *rn = r->n;

  /* prime modulus - 2 */
  assh_bnword_t p = 0, *pn = mt->mod.n;
  assh_bnslong_t t = ~(assh_bnlong_t)0 << (ASSH_BIGNUM_W + 1);

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

