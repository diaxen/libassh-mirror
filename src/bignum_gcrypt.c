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

void assh_bignum_print(FILE *out, const char *name,
		       const struct assh_bignum_s *bn)
{
  uint8_t buf[bn->l / 4 + 2];
  size_t l;

  assert(bn->n != NULL);

  if (name != NULL)
    fprintf(out, "%s: ", name);
  if (!gcry_mpi_print(GCRYMPI_FMT_HEX, buf, sizeof(buf), &l, bn->n))
    fwrite(buf, l, 1, out);
  else
    fputs("[error]", out);  
  if (name != NULL)
    fputs("\n", out);  
}

assh_error_t assh_bignum_from_data(struct assh_bignum_s *bn,
                                   const uint8_t * __restrict__ data,
				   size_t data_len)
{
  assh_error_t err;

  if (bn->n != NULL)
    gcry_mpi_release(bn->n);
  ASSH_ERR_RET(gcry_mpi_scan(&bn->n, GCRYMPI_FMT_USG, data, data_len, NULL)
               ? ASSH_ERR_CRYPTO : 0);

  return ASSH_OK;
}

size_t assh_bignum_mpint_size(const struct assh_bignum_s *bn)
{
  return bn->l / 8 + 6;
}

assh_error_t assh_bignum_to_mpint(const struct assh_bignum_s *bn,
                                  uint8_t * __restrict__ mpint)
{
  assh_error_t err;

  assert(bn->n != NULL);
  ASSH_ERR_RET(gcry_mpi_print(GCRYMPI_FMT_SSH, mpint, bn->l / 8 + 6, NULL, bn->n)
	       ? ASSH_ERR_CRYPTO : 0);
  return ASSH_OK;
}

assh_error_t
assh_bignum_msb_to_data(const struct assh_bignum_s *bn,
                        uint8_t * __restrict__ data, size_t data_len)
{
  assh_error_t err;

  assert(bn->n != NULL);
  ASSH_ERR_RET(gcry_mpi_print(GCRYMPI_FMT_USG, data, data_len, NULL, bn->n)
	       ? ASSH_ERR_CRYPTO : 0);

  return ASSH_OK;
}

assh_error_t
assh_bignum_rand(struct assh_context_s *c,
                 struct assh_bignum_s *bn)
{
  assh_error_t err;
  uint8_t rnd[bn->l / 8];

  ASSH_ERR_RET(c->prng->f_get(c, rnd, sizeof(rnd)));

  if (bn->n != NULL)
    gcry_mpi_release(bn->n);
  ASSH_ERR_RET(gcry_mpi_scan(&bn->n, GCRYMPI_FMT_USG, rnd, sizeof(rnd), NULL)
	       ? ASSH_ERR_CRYPTO : 0);

  return ASSH_OK;
}

assh_error_t
assh_bignum_uint(struct assh_bignum_s *bn,
                 unsigned int x)
{
  assh_error_t err;

  if (bn->n == NULL)
    bn->n = gcry_mpi_new(bn->l);
  ASSH_ERR_RET(bn->n == NULL ? ASSH_ERR_MEM : 0);
  gcry_mpi_set_ui(bn->n, x);  

  return ASSH_OK;
}

assh_error_t
assh_bignum_copy(struct assh_bignum_s *a,
                 const struct assh_bignum_s *b)
{
  assh_error_t err;

  if (a->n == NULL)
    a->n = gcry_mpi_new(a->l);
  ASSH_ERR_RET(a->n == NULL ? ASSH_ERR_MEM : 0);
  gcry_mpi_set(a->n, b->n);  

  return ASSH_OK;
}

int assh_bignum_cmp(const struct assh_bignum_s *a,
		    const struct assh_bignum_s *b)
{
  assert(a->n != NULL);
  assert(b->n != NULL);

  return gcry_mpi_cmp(b->n, a->n);
}

int assh_bignum_cmp_uint(const struct assh_bignum_s *a, unsigned int x)
{
  assert(a->n != NULL);
  return -gcry_mpi_cmp_ui(a->n, x);
}

assh_bool_t assh_bignum_cmpz(const struct assh_bignum_s *a)
{
  assert(a->n != NULL);
  return gcry_mpi_cmp_ui(a->n, 0) == 0;
}

assh_error_t
assh_bignum_add(struct assh_bignum_s *r,
		const struct assh_bignum_s *a,
		const struct assh_bignum_s *b)
{
  assh_error_t err;

  if (r->n == NULL)
    r->n = gcry_mpi_new(r->l);
  ASSH_ERR_RET(r->n == NULL ? ASSH_ERR_MEM : 0);
  assert(a->n != NULL);
  assert(b->n != NULL);

  gcry_mpi_add(r->n, a->n, b->n);

  return ASSH_OK;
}

assh_error_t
assh_bignum_sub(struct assh_bignum_s *r,
		const struct assh_bignum_s *a,
		const struct assh_bignum_s *b)
{
  assh_error_t err;

  if (r->n == NULL)
    r->n = gcry_mpi_new(r->l);
  ASSH_ERR_RET(r->n == NULL ? ASSH_ERR_MEM : 0);
  assert(a->n != NULL);
  assert(b->n != NULL);

  gcry_mpi_sub(r->n, a->n, b->n);

  return ASSH_OK;
}

assh_error_t
assh_bignum_mul(struct assh_bignum_s *r,
		const struct assh_bignum_s *a,
		const struct assh_bignum_s *b)
{
  assh_error_t err;

  if (r->n == NULL)
    r->n = gcry_mpi_new(r->l);
  ASSH_ERR_RET(r->n == NULL ? ASSH_ERR_MEM : 0);
  assert(a->n != NULL);
  assert(b->n != NULL);

  gcry_mpi_mul(r->n, a->n, b->n);

  return ASSH_OK;
}

assh_error_t
assh_bignum_mulmod(struct assh_bignum_s *r,
                   const struct assh_bignum_s *a,
                   const struct assh_bignum_s *b,
                   const struct assh_bignum_s *m)
{
  assh_error_t err;

  if (r->n == NULL)
    r->n = gcry_mpi_new(r->l);
  ASSH_ERR_RET(r->n == NULL ? ASSH_ERR_MEM : 0);
  assert(a->n != NULL);
  assert(b->n != NULL);
  assert(m->n != NULL);

  gcry_mpi_mulm(r->n, a->n, b->n, m->n);

  return ASSH_OK;
}

assh_error_t
assh_bignum_modinv(struct assh_bignum_s *r,
                   const struct assh_bignum_s *a,
                   const struct assh_bignum_s *m)
{
  assh_error_t err;

  if (r->n == NULL)
    r->n = gcry_mpi_new(r->l);
  ASSH_ERR_RET(r->n == NULL ? ASSH_ERR_MEM : 0);
  assert(a->n != NULL);
  assert(m->n != NULL);

  ASSH_ERR_RET(gcry_mpi_invm(r->n, a->n, m->n)
	       ? 0 : ASSH_ERR_OVERFLOW);

  return ASSH_OK;
}

assh_error_t
assh_bignum_div(struct assh_bignum_s *r,
                struct assh_bignum_s *d,
                const struct assh_bignum_s *a,
                const struct assh_bignum_s *b)
{
  assh_error_t err;

  if (r->n == NULL)
    r->n = gcry_mpi_new(r->l);
  ASSH_ERR_RET(r->n == NULL ? ASSH_ERR_MEM : 0);
  if (d != NULL)
    {
      if (d->n == NULL)
	d->n = gcry_mpi_new(d->l);
      ASSH_ERR_RET(d->n == NULL ? ASSH_ERR_MEM : 0);
    }
  assert(a->n != NULL);
  assert(b->n != NULL);

  ASSH_ERR_RET(gcry_mpi_cmp_ui(b->n, 0) ? 0 : ASSH_ERR_OVERFLOW);

  gcry_mpi_div(d == NULL ? NULL : d->n, r->n, a->n, b->n, 0);

  return ASSH_OK;  
}

assh_error_t
assh_bignum_rshift(struct assh_bignum_s *r,
                   const struct assh_bignum_s *a,
                   unsigned int n)
{
  assh_error_t err;

  if (r->n == NULL)
    r->n = gcry_mpi_new(r->l);
  ASSH_ERR_RET(r->n == NULL ? ASSH_ERR_MEM : 0);
  assert(a->n != NULL);

  gcry_mpi_rshift(r->n, a->n, n);

  return ASSH_OK;
}

assh_error_t
assh_bignum_expmod(struct assh_bignum_s *r,
                   const struct assh_bignum_s *x,
                   const struct assh_bignum_s *e,
                   const struct assh_bignum_s *m)
{
  assh_error_t err;

  if (r->n == NULL)
    r->n = gcry_mpi_new(r->l);
  ASSH_ERR_RET(r->n == NULL ? ASSH_ERR_MEM : 0);
  assert(x->n != NULL);
  assert(e->n != NULL);
  assert(m->n != NULL);

  gcry_mpi_powm(r->n, x->n, e->n, m->n);

  return ASSH_OK;
}

