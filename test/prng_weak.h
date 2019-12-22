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

#ifndef ASSH_TEST_PRNG_WEAK_H_
#define ASSH_TEST_PRNG_WEAK_H_

#include <stdint.h>
#include <stdlib.h>
#include <assh/assh_prng.h>
#include <assh/assh_buffer.h>

static const uint32_t prng_rand_max = 0xffffffffULL;

uint32_t assh_prng_rand_seed(uint64_t *seed)
{
  /* 64 bits lfsr */
  *seed = (-(*seed & 1) & 0x81ec82f69eb5a9d3ULL)
            ^ (*seed >> 1);

  /* diffusion */
  uint64_t r = *seed;
  uint64_t c = 2466808117ULL;
  r = ((uint32_t)r * c) ^ ((uint32_t)(r >> 32) * c);
  r = r ^ (r >> 32);

  return r;
}

static uint64_t prng_seed = 1;

uint32_t assh_prng_rand()
{
  return assh_prng_rand_seed(&prng_seed);
}

void assh_prng_seed(uint64_t seed)
{
  if (!seed)
    seed++;
  prng_seed = seed;
}

static ASSH_PRNG_INIT_FCN(assh_prng_dummy_init)
{
  uint8_t *p = malloc(8);
  uint64_t s;

  if (!p)
    return ASSH_ERR_MEM;

  c->prng_pv = p;

  if (seed)
    {
      if (seed->size < 8)
	return ASSH_ERR_BAD_ARG;
      s = assh_load_u64le(seed->data);
      s |= !s;
    }
  else
    {
      s = assh_load_u64le((const uint8_t*)"abcdefgh");
    }

  assh_store_u64le(p, s);

  return ASSH_OK;
}

static ASSH_PRNG_GET_FCN(assh_prng_dummy_get)
{
  uint64_t s = assh_load_u64le(c->prng_pv);
  size_t i;

  if (quality & ASSH_PRNG_BIGNUM_FLAG)
    {
      unsigned m = CONFIG_ASSH_BIGNUM_WORD / 8 - 1;
      assert(!(rdata_len & m));

      union {
	uint32_t u32;
	uint8_t u8[4];
      } e;

      /* byte swap mask depends on endianness */
      e.u32 = 1;
      unsigned x = e.u8[0] ? 0 : m;

      for (i = 0; i < rdata_len; i++)
	rdata[i ^ x] = assh_prng_rand_seed(&s);

      /* align to next bignum large word boundary */
      while (i++ & 7)
	assh_prng_rand_seed(&s);
    }
  else
    {
      for (i = 0; i < rdata_len; i++)
	rdata[i] = assh_prng_rand_seed(&s);
    }

  assh_store_u64le(c->prng_pv, s);

  return ASSH_OK;
}

static ASSH_PRNG_CLEANUP_FCN(assh_prng_dummy_cleanup)
{
  free(c->prng_pv);
}

static const struct assh_prng_s assh_prng_dummy =
{
  .f_init = assh_prng_dummy_init,
  .f_get = assh_prng_dummy_get,
  .f_cleanup = assh_prng_dummy_cleanup,
};

#endif
