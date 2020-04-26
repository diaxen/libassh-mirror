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

#define ASSH_ABI_UNSAFE  /* do not warn */

#include "test.h"

#include <assh/assh_alloc.h>
#include <assh/assh_kex.h>
#include <assh/assh_mac.h>
#include <assh/assh_compress.h>
#include <assh/assh_cipher.h>
#include <assh/assh_session.h>
#include <assh/assh_sign.h>
#include <assh/assh_buffer.h>

#include <stdint.h>
#include <stdlib.h>

#ifdef CONFIG_ASSH_VALGRIND
# include <valgrind/memcheck.h>
#endif

/**************************************************************/

uint32_t test_packet_fuzz = 0;
unsigned long test_packet_fuzz_bits = 0;

static ASSH_CIPHER_INIT_FCN(assh_fuzz_init)
{
  return ASSH_OK;
}

static ASSH_CIPHER_PROCESS_FCN(assh_fuzz_process)
{
  if (test_packet_fuzz)
    test_packet_fuzz_bits += test_fuzz_mangle(data, len, test_packet_fuzz);
  return ASSH_OK;
}

static ASSH_CIPHER_CLEANUP_FCN(assh_fuzz_cleanup)
{
}

const struct assh_algo_cipher_s test_cipher_fuzz =
{
  ASSH_ALGO_BASE(CIPHER, "assh-test", 0, 99,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_ASSH,
                      "fuzz" })
  ),
  .ctx_size = 0,
  .block_size = 8,
  .head_size = 4,
  .f_init = assh_fuzz_init,
  .f_process = assh_fuzz_process,
  .f_cleanup = assh_fuzz_cleanup,
};

void test_cipher_fuzz_initreg(struct assh_context_s *c,
                              struct assh_session_s *s)
{
  struct assh_kex_keys_s *keys;

  while (assh_alloc(c, sizeof(*keys), ASSH_ALLOC_INTERNAL, (void**)&keys))
    /* retry due to alloc fuzz */;

  keys->cipher_algo = &test_cipher_fuzz;
  keys->cipher_ctx = NULL;
  keys->mac_algo = &assh_mac_none;
  keys->mac_ctx = NULL;
  keys->cmp_algo = &assh_compress_none;
  keys->cmp_ctx = NULL;
  s->cur_keys_out = keys;
}

unsigned
test_fuzz_mangle(uint8_t *data, size_t len, uint32_t ratio)
{
  uint64_t r = test_prng_rand_max / ratio;
  uint32_t i, j;

  for (i = j = 0; i < len * 8; i++)
    if (r > test_prng_rand() * 8ULL)
      {
	data[i / 8] ^= 1 << (i % 8);
	j++;
      }

  return j;
}

/**************************************************************/

const uint32_t test_prng_rand_max = 0xffffffffULL;
uint64_t test_prng_seed = 1;

uint32_t test_prng_rand_seed(uint64_t *seed)
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

static ASSH_PRNG_INIT_FCN(test_prng_dummy_init)
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

static ASSH_PRNG_GET_FCN(test_prng_dummy_get)
{
  uint64_t s = assh_load_u64le(c->prng_pv);
  size_t i;

  if (quality & ASSH_PRNG_BIGNUM_FLAG)
    {
#ifdef CONFIG_ASSH_BIGNUM_BUILTIN
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
	rdata[i ^ x] = test_prng_rand_seed(&s);

      /* align to next bignum large word boundary */
      while (i++ & 7)
	test_prng_rand_seed(&s);
#else
      TEST_FAIL("prng bignum");
#endif
    }
  else
    {
      for (i = 0; i < rdata_len; i++)
	rdata[i] = test_prng_rand_seed(&s);
    }

  assh_store_u64le(c->prng_pv, s);

  return ASSH_OK;
}

static ASSH_PRNG_CLEANUP_FCN(test_prng_dummy_cleanup)
{
  free(c->prng_pv);
}

const struct assh_prng_s test_prng_dummy =
{
  .f_init = test_prng_dummy_init,
  .f_get = test_prng_dummy_get,
  .f_cleanup = test_prng_dummy_cleanup,
};

/**************************************************************/

assh_status_t
test_algo_lookup(enum assh_algo_class_e cl, const char *name,
		 const char *variant, const char *implem,
		 const struct assh_algo_s **algo)
{
  if (!strcmp(name, "fuzz") && cl == ASSH_ALGO_CIPHER)
    {
      *algo = &test_cipher_fuzz.algo;
      return ASSH_OK;
    }

  if (!strcmp(name, "none") || !strcmp(name, "none@libassh.org"))
    {
      switch (cl)
	{
	case ASSH_ALGO_KEX:
	  *algo = &assh_kex_none.algo_wk.algo;
	  return ASSH_OK;
	case ASSH_ALGO_SIGN:
	  *algo = &assh_sign_none.algo_wk.algo;
	  return ASSH_OK;
	case ASSH_ALGO_CIPHER:
	  *algo = &assh_cipher_none.algo;
	  return ASSH_OK;
	case ASSH_ALGO_MAC:
	  *algo = &assh_mac_none.algo;
	  return ASSH_OK;
	case ASSH_ALGO_COMPRESS:
	  *algo = &assh_compress_none.algo;
	  return ASSH_OK;
	default:
	  abort();
	}
    }

  const struct assh_algo_s **table = assh_algo_table;
  const struct assh_algo_s *a;

  while ((a = *table++) != NULL)
    {
      if (cl != ASSH_ALGO_ANY && cl != a->class_)
	continue;

      const struct assh_algo_name_s *n;
      for (n = a->names; n->spec; n++)
	if (!strcmp(name, n->name))
	  break;

      if (!n->spec)
	continue;

      if (implem && strcmp(implem, a->implem) && a->nondeterministic)
	continue;

      if (variant && (!a->variant || strcmp(variant, a->variant)))
	continue;

      *algo = a;
      return ASSH_OK;
    }

  return ASSH_NOT_FOUND;
}

/**************************************************************/

size_t test_alloc_size = 0;
uint32_t test_alloc_fuzz = 0;
unsigned long test_alloc_fuzz_fails = 0;

ASSH_ALLOCATOR(test_leaks_allocator)
{
  if (*ptr == NULL)
    {
      if (test_alloc_fuzz && test_prng_rand() % test_alloc_fuzz == 0)
	{
	  test_alloc_fuzz_fails++;
	  return ASSH_ERR_MEM;
	}
      size_t *bsize = malloc(TEST_ALLOC_ALIGN + size);
      if (bsize != NULL)
	{
	  *ptr = (uint8_t*)bsize + TEST_ALLOC_ALIGN;
	  *bsize = size;
	  test_alloc_size += size;
	  memset(*ptr, 0xa5, size);
#ifdef CONFIG_ASSH_VALGRIND
	  VALGRIND_MAKE_MEM_UNDEFINED(*ptr, size);
#endif
	  return ASSH_OK;
	}
      return ASSH_ERR_MEM;
    }
  else if (size == 0)
    {
      size_t *bsize = (void*)((uint8_t*)*ptr - TEST_ALLOC_ALIGN);
      test_alloc_size -= *bsize;
      memset((void*)bsize, 0x5a, *bsize);
      free((void*)bsize);
      return ASSH_OK;
    }
  else
    {
      if (test_alloc_fuzz && test_prng_rand() % test_alloc_fuzz == 0)
	{
	  test_alloc_fuzz_fails++;
	  return ASSH_ERR_MEM;
	}
      size_t *bsize = (void*)((uint8_t*)*ptr - TEST_ALLOC_ALIGN);
      bsize = realloc(bsize, TEST_ALLOC_ALIGN + size);
      if (bsize != NULL)
	{
	  test_alloc_size -= *bsize;
	  test_alloc_size += size;
	  *ptr = (uint8_t*)bsize + TEST_ALLOC_ALIGN;
	  *bsize = size;
	  return ASSH_OK;
	}
      return ASSH_ERR_MEM;
    }
}

