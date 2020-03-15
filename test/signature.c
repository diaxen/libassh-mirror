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

#include <assh/assh_sign.h>
#include <assh/assh_context.h>
#include <assh/assh_prng.h>

#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include "sign.h"
#include "prng_weak.h"
#include "test.h"
#include "leaks_check.h"

void test_const()
{
  int i, j;

  for (i = 0; algos[i].algo; i++)
    {
      const struct assh_algo_s **a;
      assh_bool_t done = 0;

      for (a = assh_algo_table; *a; a++)
	{
	  const struct assh_algo_sign_s *sa = (void*)*a;

	  if (!assh_algo_name_match(*a, ASSH_ALGO_SIGN,
				    algos[i].algo, strlen(algos[i].algo)))
	    continue;

	  if (algos[i].variant && (!sa->algo_wk.algo.variant ||
		   strcmp(algos[i].variant, sa->algo_wk.algo.variant)))
	    continue;

	  done = 1;

	  struct assh_key_s *key;

	  fprintf(stderr, "\n%s (%s) (%s) const sign/verify: ",
		  assh_algo_name(&sa->algo_wk.algo), sa->algo_wk.algo.implem,
		  sa->algo_wk.algo.variant ? sa->algo_wk.algo.variant : "");

	  struct assh_context_s *context;

	  if (assh_context_create(&context, ASSH_CLIENT_SERVER,
				  assh_leaks_allocator, NULL, &assh_prng_dummy, NULL))
	    TEST_FAIL("context create\n");

	  if (assh_algo_register_va(context, 0, 0, 0, sa, NULL))
	    TEST_FAIL("algo register\n");

	  uint8_t key_blob[algos[i].key_len];
	  memcpy(key_blob, algos[i].key, sizeof(key_blob));

	  fprintf(stderr, "L");
	  const uint8_t *kb = key_blob + 1;
	  if (assh_key_load(context, &key, sa->algo_wk.key_algo, ASSH_ALGO_SIGN,
			    key_blob[0], &kb, sizeof(key_blob) - 1))
	    TEST_FAIL("key load\n");

	  size_t sign_len;

	  uint8_t data[11 + 27 + 33];
	  struct assh_cbuffer_s d[3] = {
		{ .data = data,           .len = 11 },
		{ .data = data + 11,      .len = 27 },
		{ .data = data + 11 + 27, .len = 33 }
	  };
	  for (j = 0; j < sizeof(data); j++)
	    data[j] = j;

	  fprintf(stderr, "g");
	  if (assh_sign_generate(context, sa, key, 3, d, NULL, &sign_len))
	    TEST_FAIL("sign generate\n");

	  if (algos[i].sign) {
	    fprintf(stderr, "c");

	    if (sign_len != algos[i].sign_len)
	      {
		fprintf(stderr, "expected len %zu\n", algos[i].sign_len);
		fprintf(stderr, "wrong %zu\n", sign_len);
		abort();
	      }
	  }

	  uint8_t sign[sign_len];
	  if (assh_sign_generate(context, sa, key, 3, d, sign, &sign_len))
	    TEST_FAIL("sign generate\n");

	  if (algos[i].sign && (!algos[i].implem ||
				!strcmp(algos[i].implem, sa->algo_wk.algo.implem)))
	    if (memcmp(algos[i].sign, sign, sign_len))
	      {
		assh_hexdump("expected", algos[i].sign, sign_len);
		assh_hexdump("wrong", sign, sign_len);
		TEST_FAIL("unexpected signature\n");
	      }

	  fprintf(stderr, "v");
	  assh_safety_t sign_safety;
	  if (assh_sign_check(context, sa, key, 3, d, sign, sign_len, &sign_safety))
	    TEST_FAIL("sign check\n");

	  if (sign_safety > sa->algo_wk.algo.safety || sign_safety > key->safety)
	    TEST_FAIL("sign safety\n");

	  data[assh_prng_rand() % sizeof(data)]++;

	  fprintf(stderr, "V");
	  if (!assh_sign_check(context, sa, key, 3, d, sign, sign_len, &sign_safety))
	    TEST_FAIL("sign check\n");

	  assh_key_drop(context, &key);
	  assh_context_release(context);

	  if (alloc_size != 0)
	    TEST_FAIL("memory leak detected, %zu bytes allocated\n", alloc_size);
	}

      if (!done)
	fprintf(stderr, "skipping %s, no implementation\n", algos[i].algo);
    }
}

void test_load(unsigned int max_size)
{
  int i;

  for (i = 0; algos[i].algo; i++)
    {
      const struct assh_algo_s **a;
      assh_bool_t done = 0;

      for (a = assh_algo_table; *a; a++)
	{
	  const struct assh_algo_sign_s *sa = (void*)*a;

	  if (!assh_algo_name_match(*a, ASSH_ALGO_SIGN,
				    algos[i].algo, strlen(algos[i].algo)))
	    continue;

	  if (algos[i].variant && (!sa->algo_wk.algo.variant ||
		   strcmp(algos[i].variant, sa->algo_wk.algo.variant)))
	    continue;

	  done = 1;

	  struct assh_key_s *key;

	  fprintf(stderr, "\n%s (%s) (%s) const load/validate: ",
		  assh_algo_name(&sa->algo_wk.algo), sa->algo_wk.algo.implem,
		  sa->algo_wk.algo.variant ? sa->algo_wk.algo.variant : "");

	  struct assh_context_s *context;

	  if (assh_context_create(&context, ASSH_CLIENT_SERVER,
				  assh_leaks_allocator, NULL, &assh_prng_dummy, NULL))
	    TEST_FAIL("context create\n");

	  if (assh_algo_register_va(context, 0, 0, 0, sa, NULL))
	    TEST_FAIL("algo register\n");

	  uint8_t key_blob[algos[i].key_len];

	  /* test key loading and validation */
	  int j;
	  for (j = 0; j < max_size; j++)
	    {
	      memcpy(key_blob, algos[i].key, sizeof(key_blob));
	      int bad = j & 1;

	      if (bad)
		{
		  unsigned int r1 = assh_prng_rand() % sizeof(key_blob);
		  unsigned char r2 = assh_prng_rand();
		  if (!r2)
		    r2++;
#ifdef CONFIG_ASSH_DEBUG_SIGN
		  fprintf(stderr, "Mangling key byte %u, previous=0x%02x, new=0x%02x\n",
			  r1, key_blob[r1], key_blob[r1] ^ r2);
#endif
		  key_blob[r1] ^= r2;
		  fprintf(stderr, "B");
		}
	      else
		{
		  fprintf(stderr, "G");
		}

	      fprintf(stderr, "l");
	      const uint8_t *kb = key_blob + 1;
	      assh_status_t err = assh_key_load(context, &key, sa->algo_wk.key_algo, ASSH_ALGO_SIGN,
						key_blob[0], &kb, sizeof(key_blob) - 1);

	      if (!bad)
		{
		  TEST_ASSERT(err == ASSH_OK);
		}
	      else if (err == ASSH_OK)
		{
		  fprintf(stderr, "C");

		  enum assh_key_validate_result_e r;
		  if (assh_key_validate(context, key, &r))
		    TEST_FAIL("validate");

		  TEST_ASSERT(bad || r > 0);
		}

	      if (err == ASSH_OK)
		assh_key_drop(context, &key);
	    }

	  assh_context_release(context);

	  if (alloc_size != 0)
	    TEST_FAIL("memory leak detected, %zu bytes allocated\n", alloc_size);
	}

      if (!done)
	fprintf(stderr, "skipping %s, no implementation\n", algos[i].algo);
    }
}

int main(int argc, char **argv)
{
  unsigned int s = argc > 1 ? atoi(argv[1]) : time(0);

  if (assh_deps_init())
    TEST_FAIL("deps init");

  assh_prng_seed(s);
  fprintf(stderr, "Seed: %u", s);

  test_const();

  test_load(16);

  fprintf(stderr, "\nDone.\n");
  return 0;
}

