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
#define ASSH_ABI_UNSAFE  /* do not warn */

#include <assh/assh_sign.h>
#include <assh/assh_context.h>
#include <assh/assh_prng.h>

#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include "sign.h"
#include "test.h"

void test_const()
{
  int i, j;

  for (i = 0; algos[i].algo; i++)
    {
      const struct assh_algo_s **a;
      assh_bool_t done = 0;

      for (a = assh_algo_table; *a; a++)
	{
	  if (!assh_algo_supported(*a))
	    continue;

	  if (!assh_algo_name_match(*a, ASSH_ALGO_SIGN,
				    algos[i].algo, strlen(algos[i].algo)))
	    continue;

	  const struct assh_algo_sign_s *sa = assh_algo_sign(*a);

	  if (algos[i].variant && (!sa->algo_wk.algo.variant ||
		   strcmp(algos[i].variant, sa->algo_wk.algo.variant)))
	    continue;

	  done = 1;

	  struct assh_key_s *key;

	  printf("\n%s (%s) (%s) const sign/verify: ",
		  assh_algo_name(&sa->algo_wk.algo), sa->algo_wk.algo.implem,
		  sa->algo_wk.algo.variant ? sa->algo_wk.algo.variant : "");

	  struct assh_context_s *context;

	  if (assh_context_create(&context, ASSH_CLIENT_SERVER,
				  test_leaks_allocator, NULL, &test_prng_dummy, NULL))
	    TEST_FAIL("context create\n");

	  if (assh_algo_register_va(context, 0, sa, NULL))
	    TEST_FAIL("algo register\n");

	  uint8_t key_blob[algos[i].key_len];
	  memcpy(key_blob, algos[i].key, sizeof(key_blob));

	  putchar('L');
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

	  putchar('g');
	  if (assh_sign_generate(context, sa, key, 3, d, NULL, &sign_len))
	    TEST_FAIL("sign generate\n");

	  if (algos[i].sign) {
	    putchar('c');

	    if (sign_len != algos[i].sign_len)
	      {
		fprintf(stderr, "expected len %zu\n", algos[i].sign_len);
		fprintf(stderr, "wrong %zu\n", sign_len);
		TEST_FAIL("wrong sign len");
	      }
	  }

	  uint8_t sign[sign_len];
	  if (assh_sign_generate(context, sa, key, 3, d, sign, &sign_len))
	    TEST_FAIL("sign generate\n");

	  if (algos[i].sign && (!algos[i].implem ||
				!strcmp(algos[i].implem, sa->algo_wk.algo.implem)))
	    if (memcmp(algos[i].sign, sign, sign_len))
	      {
		assh_hexdump(stderr, "expected", algos[i].sign, sign_len);
		assh_hexdump(stderr, "wrong", sign, sign_len);
		TEST_FAIL("unexpected signature\n");
	      }

	  putchar('v');
	  assh_safety_t sign_safety;
	  if (assh_sign_check(context, sa, key, 3, d, sign, sign_len, &sign_safety))
	    TEST_FAIL("sign check\n");

	  if (sign_safety > sa->algo_wk.algo.safety || sign_safety > key->safety)
	    TEST_FAIL("sign safety\n");

	  data[test_prng_rand() % sizeof(data)]++;

	  putchar('V');
	  if (!assh_sign_check(context, sa, key, 3, d, sign, sign_len, &sign_safety))
	    TEST_FAIL("sign check\n");

	  assh_key_drop(context, &key);
	  assh_context_release(context);

	  if (test_alloc_size != 0)
	    TEST_FAIL("memory leak detected, %zu bytes allocated\n", test_alloc_size);
	}

      if (!done)
	printf("skipping %s, no implementation\n", algos[i].algo);
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
	  if (!assh_algo_supported(*a))
	    continue;

	  if (!assh_algo_name_match(*a, ASSH_ALGO_SIGN,
				    algos[i].algo, strlen(algos[i].algo)))
	    continue;

	  const struct assh_algo_sign_s *sa = assh_algo_sign(*a);

	  if (algos[i].variant && (!sa->algo_wk.algo.variant ||
		   strcmp(algos[i].variant, sa->algo_wk.algo.variant)))
	    continue;

	  done = 1;

	  struct assh_key_s *key;

	  printf("\n%s (%s) (%s) const load/validate: ",
		  assh_algo_name(&sa->algo_wk.algo), sa->algo_wk.algo.implem,
		  sa->algo_wk.algo.variant ? sa->algo_wk.algo.variant : "");

	  struct assh_context_s *context;

	  if (assh_context_create(&context, ASSH_CLIENT_SERVER,
				  test_leaks_allocator, NULL, &test_prng_dummy, NULL))
	    TEST_FAIL("context create\n");

	  if (assh_algo_register_va(context, 0, sa, NULL))
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
		  unsigned int r1 = test_prng_rand() % sizeof(key_blob);
		  unsigned char r2 = test_prng_rand();
		  if (!r2)
		    r2++;
#ifdef CONFIG_ASSH_DEBUG_SIGN
		  ASSH_DEBUG("Mangling key byte %u, previous=0x%02x, new=0x%02x\n",
			     r1, key_blob[r1], key_blob[r1] ^ r2);
#endif
		  key_blob[r1] ^= r2;
		  putchar('B');
		}
	      else
		{
		  putchar('G');
		}

	      putchar('l');
	      const uint8_t *kb = key_blob + 1;
	      assh_status_t err = assh_key_load(context, &key, sa->algo_wk.key_algo, ASSH_ALGO_SIGN,
						key_blob[0], &kb, sizeof(key_blob) - 1);

	      if (!bad)
		{
		  TEST_ASSERT(err == ASSH_OK);
		}
	      else if (err == ASSH_OK)
		{
		  putchar('C');

		  enum assh_key_validate_result_e r;
		  if (assh_key_validate(context, key, &r))
		    TEST_FAIL("validate");

		  TEST_ASSERT(bad || r > 0);
		}

	      if (err == ASSH_OK)
		assh_key_drop(context, &key);
	    }

	  assh_context_release(context);

	  if (test_alloc_size != 0)
	    TEST_FAIL("memory leak detected, %zu bytes allocated\n", test_alloc_size);
	}

      if (!done)
	printf("skipping %s, no implementation\n", algos[i].algo);
    }
}

int main(int argc, char **argv)
{
  setvbuf(stdout, NULL, _IONBF, 0);

  unsigned int s = argc > 1 ? atoi(argv[1]) : time(0);

  if (assh_deps_init())
    TEST_FAIL("deps init");

  test_prng_set_seed(s);
  printf("Seed: %u", s);

  test_const();

  test_load(16);

  puts("\n\nTest passed");
  return 0;
}

