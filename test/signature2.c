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
#include <getopt.h>

#include "sign.h"
#include "test.h"

#define TEST_STEP 4

struct assh_context_s *context;

enum action_e {
  ACTION_NEW_KEYS = 1,
  ACTION_VALIDATE_KEYS = 2,
  ACTION_FUZZ_CHECK = 4,
};

void test_sign(unsigned int max_size, enum action_e action)
{
  int i;

  max_size -= max_size % TEST_STEP;

  for (i = 0; algos[i].algo; i++)
    {
      const struct assh_algo_s **a;
      assh_bool_t done = 0;

      for (a = assh_algo_table; *a; a++)
	{
	  if (!assh_algo_name_match(*a, ASSH_ALGO_SIGN,
				    algos[i].algo, strlen(algos[i].algo)))
	    continue;

	  const struct assh_algo_sign_s *sa = assh_algo_sign(*a);

	  if (algos[i].variant && (!sa->algo_wk.algo.variant ||
		   strcmp(algos[i].variant, sa->algo_wk.algo.variant)))
	    continue;

	  done = 1;

	  struct assh_key_s *key, *key2;

	  printf("\n%s (%s) (%s) sign/verify: ",
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
	  if (assh_key_load(context, &key2, sa->algo_wk.key_algo, ASSH_ALGO_SIGN,
			    key_blob[0], &kb, sizeof(key_blob) - 1))
	    TEST_FAIL("key load");

#ifdef CONFIG_ASSH_KEY_VALIDATE
	  if (action & ACTION_VALIDATE_KEYS)
	    {
	      enum assh_key_validate_result_e r;
	      if (assh_key_validate(context, key2, &r))
		TEST_FAIL("key validate");
	      TEST_ASSERT(r > 0);
	    }
#endif

	  TEST_ASSERT(assh_key_cmp(context, key2, key2, 0));
	  TEST_ASSERT(assh_key_cmp(context, key2, key2, 1));

	  key = key2;

	  int size;
	  for (size = max_size; size != 0; )
	    {
#ifdef CONFIG_ASSH_KEY_CREATE
	      if (algos[i].gen_key && (action & ACTION_NEW_KEYS))
		{
		  size_t kbits = algos[i].kbits_min + test_prng_rand()
		    % (algos[i].kbits_max - algos[i].kbits_min + 1);
		  putchar('N');
		  if (assh_key_create(context, &key, kbits,
				      sa->algo_wk.key_algo, ASSH_ALGO_SIGN))
		    TEST_FAIL("key create");

# ifdef CONFIG_ASSH_KEY_VALIDATE
		  putchar('C');
		  enum assh_key_validate_result_e r;
		  if (assh_key_validate(context, key, &r))
		    TEST_FAIL("key validate");
		  TEST_ASSERT(r > 0);
# endif
		  TEST_ASSERT(assh_key_cmp(context, key, key, 0));
		  TEST_ASSERT(assh_key_cmp(context, key, key, 1));

		  TEST_ASSERT(!assh_key_cmp(context, key, key2, 0));
		  TEST_ASSERT(!assh_key_cmp(context, key, key2, 1));
		}
#endif

	      size -= TEST_STEP;
	      uint8_t data[size];
	      if (assh_prng_get(context, data, size,
				 ASSH_PRNG_QUALITY_WEAK))
		TEST_FAIL("prng get");

	      struct assh_cbuffer_s d[8];
	      int c = 0;
	      int s = 0;
	      while (s < size)
		{
		  int r = test_prng_rand() % 128 + 128;
		  if (s + r > size)
		    r = size - s;
		  d[c].data = data + s;
		  d[c].size = r;
		  s += r;
		  c++;
		}

	      size_t sign_len;

	      putchar('g');

	      if (assh_sign_generate(context, sa, key, c, d, NULL, &sign_len))
		TEST_FAIL("sign generate");
	      TEST_ASSERT(sign_len > 0);

	      uint8_t sign[sign_len];
	      if (assh_sign_generate(context, sa, key, c, d, sign, &sign_len))
		TEST_FAIL("sign generate");

	      putchar('v');

	      assh_safety_t sign_safety;

	      assh_status_t err = assh_sign_check(context, sa, key, c, d, sign, sign_len, &sign_safety);
	      TEST_ASSERT(err == ASSH_OK);

	      TEST_ASSERT(sign_safety <= sa->algo_wk.algo.safety &&
			  sign_safety <= key->safety);

	      if (action & ACTION_FUZZ_CHECK)
		{
		  unsigned mc, fc = 256;

		  while (fc)
		    {
		      uint8_t sign2[sign_len];
		      memcpy(sign2, sign, sign_len);

		      do {
			mc = test_fuzz_mangle(sign2, sign_len, 10 + test_prng_rand() % 1024);
		      } while (!mc);

		      putchar('V');

		      err = assh_sign_check(context, sa, key, c, d, sign2, sign_len, &sign_safety);

		      if (err != ASSH_OK)
			fc--;   /* successfully broke the signature */
		    }
		}

	      if (size)
		{
		  unsigned int r1 = test_prng_rand() % size;
		  unsigned char r2 = test_prng_rand();
		  r2 += !r2;

#ifdef CONFIG_ASSH_DEBUG_SIGN
		  ASSH_DEBUG("Mangling data byte %u, previous=0x%02x, new=0x%02x\n",
			  r1, data[r1], data[r1] ^ r2);
#endif
		  data[r1] ^= r2;

		  err = assh_sign_check(context, sa, key, c, d, sign, sign_len, &sign_safety);
		  TEST_ASSERT(err != ASSH_OK);
		}

#ifdef CONFIG_ASSH_KEY_CREATE
	      if (algos[i].gen_key && (action & ACTION_NEW_KEYS))
		assh_key_drop(context, &key);
#endif
	    }

	  assh_key_drop(context, &key2);
	  assh_context_release(context);

	  if (test_alloc_size != 0)
	    TEST_FAIL("memory leak detected, %zu bytes allocated\n", test_alloc_size);
	}

      if (!done)
	printf("skipping %s, no implementation\n", algos[i].algo);
    }
}

static void usage()
{
  printf("usage: signature2 [options]\n");

  printf(	  "Options:\n\n"

	  "    -h         show help\n"
#ifdef CONFIG_ASSH_KEY_CREATE
	  "    -n         test key creation\n"
#endif
#ifdef CONFIG_ASSH_KEY_VALIDATE
	  "    -v         test key validation\n"
#endif
	  "    -f         fuzz signature checking\n"
	  "    -m size    set the payload max size (default 128)\n"
	  "    -c count   set number of test passes (default 1)\n"
	  "    -s seed    set initial seed (default: time(0))\n"
	  );
}

int main(int argc, char **argv)
{
  setvbuf(stdout, NULL, _IONBF, 0);

  if (assh_deps_init())
    TEST_FAIL("deps init");

  enum action_e action = 0;
  unsigned seed = time(0);
  unsigned count = 1;
  unsigned max_size = 128;
  int opt;

  while ((opt = getopt(argc, argv, "nvfhs:c:m:")) != -1)
    {
      switch (opt)
	{
#ifdef CONFIG_ASSH_KEY_CREATE
	case 'n':
	  action |= ACTION_NEW_KEYS;
	  break;
#endif
#ifdef CONFIG_ASSH_KEY_VALIDATE
	case 'v':
	  action |= ACTION_VALIDATE_KEYS;
	  break;
#endif
	case 'f':
	  action |= ACTION_FUZZ_CHECK;
	  break;
	case 's':
	  seed = atoi(optarg);
	  break;
	case 'c':
	  count = atoi(optarg);
	  break;
	case 'm':
	  max_size = atoi(optarg);
	  break;
	case 'h':
	  usage();
	default:
	  return 1;
	}
    }

  if (!action)
    action = ACTION_NEW_KEYS | ACTION_VALIDATE_KEYS;

  test_prng_set_seed(seed);
  printf("Seed: %u", seed);

  while (count--)
    test_sign(max_size, action);

  puts("\n\nTest passed");
  return 0;
}

