
#include <assh/assh_sign.h>
#include <assh/assh_context.h>
#include <assh/assh_prng.h>

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <getopt.h>

#include "sign.h"
#include "prng_weak.h"
#include "test.h"
#include "fuzz.h"

#define TEST_STEP 4

struct assh_context_s *context;

enum action_e {
  ACTION_NEW_KEYS = 1,
  ACTION_VALIDATE_KEYS = 2,
  ACTION_FUZZ_CHECK = 4,
};

assh_error_t test_sign(unsigned int max_size, enum action_e action)
{
  assh_error_t err;
  int i;

  max_size -= max_size % TEST_STEP;

  for (i = 0; algos[i].algo; i++)
    {
      const struct assh_algo_sign_s *a = algos[i].algo;
      struct assh_key_s *key, *key2;

      fprintf(stderr, "\n%s sign/verify: ", assh_algo_name(&a->algo));

      uint8_t key_blob[algos[i].key_len];
      memcpy(key_blob, algos[i].key, sizeof(key_blob));

      fprintf(stderr, "L");
      const uint8_t *kb = key_blob + 1;
      ASSH_RET_ON_ERR(assh_key_load(context, &key2, a->algo.key, ASSH_ALGO_SIGN,
				 key_blob[0], &kb, sizeof(key_blob) - 1));

#ifdef CONFIG_ASSH_KEY_VALIDATE
      if (action & ACTION_VALIDATE_KEYS)
	{
	  enum assh_key_validate_result_e r;
	  ASSH_RET_ON_ERR(assh_key_validate(context, key2, &r));
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
	      size_t kbits = algos[i].kbits_min + assh_prng_rand()
                           % (algos[i].kbits_max - algos[i].kbits_min + 1);
              fprintf(stderr, "N");
	      ASSH_RET_ON_ERR(assh_key_create(context, &key, kbits,
	                    a->algo.key, ASSH_ALGO_SIGN));

# ifdef CONFIG_ASSH_KEY_VALIDATE
              fprintf(stderr, "C");
	      enum assh_key_validate_result_e r;
	      ASSH_RET_ON_ERR(assh_key_validate(context, key, &r));
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
	  ASSH_RET_ON_ERR(context->prng->f_get(context, data, size,
                                           ASSH_PRNG_QUALITY_WEAK));

	  struct assh_cbuffer_s d[8];
	  int c = 0;
	  int s = 0;
	  while (s < size)
	    {
	      int r = assh_prng_rand() % 128 + 128;
	      if (s + r > size)
		r = size - s;
	      d[c].data = data + s;
	      d[c].size = r;
	      s += r;
              c++;
	    }

	  size_t sign_len;

          fprintf(stderr, "g");

	  ASSH_RET_ON_ERR(assh_sign_generate(context, a, key, c, d, NULL, &sign_len));
	  TEST_ASSERT(sign_len > 0);

	  uint8_t sign[sign_len];
	  ASSH_RET_ON_ERR(assh_sign_generate(context, a, key, c, d, sign, &sign_len));

          fprintf(stderr, "v");

	  assh_safety_t sign_safety;

	  err = assh_sign_check(context, a, key, c, d, sign, sign_len, &sign_safety);
	  TEST_ASSERT(err == ASSH_OK);

	  TEST_ASSERT(sign_safety <= a->algo.safety && sign_safety <= key->safety);

	  if (action & ACTION_FUZZ_CHECK)
	    {
	      unsigned mc, fc = 256;

	      while (fc)
		{
		  uint8_t sign2[sign_len];
		  memcpy(sign2, sign, sign_len);

		  do {
		    mc = aash_fuzz_mangle(sign2, sign_len, 10 + assh_prng_rand() % 1024);
		  } while (!mc);

		  fprintf(stderr, "V");

		  err = assh_sign_check(context, a, key, c, d, sign2, sign_len, &sign_safety);

		  if (err != ASSH_OK)
		    fc--;   /* successfully broke the signature */
		}
	    }

	  if (size)
	    {
	      unsigned int r1 = assh_prng_rand() % size;
	      unsigned char r2 = assh_prng_rand();
	      r2 += !r2;

#ifdef CONFIG_ASSH_DEBUG_SIGN
	      fprintf(stderr, "Mangling data byte %u, previous=0x%02x, new=0x%02x\n",
	                r1, data[r1], data[r1] ^ r2);
#endif
	      data[r1] ^= r2;

	      err = assh_sign_check(context, a, key, c, d, sign, sign_len, &sign_safety);
	      TEST_ASSERT(err != ASSH_OK);
	    }

#ifdef CONFIG_ASSH_KEY_CREATE
	  if (algos[i].gen_key && (action & ACTION_NEW_KEYS))
	    assh_key_drop(context, &key);
#endif
	}

      assh_key_drop(context, &key2);
    }

  return ASSH_OK;
}

static void usage()
{
  fprintf(stderr, "usage: signature2 [options]\n");

  fprintf(stderr,
	  "Options:\n\n"

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
  assh_error_t err;

  if (assh_deps_init())
    return -1;

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

  if (assh_context_create(&context, ASSH_CLIENT_SERVER,
			NULL, NULL, &assh_prng_dummy, NULL))
    return -1;

  unsigned i;
  for (i = 0; algos[i].algo; i++)
    ASSH_RET_ON_ERR(assh_algo_register_va(context, 0, 0, 0, algos[i].algo, NULL));

  assh_prng_seed(seed);
  fprintf(stderr, "Seed: %u", seed);

  while (count--)
    if (test_sign(max_size, action))
      return 2;

  assh_context_cleanup(context);

  fprintf(stderr, "\nDone.\n");
  return 0;
}

