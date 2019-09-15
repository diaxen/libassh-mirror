
#include <assh/assh_sign.h>
#include <assh/assh_context.h>
#include <assh/assh_prng.h>

#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include "sign.h"
#include "prng_weak.h"
#include "test.h"

#define TEST_STEP 4

struct assh_context_s *context;

assh_error_t test_sign(unsigned int max_size)
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

      enum assh_key_validate_result_e r;
      ASSH_RET_ON_ERR(assh_key_validate(context, key2, &r));
      TEST_ASSERT(r > 0);

      TEST_ASSERT(assh_key_cmp(context, key2, key2, 0));
      TEST_ASSERT(assh_key_cmp(context, key2, key2, 1));

      key = key2;

      int size;
      for (size = max_size; size != 0; )
	{
	  if (algos[i].gen_key)
	    {
	      size_t kbits = algos[i].kbits_min + assh_prng_rand()
                           % (algos[i].kbits_max - algos[i].kbits_min + 1);
              fprintf(stderr, "N");
	      ASSH_RET_ON_ERR(assh_key_create(context, &key, kbits,
	                    a->algo.key, ASSH_ALGO_SIGN));
              fprintf(stderr, "C");
	      ASSH_RET_ON_ERR(assh_key_validate(context, key, &r));
	      TEST_ASSERT(r > 0);

	      TEST_ASSERT(assh_key_cmp(context, key, key, 0));
	      TEST_ASSERT(assh_key_cmp(context, key, key, 1));

	      TEST_ASSERT(!assh_key_cmp(context, key, key2, 0));
	      TEST_ASSERT(!assh_key_cmp(context, key, key2, 1));
            }

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

	  if (sign_safety > a->algo.safety || sign_safety > key->safety)
	    abort();

          unsigned int r1 = assh_prng_rand() % sign_len;
          unsigned char r2 = assh_prng_rand();
          if (!r2)
            r2++;
#ifdef CONFIG_ASSH_DEBUG_SIGN
          fprintf(stderr, "Mangling signature byte %u, previous=0x%02x, new=0x%02x\n",
                    r1, sign[r1], sign[r1] ^ r2);
#endif
	  sign[r1] ^= r2;

          fprintf(stderr, "V");

	  err = assh_sign_check(context, a, key, c, d, sign, sign_len, &sign_safety);
	  TEST_ASSERT(err != ASSH_OK);

	  sign[r1] ^= r2;

	  err = assh_sign_check(context, a, key, c, d, sign, sign_len, &sign_safety);
	  TEST_ASSERT(err == ASSH_OK);

	  if (sign_safety > a->algo.safety || sign_safety > key->safety)
	    abort();

	  if (size)
	    {
	      r1 = assh_prng_rand() % size;

#ifdef CONFIG_ASSH_DEBUG_SIGN
	      fprintf(stderr, "Mangling data byte %u, previous=0x%02x, new=0x%02x\n",
	                r1, data[r1], data[r1] ^ r2);
#endif
	      data[r1] ^= r2;

	      err = assh_sign_check(context, a, key, c, d, sign, sign_len, &sign_safety);
	      TEST_ASSERT(err != ASSH_OK);
	    }

	  if (algos[i].gen_key)
	    assh_key_drop(context, &key);
	}

      assh_key_drop(context, &key2);
    }

  return ASSH_OK;
}

int main(int argc, char **argv)
{
  unsigned int s = argc > 1 ? atoi(argv[1]) : time(0);
  assh_error_t err;
  int i;

  if (assh_deps_init())
    return -1;

  if (assh_context_create(&context, ASSH_CLIENT_SERVER,
			NULL, NULL, &assh_prng_dummy, NULL))
    return -1;

  for (i = 0; algos[i].algo; i++)
    ASSH_RET_ON_ERR(assh_algo_register_va(context, 0, 0, 0, algos[i].algo, NULL));

  assh_prng_seed(s);
  fprintf(stderr, "Seed: %u", s);

  if (test_sign(128))
    return 2;

  assh_context_cleanup(context);

  fprintf(stderr, "\nDone.\n");
  return 0;
}

