
#include <assh/assh_sign.h>
#include <assh/assh_context.h>
#include <assh/assh_prng.h>

#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include "sign.h"
#include "prng_weak.h"
#include "test.h"

struct assh_context_s *context;

assh_error_t test_const()
{
  assh_error_t err;
  int i, j;

  for (i = 0; algos[i].algo; i++)
    {
      const struct assh_algo_sign_s *a = algos[i].algo;
      struct assh_key_s *key;

      fprintf(stderr, "\n%s const sign/verify: ", assh_algo_name(&a->algo));

      uint8_t key_blob[algos[i].key_len];
      memcpy(key_blob, algos[i].key, sizeof(key_blob));

      fprintf(stderr, "L");
      const uint8_t *kb = key_blob + 1;
      ASSH_RET_ON_ERR(assh_key_load(context, &key, a->algo.key, ASSH_ALGO_SIGN,
		 key_blob[0], &kb, sizeof(key_blob) - 1));

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
      ASSH_RET_ON_ERR(assh_sign_generate(context, a, key, 3, d, NULL, &sign_len));

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
      ASSH_RET_ON_ERR(assh_sign_generate(context, a, key, 3, d, sign, &sign_len));

      if (algos[i].sign) {
	if (memcmp(algos[i].sign, sign, sign_len))
	  {
#ifdef CONFIG_ASSH_DEBUG
	    assh_hexdump("expected", algos[i].sign, sign_len);
	    assh_hexdump("wrong", sign, sign_len);
#endif
	    abort();
	  }
      }

      fprintf(stderr, "v");
      assh_safety_t sign_safety;
      if (assh_sign_check(context, a, key, 3, d, sign, sign_len, &sign_safety))
	abort();

      if (sign_safety > a->algo.safety || sign_safety > key->safety)
	abort();

      data[assh_prng_rand() % sizeof(data)]++;

      fprintf(stderr, "V");
      if (!assh_sign_check(context, a, key, 3, d, sign, sign_len, &sign_safety))
	abort();

      assh_key_drop(context, &key);
    }

  return ASSH_OK;
}

assh_error_t test_load(unsigned int max_size)
{
  assh_error_t err;
  int i;

  for (i = 0; algos[i].algo; i++)
    {
      const struct assh_algo_sign_s *a = algos[i].algo;
      struct assh_key_s *key;

      fprintf(stderr, "\n%s key load/validate: ", assh_algo_name(&a->algo));

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
	  err = assh_key_load(context, &key, a->algo.key, ASSH_ALGO_SIGN,
			      key_blob[0], &kb, sizeof(key_blob) - 1);

	  if (!bad)
	    {
	      TEST_ASSERT(err == ASSH_OK);
	    }
	  else if (err == ASSH_OK)
	    {
	      fprintf(stderr, "C");

	      enum assh_key_validate_result_e r;
	      ASSH_RET_ON_ERR(assh_key_validate(context, key, &r));

	      TEST_ASSERT(bad || r > 0);
	    }

	  if (err == ASSH_OK)
	    assh_key_drop(context, &key);
	}
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
			NULL, NULL, &assh_prng_weak, NULL))
    return -1;

  for (i = 0; algos[i].algo; i++)
    ASSH_RET_ON_ERR(assh_algo_register_va(context, 0, 0, 0, algos[i].algo, NULL));

  assh_prng_seed(s);
  fprintf(stderr, "Seed: %u", s);

  if (test_const())
    return 1;

  if (test_load(16))
    return 3;

  assh_context_cleanup(context);

  fprintf(stderr, "\nDone.\n");
  return 0;
}

