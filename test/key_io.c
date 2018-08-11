
#include <assh/assh_key.h>
#include <assh/helper_key.h>

#include <assh/key_rsa.h>
#include <assh/key_dsa.h>
#include <assh/key_ecdsa.h>
#include <assh/key_eddsa.h>

#include <time.h>

#include "prng_weak.h"
#include "leaks_check.h"
#include "test.h"

struct tests_s
{
  const struct assh_key_algo_s *algo;
  size_t bits_min, bits_max;
  enum assh_key_format_e format;
  const char *pass, *comment;
};

/* test key blob load/store functions implemented in key modules */
static assh_error_t test_algo(struct assh_context_s *c)
{
  static const struct tests_s algo_tests[] =
    {
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PUB_RFC4253 },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PUB_PEM_ASN1 },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PV_PEM_ASN1 },

      { &assh_key_dsa, 1024, 1536, ASSH_KEY_FMT_PUB_RFC4253 },
      { &assh_key_dsa, 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY },
      { &assh_key_dsa, 1024, 1536, ASSH_KEY_FMT_PV_PEM_ASN1 },

      { &assh_key_ecdsa_nistp, 256, 256, ASSH_KEY_FMT_PUB_RFC4253 },
      { &assh_key_ecdsa_nistp, 256, 256, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY },
      { &assh_key_ecdsa_nistp, 256, 256, ASSH_KEY_FMT_PV_PEM_ASN1 },

      { &assh_key_ecdsa_nistp, 384, 384, ASSH_KEY_FMT_PUB_RFC4253 },
      { &assh_key_ecdsa_nistp, 384, 384, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY },
      { &assh_key_ecdsa_nistp, 384, 384, ASSH_KEY_FMT_PV_PEM_ASN1 },

      { &assh_key_ecdsa_nistp, 521, 521, ASSH_KEY_FMT_PUB_RFC4253 },
      { &assh_key_ecdsa_nistp, 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY },
      { &assh_key_ecdsa_nistp, 521, 521, ASSH_KEY_FMT_PV_PEM_ASN1 },

      { &assh_key_ed25519, 255, 255, ASSH_KEY_FMT_PUB_RFC4253 },
      { &assh_key_ed25519, 255, 255, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY },

      { &assh_key_eddsa_e382, 382, 382, ASSH_KEY_FMT_PUB_RFC4253 },
      { &assh_key_eddsa_e382, 382, 382, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY },

      { &assh_key_eddsa_e521, 521, 521, ASSH_KEY_FMT_PUB_RFC4253 },
      { &assh_key_eddsa_e521, 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY },

      { NULL }
    };

  const struct tests_s *t;
  const struct assh_key_algo_s *algo = NULL;
  size_t bits_min = 0, bits_max = 0;
  struct assh_key_s *key1 = NULL, *key2;

  for (t = algo_tests; t->algo != NULL; t++)
    {
      if (t->algo != algo || t->bits_min != bits_min || t->bits_max != bits_max)
	{
	  /* create new key */
	  size_t bits = t->bits_min + assh_prng_rand() % (t->bits_max - t->bits_min + 1);
	  fprintf(stderr, "\nkey type: %s, size: %zu\n", t->algo->name, bits);
	  assh_key_drop(c, &key1);
	  TEST_ASSERT(!assh_key_create(c, &key1, bits, t->algo, ASSH_ALGO_SIGN));
	}

      /* get estimated size of key blob */
      fprintf(stderr, "o");
      size_t blob_len1 = 0, blob_len2 = 0;
      TEST_ASSERT(!assh_key_output(c, key1, NULL, &blob_len1, t->format));
      TEST_ASSERT(blob_len1 > 0 && blob_len1 < (1 << 20));

      /* allocate space for key blob */
      uint8_t *blob1 = malloc(blob_len1);
      TEST_ASSERT(blob1 != NULL);

      /* store key blob to memory */
      fprintf(stderr, "O");
      TEST_ASSERT(!assh_key_output(c, key1, blob1, &blob_len2, t->format));

      /* check estimated size against actual size */
      TEST_ASSERT(blob_len2 > 0 && blob_len2 <= blob_len1);

      /* reload key from blob */
      const uint8_t *blob2 = blob1;
      size_t padding = assh_prng_rand() % 32;	/* may load from large buffer */

      fprintf(stderr, "l");
      TEST_ASSERT(!assh_key_load(c, &key2, t->algo, ASSH_ALGO_SIGN, t->format,
				 &blob2, blob_len2 + padding));

      /* check loaded blob end pointer */
      TEST_ASSERT(blob1 + blob_len2 == blob2);

      algo = t->algo;
      bits_min = t->bits_min;
      bits_max = t->bits_max;

      free(blob1);
      assh_key_drop(c, &key2);
    }

  assh_key_drop(c, &key1);

  return 0;
}

/* test key container load/save functions implemented in helpers */
static assh_error_t test_helper(struct assh_context_s *c)
{
  static const struct tests_s helper_tests[] =
    {
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PUB_RFC4253 },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PUB_RFC4716 },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PUB_RFC4716, NULL, "com ent" },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PUB_OPENSSH },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PUB_OPENSSH, NULL, "com ent" },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PUB_PEM_ASN1 },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PUB_PEM },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1 },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1, NULL, "com ent" },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1, "passphrase" },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1, "passphrase", "com ent" },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PV_PEM_ASN1 },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PV_PEM },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PV_PEM, "passphrase" },

      { &assh_key_dsa, 1024, 1536, ASSH_KEY_FMT_PUB_RFC4253 },
      { &assh_key_dsa, 1024, 1536, ASSH_KEY_FMT_PUB_RFC4716 },
      { &assh_key_dsa, 1024, 1536, ASSH_KEY_FMT_PUB_OPENSSH },
      { &assh_key_dsa, 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY },
      { &assh_key_dsa, 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB },
      { &assh_key_dsa, 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1 },
      { &assh_key_dsa, 1024, 1536, ASSH_KEY_FMT_PV_PEM_ASN1 },
      { &assh_key_dsa, 1024, 1536, ASSH_KEY_FMT_PV_PEM },
      { &assh_key_dsa, 1024, 1536, ASSH_KEY_FMT_PV_PEM, "passphrase" },

      { &assh_key_ecdsa_nistp, 256, 256, ASSH_KEY_FMT_PUB_RFC4253 },
      { &assh_key_ecdsa_nistp, 256, 256, ASSH_KEY_FMT_PUB_RFC4716 },
      { &assh_key_ecdsa_nistp, 256, 256, ASSH_KEY_FMT_PUB_OPENSSH },
      { &assh_key_ecdsa_nistp, 256, 256, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY },
      { &assh_key_ecdsa_nistp, 256, 256, ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB },
      { &assh_key_ecdsa_nistp, 256, 256, ASSH_KEY_FMT_PV_OPENSSH_V1 },
      { &assh_key_ecdsa_nistp, 256, 256, ASSH_KEY_FMT_PV_OPENSSH_V1, "passphrase" },
      { &assh_key_ecdsa_nistp, 256, 256, ASSH_KEY_FMT_PV_PEM_ASN1 },
      { &assh_key_ecdsa_nistp, 256, 256, ASSH_KEY_FMT_PV_PEM },
      { &assh_key_ecdsa_nistp, 256, 256, ASSH_KEY_FMT_PV_PEM, "passphrase" },

      { &assh_key_ecdsa_nistp, 521, 521, ASSH_KEY_FMT_PUB_RFC4253 },
      { &assh_key_ecdsa_nistp, 521, 521, ASSH_KEY_FMT_PUB_RFC4716 },
      { &assh_key_ecdsa_nistp, 521, 521, ASSH_KEY_FMT_PUB_OPENSSH },
      { &assh_key_ecdsa_nistp, 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY },
      { &assh_key_ecdsa_nistp, 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB },
      { &assh_key_ecdsa_nistp, 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1 },
      { &assh_key_ecdsa_nistp, 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1, "passphrase" },
      { &assh_key_ecdsa_nistp, 521, 521, ASSH_KEY_FMT_PV_PEM_ASN1 },
      { &assh_key_ecdsa_nistp, 521, 521, ASSH_KEY_FMT_PV_PEM },
      { &assh_key_ecdsa_nistp, 521, 521, ASSH_KEY_FMT_PV_PEM, "passphrase" },

      { &assh_key_ed25519, 255, 255, ASSH_KEY_FMT_PUB_RFC4253 },
      { &assh_key_ed25519, 255, 255, ASSH_KEY_FMT_PUB_RFC4716 },
      { &assh_key_ed25519, 255, 255, ASSH_KEY_FMT_PUB_OPENSSH },
      { &assh_key_ed25519, 255, 255, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY },
      { &assh_key_ed25519, 255, 255, ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB },
      { &assh_key_ed25519, 255, 255, ASSH_KEY_FMT_PV_OPENSSH_V1 },
      { &assh_key_ed25519, 255, 255, ASSH_KEY_FMT_PV_OPENSSH_V1, "passphrase" },

      { &assh_key_eddsa_e382, 382, 382, ASSH_KEY_FMT_PUB_RFC4253 },
      { &assh_key_eddsa_e382, 382, 382, ASSH_KEY_FMT_PUB_RFC4716 },
      { &assh_key_eddsa_e382, 382, 382, ASSH_KEY_FMT_PUB_OPENSSH },
      { &assh_key_eddsa_e382, 382, 382, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY },
      { &assh_key_eddsa_e382, 382, 382, ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB },
      { &assh_key_eddsa_e382, 382, 382, ASSH_KEY_FMT_PV_OPENSSH_V1 },
      { &assh_key_eddsa_e382, 382, 382, ASSH_KEY_FMT_PV_OPENSSH_V1, "passphrase" },

      { &assh_key_eddsa_e521, 521, 521, ASSH_KEY_FMT_PUB_RFC4253 },
      { &assh_key_eddsa_e521, 521, 521, ASSH_KEY_FMT_PUB_RFC4716 },
      { &assh_key_eddsa_e521, 521, 521, ASSH_KEY_FMT_PUB_OPENSSH },
      { &assh_key_eddsa_e521, 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY },
      { &assh_key_eddsa_e521, 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB },
      { &assh_key_eddsa_e521, 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1 },
      { &assh_key_eddsa_e521, 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1, "passphrase" },

      { NULL }
    };

  const struct tests_s *t;
  const struct assh_key_algo_s *algo = NULL;
  size_t bits_min = 0, bits_max = 0;
  struct assh_key_s *key1 = NULL, *key2;

  for (t = helper_tests; t->algo != NULL; t++)
    {
      if (t->algo != algo || t->bits_min != bits_min || t->bits_max != bits_max)
	{
	  /* create new key */
	  assh_key_drop(c, &key1);
	  size_t bits = t->bits_min + assh_prng_rand() % (t->bits_max - t->bits_min + 1);
	  fprintf(stderr, "\nkey type: %s, size: %zu\n", t->algo->name, bits);
	  TEST_ASSERT(!assh_key_create(c, &key1, bits, t->algo, ASSH_ALGO_SIGN));
	}

      if (t->comment != NULL)
	TEST_ASSERT(!assh_key_comment(c, key1, t->comment));

      /* save key to file */
      fprintf(stderr, "s");
      TEST_ASSERT(!assh_save_key_filename(c, key1, "test.key", t->format, t->pass));

      /* reload key from file */
      fprintf(stderr, "l");
      TEST_ASSERT(!assh_load_key_filename(c, &key2, t->algo,
			  ASSH_ALGO_SIGN, "test.key", t->format, t->pass, 0));

      /* compare loaded key to original */
      TEST_ASSERT(assh_key_cmp(c, key1, key2, assh_key_pub_fmt(t->format)));

#ifdef CONFIG_ASSH_KEY_VALIDATE
      /* validate loaded key */
      enum assh_key_validate_result_e r;
      TEST_ASSERT(!assh_key_validate(c, key2, &r) && r > 0);
#endif

      if (t->comment != NULL)
	{
	  TEST_ASSERT(key2->comment != NULL);
	  TEST_ASSERT(!strcmp(t->comment, key2->comment));
	}

      algo = t->algo;
      bits_min = t->bits_min;
      bits_max = t->bits_max;

      assh_key_drop(c, &key2);
    }

  assh_key_drop(c, &key1);

  return 0;
}

int main(int argc, char **argv)
{
  struct assh_context_s *context;

  if (assh_deps_init())
    return -1;

  if (assh_context_create(&context, ASSH_CLIENT_SERVER,
			  assh_leaks_allocator, NULL, &assh_prng_weak, NULL))
    return -1;

  if (assh_algo_register_default(context, 99, 10, 0) != ASSH_OK)
    return -1;

  size_t k, count = argc > 1 ? atoi(argv[1]) : 10;

  int t = time(0);
  assh_prng_seed(t);
  fprintf(stderr, "Seed: %u\n", t);

  for (k = 0; k < count; k++)
    {
      if (test_algo(context))
	abort();
      if (test_helper(context))
      	abort();
    }

  if (alloc_size == 0)
    TEST_FAIL("leak checking not working\n");

  assh_context_release(context);

  if (alloc_size != 0)
    TEST_FAIL("memory leak detected, %zu bytes allocated\n", alloc_size);

  fprintf(stderr, "\nDone.\n");
  return 0;
}
