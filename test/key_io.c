
#include <assh/assh_key.h>
#include <assh/assh_sign.h>
#include <assh/assh_cipher.h>
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
  assh_bool_t private;
  const char *pass, *comment;
};

static void
test_sign(struct assh_context_s *c,
	  struct assh_key_s *pvkey, struct assh_key_s *pubkey)
{
  const struct assh_algo_sign_s *salgo;
  TEST_ASSERT(!assh_algo_by_key(c, pvkey, NULL,
	         (const struct assh_algo_s **)&salgo));

  struct assh_cbuffer_s buf;
  buf.str = "test";
  buf.len = 4;

  size_t slen;
  TEST_ASSERT(!assh_sign_generate(c, salgo, pvkey, 1, &buf, NULL, &slen));
  uint8_t sign[slen];
  TEST_ASSERT(!assh_sign_generate(c, salgo, pvkey, 1, &buf, sign, &slen));

  assh_safety_t safety;
  TEST_ASSERT(!assh_sign_check(c, salgo, pubkey, 1, &buf, sign, slen, &safety));
}

/* test key blob load/store functions implemented in key modules */
static assh_error_t test_algo(struct assh_context_s *c, size_t count)
{
  static const struct tests_s algo_tests[] =
    {
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PUB_RFC4253, 0 },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PUB_PEM_ASN1, 0 },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PV_PEM_ASN1, 1 },

      { &assh_key_dsa, 1024, 1536, ASSH_KEY_FMT_PUB_RFC4253, 0 },
      { &assh_key_dsa, 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },
      { &assh_key_dsa, 1024, 1536, ASSH_KEY_FMT_PV_PEM_ASN1, 1 },

      { &assh_key_ecdsa_nistp, 256, 256, ASSH_KEY_FMT_PUB_RFC4253, 0 },
      { &assh_key_ecdsa_nistp, 256, 256, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },
      { &assh_key_ecdsa_nistp, 256, 256, ASSH_KEY_FMT_PV_PEM_ASN1, 1 },

      { &assh_key_ecdsa_nistp, 384, 384, ASSH_KEY_FMT_PUB_RFC4253, 0 },
      { &assh_key_ecdsa_nistp, 384, 384, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },
      { &assh_key_ecdsa_nistp, 384, 384, ASSH_KEY_FMT_PV_PEM_ASN1, 1 },

      { &assh_key_ecdsa_nistp, 521, 521, ASSH_KEY_FMT_PUB_RFC4253, 0 },
      { &assh_key_ecdsa_nistp, 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },
      { &assh_key_ecdsa_nistp, 521, 521, ASSH_KEY_FMT_PV_PEM_ASN1, 1 },

      { &assh_key_ed25519, 255, 255, ASSH_KEY_FMT_PUB_RFC4253, 0 },
      { &assh_key_ed25519, 255, 255, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },

      { &assh_key_eddsa_e382, 382, 382, ASSH_KEY_FMT_PUB_RFC4253, 0 },
      { &assh_key_eddsa_e382, 382, 382, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },

      { &assh_key_eddsa_e521, 521, 521, ASSH_KEY_FMT_PUB_RFC4253, 0 },
      { &assh_key_eddsa_e521, 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },

      { NULL }
    };

  const struct tests_s *t;
  const struct assh_key_algo_s *algo = NULL;
  size_t bits_min = 0, bits_max = 0;
  enum assh_key_format_e format = ASSH_KEY_FMT_NONE;
  struct assh_key_s *key1 = NULL, *key2;
  size_t i;

  for (t = algo_tests; t->algo != NULL; t++)
   for (i = 0; i < count; i++)
    {
      if (format != t->format || t->algo != algo)
	{
	  format = t->format;
	  fprintf(stderr, "\n%s, %s format: ",
		  t->algo->name, assh_key_format_desc(t->format)->name);
	}

      if (t->algo != algo || t->bits_min != bits_min || t->bits_max != bits_max)
	{
	  /* create new key */
	  size_t bits = t->bits_min + assh_prng_rand() % (t->bits_max - t->bits_min + 1);
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
      blob_len2 = blob_len1;
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

      TEST_ASSERT(assh_key_cmp(c, key1, key2, !t->private));
      TEST_ASSERT(assh_key_cmp(c, key2, key1, !t->private));

      test_sign(c, key1, key2);
      if (t->private)
	test_sign(c, key2, key1);

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
static assh_error_t test_helper(struct assh_context_s *c, size_t count)
{
  static const struct tests_s helper_tests[] =
    {
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PUB_RFC4253, 0 },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PUB_RFC4716, 0 },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PUB_RFC4716, 0, NULL, "com ent" },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PUB_OPENSSH, 0 },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PUB_OPENSSH, 0, NULL, "com ent" },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PUB_PEM_ASN1, 0 },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PUB_PEM, 0 },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB, 1 },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1, 1 },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1, 1, NULL, "com ent" },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1, 1, "passphrase" },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1, 1, "passphrase", "com ent" },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PV_PEM_ASN1, 1 },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PV_PEM, 1 },
      { &assh_key_rsa, 1024, 1536, ASSH_KEY_FMT_PV_PEM, 1, "passphrase" },

      { &assh_key_dsa, 1024, 1536, ASSH_KEY_FMT_PUB_RFC4253, 0 },
      { &assh_key_dsa, 1024, 1536, ASSH_KEY_FMT_PUB_RFC4716, 0 },
      { &assh_key_dsa, 1024, 1536, ASSH_KEY_FMT_PUB_OPENSSH, 0 },
      { &assh_key_dsa, 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },
      { &assh_key_dsa, 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB, 1 },
      { &assh_key_dsa, 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1, 1 },
      { &assh_key_dsa, 1024, 1536, ASSH_KEY_FMT_PV_PEM_ASN1, 1 },
      { &assh_key_dsa, 1024, 1536, ASSH_KEY_FMT_PV_PEM, 1 },
      { &assh_key_dsa, 1024, 1536, ASSH_KEY_FMT_PV_PEM, 1, "passphrase" },

      { &assh_key_ecdsa_nistp, 256, 256, ASSH_KEY_FMT_PUB_RFC4253, 0 },
      { &assh_key_ecdsa_nistp, 256, 256, ASSH_KEY_FMT_PUB_RFC4716, 0 },
      { &assh_key_ecdsa_nistp, 256, 256, ASSH_KEY_FMT_PUB_OPENSSH, 0 },
      { &assh_key_ecdsa_nistp, 256, 256, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },
      { &assh_key_ecdsa_nistp, 256, 256, ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB, 1 },
      { &assh_key_ecdsa_nistp, 256, 256, ASSH_KEY_FMT_PV_OPENSSH_V1, 1 },
      { &assh_key_ecdsa_nistp, 256, 256, ASSH_KEY_FMT_PV_OPENSSH_V1, 1, "passphrase" },
      { &assh_key_ecdsa_nistp, 256, 256, ASSH_KEY_FMT_PV_PEM_ASN1, 1 },
      { &assh_key_ecdsa_nistp, 256, 256, ASSH_KEY_FMT_PV_PEM, 1 },
      { &assh_key_ecdsa_nistp, 256, 256, ASSH_KEY_FMT_PV_PEM, 1, "passphrase" },

      { &assh_key_ecdsa_nistp, 521, 521, ASSH_KEY_FMT_PUB_RFC4253, 0 },
      { &assh_key_ecdsa_nistp, 521, 521, ASSH_KEY_FMT_PUB_RFC4716, 0 },
      { &assh_key_ecdsa_nistp, 521, 521, ASSH_KEY_FMT_PUB_OPENSSH, 0 },
      { &assh_key_ecdsa_nistp, 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },
      { &assh_key_ecdsa_nistp, 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB, 1 },
      { &assh_key_ecdsa_nistp, 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1, 1 },
      { &assh_key_ecdsa_nistp, 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1, 1, "passphrase" },
      { &assh_key_ecdsa_nistp, 521, 521, ASSH_KEY_FMT_PV_PEM_ASN1, 1 },
      { &assh_key_ecdsa_nistp, 521, 521, ASSH_KEY_FMT_PV_PEM, 1 },
      { &assh_key_ecdsa_nistp, 521, 521, ASSH_KEY_FMT_PV_PEM, 1, "passphrase" },

      { &assh_key_ed25519, 255, 255, ASSH_KEY_FMT_PUB_RFC4253, 0 },
      { &assh_key_ed25519, 255, 255, ASSH_KEY_FMT_PUB_RFC4716, 0 },
      { &assh_key_ed25519, 255, 255, ASSH_KEY_FMT_PUB_OPENSSH, 0 },
      { &assh_key_ed25519, 255, 255, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },
      { &assh_key_ed25519, 255, 255, ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB, 1 },
      { &assh_key_ed25519, 255, 255, ASSH_KEY_FMT_PV_OPENSSH_V1, 1 },
      { &assh_key_ed25519, 255, 255, ASSH_KEY_FMT_PV_OPENSSH_V1, 1, "passphrase" },

      { &assh_key_eddsa_e382, 382, 382, ASSH_KEY_FMT_PUB_RFC4253, 0 },
      { &assh_key_eddsa_e382, 382, 382, ASSH_KEY_FMT_PUB_RFC4716, 0 },
      { &assh_key_eddsa_e382, 382, 382, ASSH_KEY_FMT_PUB_OPENSSH, 0 },
      { &assh_key_eddsa_e382, 382, 382, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },
      { &assh_key_eddsa_e382, 382, 382, ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB, 1 },
      { &assh_key_eddsa_e382, 382, 382, ASSH_KEY_FMT_PV_OPENSSH_V1, 1 },
      { &assh_key_eddsa_e382, 382, 382, ASSH_KEY_FMT_PV_OPENSSH_V1, 1, "passphrase" },

      { &assh_key_eddsa_e521, 521, 521, ASSH_KEY_FMT_PUB_RFC4253, 0 },
      { &assh_key_eddsa_e521, 521, 521, ASSH_KEY_FMT_PUB_RFC4716, 0 },
      { &assh_key_eddsa_e521, 521, 521, ASSH_KEY_FMT_PUB_OPENSSH, 0 },
      { &assh_key_eddsa_e521, 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },
      { &assh_key_eddsa_e521, 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB, 1 },
      { &assh_key_eddsa_e521, 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1, 1 },
      { &assh_key_eddsa_e521, 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1, 1, "passphrase" },

      { NULL }
    };

  const struct tests_s *t;
  const struct assh_key_algo_s *algo = NULL;
  size_t bits_min = 0, bits_max = 0;
  enum assh_key_format_e format = ASSH_KEY_FMT_NONE;
  struct assh_key_s *key1 = NULL, *key2;
  size_t i;

  for (t = helper_tests; t->algo != NULL; t++)
   for (i = 0; i < count; i++)
    {
      if (format != t->format || t->algo != algo)
	{
	  format = t->format;
	  fprintf(stderr, "\n%s, %s format: ",
		  t->algo->name, assh_key_format_desc(t->format)->name);
	}

      if (t->algo != algo || t->bits_min != bits_min || t->bits_max != bits_max)
	{
	  /* create new key */
	  assh_key_drop(c, &key1);
	  size_t bits = t->bits_min + assh_prng_rand() % (t->bits_max - t->bits_min + 1);
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
      TEST_ASSERT(assh_key_cmp(c, key1, key2, !t->private));
      TEST_ASSERT(assh_key_cmp(c, key2, key1, !t->private));

      test_sign(c, key1, key2);
      if (t->private)
	test_sign(c, key2, key1);

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

  if (assh_algo_register_va(context, 0, 0, 0,
			    &assh_cipher_aes128_cbc,
			    &assh_cipher_aes256_cbc,
			    &assh_sign_rsa_sha1,
			    &assh_sign_dsa1024,
			    &assh_sign_nistp256,
			    &assh_sign_nistp384,
			    &assh_sign_nistp521,
			    &assh_sign_ed25519,
			    &assh_sign_eddsa_e382,
			    &assh_sign_eddsa_e521,
			    NULL) != ASSH_OK)
    return -1;

  size_t acount = argc > 1 ? atoi(argv[1]) : 10;
  size_t hcount = argc > 2 ? atoi(argv[2]) : 2;

  int t = time(0);
  assh_prng_seed(t);
  fprintf(stderr, "Seed: %u", t);

  if (test_algo(context, acount))
    abort();
  if (test_helper(context, hcount))
    abort();

  if (alloc_size == 0)
    TEST_FAIL("leak checking not working\n");

  assh_context_release(context);

  if (alloc_size != 0)
    TEST_FAIL("memory leak detected, %zu bytes allocated\n", alloc_size);

  fprintf(stderr, "\nDone.\n");
  return 0;
}
