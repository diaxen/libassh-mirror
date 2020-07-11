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

#include <assh/assh_key.h>
#include <assh/assh_sign.h>
#include <assh/assh_cipher.h>
#include <assh/helper_key.h>

#include <time.h>

#include "test.h"

#define KEY_ALGO_TABLE_MAXSIZE 32
static const struct assh_key_algo_s *key_algo_table[KEY_ALGO_TABLE_MAXSIZE];
static size_t key_algo_table_size;

struct tests_s
{
  enum assh_algo_class_e role;
  const char *key_algo;
  size_t bits_min, bits_max;
  enum assh_key_format_e format;
  assh_bool_t private;
  const char *pass, *comment;
};

static assh_bool_t
test_sign(struct assh_context_s *c,
	  struct assh_key_s *pv_key, struct assh_key_s *pub_key)
{
  const struct assh_algo_sign_s *sa;
  if (assh_algo_sign_by_key(c, pv_key, NULL, &sa))
    {
      printf(" ... no signature implem ... ");
      return 1;
    }

  struct assh_cbuffer_s buf;
  buf.str = "test";
  buf.len = 4;

  size_t slen;
  TEST_ASSERT(!assh_sign_generate(c, sa, pv_key, 1, &buf, NULL, &slen));
  uint8_t sign[slen];
  TEST_ASSERT(!assh_sign_generate(c, sa, pv_key, 1, &buf, sign, &slen));

  assh_safety_t safety;
  TEST_ASSERT(!assh_sign_check(c, sa, pub_key, 1, &buf, sign, slen, &safety));
  return 0;
}

/* test key blob load/store functions implemented in key modules */
static void test_algo(struct assh_context_s *c, size_t count)
{
  static const struct tests_s algo_tests[] =
    {
     { ASSH_ALGO_SIGN, "ssh-rsa", 1024, 1536, ASSH_KEY_FMT_PUB_RFC4253, 0 },
     { ASSH_ALGO_SIGN, "ssh-rsa", 1024, 1536, ASSH_KEY_FMT_PUB_PEM_ASN1, 0 },
     { ASSH_ALGO_SIGN, "ssh-rsa", 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },
     { ASSH_ALGO_SIGN, "ssh-rsa", 1024, 1536, ASSH_KEY_FMT_PV_PEM_ASN1, 1 },

     { ASSH_ALGO_SIGN, "ssh-dss", 1024, 1536, ASSH_KEY_FMT_PUB_RFC4253, 0 },
     { ASSH_ALGO_SIGN, "ssh-dss", 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },
     { ASSH_ALGO_SIGN, "ssh-dss", 1024, 1536, ASSH_KEY_FMT_PV_PEM_ASN1, 1 },

     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 256, 256, ASSH_KEY_FMT_PUB_RFC4253, 0 },
     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 256, 256, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },
     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 256, 256, ASSH_KEY_FMT_PV_PEM_ASN1, 1 },

     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 384, 384, ASSH_KEY_FMT_PUB_RFC4253, 0 },
     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 384, 384, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },
     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 384, 384, ASSH_KEY_FMT_PV_PEM_ASN1, 1 },

     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 521, 521, ASSH_KEY_FMT_PUB_RFC4253, 0 },
     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },
     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 521, 521, ASSH_KEY_FMT_PV_PEM_ASN1, 1 },

     { ASSH_ALGO_SIGN, "ssh-ed25519", 255, 255, ASSH_KEY_FMT_PUB_RFC4253, 0 },
     { ASSH_ALGO_SIGN, "ssh-ed25519", 255, 255, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },

     { ASSH_ALGO_SIGN, "eddsa-e382-shake256", 382, 382, ASSH_KEY_FMT_PUB_RFC4253, 0 },
     { ASSH_ALGO_SIGN, "eddsa-e382-shake256", 382, 382, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },

     { ASSH_ALGO_SIGN, "eddsa-e521-shake256", 521, 521, ASSH_KEY_FMT_PUB_RFC4253, 0 },
     { ASSH_ALGO_SIGN, "eddsa-e521-shake256", 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },

     { }
    };

  const struct tests_s *t;
  const struct assh_key_algo_s *key_algo = NULL;
  size_t bits_min = 0, bits_max = 0;
  enum assh_key_format_e format = ASSH_KEY_FMT_NONE;
  struct assh_key_s *key1 = NULL, *key2;
  size_t i, j;

  for (t = algo_tests; t->key_algo != NULL; t++)
    {
      assh_bool_t done = 0;

      for (j = 0; j < key_algo_table_size; j++)
	{
	  const struct assh_key_algo_s *ka = key_algo_table[j];
	  assh_bool_t skip_sign = 0;

	  if (strcmp(t->key_algo, ka->name))
	    continue;

	  done = 1;
	  for (i = 0; i < count; i++)
	    {
	      if (!key_algo || format != t->format || key_algo != ka)
		{
		  format = t->format;
		  printf("\n%s (%s), %s format: ",
			 ka->name, ka->implem,
			 assh_key_format_desc(t->format)->name);
		}

	      if (!key_algo || key_algo != ka ||
		  t->bits_min != bits_min || t->bits_max != bits_max)
		{
		  /* create new key */
		  size_t bits = t->bits_min + test_prng_rand() % (t->bits_max - t->bits_min + 1);
		  assh_key_drop(c, &key1);
		  putchar('N');
		  TEST_ASSERT(!assh_key_create(c, &key1, bits, ka, t->role));
		}

	      /* get estimated size of key blob */
	      putchar('o');
	      size_t blob_len1 = 0, blob_len2 = 0;
	      TEST_ASSERT(!assh_key_output(c, key1, NULL, &blob_len1, t->format));
	      TEST_ASSERT(blob_len1 > 0 && blob_len1 < (1 << 20));

	      /* allocate space for key blob */
	      uint8_t *blob1 = malloc(blob_len1);
	      TEST_ASSERT(blob1 != NULL);

	      /* store key blob to memory */
	      putchar('O');
	      blob_len2 = blob_len1;
	      TEST_ASSERT(!assh_key_output(c, key1, blob1, &blob_len2, t->format));

	      /* check estimated size against actual size */
	      TEST_ASSERT(blob_len2 > 0 && blob_len2 <= blob_len1);

	      /* reload key from blob */
	      const uint8_t *blob2 = blob1;
	      size_t padding = test_prng_rand() % 32;	/* may load from large buffer */

	      putchar('l');
	      TEST_ASSERT(!assh_key_load(c, &key2, ka, t->role, t->format,
					 &blob2, blob_len2 + padding));

	      /* check loaded blob end pointer */
	      TEST_ASSERT(blob1 + blob_len2 == blob2);

	      TEST_ASSERT(assh_key_cmp(c, key1, key2, !t->private));
	      TEST_ASSERT(assh_key_cmp(c, key2, key1, !t->private));

	      if (!skip_sign)
		{
		  putchar('S');
		  skip_sign = test_sign(c, key1, key2);
		  if (t->private)
		    skip_sign = test_sign(c, key2, key1);
		}

	      key_algo = ka;
	      bits_min = t->bits_min;
	      bits_max = t->bits_max;

	      free(blob1);
	      assh_key_drop(c, &key2);
	    }
	}

      if (!done)
	printf("  skipping %s, no key implementation\n", t->key_algo);
    }

  assh_key_drop(c, &key1);
}

/* test key container load/save functions implemented in helpers */
static void test_helper(struct assh_context_s *c, size_t count)
{
  static const struct tests_s helper_tests[] =
    {
     { ASSH_ALGO_SIGN, "ssh-rsa", 1024, 1536, ASSH_KEY_FMT_PUB_RFC4253, 0 },
     { ASSH_ALGO_SIGN, "ssh-rsa", 1024, 1536, ASSH_KEY_FMT_PUB_RFC4716, 0 },
     { ASSH_ALGO_SIGN, "ssh-rsa", 1024, 1536, ASSH_KEY_FMT_PUB_RFC4716, 0, NULL, "com ent" },
     { ASSH_ALGO_SIGN, "ssh-rsa", 1024, 1536, ASSH_KEY_FMT_PUB_OPENSSH, 0 },
     { ASSH_ALGO_SIGN, "ssh-rsa", 1024, 1536, ASSH_KEY_FMT_PUB_OPENSSH, 0, NULL, "com ent" },
     { ASSH_ALGO_SIGN, "ssh-rsa", 1024, 1536, ASSH_KEY_FMT_PUB_PEM_ASN1, 0 },
     { ASSH_ALGO_SIGN, "ssh-rsa", 1024, 1536, ASSH_KEY_FMT_PUB_PEM, 0 },
     { ASSH_ALGO_SIGN, "ssh-rsa", 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },
     { ASSH_ALGO_SIGN, "ssh-rsa", 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB, 1 },
     { ASSH_ALGO_SIGN, "ssh-rsa", 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1, 1 },
     { ASSH_ALGO_SIGN, "ssh-rsa", 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1, 1, NULL, "com ent" },
     { ASSH_ALGO_SIGN, "ssh-rsa", 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1, 1, "passphrase" },
     { ASSH_ALGO_SIGN, "ssh-rsa", 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1, 1, "passphrase", "com ent" },
     { ASSH_ALGO_SIGN, "ssh-rsa", 1024, 1536, ASSH_KEY_FMT_PV_PEM_ASN1, 1 },
     { ASSH_ALGO_SIGN, "ssh-rsa", 1024, 1536, ASSH_KEY_FMT_PV_PEM, 1 },
     { ASSH_ALGO_SIGN, "ssh-rsa", 1024, 1536, ASSH_KEY_FMT_PV_PEM, 1, "passphrase" },

     { ASSH_ALGO_SIGN, "ssh-dss", 1024, 1536, ASSH_KEY_FMT_PUB_RFC4253, 0 },
     { ASSH_ALGO_SIGN, "ssh-dss", 1024, 1536, ASSH_KEY_FMT_PUB_RFC4716, 0 },
     { ASSH_ALGO_SIGN, "ssh-dss", 1024, 1536, ASSH_KEY_FMT_PUB_OPENSSH, 0 },
     { ASSH_ALGO_SIGN, "ssh-dss", 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },
     { ASSH_ALGO_SIGN, "ssh-dss", 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB, 1 },
     { ASSH_ALGO_SIGN, "ssh-dss", 1024, 1536, ASSH_KEY_FMT_PV_OPENSSH_V1, 1 },
     { ASSH_ALGO_SIGN, "ssh-dss", 1024, 1536, ASSH_KEY_FMT_PV_PEM_ASN1, 1 },
     { ASSH_ALGO_SIGN, "ssh-dss", 1024, 1536, ASSH_KEY_FMT_PV_PEM, 1 },
     { ASSH_ALGO_SIGN, "ssh-dss", 1024, 1536, ASSH_KEY_FMT_PV_PEM, 1, "passphrase" },

     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 256, 256, ASSH_KEY_FMT_PUB_RFC4253, 0 },
     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 256, 256, ASSH_KEY_FMT_PUB_RFC4716, 0 },
     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 256, 256, ASSH_KEY_FMT_PUB_OPENSSH, 0 },
     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 256, 256, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },
     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 256, 256, ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB, 1 },
     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 256, 256, ASSH_KEY_FMT_PV_OPENSSH_V1, 1 },
     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 256, 256, ASSH_KEY_FMT_PV_OPENSSH_V1, 1, "passphrase" },
     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 256, 256, ASSH_KEY_FMT_PV_PEM_ASN1, 1 },
     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 256, 256, ASSH_KEY_FMT_PV_PEM, 1 },
     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 256, 256, ASSH_KEY_FMT_PV_PEM, 1, "passphrase" },

     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 521, 521, ASSH_KEY_FMT_PUB_RFC4253, 0 },
     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 521, 521, ASSH_KEY_FMT_PUB_RFC4716, 0 },
     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 521, 521, ASSH_KEY_FMT_PUB_OPENSSH, 0 },
     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },
     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB, 1 },
     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1, 1 },
     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1, 1, "passphrase" },
     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 521, 521, ASSH_KEY_FMT_PV_PEM_ASN1, 1 },
     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 521, 521, ASSH_KEY_FMT_PV_PEM, 1 },
     { ASSH_ALGO_SIGN, "ecdsa-sha2-nist", 521, 521, ASSH_KEY_FMT_PV_PEM, 1, "passphrase" },

     { ASSH_ALGO_SIGN, "ssh-ed25519", 255, 255, ASSH_KEY_FMT_PUB_RFC4253, 0 },
     { ASSH_ALGO_SIGN, "ssh-ed25519", 255, 255, ASSH_KEY_FMT_PUB_RFC4716, 0 },
     { ASSH_ALGO_SIGN, "ssh-ed25519", 255, 255, ASSH_KEY_FMT_PUB_OPENSSH, 0 },
     { ASSH_ALGO_SIGN, "ssh-ed25519", 255, 255, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },
     { ASSH_ALGO_SIGN, "ssh-ed25519", 255, 255, ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB, 1 },
     { ASSH_ALGO_SIGN, "ssh-ed25519", 255, 255, ASSH_KEY_FMT_PV_OPENSSH_V1, 1 },
     { ASSH_ALGO_SIGN, "ssh-ed25519", 255, 255, ASSH_KEY_FMT_PV_OPENSSH_V1, 1, "passphrase" },

     { ASSH_ALGO_SIGN, "eddsa-e382-shake256", 382, 382, ASSH_KEY_FMT_PUB_RFC4253, 0 },
     { ASSH_ALGO_SIGN, "eddsa-e382-shake256", 382, 382, ASSH_KEY_FMT_PUB_RFC4716, 0 },
     { ASSH_ALGO_SIGN, "eddsa-e382-shake256", 382, 382, ASSH_KEY_FMT_PUB_OPENSSH, 0 },
     { ASSH_ALGO_SIGN, "eddsa-e382-shake256", 382, 382, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },
     { ASSH_ALGO_SIGN, "eddsa-e382-shake256", 382, 382, ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB, 1 },
     { ASSH_ALGO_SIGN, "eddsa-e382-shake256", 382, 382, ASSH_KEY_FMT_PV_OPENSSH_V1, 1 },
     { ASSH_ALGO_SIGN, "eddsa-e382-shake256", 382, 382, ASSH_KEY_FMT_PV_OPENSSH_V1, 1, "passphrase" },

     { ASSH_ALGO_SIGN, "eddsa-e521-shake256", 521, 521, ASSH_KEY_FMT_PUB_RFC4253, 0 },
     { ASSH_ALGO_SIGN, "eddsa-e521-shake256", 521, 521, ASSH_KEY_FMT_PUB_RFC4716, 0 },
     { ASSH_ALGO_SIGN, "eddsa-e521-shake256", 521, 521, ASSH_KEY_FMT_PUB_OPENSSH, 0 },
     { ASSH_ALGO_SIGN, "eddsa-e521-shake256", 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 1 },
     { ASSH_ALGO_SIGN, "eddsa-e521-shake256", 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB, 1 },
     { ASSH_ALGO_SIGN, "eddsa-e521-shake256", 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1, 1 },
     { ASSH_ALGO_SIGN, "eddsa-e521-shake256", 521, 521, ASSH_KEY_FMT_PV_OPENSSH_V1, 1, "passphrase" },

     { }
    };

  const struct tests_s *t;
  const char *key_algo = NULL;
  size_t bits_min = 0, bits_max = 0;
  enum assh_key_format_e format = ASSH_KEY_FMT_NONE;
  struct assh_key_s *key1 = NULL, *key2;
  size_t i;

  for (t = helper_tests; t->key_algo != NULL; t++)
    {
      const struct assh_key_algo_s *ka;
      assh_bool_t skip_sign = 0;

      if (assh_key_algo_by_name(c, t->role, t->key_algo,
				strlen(t->key_algo), &ka))
	{
	  printf("  skipping %s, no key implementation\n", t->key_algo);
	  continue;
	}

      for (i = 0; i < count; i++)
	{
	  if (!key_algo || format != t->format || strcmp(key_algo, t->key_algo))
	    {
	      format = t->format;
	      printf("\n%s (%s), %s format: ", t->key_algo, ka->implem,
		     assh_key_format_desc(t->format)->name);
	    }

	  if (!key_algo || strcmp(key_algo, t->key_algo) ||
	      t->bits_min != bits_min || t->bits_max != bits_max)
	    {
	      /* create new key */
	      size_t bits = t->bits_min + test_prng_rand() % (t->bits_max - t->bits_min + 1);
	      assh_key_drop(c, &key1);
	      putchar('N');
	      TEST_ASSERT(!assh_key_create(c, &key1, bits, ka, t->role));
	    }

	  if (t->comment != NULL)
	    TEST_ASSERT(!assh_key_comment(c, key1, t->comment));

	  /* save key to file */
	  putchar('s');
	  TEST_ASSERT(!asshh_key_save_filename(c, key1, "test.key", t->format, t->pass));

	  /* reload key from file */
	  putchar('l');
	  TEST_ASSERT(!asshh_key_load_filename(c, &key2, t->key_algo,
					       t->role, "test.key", t->format, t->pass, 0));

	  /* compare loaded key to original */
	  TEST_ASSERT(assh_key_cmp(c, key1, key2, !t->private));
	  TEST_ASSERT(assh_key_cmp(c, key2, key1, !t->private));

	  if (!skip_sign)
	    {
	      putchar('S');
	      skip_sign = test_sign(c, key1, key2);
	      if (t->private)
		skip_sign = test_sign(c, key2, key1);
	    }

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

	  key_algo = t->key_algo;
	  bits_min = t->bits_min;
	  bits_max = t->bits_max;

	  assh_key_drop(c, &key2);
	}
    }

  assh_key_drop(c, &key1);
}

int main(int argc, char **argv)
{
  setvbuf(stdout, NULL, _IONBF, 0);

  struct assh_context_s *context;

  if (assh_deps_init())
    TEST_FAIL("deps init");

  if (assh_context_create(&context, ASSH_CLIENT_SERVER,
			  test_leaks_allocator, NULL, &test_prng_dummy, NULL))
    TEST_FAIL("context create");

  if (assh_algo_register_static(context, assh_algo_table))
    TEST_FAIL("algo register");

  key_algo_table_size = KEY_ALGO_TABLE_MAXSIZE;
  if (assh_key_algo_enumerate_implems(context, ASSH_ALGO_ANY,
				      &key_algo_table_size, key_algo_table))
    TEST_FAIL("algo enum");

  size_t acount = argc > 1 ? atoi(argv[1]) : 10;
  size_t hcount = argc > 2 ? atoi(argv[2]) : 2;

  int t = time(0);
  test_prng_set_seed(t);
  printf("Seed: %u", t);

  test_algo(context, acount);

  test_helper(context, hcount);

  if (test_alloc_size == 0)
    TEST_FAIL("leak checking not working\n");

  assh_context_release(context);

  if (test_alloc_size != 0)
    TEST_FAIL("memory leak detected, %zu bytes allocated\n", test_alloc_size);

  puts("\n\nTest passed");
  return 0;
}
