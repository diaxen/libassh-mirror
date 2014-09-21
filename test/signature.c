
#include <assh/assh_sign.h>
#include <assh/assh_context.h>
#include <assh/assh_prng.h>

#include <stdint.h>
#include "keys.h"

#ifdef CONFIG_ASSH_USE_GCRYPT
# include <gcrypt.h>
#endif

struct algo_s
{
  const struct assh_algo_sign_s *algo;
  const uint8_t *key;
  size_t key_len;
};

struct algo_s algos[] = {
  { &assh_sign_dss,             dsa1024_key, sizeof(dsa1024_key) },
  { &assh_sign_rsa_sha1_md5,    rsa1024_key, sizeof(rsa1024_key) },
  { &assh_sign_rsa_sha256_2048, rsa2048_key, sizeof(rsa2048_key) },
  { NULL },
};

#define TEST_SIZE 128

int main(int argc, char **argv)
{
  assh_error_t err;
  struct assh_context_s context;
  int i;

#ifdef CONFIG_ASSH_USE_GCRYPT
  if (!gcry_check_version(GCRYPT_VERSION))
    return -1;
#endif

  assh_context_init(&context, ASSH_SERVER);
  ASSH_ERR_RET(assh_context_prng(&context, NULL));

  for (i = 0; algos[i].algo; i++)
    ASSH_ERR_RET(assh_algo_register_va(&context, 0, 0, algos[i].algo, NULL));

  for (i = 0; algos[i].algo; i++)
    {
      const struct assh_algo_sign_s *a = algos[i].algo;
      struct assh_key_s *key;

      fprintf(stderr, "\n%s sign/verify: ", a->algo.name);

      uint8_t key_blob[algos[i].key_len];
      memcpy(key_blob, algos[i].key, sizeof(key_blob));

      ASSH_ERR_RET(assh_key_load(&context, &key, a->algo.key, ASSH_ALGO_SIGN,
				 ASSH_KEY_FMT_PV_PEM_ASN1,
                                 key_blob, sizeof(key_blob)));

      int size;
      for (size = TEST_SIZE; size != 0; )
	{
	  size--;
	  uint8_t data[size];
	  ASSH_ERR_RET(context.prng->f_get(&context, data, size,
                                           ASSH_PRNG_QUALITY_WEAK));

	  const uint8_t * ptr[8];
	  size_t sz[8];
	  int c = 0;
	  int s = 0;
	  while (s < size)
	    {
	      int r = rand() % 128 + 128;
	      if (s + r > size)
		r = size - s;
	      ptr[c] = data + s;
	      sz[c] = r;
	      s += r;
              c++;
	    }

	  size_t sign_len;

          fprintf(stderr, "g");

	  ASSH_ERR_RET(a->f_generate(&context, key, c, ptr, sz, NULL, &sign_len));
	  assert(sign_len > 0);

	  uint8_t sign[sign_len];
	  ASSH_ERR_RET(a->f_generate(&context, key, c, ptr, sz, sign, &sign_len));

          fprintf(stderr, "v");

	  err = a->f_verify(&context, key, c, ptr, sz, sign, sign_len);
	  assert(err == ASSH_OK);

          unsigned int r1 = rand() % sign_len;
          unsigned char r2 = rand();
          if (!r2)
            r2++;
#ifdef CONFIG_ASSH_DEBUG_SIGN
          fprintf(stderr, "Mangling signature byte %u, previous=0x%02x, new=0x%02x\n",
                    r1, sign[r1], sign[r1] ^ r2);
#endif
	  sign[r1] ^= r2;

          fprintf(stderr, "V");

	  err = a->f_verify(&context, key, c, ptr, sz, sign, sign_len);
	  assert(err != ASSH_OK);
	}

      assh_key_drop(&context, &key);

      fprintf(stderr, "\n%s key load/validate: ", a->algo.name);

      /* test key loading and validation */
      int j;
      for (j = 0; j < TEST_SIZE; j++)
	{
          memcpy(key_blob, algos[i].key, sizeof(key_blob));
	  int bad = j > 0;

	  if (bad)		/* mangle key blob on odd iterations */
	    {
	      unsigned int r1 = rand() % sizeof(key_blob);
	      unsigned char r2 = rand();
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
	  err = assh_key_load(&context, &key, a->algo.key, ASSH_ALGO_SIGN,
			      ASSH_KEY_FMT_PV_PEM_ASN1,
			      key_blob, sizeof(key_blob));

	  if (!bad)
	    assert(err == ASSH_OK);
	  else if (err != ASSH_OK)
	    continue;

	  fprintf(stderr, "V");

	  err = assh_key_validate(&context, key);

	  assert(bad || (err == ASSH_OK));
	  //	  assert(!bad || (err != ASSH_OK));

          assh_key_drop(&context, &key);
        }

    }

  fprintf(stderr, "\nDone.\n");
  return 0;
}

