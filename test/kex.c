/*

  libassh - asynchronous ssh2 client/server library.

  Copyright (C) 2013 Alexandre Becoulet <alexandre.becoulet@free.fr>

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

#include <assh/assh_session.h>
#include <assh/assh_context.h>
#include <assh/assh_kex.h>
#include <assh/assh_cipher.h>
#include <assh/assh_sign.h>
#include <assh/assh_mac.h>
#include <assh/assh_prng.h>
#include <assh/assh_compress.h>
#include <assh/assh_transport.h>
#include <assh/assh_connection.h>
#include <assh/assh_service.h>
#include <assh/assh_event.h>

#include <assh/key_rsa.h>
#include <assh/key_dsa.h>
#include <assh/key_eddsa.h>
#include <assh/key_ecdsa.h>

#include "prng_weak.h"
#include "leaks_check.h"
#include "fifo.h"
#include "keys.h"
#include "test.h"
#include "cipher_fuzz.h"

#ifdef CONFIG_ASSH_USE_GCRYPT
# include <gcrypt.h>
#endif

#include <stdio.h>

struct fifo_s fifo[2];
struct assh_context_s context[2];
struct assh_session_s session[2];

struct algo_with_key_s
{
  const void *algo;
  const struct assh_key_ops_s *key_algo;
  const uint8_t *key_blob;
  size_t key_size;
};

/* all kex algorithms, multiple set of parameters */
static const struct algo_with_key_s kex_list_long[] =
{
  { &assh_kex_none,              NULL, NULL, 0 },
  { &assh_kex_curve25519_sha256, NULL, NULL, 0 },
  { &assh_kex_m383_sha384,	   NULL, NULL, 0 },
  { &assh_kex_m511_sha512,	   NULL, NULL, 0 },
  { &assh_kex_sha2_nistp256,	   NULL, NULL, 0 },
  { &assh_kex_sha2_nistp384,	   NULL, NULL, 0 },
  { &assh_kex_sha2_nistp521,	   NULL, NULL, 0 },
  { &assh_kex_dh_group1_sha1,	   NULL, NULL, 0 },
  { &assh_kex_dh_group14_sha1,   NULL, NULL, 0 },
  { &assh_kex_dh_group14_sha256,   NULL, NULL, 0 },
  { &assh_kex_dh_group15_sha512,   NULL, NULL, 0 },
  { &assh_kex_dh_group16_sha512,   NULL, NULL, 0 },
  { &assh_kex_dh_group17_sha512,   NULL, NULL, 0 },
  { &assh_kex_dh_group18_sha512,   NULL, NULL, 0 },
  { &assh_kex_dh_gex_sha1,	   NULL, NULL, 0 },
  { &assh_kex_dh_gex_sha256_12,  NULL, NULL, 0 },
  { &assh_kex_rsa1024_sha1,	   NULL, NULL, 0 },
  { &assh_kex_rsa1024_sha1,	   &assh_key_rsa, rsa1024_key, sizeof(rsa1024_key) },
  { &assh_kex_rsa2048_sha256,	   &assh_key_rsa, rsa2048_key, sizeof(rsa2048_key) },
  { NULL },
};

/* all kex algorithms, single set of parameters */
static const struct algo_with_key_s kex_list_all[] =
{
  { &assh_kex_none,              NULL, NULL, 0 },
  { &assh_kex_curve25519_sha256, NULL, NULL, 0 },
  { &assh_kex_sha2_nistp256,	   NULL, NULL, 0 },
  { &assh_kex_dh_group1_sha1,	   NULL, NULL, 0 },
  { &assh_kex_dh_gex_sha1,	   NULL, NULL, 0 },
  { &assh_kex_rsa1024_sha1,	   NULL, NULL, 0 },
  { &assh_kex_rsa1024_sha1,	   &assh_key_rsa, rsa1024_key, sizeof(rsa1024_key) },
  { NULL },
};

/* minimal set of kex algorithms for testing other classes */
static const struct algo_with_key_s kex_list_short[] =
{
  { &assh_kex_none,              NULL, NULL, 0 },
  { &assh_kex_curve25519_sha256, NULL, NULL, 0 },
  { NULL }
};

/* all sign algorithms, multiple set of parameters */
static const struct algo_with_key_s sign_list_long[] =
{
  { &assh_sign_none,              &assh_key_none, (const uint8_t*)"\0", 0 },
  { &assh_sign_dsa,               &assh_key_dsa, dsa1024_key, sizeof(dsa1024_key) - 1 },
  { &assh_sign_nistp256,          &assh_key_ecdsa_nistp, ecdsa_nistp256_key, sizeof(ecdsa_nistp256_key) - 1 },
  { &assh_sign_nistp384,          &assh_key_ecdsa_nistp, ecdsa_nistp384_key, sizeof(ecdsa_nistp384_key) - 1 },
  { &assh_sign_nistp521,          &assh_key_ecdsa_nistp, ecdsa_nistp521_key, sizeof(ecdsa_nistp521_key) - 1 },
  //  { &assh_sign_dsa2048_sha224,    &assh_key_dsa, dsa2048_key, sizeof(dsa2048_key) },
  { &assh_sign_dsa2048_sha256,    &assh_key_dsa, dsa2048_key, sizeof(dsa2048_key) - 1 },
  { &assh_sign_dsa3072_sha256,    &assh_key_dsa, dsa3072_key, sizeof(dsa3072_key) - 1 },
  { &assh_sign_rsa_sha1_md5,      &assh_key_rsa, rsa1024_key, sizeof(rsa1024_key) - 1 },
  { &assh_sign_rsa_sha1,          &assh_key_rsa, rsa1024_key, sizeof(rsa1024_key) - 1 },
  { &assh_sign_rsa_sha1_2048,     &assh_key_rsa, rsa2048_key, sizeof(rsa2048_key) - 1 },
  { &assh_sign_rsa_sha256,        &assh_key_rsa, rsa2048_key, sizeof(rsa2048_key) - 1 },
  { &assh_sign_rsa_sha512,        &assh_key_rsa, rsa3072_key, sizeof(rsa3072_key) - 1 },
  { &assh_sign_ed25519,           &assh_key_ed25519, ed25519_key, sizeof(ed25519_key) - 1 },
  { &assh_sign_eddsa_e382,        &assh_key_eddsa_e382, eddsa_e382_key, sizeof(eddsa_e382_key) - 1 },
  { NULL }
};

/* all sign algorithms, single set of parameters */
static const struct algo_with_key_s sign_list_all[] =
{
  { &assh_sign_none,              &assh_key_none, (const uint8_t*)"\0", 0 },
  { &assh_sign_dsa,               &assh_key_dsa, dsa1024_key, sizeof(dsa1024_key) - 1 },
  { &assh_sign_nistp256,          &assh_key_ecdsa_nistp, ecdsa_nistp256_key, sizeof(ecdsa_nistp256_key) - 1 },
  { &assh_sign_rsa_sha1_md5,      &assh_key_rsa, rsa1024_key, sizeof(rsa1024_key) - 1 },
  { &assh_sign_ed25519,           &assh_key_ed25519, ed25519_key, sizeof(ed25519_key) - 1 },
  { NULL }
};

/* minimal set of sign algorithms for testing other classes */
static const struct algo_with_key_s sign_list_short[] =
{
  { &assh_sign_none,              &assh_key_none, (const uint8_t*)"\0", 0 },
  { NULL }
};

/* all mac algorithms */
static const struct assh_algo_mac_s *mac_list_long[] =
{
  &assh_hmac_none,
# ifdef CONFIG_ASSH_HASH_MD5
  &assh_hmac_md5,
  &assh_hmac_md5_96,
  &assh_hmac_md5_etm,
  &assh_hmac_md5_96_etm,
# endif
# ifdef CONFIG_ASSH_HASH_SHA1
  &assh_hmac_sha1,
  &assh_hmac_sha1_96,
  &assh_hmac_sha1_etm,
  &assh_hmac_sha1_96_etm,
# endif
# ifdef CONFIG_ASSH_HASH_SHA2
  &assh_hmac_sha256,
  &assh_hmac_sha512,
  &assh_hmac_sha256_etm,
  &assh_hmac_sha512_etm,
# endif
# ifdef CONFIG_ASSH_HASH_RIPEMD160
  &assh_hmac_ripemd160,
# endif
  NULL
};

/* minimal set of mac algorithms for testing other classes */
static const struct assh_algo_mac_s *mac_list_short[] =
{
  &assh_hmac_md5,
  NULL
};

/* single mac algorithm which let mangled packet through */
static const struct assh_algo_mac_s *mac_list_fuzz[] =
{
  &assh_hmac_none,
  NULL
};

/* all cipher algorithms */
static const struct assh_algo_cipher_s *cipher_list_long[] =
{
# ifdef CONFIG_ASSH_CIPHER_TDES
  &assh_cipher_tdes_cbc,
#  ifdef CONFIG_ASSH_MODE_CTR
  &assh_cipher_tdes_ctr,
#  endif
# endif

# ifdef CONFIG_ASSH_CIPHER_CAST128
  &assh_cipher_cast128_cbc,
#  ifdef CONFIG_ASSH_MODE_CTR
  &assh_cipher_cast128_ctr,
#  endif
# endif

# ifdef CONFIG_ASSH_CIPHER_IDEA
  &assh_cipher_idea_cbc,
#  ifdef CONFIG_ASSH_MODE_CTR
  &assh_cipher_idea_ctr,
#  endif
# endif

# ifdef CONFIG_ASSH_CIPHER_BLOWFISH
  &assh_cipher_blowfish_cbc,
#  ifdef CONFIG_ASSH_MODE_CTR
  &assh_cipher_blowfish_ctr,
#  endif
# endif

# ifdef CONFIG_ASSH_CIPHER_TWOFISH
  &assh_cipher_twofish128_cbc,
  &assh_cipher_twofish256_cbc,
#  ifdef CONFIG_ASSH_MODE_CTR
  &assh_cipher_twofish128_ctr,
  &assh_cipher_twofish256_ctr,
#  endif
#  ifdef CONFIG_ASSH_MODE_GCM
  &assh_cipher_twofish128_gcm,
  &assh_cipher_twofish256_gcm,
#  endif
# endif

# ifdef CONFIG_ASSH_CIPHER_SERPENT
  &assh_cipher_serpent128_cbc,
  &assh_cipher_serpent192_cbc,
  &assh_cipher_serpent256_cbc,
#  ifdef CONFIG_ASSH_MODE_CTR
  &assh_cipher_serpent128_ctr,
  &assh_cipher_serpent192_ctr,
  &assh_cipher_serpent256_ctr,
#  endif
#  ifdef CONFIG_ASSH_MODE_GCM
  &assh_cipher_serpent128_gcm,
  &assh_cipher_serpent256_gcm,
#  endif
# endif

# ifdef CONFIG_ASSH_CIPHER_ARCFOUR
  &assh_cipher_arc4,
  &assh_cipher_arc4_128,
  &assh_cipher_arc4_256,
# endif

# ifdef CONFIG_ASSH_CIPHER_AES
  &assh_cipher_aes128_cbc,
  &assh_cipher_aes192_cbc,
  &assh_cipher_aes256_cbc,
#  ifdef CONFIG_ASSH_MODE_CTR
  &assh_cipher_aes128_ctr,
  &assh_cipher_aes192_ctr,
  &assh_cipher_aes256_ctr,
#  endif
#  ifdef CONFIG_ASSH_MODE_GCM
  &assh_cipher_aes128_gcm,
  &assh_cipher_aes256_gcm,
#  endif
# endif

# ifdef CONFIG_ASSH_CIPHER_CAMELLIA
  &assh_cipher_camellia128_cbc,
  &assh_cipher_camellia192_cbc,
  &assh_cipher_camellia256_cbc,
#  ifdef CONFIG_ASSH_MODE_CTR
  &assh_cipher_camellia128_ctr,
  &assh_cipher_camellia192_ctr,
  &assh_cipher_camellia256_ctr,
#  endif
# endif

# ifdef CONFIG_ASSH_CIPHER_CHACHAPOLY
  &assh_cipher_chachapoly,
# endif
  NULL
};

/* cipher algorithms with different cipher_key_size for kex testing */
static const struct assh_algo_cipher_s *cipher_list_short[] =
{
  &assh_cipher_none,
  &assh_cipher_arc4,
  &assh_cipher_aes256_ctr,
  NULL
};

/* single cipher algorithms which mangle packet content */
static const struct assh_algo_cipher_s *cipher_list_fuzz[] =
{
  &assh_cipher_fuzz,
  NULL
};

/* all compression algorithms */
static const struct assh_algo_compress_s *comp_list_long[] =
{
  &assh_compress_none,
# ifdef CONFIG_ASSH_USE_ZLIB
  &assh_compress_zlib,
  &assh_compress_zlib_openssh,
# endif
  NULL
};

/* minimal set of compression algorithms for testing other classes */
static const struct assh_algo_compress_s *comp_list_short[] =
{
  &assh_compress_none,
  NULL
};

static unsigned long kex_client_done_count = 0;
static unsigned long kex_server_done_count = 0;
static unsigned long kex_hostkey_lookup_count = 0;

void test(const struct assh_algo_kex_s *kex,
	  const struct assh_algo_sign_s *sign,
	  const struct assh_algo_cipher_s *cipher,
	  const struct assh_algo_mac_s *mac,
	  const struct assh_algo_compress_s *comp,
	  const struct algo_with_key_s *kex_key,
	  const struct algo_with_key_s *sign_key)
{
  if (assh_context_init(&context[0], ASSH_SERVER,
			assh_leaks_allocator, NULL, &assh_prng_weak, NULL) ||
      assh_context_init(&context[1], ASSH_CLIENT,
			assh_leaks_allocator, NULL, &assh_prng_weak, NULL))
    TEST_FAIL("ctx init\n");

  uint_fast8_t i;
  uint_fast8_t done = 0;

  fprintf(stderr, "%-36s %-30s %-30s %-30s %s\n",
	  assh_algo_name(&kex->algo), assh_algo_name(&sign->algo),
	  assh_algo_name(&cipher->algo), assh_algo_name(&mac->algo),
	  assh_algo_name(&comp->algo));

  for (i = 0; i < 2; i++)
    {
      struct assh_context_s *c = &context[i];

      fifo_init(&fifo[i]);

      if (assh_service_register_va(c, &assh_service_connection, NULL))
	TEST_FAIL("service register\n");

      if (assh_algo_register_va(c, 0, 0, 0, kex, sign, cipher, mac, comp, NULL) != ASSH_OK)
	TEST_FAIL("algo register\n");

      if (i == 0 && sign_key->key_algo != NULL)
	{
	  do {
	  const uint8_t *key_blob = sign_key->key_blob + 1;
	  if (assh_key_load(c, &c->keys,
			    sign_key->key_algo, ASSH_ALGO_SIGN, sign_key->key_blob[0],
			    &key_blob, sign_key->key_size))
	    {
	      if (alloc_fuzz)
		continue;
	      TEST_FAIL("sign key load\n");
	    }
	  } while (0);
	}

      if (i == 0 && kex_key->key_algo != NULL)
	{
	  do {
	  const uint8_t *key_blob = kex_key->key_blob + 1;
	  if (assh_key_load(c, &c->keys,
			    kex_key->key_algo, ASSH_ALGO_KEX, kex_key->key_blob[0],
			    &key_blob, kex_key->key_size))
	    {
	      if (alloc_fuzz)
		continue;
	      TEST_FAIL("kex key load\n");
	    }
	  } while (0);
	}

      if (assh_session_init(c, &session[i]) != ASSH_OK)
	TEST_FAIL("session init\n");

      assh_cipher_fuzz_initreg(c, &session[i]);
    }

  uint_fast8_t stall = 0;

  while (1) 
    {
      for (i = 0; i < 2; i++)
	{
	  struct assh_event_s event;

	  ASSH_DEBUG("=== session %u %u ===\n", i, stall);

	  if (!assh_event_get(&session[i], &event, 0))
	    TEST_FAIL("event_get %u terminated\n", i);

	  switch (event.id)
	    {
	    case ASSH_EVENT_ERROR:
	      if (packet_fuzz || alloc_fuzz)
		goto done;
	      TEST_FAIL("error %u %lx\n", i, event.error.code);
	      break;

	    case ASSH_EVENT_KEX_HOSTKEY_LOOKUP:
	      assert(i == 1);
	      event.kex.hostkey_lookup.accept = 1;
	      kex_hostkey_lookup_count++;
	      break;

	    case ASSH_EVENT_KEX_DONE:
	      ASSH_DEBUG("kex safety %u: %u\n", i, event.kex.done.safety);
	      if (i)
		kex_client_done_count++;
	      else
		kex_server_done_count++;
	      break;

	    case ASSH_EVENT_READ:
	      if (fifo_rw_event(fifo, &event, i))
		stall++;
	      break;

	    case ASSH_EVENT_WRITE:
	      if (!fifo_rw_event(fifo, &event, i))
		stall = 0;
	      break;

	    case ASSH_EVENT_CONNECTION_START:
#warning transfer more data
	      done |= 1 << i;

	      if (done == 3)
		goto done;
	      break;

	    default:
	      ASSH_DEBUG("event %u not handled\n", event.id);
	    }

	  assh_event_done(&session[i], &event, ASSH_OK);

	  if (stall >= 100)
	    {
	      /* packet exchange is stalled, hopefully due to a fuzzing error */
	      if (!packet_fuzz)
		TEST_FAIL("stalled %u\n", i);
	      ASSH_DEBUG("=== stall ===");
	      goto done;
	    }
	}
    }

 done:
  assh_session_cleanup(&session[0]);
  assh_context_cleanup(&context[0]);
  assh_session_cleanup(&session[1]);
  assh_context_cleanup(&context[1]);

  if (alloc_size != 0)
    TEST_FAIL("memory leak detected, %zu bytes allocated\n", alloc_size);
}

void test_loop(unsigned int seed,
	       const struct algo_with_key_s *kex,
	       const struct algo_with_key_s *sign,
	       const struct assh_algo_cipher_s **cipher,
	       const struct assh_algo_mac_s **mac,
	       const struct assh_algo_compress_s **comp)
{
  const struct algo_with_key_s *kex_list = kex;
  const struct algo_with_key_s *sign_list = sign;
  const struct assh_algo_cipher_s **cipher_list = cipher;
  const struct assh_algo_mac_s **mac_list = mac;

  fprintf(stderr, "Seed: %9u\n", seed);

  while (*comp)
    {
      while (*mac)
	{
	  while (*cipher)
	    {
	      while (sign->algo)
		{
		  while (kex->algo)
		    {
		      srand(seed);
		      test(kex->algo, sign->algo, *cipher, *mac, *comp,
			   kex, sign);
		      kex++;
		    }
		  kex = kex_list;
		  sign++;
		}
	      sign = sign_list;
	      cipher++;
	    }
	  cipher = cipher_list;
	  mac++;
	}
      mac = mac_list;
      comp++;
    }
}

int main(int argc, char **argv)
{
  unsigned int count = argc > 1 ? atoi(argv[1]) : 1;
  unsigned int action = argc > 2 ? atoi(argv[2]) : 1;
  unsigned int s = argc > 3 ? atoi(argv[3]) : time(0);

  unsigned int k;

  for (k = 0; k < count; k++)
    {
      unsigned seed = s + k;

      /* run some sessions, use various algorithms */
      if (action & 1)
	{
	  alloc_fuzz = 0;
	  packet_fuzz = 0;

	  /* test cipher and mac */
	  test_loop(seed, kex_list_short, sign_list_short, cipher_list_long, mac_list_long, comp_list_short);
	  /* test compression */
	  test_loop(seed, kex_list_short, sign_list_short, cipher_list_short, mac_list_short, comp_list_long);
	  /* test sign */
	  test_loop(seed, kex_list_all, sign_list_long, cipher_list_short, mac_list_short, comp_list_short);
	  /* test kex */
	  test_loop(seed, kex_list_long, sign_list_short, cipher_list_short, mac_list_short, comp_list_short);
	}

      /* run some more sessions with some packet error */
      if (action & 2)
	{
	  alloc_fuzz = 0;
	  packet_fuzz = 10 + rand() % 1024;

	  /* fuzz compression parsing */
	  test_loop(seed, kex_list_short, sign_list_short, cipher_list_fuzz, mac_list_fuzz, comp_list_long);
	  /* fuzz signature parsing */
	  test_loop(seed, kex_list_short, sign_list_long, cipher_list_fuzz, mac_list_fuzz, comp_list_short);
	  /* fuzz kex parsing */
	  test_loop(seed, kex_list_long, sign_list_short, cipher_list_fuzz, mac_list_fuzz, comp_list_short);
	}

      /* run some more sessions with some allocation fails */
      if (action & 4)
	{
	  alloc_fuzz = 4 + rand() % 32;
	  packet_fuzz = 0;

	  /* fuzz cipher and mac allocation */
	  test_loop(seed, kex_list_short, sign_list_short, cipher_list_long, mac_list_long, comp_list_short);
	  /* fuzz compression allocation */
	  test_loop(seed, kex_list_short, sign_list_short, cipher_list_short, mac_list_short, comp_list_long);
	  /* fuzz kex and sign allocation */
	  test_loop(seed, kex_list_all, sign_list_all, cipher_list_short, mac_list_short, comp_list_short);
	}
    }

  if (action & 6)
    {
      fprintf(stderr, "Summary:\n"
	      "  %8lu client kex done\n"
	      "  %8lu server kex done\n"
	      "  %8lu client host key lookup\n"
	      "  %8lu fuzz packet bit errors\n"
	      "  %8lu fuzz memory allocation fails\n"
	      ,
	      kex_client_done_count,
	      kex_server_done_count,
	      kex_hostkey_lookup_count,
	      packet_fuzz_bits,
	      alloc_fuzz_fails
	      );
    }
  else
    {
      fprintf(stderr, "Done\n");
    }

  return 0;
}

