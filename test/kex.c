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
#include <assh/assh_userauth.h>
#include <assh/helper_key.h>

#include "prng_weak.h"
#include "leaks_check.h"
#include "fifo.h"
#include "keys.h"
#include "test.h"
#include "cipher_fuzz.h"

#include <stdio.h>
#include <getopt.h>

struct fifo_s fifo[2];
struct assh_context_s context[2];
struct assh_session_s session[2];

struct algo_with_key_s
{
  const char *algo;
  const char *variant;
  const char *key_algo;
  const uint8_t *key_blob;
  size_t key_size;
};

const char *kex_filter = NULL;
const char *sign_filter = NULL;
const char *cipher_filter = NULL;
const char *mac_filter = NULL;
const char *comp_filter = NULL;

/* all kex algorithms, multiple set of parameters */
static const struct algo_with_key_s kex_list_slow[] =
{
  { "none@libassh.org",                    NULL, NULL, NULL, 0 },
  { "curve25519-sha256@libssh.org",        NULL, NULL, NULL, 0 },
  { "m383-sha384@libassh.org",             NULL, NULL, NULL, 0 },
  { "m511-sha512@libassh.org",             NULL, NULL, NULL, 0 },
  { "ecdh-sha2-nistp256",                  NULL, NULL, NULL, 0 },
  { "ecdh-sha2-nistp384",                  NULL, NULL, NULL, 0 },
  { "ecdh-sha2-nistp521",                  NULL, NULL, NULL, 0 },
  { "diffie-hellman-group1-sha1",          NULL, NULL, NULL, 0 },
  { "diffie-hellman-group14-sha1",         NULL, NULL, NULL, 0 },
  { "diffie-hellman-group14-sha256",       NULL, NULL, NULL, 0 },
  { "diffie-hellman-group15-sha512",       NULL, NULL, NULL, 0 },
  { "diffie-hellman-group16-sha512",       NULL, NULL, NULL, 0 },
  { "diffie-hellman-group17-sha512",       NULL, NULL, NULL, 0 },
  { "diffie-hellman-group18-sha512",       NULL, NULL, NULL, 0 },
  { "diffie-hellman-group-exchange-sha1",  "1024 <= group <= 4096", NULL, NULL, 0 },
  { "diffie-hellman-group-exchange-sha256", "1024 <= group <= 2048", NULL, NULL, 0 },
  { "diffie-hellman-group-exchange-sha256", "2048 <= group <= 4096", NULL, NULL, 0 },
  { "diffie-hellman-group-exchange-sha256", "group >= 4096", NULL, NULL, 0 },
#ifdef CONFIG_ASSH_KEY_CREATE
  { "rsa1024-sha1",                        NULL, NULL, NULL, 0 },
#endif
  { "rsa1024-sha1",                        NULL, "ssh-rsa",
    rsa1024_key, sizeof(rsa1024_key) },
  { "rsa2048-sha256",                      NULL, "ssh-rsa",
    rsa2048_key, sizeof(rsa2048_key) },
  { NULL },
};

/* all kex algorithms, reduced set of parameters */
static const struct algo_with_key_s kex_list_long[] =
{
  { "none@libassh.org",                    NULL, NULL, NULL, 0 },
  { "curve25519-sha256@libssh.org",        NULL, NULL, NULL, 0 },
  { "m383-sha384@libassh.org",             NULL, NULL, NULL, 0 },
  { "m511-sha512@libassh.org",             NULL, NULL, NULL, 0 },
  { "ecdh-sha2-nistp256",                  NULL, NULL, NULL, 0 },
  { "ecdh-sha2-nistp384",                  NULL, NULL, NULL, 0 },
  { "ecdh-sha2-nistp521",                  NULL, NULL, NULL, 0 },
  { "diffie-hellman-group1-sha1",          NULL, NULL, NULL, 0 },
  { "diffie-hellman-group14-sha256",       NULL, NULL, NULL, 0 },
  { "diffie-hellman-group-exchange-sha256", "1024 <= group <= 2048", NULL, NULL, 0 },
#ifdef CONFIG_ASSH_KEY_CREATE
  { "rsa1024-sha1",                        NULL, NULL, NULL, 0 },
#endif
  { "rsa2048-sha256",                      NULL, "ssh-rsa",
    rsa2048_key, sizeof(rsa2048_key) },
  { NULL },
};

/* all kex algorithms, single set of parameters */
static const struct algo_with_key_s kex_list_all[] =
{
  { "none@libassh.org",                    NULL, NULL, NULL, 0 },
  { "curve25519-sha256@libssh.org",        NULL, NULL, NULL, 0 },
  { "ecdh-sha2-nistp256",                  NULL, NULL, NULL, 0 },
  { "diffie-hellman-group1-sha1",          NULL, NULL, NULL, 0 },
  { "diffie-hellman-group-exchange-sha256", "1024 <= group <= 2048", NULL, NULL, 0 },
#ifdef CONFIG_ASSH_KEY_CREATE
  { "rsa1024-sha1",                        NULL, NULL, NULL, 0 },
#endif
  { "rsa1024-sha1",                        NULL, "ssh-rsa",
    rsa1024_key, sizeof(rsa1024_key) },
  { NULL },
};

/* minimal set of kex algorithms for testing other classes */
static const struct algo_with_key_s kex_list_short[] =
{
  { "none@libassh.org",                    NULL, NULL, NULL, 0 },
  { "curve25519-sha256@libssh.org",        NULL, NULL, NULL, 0 },
  { NULL }
};

/* all sign algorithms, multiple set of parameters */
static const struct algo_with_key_s sign_list_long[] =
{
  { "none@libassh.org",            NULL,                    "none",
    (const uint8_t*)"\0", 0 },
  { "ssh-dss",                     "key >= 1024",           "ssh-dss",
    dsa1024_key, sizeof(dsa1024_key) - 1 },
  { "ssh-dss",                     NULL,                    "ssh-dss",
    dsa1024_key, sizeof(dsa1024_key) - 1 },
  { "ecdsa-sha2-nistp256",         NULL,                    "ecdsa-sha2-nist",
    ecdsa_nistp256_key, sizeof(ecdsa_nistp256_key) - 1 },
  { "ecdsa-sha2-nistp384",         NULL,                    "ecdsa-sha2-nist",
    ecdsa_nistp384_key, sizeof(ecdsa_nistp384_key) - 1 },
  { "ecdsa-sha2-nistp521",         NULL,                    "ecdsa-sha2-nist",
    ecdsa_nistp521_key, sizeof(ecdsa_nistp521_key) - 1 },
//{ "dsa2048-sha224@libassh.org",  NULL,                    "ssh-dss",
//  dsa2048_key, sizeof(dsa2048_key) - 1 },
  { "dsa2048-sha256@libassh.org",  NULL,                    "ssh-dss",
    dsa2048_key, sizeof(dsa2048_key) - 1 },
  { "dsa3072-sha256@libassh.org",  NULL,                    "ssh-dss",
    dsa3072_key, sizeof(dsa3072_key) - 1 },
  { "ssh-rsa",                     "sha*, md5, key >= 768", "ssh-rsa",
    rsa1024_key, sizeof(rsa1024_key) - 1 },
  { "ssh-rsa",                     "sha*, key >= 1024",     "ssh-rsa",
    rsa1024_key, sizeof(rsa1024_key) - 1 },
  { "ssh-rsa",                     "sha*, key >= 2048",     "ssh-rsa",
    rsa2048_key, sizeof(rsa2048_key) - 1 },
  { "rsa-sha2-256",                NULL,                    "ssh-rsa",
    rsa2048_key, sizeof(rsa2048_key) - 1 },
  { "rsa-sha2-512",                NULL,                    "ssh-rsa",
    rsa3072_key, sizeof(rsa3072_key) - 1 },
  { "ssh-ed25519",                 NULL,                    "ssh-ed25519",
    ed25519_key, sizeof(ed25519_key) - 1 },
  { "eddsa-e382-shake256@libassh.org", NULL, "eddsa-e382-shake256@libassh.org",
    eddsa_e382_key, sizeof(eddsa_e382_key) - 1 },
  { NULL }
};

/* all sign algorithms, single set of parameters */
static const struct algo_with_key_s sign_list_all[] =
{
  { "none@libassh.org",            NULL,                    "none",
    (const uint8_t*)"\0", 0 },
  { "ssh-dss",                     "key >= 768",            "ssh-dss",
    dsa1024_key, sizeof(dsa1024_key) - 1 },
  { "ecdsa-sha2-nistp256",         NULL,                    "ecdsa-sha2-nist",
    ecdsa_nistp256_key, sizeof(ecdsa_nistp256_key) - 1 },
  { "ssh-rsa",                     "sha*, md5, key >= 768", "ssh-rsa",
    rsa1024_key, sizeof(rsa1024_key) - 1 },
  { "ssh-ed25519",                 NULL,                    "ssh-ed25519",
    ed25519_key, sizeof(ed25519_key) - 1 },
  { NULL }
};

/* minimal set of sign algorithms for testing other classes */
static const struct algo_with_key_s sign_list_short[] =
{
  { "none@libassh.org",            NULL,                    "none",
    (const uint8_t*)"\0", 0 },
  { NULL }
};

/* all mac algorithms */
static const char *mac_list_long[] =
{
  "none",
  "hmac-md5",
  "hmac-md5-96",
  "hmac-md5-etm@openssh.com",
  "hmac-md5-96-etm@openssh.com",
  "hmac-sha1",
  "hmac-sha1-96",
  "hmac-sha1-etm@openssh.com",
  "hmac-sha1-96-etm@openssh.com",
  "hmac-sha2-256",
  "hmac-sha2-512",
  "hmac-sha2-256-etm@openssh.com",
  "hmac-sha2-512-etm@openssh.com",
  "hmac-ripemd160",
  NULL
};

/* minimal set of mac algorithms for testing other classes */
static const char *mac_list_short[] =
{
  "hmac-md5",
  NULL
};

/* single mac algorithm which let mangled packet through */
static const char *mac_list_fuzz[] =
{
  "none",
  NULL
};

/* all cipher algorithms */
static const char *cipher_list_long[] =
{
  "3des-cbc",
  "3des-ctr",
  "cast128-cbc",
  "cast128-ctr",
  "idea-cbc",
  "idea-ctr",
  "blowfish-cbc",
  "blowfish-ctr",
  "twofish128-cbc",
  "twofish192-cbc",
  "twofish256-cbc",
  "twofish128-ctr",
  "twofish192-ctr",
  "twofish256-ctr",
  "twofish128-gcm@libassh.org",
  "twofish256-gcm@libassh.org",
  "serpent128-cbc",
  "serpent192-cbc",
  "serpent256-cbc",
  "serpent128-ctr",
  "serpent192-ctr",
  "serpent256-ctr",
  "serpent128-gcm@libassh.org",
  "serpent256-gcm@libassh.org",
  "arcfour",
  "arcfour128",
  "arcfour256",
  "aes128-cbc",
  "aes192-cbc",
  "aes256-cbc",
  "aes128-ctr",
  "aes192-ctr",
  "aes256-ctr",
  "aes128-gcm@openssh.com",
  "aes256-gcm@openssh.com",
  "camellia128-cbc",
  "camellia192-cbc",
  "camellia256-cbc",
  "camellia128-ctr",
  "camellia192-ctr",
  "camellia256-ctr",
  "chacha20-poly1305@openssh.com",
  NULL
};

/* cipher algorithms with different cipher_key_size for kex testing */
static const char *cipher_list_short[] =
{
  "none",
  "arcfour",
  "aes192-ctr",
  "aes192-cbc",
  "aes256-ctr",
  "aes256-cbc",
  NULL
};

/* single cipher algorithms which mangle packet content */
static const char *cipher_list_fuzz[] =
{
  "fuzz",
  NULL
};

/* all compression algorithms */
static const char *comp_list_long[] =
{
  "none",
  "zlib",
  "zlib@openssh.com",
  NULL
};

/* minimal set of compression algorithms for testing other classes */
static const char *comp_list_short[] =
{
  "none",
  NULL
};

static unsigned long kex_client_done_count = 0;
static unsigned long kex_server_done_count = 0;
static unsigned long kex_hostkey_lookup_count = 0;
static unsigned long kex_rekex_count = 0;

void test(const struct assh_algo_kex_s *ka,
	  const struct assh_algo_sign_s *sa,
	  const struct assh_algo_cipher_s *ca,
	  const struct assh_algo_mac_s *ma,
	  const struct assh_algo_compress_s *cpa,
	  const struct algo_with_key_s *kex_key,
	  const struct algo_with_key_s *sign_key,
	  unsigned seed, unsigned cycles)
{
  const struct assh_algo_s *algos[] = {
    &ka->algo_wk.algo, &sa->algo_wk.algo, &ca->algo, &ma->algo, &cpa->algo,
    NULL
  };

  if (assh_context_init(&context[0], ASSH_SERVER,
			assh_leaks_allocator, NULL, &assh_prng_dummy, NULL) ||
      assh_algo_register_static(&context[0], algos) ||
      assh_context_init(&context[1], ASSH_CLIENT,
			assh_leaks_allocator, NULL, &assh_prng_dummy, NULL) ||
      assh_algo_register_static(&context[1], algos))
    TEST_FAIL("ctx init\n");

  unsigned i;
  unsigned done_count[2] = { 0, 0 };
  uint_fast8_t started = 0;
  struct assh_channel_s *ch[2];

  fprintf(stderr, "%u: %s (%s), %s, %s, %s, %s\n", seed,
	  assh_algo_name(&ka->algo_wk.algo), ka->algo_wk.algo.implem,
	  assh_algo_name(&sa->algo_wk.algo),
	  assh_algo_name(&ca->algo), assh_algo_name(&ma->algo),
	  assh_algo_name(&cpa->algo));

  for (i = 0; i < 2; i++)
    {
      struct assh_context_s *c = &context[i];

      fifo_init(&fifo[i]);

      if (assh_service_register_va(c, &assh_service_connection, NULL))
	TEST_FAIL("service register\n");

      if (i == 0 && sign_key->key_algo != NULL)
	{
	  do {
	  const uint8_t *key_blob = sign_key->key_blob + 1;
	  if (asshh_key_load(c, &c->keys,
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
	  if (asshh_key_load(c, &c->keys,
			    kex_key->key_algo, ASSH_ALGO_KEX, kex_key->key_blob[0],
			    &key_blob, kex_key->key_size))
	    {
	      if (alloc_fuzz)
		continue;
	      TEST_FAIL("kex key load\n");
	    }
	  } while (0);
	}

      if (assh_session_init(c, &session[i]) ||
	  assh_kex_set_threshold(&session[i], 1024 + assh_prng_rand() % 1024))
	TEST_FAIL("sessions init");

      assh_userauth_done(&session[i]);
      assh_cipher_fuzz_initreg(c, &session[i]);
    }

  uint_fast8_t stall = 0;

  char data[256];
  for (i = 0; i < sizeof(data); i++)
    data[i] = assh_prng_rand();

  while (done_count[0] < cycles &&
	 done_count[1] < cycles)
    {
      for (i = 0; i < 2; i++)
	{
	  struct assh_event_s event;

	  ASSH_DEBUG("=== session %u %u ===\n", i, stall);

	  if ((started >> i) & 1)
	    {
	      size_t size = assh_prng_rand() % sizeof(data);
	      assh_channel_data(ch[i], (const uint8_t*)data, &size);
	    }

	  if (!assh_event_get(&session[i], &event, 0))
	    {
	      if (!packet_fuzz)
		TEST_FAIL("seed %u, event_get %u terminated\n", seed, i);
	      else
		goto done;
	    }

	  switch (event.id)
	    {
	    case ASSH_EVENT_CHANNEL_FAILURE:
	    case ASSH_EVENT_SESSION_ERROR:
	      if (packet_fuzz || alloc_fuzz)
		goto done;
	      TEST_FAIL("seed %u, error %u %lx\n", seed, i,
			event.session.error.code);
	      break;

	    case ASSH_EVENT_KEX_HOSTKEY_LOOKUP:
	      assert(i == 1);
	      event.kex.hostkey_lookup.accept = 1;
	      kex_hostkey_lookup_count++;
	      break;

	    case ASSH_EVENT_KEX_DONE:
	      ASSH_DEBUG("kex safety %u: %u\n", i, event.kex.done.safety);
	      if (event.kex.done.initial != !done_count[i])
		TEST_FAIL("seed %u, kex done initial\n", seed);
	      if (!event.kex.done.initial)
		kex_rekex_count++;
	      done_count[i]++;
	      if (i)
		kex_client_done_count++;
	      else
		kex_server_done_count++;
	      break;

            case ASSH_EVENT_SERVICE_START:
              if (event.service.start.srv == &assh_service_connection)
		while (assh_channel_open(&session[i], "test", 4, NULL, 0, -1, -1, &ch[i]))
		  ;
	      break;

	    case ASSH_EVENT_CHANNEL_OPEN:
	      event.connection.channel_open.reply = ASSH_CONNECTION_REPLY_SUCCESS;
	      break;

	    case ASSH_EVENT_CHANNEL_CONFIRMATION:
	      started |= 1 << i;
	      break;

	    case ASSH_EVENT_CHANNEL_DATA:
	      event.connection.channel_data.transferred =
		event.connection.channel_data.data.size;
	      break;

	    case ASSH_EVENT_READ:
	      if (fifo_rw_event(fifo, &event, i))
		stall++;
	      break;

	    case ASSH_EVENT_WRITE:
	      stall++;
	      if (!fifo_rw_event(fifo, &event, i))
		stall = 0;
	      break;

	    default:
	      ASSH_DEBUG("event %u not handled\n", event.id);
	    }

	  assh_event_done(&session[i], &event, ASSH_OK);

	  if (stall >= 100)
	    {
	      /* packet exchange is stalled, hopefully due to a fuzzing error */
	      if (!packet_fuzz)
		TEST_FAIL("seed %u, stalled %u\n", seed, i);
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

static assh_status_t
algo_lookup(enum assh_algo_class_e cl, const char *name,
	    const char *variant, const struct assh_algo_s **algo)
{
  assh_status_t r = test_algo_lookup(cl, name, variant, NULL, algo);

  if (r)
    {
      if (variant)
	fprintf(stderr, "  %s (%s) not supported\n", name, variant);
      else
	fprintf(stderr, "  %s not supported\n", name);
    }

  return r;
}

static assh_bool_t test_loop_2(unsigned int seed,
			       const struct assh_algo_kex_s *ka,
			       const struct algo_with_key_s *kex,
			       const struct algo_with_key_s *sign,
			       const char **cipher,
			       const char **mac,
			       const char **comp,
			       unsigned cycles)
{
  const struct algo_with_key_s *sign_list = sign;
  const char **cipher_list = cipher;
  const char **mac_list = mac;
  assh_bool_t kex_done = 0;

  while (*comp)
    {
      const struct assh_algo_compress_s *cpa;

      if ((!comp_filter || strstr(*comp, comp_filter)) &&
	  !algo_lookup(ASSH_ALGO_COMPRESS, *comp, NULL,
		       (const struct assh_algo_s **)&cpa))

	while (*mac)
	  {
	    const struct assh_algo_mac_s *ma;

	    if ((!mac_filter || strstr(*mac, mac_filter)) &&
		!algo_lookup(ASSH_ALGO_MAC, *mac, NULL,
			     (const struct assh_algo_s **)&ma))
	      while (*cipher)
		{
		  const struct assh_algo_cipher_s *ca;

		  if ((!cipher_filter || strstr(*cipher, cipher_filter)) &&
		      !algo_lookup(ASSH_ALGO_CIPHER, *cipher, NULL,
				   (const struct assh_algo_s **)&ca))

		    while (sign->algo)
		      {
			const struct assh_algo_sign_s *sa;

			if ((!sign_filter || strstr(sign->algo, sign_filter)) &&
			    !algo_lookup(ASSH_ALGO_SIGN, sign->algo, sign->variant,
					 (const struct assh_algo_s **)&sa))
			  {
			    assh_prng_seed(seed);
			    kex_done = 1;
			    test(ka, sa, ca, ma, cpa,
				 kex, sign, seed, cycles);
			  }
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

  return kex_done;
}

void test_loop(unsigned int seed,
	       const struct algo_with_key_s *kex,
	       const struct algo_with_key_s *sign,
	       const char **cipher,
	       const char **mac,
	       const char **comp,
	       unsigned cycles)
{
  const struct assh_algo_kex_s *ka;

  while (kex->algo)
    {
      if (!strcmp(kex->algo, "none@libassh.org"))
	{
	  test_loop_2(seed, &assh_kex_none, kex, sign, cipher, mac, comp, cycles);
	}
      else
	{
	  assh_bool_t kex_done = 0;
	  const struct assh_algo_s **a;

	  for (a = assh_algo_table; *a; a++)
	    {
	      if (!assh_algo_name_match(*a, ASSH_ALGO_KEX,
					kex->algo, strlen(kex->algo)))
		continue;
	      ka = (const void*)*a;

	      if (kex_filter && !strstr(kex->algo, kex_filter))
		continue;

	      if (kex->variant && (!ka->algo_wk.algo.variant ||
				   strcmp(kex->variant, ka->algo_wk.algo.variant)))
		continue;

	      kex_done |= test_loop_2(seed, ka, kex, sign, cipher, mac, comp, cycles);
	    }

	  if (!kex_done)
	    fprintf(stderr, "  %s skipped, not supported\n", kex->algo);
	}

      kex++;
    }
}

static void usage()
{
  fprintf(stderr, "usage: kex [options]\n");

  fprintf(stderr,
	  "Options:\n\n"

	  "    -h         show help\n"
	  "    -t         run non-fuzzing tests\n"
	  "    -a         run memory allocator fuzzing tests\n"
	  "    -p         run packet corruption fuzzing tests\n"
	  "    -f         run more fuzzing tests\n"
	  "    -m         test more algorithm variants (slow)\n"
	  "    -K substr  filter by key-exchange algo name\n"
	  "    -S substr  filter by signature algo name\n"
	  "    -C substr  filter by cipher algo name\n"
	  "    -M substr  filter by mac algo name\n"
	  "    -P substr  filter by compression algo name\n"
	  "    -c count   set number of test passes (default 100)\n"
	  "    -s seed    set initial seed (default: time(0))\n"
	  );
}

int main(int argc, char **argv)
{
  if (assh_deps_init())
    return -1;

  enum action_e {
    ACTION_NOFUZZING = 1,
    ACTION_PACKET_FUZZ = 2,
    ACTION_ALLOC_FUZZ = 4,
    ACTION_ALL_FUZZ = 8
  };

  enum action_e action = 0;
  unsigned int count = 0;
  unsigned int seed = time(0);
  assh_bool_t slow = 0;
  int opt;

  while ((opt = getopt(argc, argv, "tpafhms:c:K:S:C:M:P:")) != -1)
    {
      switch (opt)
	{
	case 't':
	  action |= ACTION_NOFUZZING;
	  break;
	case 'p':
	  action |= ACTION_PACKET_FUZZ;
	  if (!count)
	    count = 50;
	  break;
	case 'a':
	  action |= ACTION_ALLOC_FUZZ;
	  if (!count)
	    count = 50;
	  break;
	case 'f':
	  action |= ACTION_ALL_FUZZ;
	  if (!count)
	    count = 50;
	  break;
	case 's':
	  seed = atoi(optarg);
	  break;
	case 'm':
	  slow = 1;
	  break;
	case 'c':
	  count = atoi(optarg);
	  break;
	case 'K':
	  kex_filter = optarg;
	  break;
	case 'S':
	  sign_filter = optarg;
	  break;
	case 'C':
	  cipher_filter = optarg;
	  break;
	case 'M':
	  mac_filter = optarg;
	  break;
	case 'P':
	  comp_filter = optarg;
	  break;
	case 'h':
	  usage();
	default:
	  return 1;
	}
    }

  if (!action)
    action = ACTION_NOFUZZING;
  if (!count)
    count++;

  unsigned int k;

  for (k = 0; k < count; k++)
    {
      unsigned s = seed + k;

      /* run some sessions, use various algorithms */
      if (action & ACTION_NOFUZZING)
	{
	  alloc_fuzz = 0;
	  packet_fuzz = 0;

	  /* test cipher and mac */
	  test_loop(s, kex_list_short, sign_list_short, cipher_list_long, mac_list_long, comp_list_short, 2);
	  /* test compression */
	  test_loop(s, kex_list_short, sign_list_short, cipher_list_short, mac_list_short, comp_list_long, 2);
	  /* test sign */
	  test_loop(s, kex_list_all, sign_list_long, cipher_list_short, mac_list_short, comp_list_short, 2);
	  /* test kex */
	  if (slow)
	    test_loop(s, kex_list_slow, sign_list_short, cipher_list_short, mac_list_short, comp_list_short, 2);
	  else
	    test_loop(s, kex_list_long, sign_list_short, cipher_list_short, mac_list_short, comp_list_short, 2);
	}

      /* run some more sessions with some packet error */
      if (action & ACTION_PACKET_FUZZ)
	{
	  alloc_fuzz = 0;
	  packet_fuzz = 10 + assh_prng_rand() % 1024;

	  /* fuzz compression parsing */
	  test_loop(s, kex_list_short, sign_list_short, cipher_list_fuzz, mac_list_fuzz, comp_list_long, 4);
	  /* fuzz signature parsing */
	  test_loop(s, kex_list_short, sign_list_long, cipher_list_fuzz, mac_list_fuzz, comp_list_short, 4);
	  /* fuzz kex parsing */
	  if (slow)
	    test_loop(s, kex_list_slow, sign_list_short, cipher_list_fuzz, mac_list_fuzz, comp_list_short, 4);
	  else
	    test_loop(s, kex_list_long, sign_list_short, cipher_list_fuzz, mac_list_fuzz, comp_list_short, 4);
	}

      /* run some more sessions with some allocation fails */
      if (action & ACTION_ALLOC_FUZZ)
	{
	  alloc_fuzz = 4 + assh_prng_rand() % 128;
	  packet_fuzz = 0;

	  /* fuzz cipher and mac allocation */
	  test_loop(s, kex_list_short, sign_list_short, cipher_list_long, mac_list_long, comp_list_short, 4);
	  /* fuzz compression allocation */
	  test_loop(s, kex_list_short, sign_list_short, cipher_list_short, mac_list_short, comp_list_long, 4);
	  /* fuzz kex and sign allocation */
	  test_loop(s, kex_list_all, sign_list_all, cipher_list_short, mac_list_short, comp_list_short, 4);
	}

      if (action & ACTION_ALL_FUZZ)
	{
	  alloc_fuzz = 64 + assh_prng_rand() % 64;
	  packet_fuzz = 512 + assh_prng_rand() % 512;

	  /* fuzz compression parsing */
	  test_loop(s, kex_list_short, sign_list_short, cipher_list_fuzz, mac_list_fuzz, comp_list_long, 4);
	  /* fuzz signature parsing */
	  test_loop(s, kex_list_short, sign_list_long, cipher_list_fuzz, mac_list_fuzz, comp_list_short, 4);
	  /* fuzz kex parsing */
	  if (slow)
	    test_loop(s, kex_list_slow, sign_list_short, cipher_list_fuzz, mac_list_fuzz, comp_list_short, 4);
	  else
	    test_loop(s, kex_list_long, sign_list_short, cipher_list_fuzz, mac_list_fuzz, comp_list_short, 4);
	}
    }

  fprintf(stderr, "\nSummary:\n"
	      "  %8lu client kex done\n"
	      "  %8lu server kex done\n"
	      "  %8lu client host key lookup\n"
	      "  %8lu re-kex\n"
	      ,
	      kex_client_done_count,
	      kex_server_done_count,
	      kex_hostkey_lookup_count,
	      kex_rekex_count
	  );

  if (action & (ACTION_PACKET_FUZZ | ACTION_ALLOC_FUZZ | ACTION_ALL_FUZZ))
    fprintf(stderr, "\nFuzzing:\n"
	      "  %8lu fuzz packet bit errors\n"
	      "  %8lu fuzz memory allocation fails\n"
	      ,
	      packet_fuzz_bits,
	      alloc_fuzz_fails
	  );

  return 0;
}

