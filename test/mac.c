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

#include <assh/assh.h>
#include <assh/assh_mac.h>
#include <assh/assh_context.h>

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "test.h"
#include "leaks_check.h"

struct mac_test_s
{
  const struct assh_algo_mac_s *algo;
  const char *key;
  const char *in;
  const char *out;
  uint32_t seq;
  uint_fast8_t in_size;
  uint_fast8_t key_size;
  uint_fast8_t mac_size;
};

const struct mac_test_s vectors[] =
{
  { .algo = &assh_hmac_md5,
    .in_size = 16, .seq = 42,
    .key_size = 16, .mac_size = 16,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x14\xe6\x64\x01\xdd\x34\x89\xa7\xc6\x33\x2d\xed\x75\x46\x88\xc1"
  },

  { .algo = &assh_hmac_md5,
    .in_size = 112, .seq = 42,
    .key_size = 16, .mac_size = 16,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\xa2\x89\x6a\x6b\x5d\xa3\x44\xee\xee\x84\x1e\x8a\xeb\xa4\xd8\x5d"
  },

  { .algo = &assh_hmac_md5_etm,
    .in_size = 16, .seq = 42,
    .key_size = 16, .mac_size = 16,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x14\xe6\x64\x01\xdd\x34\x89\xa7\xc6\x33\x2d\xed\x75\x46\x88\xc1"
  },

  { .algo = &assh_hmac_md5_etm,
    .in_size = 112, .seq = 42,
    .key_size = 16, .mac_size = 16,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\xa2\x89\x6a\x6b\x5d\xa3\x44\xee\xee\x84\x1e\x8a\xeb\xa4\xd8\x5d"
  },

  { .algo = &assh_hmac_md5_96,
    .in_size = 16, .seq = 42,
    .key_size = 16, .mac_size = 12,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x14\xe6\x64\x01\xdd\x34\x89\xa7\xc6\x33\x2d\xed"
  },

  { .algo = &assh_hmac_md5_96,
    .in_size = 112, .seq = 42,
    .key_size = 16, .mac_size = 12,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\xa2\x89\x6a\x6b\x5d\xa3\x44\xee\xee\x84\x1e\x8a"
  },

  { .algo = &assh_hmac_md5_96_etm,
    .in_size = 16, .seq = 42,
    .key_size = 16, .mac_size = 12,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x14\xe6\x64\x01\xdd\x34\x89\xa7\xc6\x33\x2d\xed"
  },

  { .algo = &assh_hmac_md5_96_etm,
    .in_size = 112, .seq = 42,
    .key_size = 16, .mac_size = 12,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\xa2\x89\x6a\x6b\x5d\xa3\x44\xee\xee\x84\x1e\x8a"
  },

  { .algo = &assh_hmac_sha1,
    .in_size = 16, .seq = 42,
    .key_size = 20, .mac_size = 20,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x18\x02\x78\xa5\x98\xac\x9e\x0a\xa0\xee\x2c\xca\x29\x2e\x44\x1d\xa2\x4b\xb3\xdf"
  },

  { .algo = &assh_hmac_sha1,
    .in_size = 112, .seq = 42,
    .key_size = 20, .mac_size = 20,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x38\xbd\x2b\x11\xa0\x49\xa4\x56\xab\xef\x3d\x57\x27\xf8\xf7\x33\x09\x29\xd7\x6f"
  },

  { .algo = &assh_hmac_sha1_etm,
    .in_size = 16, .seq = 42,
    .key_size = 20, .mac_size = 20,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x18\x02\x78\xa5\x98\xac\x9e\x0a\xa0\xee\x2c\xca\x29\x2e\x44\x1d\xa2\x4b\xb3\xdf"
  },

  { .algo = &assh_hmac_sha1_etm,
    .in_size = 112, .seq = 42,
    .key_size = 20, .mac_size = 20,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x38\xbd\x2b\x11\xa0\x49\xa4\x56\xab\xef\x3d\x57\x27\xf8\xf7\x33\x09\x29\xd7\x6f"
  },

  { .algo = &assh_hmac_sha1_96,
    .in_size = 16, .seq = 42,
    .key_size = 20, .mac_size = 12,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x18\x02\x78\xa5\x98\xac\x9e\x0a\xa0\xee\x2c\xca"
  },

  { .algo = &assh_hmac_sha1_96,
    .in_size = 112, .seq = 42,
    .key_size = 20, .mac_size = 12,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x38\xbd\x2b\x11\xa0\x49\xa4\x56\xab\xef\x3d\x57"
  },

  { .algo = &assh_hmac_sha1_96_etm,
    .in_size = 16, .seq = 42,
    .key_size = 20, .mac_size = 12,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x18\x02\x78\xa5\x98\xac\x9e\x0a\xa0\xee\x2c\xca"
  },

  { .algo = &assh_hmac_sha1_96_etm,
    .in_size = 112, .seq = 42,
    .key_size = 20, .mac_size = 12,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x38\xbd\x2b\x11\xa0\x49\xa4\x56\xab\xef\x3d\x57"
  },

  { .algo = &assh_hmac_sha256,
    .in_size = 16, .seq = 42,
    .key_size = 32, .mac_size = 32,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x78\xf4\x74\xfb\xf0\x9b\x08\x0a\x91\xb7\x40\xb4\x9b\xbc\x31\x6a"
    "\x16\xb9\xdd\xf3\x8b\x63\xb3\x25\x84\xac\x41\xbb\x27\xa1\x47\xda"
  },

  { .algo = &assh_hmac_sha256,
    .in_size = 112, .seq = 42,
    .key_size = 32, .mac_size = 32,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x6d\xe6\x0c\x48\x99\x1d\xab\x58\x0e\x9b\x8d\x52\x53\x27\xd9\x15"
    "\x81\xbb\xae\x86\x50\x65\x58\x0e\x97\xab\x98\x90\x56\x5c\x9b\x2d"
  },

  { .algo = &assh_hmac_sha256_etm,
    .in_size = 16, .seq = 42,
    .key_size = 32, .mac_size = 32,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x78\xf4\x74\xfb\xf0\x9b\x08\x0a\x91\xb7\x40\xb4\x9b\xbc\x31\x6a"
    "\x16\xb9\xdd\xf3\x8b\x63\xb3\x25\x84\xac\x41\xbb\x27\xa1\x47\xda"
  },

  { .algo = &assh_hmac_sha256_etm,
    .in_size = 112, .seq = 42,
    .key_size = 32, .mac_size = 32,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x6d\xe6\x0c\x48\x99\x1d\xab\x58\x0e\x9b\x8d\x52\x53\x27\xd9\x15"
    "\x81\xbb\xae\x86\x50\x65\x58\x0e\x97\xab\x98\x90\x56\x5c\x9b\x2d"
  },

  { .algo = &assh_hmac_sha512,
    .in_size = 16, .seq = 42,
    .key_size = 64, .mac_size = 64,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x57\x39\xb5\x82\x92\x46\x5c\x36\x20\x50\x0b\xef\x28\xbd\xf4\x0f"
    "\xa0\xef\xb7\x68\xf8\x01\x94\x56\x19\x2e\xf6\x5b\xe5\x36\x7d\x9d"
    "\xea\x55\xe5\x38\xc0\x18\xea\xda\xa6\x0c\x11\x55\x1b\xc0\x39\x5d"
    "\xb8\x37\x19\x5e\x91\x3b\x87\x0d\x97\x4e\x8b\x3e\x95\xd8\xa1\x7b"
  },

  { .algo = &assh_hmac_sha512,
    .in_size = 216, .seq = 42,
    .key_size = 64, .mac_size = 64,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x50\xbb\xa6\x50\x3e\xef\xaf\x94\x5d\x78\x6c\xb4\x92\x00\xb9\xa4"
    "\x7d\x48\x2f\x34\xf8\x93\xa5\x23\x1b\x3a\x70\x37\xd5\x89\xf9\xad"
    "\x6b\x95\x7a\x4c\x51\x4f\xe1\x3b\x44\x25\xf4\x45\x87\xce\x92\x3e"
    "\x7d\xd9\x83\x01\x6b\x72\xf0\x77\x53\xa1\xb0\x3b\xc5\xec\xe7\xca"
  },

  { .algo = &assh_hmac_sha512_etm,
    .in_size = 16, .seq = 42,
    .key_size = 64, .mac_size = 64,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x57\x39\xb5\x82\x92\x46\x5c\x36\x20\x50\x0b\xef\x28\xbd\xf4\x0f"
    "\xa0\xef\xb7\x68\xf8\x01\x94\x56\x19\x2e\xf6\x5b\xe5\x36\x7d\x9d"
    "\xea\x55\xe5\x38\xc0\x18\xea\xda\xa6\x0c\x11\x55\x1b\xc0\x39\x5d"
    "\xb8\x37\x19\x5e\x91\x3b\x87\x0d\x97\x4e\x8b\x3e\x95\xd8\xa1\x7b"
  },

  { .algo = &assh_hmac_sha512_etm,
    .in_size = 216, .seq = 42,
    .key_size = 64, .mac_size = 64,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x50\xbb\xa6\x50\x3e\xef\xaf\x94\x5d\x78\x6c\xb4\x92\x00\xb9\xa4"
    "\x7d\x48\x2f\x34\xf8\x93\xa5\x23\x1b\x3a\x70\x37\xd5\x89\xf9\xad"
    "\x6b\x95\x7a\x4c\x51\x4f\xe1\x3b\x44\x25\xf4\x45\x87\xce\x92\x3e"
    "\x7d\xd9\x83\x01\x6b\x72\xf0\x77\x53\xa1\xb0\x3b\xc5\xec\xe7\xca"
  },

#ifdef CONFIG_ASSH_HASH_RIPEMD160
  { .algo = &assh_hmac_ripemd160,
    .in_size = 16, .seq = 42,
    .key_size = 20, .mac_size = 20,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\xcb\x0b\x2b\x22\x7a\xb6\x49\x13\xea\xf8\xce\xfd\xf1\x9f\x02\x8b\x81\xba\xd4\xd5"
  },

  { .algo = &assh_hmac_ripemd160_etm,
    .in_size = 16, .seq = 42,
    .key_size = 20, .mac_size = 20,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\xcb\x0b\x2b\x22\x7a\xb6\x49\x13\xea\xf8\xce\xfd\xf1\x9f\x02\x8b\x81\xba\xd4\xd5"
  },
#endif

  { 0 }
};

int
main(int argc, char **argv)
{
  if (assh_deps_init())
    return -1;

  struct assh_context_s context;

  uint_fast8_t i;
  for (i = 0; vectors[i].algo != NULL; i++)
    {
      if (assh_context_init(&context, ASSH_CLIENT_SERVER, assh_leaks_allocator,
			    NULL, NULL, NULL))
	TEST_FAIL("context init");

      const struct mac_test_s *t = &vectors[i];
      const struct assh_algo_mac_s *algo = t->algo;

      if (t->key_size != algo->key_size)
	TEST_FAIL("key size");
      if (t->mac_size != algo->mac_size)
	TEST_FAIL("mac size");

      size_t in_size = t->in_size;
      size_t out_size = t->mac_size;
      uint32_t seq = t->seq;

      uint8_t *in;

      if (t->in != NULL)
	{
	  /* use static input data */
	  in = (uint8_t *)t->in;
	}
      else
	{
	  /* use randomly generated input */
	  in = malloc(in_size);
	  uint64_t seed = t->seq;
	  for (unsigned i = 0; i < in_size; i++)
	    in[i] = assh_prng_rand_seed(&seed);
	}

      uint8_t out[out_size];
      memset(out, 0, out_size);

      void *ctx = malloc(algo->ctx_size);

      fprintf(stderr, "testing %s (%zu bytes): ", assh_algo_name(&algo->algo), in_size);

      if (algo->f_init(&context, ctx, (const uint8_t*)t->key))
	TEST_FAIL("compute init");

      fprintf(stderr, "C");
      if (algo->f_compute(ctx, seq, in, in_size, out))
	TEST_FAIL("compute %u", i);

      if (memcmp(out, t->out, out_size))
	{
	  assh_hexdump("output", out, out_size);
	  assh_hexdump("expected", t->out, out_size);
	  TEST_FAIL("mac wrong output %u", i);
	}

      fprintf(stderr, "1");
      if (algo->f_check(ctx, seq, in, in_size, out))
	TEST_FAIL("check good %u", i);

      fprintf(stderr, "t");
      out[rand() % out_size] ^= 1 << (rand() % 8);

      fprintf(stderr, "2");
      if (!algo->f_check(ctx, seq, in, in_size, out))
	TEST_FAIL("check wrong %u", i);

      if (t->in == NULL)
	{
	  fprintf(stderr, "T");
	  in[rand() % in_size] ^= 1 << (rand() % 8);

	  fprintf(stderr, "3");
	  if (!algo->f_check(ctx, seq, in, in_size, (const uint8_t*)t->out))
	    TEST_FAIL("check wrong %u", i);

	  fprintf(stderr, "c");
	  if (algo->f_compute(ctx, seq, in, in_size, out))
	    TEST_FAIL("compute %u", i);

	  if (!memcmp(out, t->out, out_size))
	    {
	      assh_hexdump("output", out, out_size);
	      assh_hexdump("expected", t->out, out_size);
	      TEST_FAIL("mac good output %u", i);
	    }
	}

      fprintf(stderr, "\n");

      if (t->in == NULL)
	free(in);

      algo->f_cleanup(&context, ctx);
      free(ctx);

      assh_context_cleanup(&context);

      if (alloc_size != 0)
	TEST_FAIL("memory leak detected, %zu bytes allocated\n", alloc_size);
    }

  return 0;
}
