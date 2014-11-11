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
#include <assh/assh_hash.h>
#include <assh/assh_context.h>

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef CONFIG_ASSH_USE_GCRYPT
# include <gcrypt.h>
#endif

#define BUFSIZE 4096

struct hash_test_s
{
  const struct assh_hash_algo_s *algo;
  size_t out_len;
  const char *out;
};

const struct hash_test_s tests[] =
  {
    { &assh_hash_md5, 16,
      "\x4e\x96\xb1\x70\x21\x78\x3f\x29\x74\x27\x3c\x05\xc8\x2b\x9b\xcf" },
    { &assh_hash_sha1, 20,
      "\xfb\x37\x24\x77\x87\x08\x8f\x13\xff\x19\x5b\xb1\xae\x86\x56\x3a"
      "\xd2\x06\x49\xec" },
    { &assh_hash_sha224, 28,
      "\x47\x9e\xf7\xb2\xf3\xcd\xe6\x90\xa6\x95\xaf\xe9\x31\x78\xc2\x55"
      "\x96\x6f\x71\x2e\x58\x51\x14\x38\xc3\x77\x4d\x14" },
    { &assh_hash_sha256, 32,
      "\x0a\x4e\xe8\x76\xe8\x43\xe0\x78\xc2\x05\x38\xf3\x2e\xb8\xdc\x46"
      "\xc0\xac\x8c\x3a\x5b\x5d\xa2\x81\x26\x85\x49\x61\x5e\x6d\xaf\x2b" },
    { &assh_hash_sha384, 48,
      "\xb4\x70\x30\xce\xdd\xf1\xf5\x55\x45\x4d\x6e\xfc\xa8\x40\xb4\x21"
      "\x92\xff\xc1\x32\x10\xe1\x1f\x49\x73\x8c\xa7\x04\x65\x6e\x9b\x2e"
      "\xa9\xa2\xd9\x0f\xe2\xb4\x9f\x1e\xab\xc4\xdb\x49\x74\x50\xee\x14" },
    { &assh_hash_sha512, 64,
      "\x42\xf4\xc6\xcc\xb3\xf6\x0e\x0e\x35\xc1\x75\x6c\x6b\xba\x3c\x89"
      "\x84\x23\xdf\x8e\x33\x15\x09\xaf\x04\xf3\xd6\x06\x14\x41\xb0\x06"
      "\xb3\x33\x1d\x41\x76\x07\xbf\x04\x65\x35\x5b\x64\x32\xd9\xf9\x8a"
      "\xc9\x0f\x0b\x29\xaa\xaa\x0d\xa2\x2f\xdf\xad\x85\xb6\xed\x29\xf1" },
    { 0 }
  };

int
main(int argc, char **argv)
{
  uint_fast8_t err = 0;

  struct assh_context_s context;

#ifdef CONFIG_ASSH_USE_GCRYPT
  if (!gcry_check_version(GCRYPT_VERSION))
    return -1;
#endif

  assh_context_init(&context, ASSH_SERVER);

  uint_fast8_t i;
  for (i = 0; tests[i].algo != NULL; i++)
    {
      const struct assh_hash_algo_s *algo = tests[i].algo;

      uint8_t buf[BUFSIZE];
      memset(buf, 42, sizeof(buf));

      void *ctx = malloc(algo->ctx_size);
      void *ctx2 = malloc(algo->ctx_size);

      fprintf(stderr, "testing %s\n", algo->name);

      size_t hash_size = tests[i].out_len;
#if 0
      assh_hash_init(&context, ctx, algo);
      assh_hash_final(ctx, buf, hash_size);
      assh_hexdump("empty", buf, hash_size);
      assh_hash_cleanup(ctx);

      assh_hash_init(&context, ctx, algo);
      assh_hash_update(ctx, "abc", 3);
      assh_hash_final(ctx, buf, hash_size);
      assh_hexdump("abc", buf, hash_size);
      assh_hash_cleanup(ctx);
#endif

      uint_fast16_t j;
      for (j = 0; j <= BUFSIZE; j++)
	{
	  if (assh_hash_init(&context, ctx, algo))
	    {
	      err++;
	      break;
	    }
	  assh_hash_update(ctx, buf, j);

	  if (j == BUFSIZE / 2)
	    {
	      if (assh_hash_copy(ctx2, ctx))
		{
		  err++;
		  assh_hash_cleanup(ctx);
		  break;
		}
	      assh_hash_cleanup(ctx);
	      void *tmp = ctx;
	      ctx = ctx2;
	      ctx2 = tmp;
	    }

	  assh_hash_update(ctx, buf, j);
	  assh_hash_final(ctx, buf, hash_size);
	  assh_hash_cleanup(ctx);
	}

      free(ctx);
      free(ctx2);

      if (memcmp(buf, tests[i].out, hash_size))
	{
	  assh_hexdump("hash result", buf, hash_size);
	  assh_hexdump("expected   ", tests[i].out, hash_size);
	  err++;
	}
    }  

  return err > 0;
}

