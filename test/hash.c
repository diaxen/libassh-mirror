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
  const struct assh_hash_s *algo;
  const char *out;
};

const struct hash_test_s tests[] =
  {
    { &assh_hash_md5,
      "\x4e\x96\xb1\x70\x21\x78\x3f\x29\x74\x27\x3c\x05\xc8\x2b\x9b\xcf" },
    { &assh_hash_sha1,
      "\xfb\x37\x24\x77\x87\x08\x8f\x13\xff\x19\x5b\xb1\xae\x86\x56\x3a\xd2\x06\x49\xec" },
    { &assh_hash_sha224,
      "\x47\x9e\xf7\xb2\xf3\xcd\xe6\x90\xa6\x95\xaf\xe9\x31\x78\xc2\x55\x96\x6f\x71\x2e\x58\x51\x14\x38\xc3\x77\x4d\x14" },
    { &assh_hash_sha256,
      "\x0a\x4e\xe8\x76\xe8\x43\xe0\x78\xc2\x05\x38\xf3\x2e\xb8\xdc\x46\xc0\xac\x8c\x3a\x5b\x5d\xa2\x81\x26\x85\x49\x61\x5e\x6d\xaf\x2b" },
    { &assh_hash_sha384,
      "\xa6\x2b\x38\x14\x5b\x1a\x92\x7e\xc6\x64\x1e\x12\xce\x80\x49\xbc\x37\x1f\xf1\x28\xb6\x75\x66\x0e\x81\x42\xb6\xf3\x00\xe9\x95\x0b\x93\xc2\x16\x2e\x3f\x38\x6c\xc1\xf7\x85\xea\x9c\xa9\x20\x6a\xa9\x8f\x25\xaf\xd3\x28\x33\x2e\xda" },
    { &assh_hash_sha512,
      "\x42\xf4\xc6\xcc\xb3\xf6\x0e\x0e\x35\xc1\x75\x6c\x6b\xba\x3c\x89\x84\x23\xdf\x8e\x33\x15\x09\xaf\x04\xf3\xd6\x06\x14\x41\xb0\x06\xb3\x33\x1d\x41\x76\x07\xbf\x04\x65\x35\x5b\x64\x32\xd9\xf9\x8a\xc9\x0f\x0b\x29\xaa\xaa\x0d\xa2\x2f\xdf\xad\x85\xb6\xed\x29\xf1" },
    { 0 }
  };


int
main(int argc, char **argv)
{
  uint_fast8_t err = 0;

#ifdef CONFIG_ASSH_USE_GCRYPT
  if (!gcry_check_version(GCRYPT_VERSION))
    return -1;
#endif

  uint_fast8_t i;
  for (i = 0; tests[i].algo != NULL; i++)
    {
      const struct assh_hash_s *algo = tests[i].algo;

      uint8_t buf[BUFSIZE];
      memset(buf, 42, sizeof(buf));

      void *ctx = malloc(algo->ctx_size);
      void *ctx2 = malloc(algo->ctx_size);

      fprintf(stderr, "testing %s\n", algo->name);

      uint_fast16_t j;
      for (j = 0; j <= BUFSIZE; j++)
	{
	  if (algo->f_init(ctx))
	    {
	      err++;
	      break;
	    }
	  algo->f_update(ctx, buf, j);

	  if (j == BUFSIZE / 2)
	    {
	      if (algo->f_copy(ctx2, ctx))
		{
		  err++;
		  algo->f_final(ctx, NULL);
		  break;
		}
	      algo->f_final(ctx, NULL);
	      void *tmp = ctx;
	      ctx = ctx2;
	      ctx2 = tmp;
	    }

	  algo->f_update(ctx, buf, j);
	  algo->f_final(ctx, buf);
	}

      free(ctx);
      free(ctx2);

      if (memcmp(buf, tests[i].out, algo->hash_size))
	{
	  assh_hexdump("hash result", buf, algo->hash_size);
	  assh_hexdump("expected   ", tests[i].out, algo->hash_size);
	  err++;
	}
    }  

  return err > 0;
}

