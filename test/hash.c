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
    { &assh_hash_sha3_256, 32,
      "\x51\x77\x0d\x82\xd4\x3a\x65\x75\x4d\x87\x64\xc4\xb3\xdd\xa8\x14"
      "\xa3\xc5\x92\x72\x13\x9d\x5a\x42\x47\xa1\x4d\xc5\x04\xa9\xaa\xa8" },
    { &assh_hash_sha3_512, 64,
      "\x48\x1e\x9c\x40\x93\xb5\xf4\x6f\xb8\x2c\xeb\xc7\x06\x43\x18\x5d"
      "\x14\x32\xe2\xfd\xdb\x73\x34\x99\x96\x30\x00\xcd\xbb\x11\x4b\xe6"
      "\xe4\x06\xd5\x26\xec\x2b\x29\xef\xc1\x28\x34\xa5\x5f\x24\xfb\x01"
      "\x28\x6d\xac\x01\x46\x73\xb2\xe8\xdf\x97\x97\x4e\x78\x38\xf9\xa4" },
    { &assh_hash_shake_128, 200,
      "\x6c\x72\x38\x7a\x20\xf7\xd3\xd9\x9f\xb2\xb1\xcd\xb9\x0e\x92\xb0"
      "\xe9\x71\x32\xa6\x83\x02\xcb\xc1\xe0\x1b\xb7\x42\xdb\x4f\xc3\x67"
      "\x0a\xc3\xf8\xe2\x39\xa3\x8a\xc8\xa4\x53\xf9\x0c\xc7\x72\x06\x20"
      "\xc9\xf2\x12\x3b\xae\xbe\x00\x6c\x61\xda\xa9\x8f\xa3\x7f\xdb\x14"
      "\xfe\x25\xa3\xd8\xb3\x68\xb4\xd9\xba\x26\x8e\x99\x7c\xe3\xbc\x39"
      "\x17\x0d\x80\xe2\xc7\x79\x06\x7c\xfb\xbc\x20\xb4\x66\x68\xef\xd5"
      "\x45\x00\x1c\x9f\x6b\xdf\xda\xbc\x93\xdc\x48\x10\x3c\xd3\xdf\xe6"
      "\x64\xcb\x1d\x1b\x08\x67\x9d\x8d\x9c\xac\x04\xb0\xbc\x91\x16\x21"
      "\x5d\x6f\xcc\x7e\x1f\x91\xc4\x06\xa1\xe7\x12\x7c\x6d\x70\xbe\x7b"
      "\xee\x7a\xc6\x57\x07\x73\xf5\x9c\x7e\x27\x6e\x04\x9c\x02\xf6\x0e"
      "\xa0\x46\xae\x9a\xce\x45\x3b\xf6\xdc\xc2\xd1\xaf\xc9\x79\x8c\x8a"
      "\xc9\xe8\xc8\x7b\x30\xc8\xc0\x65\x2f\x51\x09\x34\xa7\x45\xd8\x08"
      "\x51\x56\xc4\x86\xc2\xba\x2f\x27" },
    { &assh_hash_shake_256, 304,
      "\x83\x6c\x4c\xd7\x8a\xc6\xee\x5e\xdc\x07\x75\x26\x0d\xb7\x54\x36"
      "\xac\x4a\x4b\x85\x5d\x5f\x21\xb4\x55\x97\xae\x26\x25\x06\xfd\xd1"
      "\xde\x79\x05\x3b\xe4\x76\x5b\xb9\x2c\xe0\x20\x35\x8c\x55\xe0\x9d"
      "\x1b\x1c\xdc\x46\x97\x56\x01\xeb\xec\x46\x32\xd7\xd2\xce\x52\x22"
      "\x84\xc8\xb7\xdb\x7f\x8b\xd6\x6a\x66\x0f\xe5\x82\x64\xf9\xb0\x01"
      "\x66\x9d\x90\x79\x84\x80\x18\x49\xd3\x64\x66\x31\x78\x89\x63\x83"
      "\xc9\x83\x05\x22\x35\x88\x53\x19\xa0\x99\xa2\x73\x0f\x43\xc1\x07"
      "\xdb\x2e\xca\x86\x7f\x6e\x6f\xef\x2f\x3d\xfa\xf1\x8a\x52\x7f\x05"
      "\x9b\x09\x7a\x36\xc7\x3c\x89\x37\x63\xd4\xcb\x19\x44\xf9\x9c\x18"
      "\x0c\x94\xc5\x7a\x31\xab\xcb\xa9\x60\x2e\x38\xc9\x02\x6c\x02\x66"
      "\x15\xd0\x2b\x7d\x9b\x1e\x2f\x44\x81\xb4\x69\x32\x3b\xb8\xea\x25"
      "\x9d\x7c\xc0\x7d\x28\x52\x4c\xef\x3d\xd5\x37\x8c\xdd\xf7\x45\x66"
      "\x38\xe5\x73\x65\xe4\x4b\x89\x12\xc9\x57\x82\x14\x67\xe5\x75\xdd"
      "\x36\xac\xf2\xee\x25\x86\x50\x46\xad\xca\x26\xec\x44\x34\x59\xb9"
      "\x68\x98\x1d\x61\x4f\xad\xf1\xcc\x72\xf9\x70\x6e\x8e\xd6\xd5\xa6"
      "\x29\x7d\x78\x96\x38\xc7\x0a\xdf\x86\xe1\xb2\x86\x34\xe7\x19\xe2"
      "\x40\xf6\xe7\x50\x18\x76\xde\x5f\x9e\xe1\xed\x8d\x6f\x1c\x0c\xf2"
      "\xfc\x53\xc4\xb6\x91\xcc\x1c\x2e\xd9\xa1\xa3\xfa\xfa\xc5\x12\x9d"
      "\xab\xd5\x0e\xb3\xa9\xd9\x52\x91\x3b\x3c\xd9\xe6\xf0\x6a\x84\x76" },
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
  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
#endif

  if (assh_context_init(&context, ASSH_CLIENT_SERVER, NULL, NULL, NULL, NULL))
    return -1;

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
#ifdef CONFIG_ASSH_DEBUG
      assh_hexdump("empty", buf, hash_size);
#endif
      assh_hash_cleanup(ctx);

      assh_hash_init(&context, ctx, algo);
      assh_hash_update(ctx, "abc", 3);
      assh_hash_final(ctx, buf, hash_size);
#ifdef CONFIG_ASSH_DEBUG
      assh_hexdump("abc", buf, hash_size);
#endif
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
#ifdef CONFIG_ASSH_DEBUG
	  assh_hexdump("hash result", buf, hash_size);
	  assh_hexdump("expected   ", tests[i].out, hash_size);
#endif
	  err++;
	}
    }  

  return err > 0;
}

