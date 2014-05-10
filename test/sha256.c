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

#include <assh/hash_sha256.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*
 *  those are the standard FIPS-180-2 test vectors
 *  originally written by Christophe Devine
 *
 *  This code has been distributed as PUBLIC DOMAIN.
 */

static char *msg[] = 
  {
    "abc",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    NULL
  };

static char *val[] =
  {
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
  };

int main(int argc, char *argv[])
{
  FILE *f;
  int i, j;
  char output[65];
  struct assh_hash_sha256_context_s ctx;
  unsigned char buf[1000];
  unsigned char sha256sum[32];

  if (argc < 2)
    {
      printf("\n SHA-256 Validation Tests:\n\n");

      for (i = 0; i < 3; i++)
        {
	  printf(" Test %d ", i + 1);

	  assh_sha256_init(&ctx);

	  if (i < 2)
            {
	      assh_sha256_update(&ctx, (uint8_t*)msg[i],
				 strlen(msg[i]));
            }
	  else
            {
	      memset(buf, 'a', 1000);

	      for(j = 0; j < 1000; j++)
		assh_sha256_update(&ctx, (uint8_t*)buf, 1000);
            }

	  assh_sha256_final(&ctx, sha256sum);

	  for(j = 0; j < 32; j++)
	      sprintf(output + j * 2, "%02x", sha256sum[j]);

	  if (memcmp(output, val[i], 64))
            {
	      printf("failed!\n");
	      return (1);
            }

	  printf("passed.\n");
        }

      printf("\n");
    }
  else
    {
      if (!(f = fopen(argv[1], "rb")))
        {
	  perror("fopen");
	  return 1;
        }

      assh_sha256_init(&ctx);

      while ((i = fread( buf, 1, sizeof(buf), f)) > 0)
	assh_sha256_update(&ctx, buf, i);

      assh_sha256_final(&ctx, sha256sum);

      for(j = 0; j < 32; j++)
	printf("%02x", sha256sum[j]);

      printf("  %s\n", argv[1]);
    }

  return 0;
}

