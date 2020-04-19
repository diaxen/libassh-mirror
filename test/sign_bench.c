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

#include <assh/assh.h>
#include <assh/assh_algo.h>
#include <assh/assh_sign.h>
#include <assh/assh_context.h>

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "test.h"

struct sign_bench_s
{
  const char *name;
  size_t key_bits;
};

static const struct sign_bench_s vectors[] =
{
  { "ssh-ed25519", 255 },
  { "eddsa-e382-shake256@libassh.org", 382 },
  { "eddsa-e521-shake256@libassh.org", 521 },
  { "ecdsa-sha2-nistp256", 256 },
  { "ecdsa-sha2-nistp384", 384 },
  { "ecdsa-sha2-nistp521", 521 },
  { "ssh-rsa", 1024 },
  { "ssh-rsa", 2048 },
  { "ssh-rsa", 4096 },
  { "rsa-sha2-256", 1024 },
  { "rsa-sha2-256", 2048 },
  { "rsa-sha2-256", 4096 },
  { "rsa-sha2-512", 1024 },
  { "rsa-sha2-512", 2048 },
  { "rsa-sha2-512", 4096 },
  { "ssh-dss", 1024 },
  { "ssh-dss", 2048 },
  { "ssh-dss", 4096 },
  { "dsa2048-sha224@libassh.org", 1024 },
  { "dsa2048-sha224@libassh.org", 2048 },
  { "dsa2048-sha224@libassh.org", 4096 },
  { "dsa3072-sha256@libassh.org", 1024 },
  { "dsa3072-sha256@libassh.org", 2048 },
  { "dsa3072-sha256@libassh.org", 4096 },
  { NULL }
};

static void bench(const struct assh_algo_sign_s *sa,
		  const struct assh_key_algo_s *ka, unsigned kbits)
{
  printf("%-32s %-13s %4u-bit  ",
	  assh_algo_name(&sa->algo_wk.algo),
	  sa->algo_wk.algo.implem, kbits);

  struct assh_context_s context;

  if (assh_context_init(&context, ASSH_CLIENT_SERVER,
			NULL, NULL, NULL, NULL))
    TEST_FAIL("context init");

  if (assh_algo_register_va(&context, 0, 0, 0, &sa->algo_wk.algo, NULL))
    TEST_FAIL("algo register");

  struct assh_key_s *key;

  if (assh_key_create(&context, &key, kbits, ka, ASSH_ALGO_SIGN))
    TEST_FAIL("key create");

  struct timeval tp_start, tp_end;

  /* generate */
  uint8_t data[1024] = {};

  size_t sign_len, sign_len2;
  struct assh_cbuffer_s d = {
     .data = data,
     .len = sizeof(data)
  };

  if (assh_sign_generate(&context, sa, key, 1, &d, NULL, &sign_len))
    TEST_FAIL("generate");
  uint8_t sig[sign_len];

  uint64_t dt;
  unsigned cycles = 0;
  gettimeofday(&tp_start, NULL);
  do {
    sign_len2 = sign_len;
    if (assh_sign_generate(&context, sa, key, 1, &d, sig, &sign_len2))
      TEST_FAIL("generate");
    gettimeofday(&tp_end, NULL);
    cycles++;

    dt = ((uint64_t)tp_end.tv_sec * 1000000 + tp_end.tv_usec) -
         ((uint64_t)tp_start.tv_sec * 1000000 + tp_start.tv_usec);

  } while (dt < 500000 && cycles < 1000);

  ssize_t l = 9 - printf("%.1f", 1000000. * cycles / dt);
  while (l-- > 0)
    putchar(' ');

  /* check */
  cycles = 0;
  gettimeofday(&tp_start, NULL);
  do {
    assh_safety_t safety;
    if (assh_sign_check(&context, sa, key, 1, &d, sig, sign_len2, &safety))
      TEST_FAIL("check");
    gettimeofday(&tp_end, NULL);
    cycles++;

    dt = ((uint64_t)tp_end.tv_sec * 1000000 + tp_end.tv_usec) -
         ((uint64_t)tp_start.tv_sec * 1000000 + tp_start.tv_usec);

  } while (dt < 500000 && cycles < 1000);

  l = 9 - printf("%.1f", 1000000. * cycles / dt);
  while (l-- > 0)
    putchar(' ');

  if (sa->algo_wk.algo.variant)
    printf("   (%s)\n", sa->algo_wk.algo.variant);
  else
    putchar('\n');

  assh_key_drop(&context, &key);
  assh_context_cleanup(&context);
}

int main()
{
  if (assh_deps_init())
    return -1;

  printf(	  "  Algorithm                      Implem         Key      Sign/s   Verify/s\n"
	  "--------------------------------------------------------------------------\n");

  uint_fast16_t i;
  for (i = 0; vectors[i].name != NULL; i++)
    {
      const struct sign_bench_s *t = &vectors[i];
      const struct assh_algo_s **a;

      for (a = assh_algo_table; *a; a++)
	{
	  if (!assh_algo_name_match(*a, ASSH_ALGO_SIGN,
				    t->name, strlen(t->name)))
	    continue;


	  const struct assh_algo_sign_s *sa = (void*)*a;
	  const struct assh_key_algo_s *ka = sa->algo_wk.key_algo;

	  bench(sa, ka, t->key_bits);
	}
    }
}
