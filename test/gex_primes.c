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

#include <assh/assh_bignum.h>
#include <assh/assh_context.h>
#include <assh/safe_primes.h>

#include "test.h"
#include <stdio.h>

static struct assh_context_s context;

static int is_safe_prime(size_t bits, intptr_t offset, const uint8_t *base)
{
  enum bytecode_args_e
  {
    P_n, O, B, P, T
  };

  static const assh_bignum_op_t bytecode[] = {

    ASSH_BOP_SIZE (     P,      P_n                     ),
    ASSH_BOP_SIZE (     T,      O                       ),

    ASSH_BOP_MOVE(      P,      B                       ),
    ASSH_BOP_MOVE(      T,      O                       ),
    ASSH_BOP_ADD(       P,      P,      T               ),

    ASSH_BOP_ISPRIME(   P,      7,      0               ),
    ASSH_BOP_CFAIL(	1,	0                       ),

    ASSH_BOP_UINT(      T,	1			),
    ASSH_BOP_SUB(       P,      P,      T               ),
    ASSH_BOP_SHR(       P,	P,	1,    ASSH_BOP_NOREG ),

    ASSH_BOP_ISPRIME(   P,      7,      0               ),
    ASSH_BOP_CFAIL(	1,	0                       ),

    ASSH_BOP_END(),
  };

  return assh_bignum_bytecode(&context, 0, bytecode, "sidTT",
			       bits, offset, base) == ASSH_OK;
}

#define DH_MAX_GRSIZE 16384

int main(int argc, char **argv)
{
  setvbuf(stdout, NULL, _IONBF, 0);

  if (assh_deps_init())
    return -1;

  if (assh_context_init(&context, ASSH_CLIENT_SERVER,
                        NULL, NULL, &test_prng_dummy, NULL))
    return -1;

  size_t bits;

  for (bits = 1024; bits <= DH_MAX_GRSIZE; bits += 8)
    {
      uint8_t base[bits / 8];
      intptr_t offset;

      if ((bits + 8) % 256)
	putchar('.');
      else
	printf(" %tu / %u\n", bits, DH_MAX_GRSIZE);

      assh_safeprime_get(&assh_safeprimes, bits, base, &offset);

      if (!is_safe_prime(bits, offset, base))
	TEST_FAIL();

      if (bits < 2048)
	{
	  base[10] ^= 1;
	  if (is_safe_prime(bits, offset, base))
	    TEST_FAIL();
	}
    }

  assh_context_cleanup(&context);

  puts("\nTest passed");
  return 0;
}

