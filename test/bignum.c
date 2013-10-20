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


#include <assh/assh_bignum.h>
#include <assh/assh_context.h>
#include <assh/assh_prng.h>

#ifdef CONFIG_ASSH_USE_GCRYPT
# include <gcrypt.h>
#endif

#include <stdlib.h>

 /* 1024 bits prime number */
static const uint8_t *prime = (const uint8_t*)"\x00\x00\x00\x81"
  "\x00\xff\xff\xff\xff\xff\xff\xff\xff\xc9\x0f\xda\xa2\x21\x68\xc2\x34"
  "\xc4\xc6\x62\x8b\x80\xdc\x1c\xd1\x29\x02\x4e\x08\x8a\x67\xcc\x74"
  "\x02\x0b\xbe\xa6\x3b\x13\x9b\x22\x51\x4a\x08\x79\x8e\x34\x04\xdd"
  "\xef\x95\x19\xb3\xcd\x3a\x43\x1b\x30\x2b\x0a\x6d\xf2\x5f\x14\x37"
  "\x4f\xe1\x35\x6d\x6d\x51\xc2\x45\xe4\x85\xb5\x76\x62\x5e\x7e\xc6"
  "\xf4\x4c\x42\xe9\xa6\x37\xed\x6b\x0b\xff\x5c\xb6\xf4\x06\xb7\xed"
  "\xee\x38\x6b\xfb\x5a\x89\x9f\xa5\xae\x9f\x24\x11\x7c\x4b\x1f\xe6"
  "\x49\x28\x66\x51\xec\xe6\x53\x81\xff\xff\xff\xff\xff\xff\xff\xff";

struct assh_context_s context;

assh_error_t test_shift()
{
  assh_error_t err;

  ASSH_BIGNUM_ALLOC(&context, a, 256, err_);
  ASSH_BIGNUM_ALLOC(&context, r, 256, err_);

  ASSH_ERR_GTO(assh_bignum_rand(&context, a), err_);
  assh_bignum_print(stderr, "shift", a);

  ASSH_ERR_GTO(assh_bignum_rshift(r, a, 32), err_);
  assh_bignum_print(stderr, "rshift 32", r);

  ASSH_ERR_GTO(assh_bignum_rshift(r, a, 16), err_);
  assh_bignum_print(stderr, "rshift 16", r);

  ASSH_ERR_GTO(assh_bignum_rshift(r, a, 1), err_);
  assh_bignum_print(stderr, "rshift 1", r);

  return 0;

 err_:
  fprintf(stderr, "Shift error\n");
  assh_bignum_print(stderr, "a", a);
  assh_bignum_print(stderr, "r", r);
  abort();
}

assh_error_t test_add_sub(unsigned int count)
{
  assh_error_t err;
  int i;

  for (i = 0; i < count; i++)
    {
      size_t la = rand() % 255 + 1;
      size_t lb = rand() % 255 + 1;
      size_t lr = ASSH_MAX(la, lb) + 1;

      ASSH_BIGNUM_ALLOC(&context, a, la, err_);
      ASSH_BIGNUM_ALLOC(&context, b, lb, err_);
      ASSH_BIGNUM_ALLOC(&context, r, lr, err_);

      ASSH_ERR_GTO(assh_bignum_rand(&context, a), err_);
      ASSH_ERR_GTO(assh_bignum_rand(&context, b), err_);

      ASSH_ERR_GTO(assh_bignum_rshift(a, a, assh_bignum_bits(a) - la), err_);
      ASSH_ERR_GTO(assh_bignum_rshift(b, b, assh_bignum_bits(b) - lb), err_);

      ASSH_ERR_GTO(assh_bignum_add(r, a, b), err_);

      ASSH_ERR_GTO(assh_bignum_sub(r, r, b), err_);

      if (assh_bignum_cmp(r, a))
        {
        err_:
          fprintf(stderr, "Add/sub error on iteration #%u\n", i);
          assh_bignum_print(stderr, "a", a);
          assh_bignum_print(stderr, "b", b);
          assh_bignum_print(stderr, "r", r);
          abort();
        }

      ASSH_BIGNUM_FREE(&context, a);
      ASSH_BIGNUM_FREE(&context, b);
      ASSH_BIGNUM_FREE(&context, r);
    }

  fprintf(stderr, "a");
  return ASSH_OK;
}

assh_error_t test_div(unsigned int count)
{
  assh_error_t err;
  int i;

  ASSH_BIGNUM_ALLOC(&context, a, 256, err_);
  ASSH_BIGNUM_ALLOC(&context, b, 256, err_);
  ASSH_BIGNUM_ALLOC(&context, c, 256, err_);
  ASSH_BIGNUM_ALLOC(&context, r, 256, err_);
  ASSH_BIGNUM_ALLOC(&context, d, 256, err_);
  ASSH_BIGNUM_ALLOC(&context, e, 512, err_);

  for (i = 0; i < count; i++)
    {
      ASSH_ERR_RET(assh_bignum_rand(&context, b));
      ASSH_ERR_RET(assh_bignum_rand(&context, c));

      ASSH_ERR_RET(assh_bignum_rshift(a, b, rand() % 255));

      if (assh_bignum_div(r, d, c, a) == ASSH_OK)
	{
	  ASSH_ERR_RET(assh_bignum_mul(e, d, a));
	  ASSH_ERR_RET(assh_bignum_add(e, e, r));

	  if (assh_bignum_cmp(e, c) != 0)
	    {
	      fprintf(stderr, "Div error on iteration #%u\n", i);
	      assh_bignum_print(stderr, "c ", c);
	      assh_bignum_print(stderr, "a ", a);
	      assh_bignum_print(stderr, "mod ", r);
	      assh_bignum_print(stderr, "div ", d);
	      assh_bignum_print(stderr, "e ", e);
            err_:
	      abort();
	    }
	}
    }

  fprintf(stderr, "d");

  ASSH_BIGNUM_FREE(&context, a);
  ASSH_BIGNUM_FREE(&context, b);
  ASSH_BIGNUM_FREE(&context, c);
  ASSH_BIGNUM_FREE(&context, r);
  ASSH_BIGNUM_FREE(&context, d);
  ASSH_BIGNUM_FREE(&context, e);

  return ASSH_OK;
}

/* This test the modinv operation. lshift, mul and div ops are used. */
assh_error_t test_modinv(unsigned int count)
{
  assh_error_t err;
  int i;

  ASSH_BIGNUM_ALLOC(&context, a, 1024+128, err_);
  ASSH_BIGNUM_ALLOC(&context, b, 1024+128, err_);
  ASSH_BIGNUM_ALLOC(&context, c, 1024+128, err_);
  ASSH_BIGNUM_ALLOC(&context, d, 2048+256, err_);
  ASSH_BIGNUM_ALLOC(&context, r, 2048+256, err_);

  ASSH_ERR_RET(assh_bignum_from_mpint(a, NULL, prime));

  for (i = 0; i < count; i++)
    {
      ASSH_ERR_RET(assh_bignum_rand(&context, c));
      ASSH_ERR_RET(assh_bignum_rshift(b, c, 129 + rand() % 900));

      ASSH_ERR_RET(assh_bignum_modinv((c), (b), (a)));

      int cmp = assh_bignum_cmp((c), (a));
      err = (cmp <= 0);

      ASSH_ERR_RET(assh_bignum_mul(d, b, c));

      ASSH_ERR_RET(assh_bignum_div(r, NULL, d, a));

      /* check (b * u) % a == 1 */
      err |= assh_bignum_cmp_uint(r, 1);

      if (err)
	{
	  fprintf(stderr, "Modinv error on iteration #%u\n", i);
	  assh_bignum_print(stderr, "a", a);
	  assh_bignum_print(stderr, "b", b);
	  assh_bignum_print(stderr, "u", c);
	  assh_bignum_print(stderr, "one", r);
        err_:
	  abort();
	}
    }

  fprintf(stderr, "i");

  ASSH_BIGNUM_FREE(&context, a);
  ASSH_BIGNUM_FREE(&context, b);
  ASSH_BIGNUM_FREE(&context, c);
  ASSH_BIGNUM_FREE(&context, d);
  ASSH_BIGNUM_FREE(&context, r);

  return ASSH_OK;
}

/* test expmod. uses div, mul, modinv */
assh_error_t test_expmod(unsigned int count)
{
  assh_error_t err;
  int i;

  ASSH_BIGNUM_ALLOC(&context, p, 1024, err_);
  ASSH_BIGNUM_ALLOC(&context, a, 1024, err_);
  ASSH_BIGNUM_ALLOC(&context, ia, 1024, err_);
  ASSH_BIGNUM_ALLOC(&context, x, 1024, err_);
  ASSH_BIGNUM_ALLOC(&context, e, 1024, err_);
  ASSH_BIGNUM_ALLOC(&context, r1, 1024, err_);
  ASSH_BIGNUM_ALLOC(&context, r2, 1024, err_);
  ASSH_BIGNUM_ALLOC(&context, r3, 1024, err_);
  ASSH_BIGNUM_ALLOC(&context, r4, 1024, err_);
  ASSH_BIGNUM_ALLOC(&context, r5, 1024, err_);

  /* prime */

  ASSH_ERR_RET(assh_bignum_from_mpint(p, NULL, prime));

  /* a modulo prime */
  ASSH_ERR_RET(assh_bignum_rand(&context, a));
  ASSH_ERR_RET(assh_bignum_div(a, NULL, a, p));

  /* a^-1 modulo prime */
  ASSH_ERR_RET(assh_bignum_modinv(ia, a, p));

  for (i = 0; i < count; i++)
    {
      ASSH_ERR_RET(assh_bignum_rand(&context, x));
      ASSH_ERR_RET(assh_bignum_rand(&context, e));

      // check ((((a * x) % p)^e) % p) * ((inv(a)^e) % p) == x^e % p
      ASSH_ERR_RET(assh_bignum_mulmod(r3, a, x, p));
      ASSH_ERR_RET(assh_bignum_expmod(r2, r3, e, p));
      ASSH_ERR_RET(assh_bignum_expmod(r1, ia, e, p));
      ASSH_ERR_RET(assh_bignum_mulmod(r4, r1, r2, p));
      ASSH_ERR_RET(assh_bignum_expmod(r5, x, e, p));

      if (assh_bignum_cmp(r4, r5))
	{
	  fprintf(stderr, "Expmod error on iteration #%u\n", i);
	  assh_bignum_print(stderr, "p",  p);
	  assh_bignum_print(stderr, "a",  a);
	  assh_bignum_print(stderr, "ia", ia);
	  assh_bignum_print(stderr, "x",  x);
	  assh_bignum_print(stderr, "e",  e);
	  assh_bignum_print(stderr, "r1", r1);
	  assh_bignum_print(stderr, "r2", r2);
	  assh_bignum_print(stderr, "r3", r3);
	  assh_bignum_print(stderr, "r4", r4);
	  assh_bignum_print(stderr, "r5", r5);
        err_:
	  abort();
	}
    }

  fprintf(stderr, "e");

  ASSH_BIGNUM_FREE(&context, p);
  ASSH_BIGNUM_FREE(&context, a);
  ASSH_BIGNUM_FREE(&context, x);
  ASSH_BIGNUM_FREE(&context, e);
  ASSH_BIGNUM_FREE(&context, r1);
  ASSH_BIGNUM_FREE(&context, r2);
  ASSH_BIGNUM_FREE(&context, r3);
  ASSH_BIGNUM_FREE(&context, r4);
  ASSH_BIGNUM_FREE(&context, r5);

  return ASSH_OK;
}

int main(int argc, char **argv)
{
  assh_error_t err;

#ifdef CONFIG_ASSH_USE_GCRYPT
  if (!gcry_check_version(GCRYPT_VERSION))
    return -1;
#endif

  assh_context_init(&context, ASSH_SERVER);
  ASSH_ERR_RET(assh_context_prng(&context, &assh_prng_xswap));

  test_shift();

  int i, count = 10;
  if (argc > 1)
    count = atoi(argv[1]);

  for (i = 0; count <= 0 || i < count; i++)
    {
      ASSH_ERR_RET(test_add_sub(0x10000));
      ASSH_ERR_RET(test_div(0x1000));
      ASSH_ERR_RET(test_modinv(0x100));
      ASSH_ERR_RET(test_expmod(0x1));
    }

  return 0;
}

