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
#include <assh/assh_packet.h>
#include <assh/assh_context.h>
#include <assh/assh_prng.h>

#ifdef CONFIG_ASSH_USE_GCRYPT
# include <gcrypt.h>
#endif

#include <stdlib.h>
#include <stdio.h>

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

  enum bytecode_args_e
  {
    A, B, C, S
  };

  static const assh_bignum_op_t bytecode[] = {
    ASSH_BOP_SIZE(      A,      S       ),
    ASSH_BOP_SIZE(      B,      S       ),

    ASSH_BOP_RAND(      A,      ASSH_BOP_NOREG, ASSH_BOP_NOREG,
                                ASSH_PRNG_QUALITY_WEAK  ),
  //ASSH_BOP_PRINT(     A,      'A'),

    ASSH_BOP_SHR(       B,      A,      0,      C),
  ASSH_BOP_PRINT(     B,      'B'),

    ASSH_BOP_SHL(       A,      B,      0,      C),
  ASSH_BOP_PRINT(     A,      'A'),

    ASSH_BOP_END(),
  };

  ASSH_ERR_GTO(assh_bignum_bytecode(&context, bytecode, "TTss",
                                    (size_t)32, (size_t)256), err_);

  fprintf(stderr, "s");
  return 0;

 err_:
  fprintf(stderr, "Shift error\n");
  abort();
}

assh_error_t test_cmp(void)
{

  enum bytecode_args_e
  {
    X_hex, Y_hex, X, Y, S
  };

  assh_bignum_op_t bytecode1[] = {
    ASSH_BOP_SIZE(	X,	S			),
    ASSH_BOP_MOVE(	X,	X_hex			),

    ASSH_BOP_SIZE(	Y,	S			),
    ASSH_BOP_MOVE(	Y,	Y_hex			),

    ASSH_BOP_CMPNE(     X,      Y,      0		),
    ASSH_BOP_CMPLT(     X,      Y,      0		),

    ASSH_BOP_UINT(      X,      16                      ),
    ASSH_BOP_CMPEQ(     X,      Y,      0		),
    ASSH_BOP_CMPLTEQ(   X,      Y,      0		),
    ASSH_BOP_CMPLTEQ(   Y,      X,      0		),

    ASSH_BOP_END(),
  };

  if (assh_bignum_bytecode(&context, bytecode1, "HHTTs", "1", "10", (size_t)64))
    abort();

  assh_bignum_op_t bytecode2[] = {
    ASSH_BOP_SIZE(	X,	S			),
    ASSH_BOP_MOVE(	X,	X_hex			),

    ASSH_BOP_SIZE(	Y,	S			),
    ASSH_BOP_MOVE(	Y,	Y_hex			),

    ASSH_BOP_CMPEQ(     X,      Y,      0		),

    ASSH_BOP_END(),
  };

  if (!assh_bignum_bytecode(&context, bytecode2, "HHTTs", "1", "10", (size_t)64))
    abort();

  assh_bignum_op_t bytecode3[] = {
    ASSH_BOP_SIZE(	X,	S			),
    ASSH_BOP_MOVE(	X,	X_hex			),

    ASSH_BOP_SIZE(	Y,	S			),
    ASSH_BOP_MOVE(	Y,	Y_hex			),

    ASSH_BOP_CMPLT(     Y,      X,      0		),

    ASSH_BOP_END(),
  };

  if (!assh_bignum_bytecode(&context, bytecode3, "HHTTs", "1", "10", (size_t)64))
    abort();

  fprintf(stderr, "c");
  return ASSH_OK;
}

assh_error_t test_add_sub(unsigned int count)
{
  assh_error_t err;
  int i;

  for (i = 0; i < count; i++)
    {
      enum bytecode_args_e
      {
        A, B, C, D, S, L
      };

      static const assh_bignum_op_t bytecode[] = {
        ASSH_BOP_SIZE(  A,      S                       ),
        ASSH_BOP_SIZE(  B,      S                       ),
        ASSH_BOP_SIZE(  C,      S                       ),

        ASSH_BOP_RAND(  A,      ASSH_BOP_NOREG, ASSH_BOP_NOREG,
                                ASSH_PRNG_QUALITY_WEAK  ),
        ASSH_BOP_RAND(  B,      ASSH_BOP_NOREG, ASSH_BOP_NOREG,
                                ASSH_PRNG_QUALITY_WEAK  ),
        ASSH_BOP_SHR(   A,      A,      0,      L       ),
        ASSH_BOP_SHR(   B,      B,      0,      L       ),

        ASSH_BOP_MOVE(  C,      B                       ),
        ASSH_BOP_CMPEQ( C,      B,      0               ),

      //ASSH_BOP_PRINT( A,      'A'                     ),
      //ASSH_BOP_PRINT( B,      'A'                     ),

        ASSH_BOP_ADD(   B,      B,      A               ),
      //ASSH_BOP_PRINT( B,      'B'                     ),
        ASSH_BOP_CMPNE( C,      B,      0               ),

        ASSH_BOP_SUB(   B,      B,      A               ),
      //ASSH_BOP_PRINT( B,      'B'                     ),
      //ASSH_BOP_PRINT( C,      'C'                     ),
        ASSH_BOP_CMPEQ( C,      B,      0               ),

        ASSH_BOP_MOVE(  B,      A                       ),
        ASSH_BOP_ADD(   B,      A,      B               ),
        ASSH_BOP_ADD(   B,      B,      A               ),
        ASSH_BOP_ADD(   B,      A,      B               ),
        ASSH_BOP_ADD(   B,      B,      A               ),

        ASSH_BOP_SIZEM( D,      S,      0,      2       ),
        ASSH_BOP_UINT(  C,      5                       ),
        ASSH_BOP_MUL(   D,      A,      C               ),
      //ASSH_BOP_PRINT( C,      'C'                     ),
      //ASSH_BOP_PRINT( D,      'D'                     ),
      //ASSH_BOP_PRINT( B,      'B'                     ),

        ASSH_BOP_CMPEQ( D,      B,      0               ),

        ASSH_BOP_END(),
      };

      ASSH_ERR_RET(assh_bignum_bytecode(&context, bytecode, "TTTTss",
                                        (size_t)256, (size_t)8));
    }

  fprintf(stderr, "a");
  return ASSH_OK;
}

assh_error_t test_div(unsigned int count)
{
  assh_error_t err;
  int i;

  for (i = 0; i < count; i++)
    {
      enum bytecode_args_e
      {
        A, B, C, D, E, S
      };

      static const assh_bignum_op_t bytecode[] = {
        ASSH_BOP_SIZE(  A,      S                       ),
        ASSH_BOP_SIZE(  B,      S                       ),
        ASSH_BOP_SIZE(  C,      S                       ),
        ASSH_BOP_SIZE(  D,      S                       ),
        ASSH_BOP_SIZEM( E,      S,      0,      2       ),

        ASSH_BOP_RAND(  A,      ASSH_BOP_NOREG, ASSH_BOP_NOREG,
                                ASSH_PRNG_QUALITY_WEAK  ),
        ASSH_BOP_RAND(  B,      ASSH_BOP_NOREG, ASSH_BOP_NOREG,
                                ASSH_PRNG_QUALITY_WEAK  ),

        ASSH_BOP_DIVMOD(C,      D,      A,      B       ),

        ASSH_BOP_MUL(   E,      B,      C               ),
        ASSH_BOP_ADD(   E,      E,      D               ),

        ASSH_BOP_CMPEQ( E,      A,      0               ),

        ASSH_BOP_END(),
      };

      ASSH_ERR_RET(assh_bignum_bytecode(&context, bytecode, "TTTTTs", (size_t)256));
    }

  fprintf(stderr, "d");
  return ASSH_OK;
}

assh_error_t test_convert(unsigned int count)
{
  assh_error_t err;
  int i;

  for (i = 0; i < count; i++)
    {
      enum bytecode_args_e
      {
        A, B, L,
        A_mpint, B_mpint
      };

      size_t s = 1 + rand() % 64;

      uint8_t mpa[s+4];
      uint8_t mpb[s+4];

      memset(mpa + 4, rand() & 127, s);

      if (mpa[4] == 0)
        s = 0;
      assh_store_u32(mpa, s);
      assh_store_u32(mpb, s);

      static const assh_bignum_op_t bytecode[] = {
      //ASSH_BOP_PRINT( A,      'A'                     ),

        ASSH_BOP_SIZE(  A,      A_mpint                 ),
      //ASSH_BOP_PRINT( A,      'A'                     ),

        ASSH_BOP_MOVE(  A,      A_mpint                 ),
      //ASSH_BOP_PRINT( A,      'A'                     ),

        ASSH_BOP_MOVE(  B_mpint,        A               ),

        ASSH_BOP_END(),
      };

      ASSH_ERR_RET(assh_bignum_bytecode(&context, bytecode, "TTsMM",
                                        (size_t)256, mpa, mpb));

      ASSH_CHK_RET(memcmp(mpa, mpb, s+4), ASSH_ERR_BAD_DATA);
    }

  fprintf(stderr, "c");
  return ASSH_OK;
}

/* This test the modinv operation. lshift, mul and div ops are used. */
assh_error_t test_modinv(unsigned int count)
{
  assh_error_t err;
  int i;

  for (i = 0; i < count; i++)
    {
      enum bytecode_args_e
      {
        P, B, C, D, S, P_mpint
      };

      static const assh_bignum_op_t bytecode[] = {

        ASSH_BOP_SIZE(  P,      P_mpint                 ),
        ASSH_BOP_MOVE(  P,      P_mpint                 ),

        ASSH_BOP_SIZE(  B,      S                       ),
        ASSH_BOP_SIZE(  C,      P                       ),
        ASSH_BOP_SIZE(  D,      P                       ),

        ASSH_BOP_RAND(  B,      ASSH_BOP_NOREG, ASSH_BOP_NOREG,
                                ASSH_PRNG_QUALITY_WEAK  ),

        ASSH_BOP_INV(   C,      B,      P               ),
        ASSH_BOP_CMPLT( C,      P,      0               ),

        ASSH_BOP_MULM(  D,      B,      C,      P       ),

        ASSH_BOP_UINT(  P,      1                       ),
        ASSH_BOP_CMPEQ( P,      D,      0               ),

        ASSH_BOP_END(),
      };

      ASSH_ERR_RET(assh_bignum_bytecode(&context, bytecode, "TTTTsM",
                              (size_t)(rand() % 900 + 100), prime));

    }

  fprintf(stderr, "i");
  return ASSH_OK;
}


/* test expmod. uses div, mul, modinv */
assh_error_t test_expmod(unsigned int count)
{
  assh_error_t err;
  int i;

  for (i = 0; i < count; i++)
    {

      enum bytecode_args_e
      {
        P, A, IA, X, E, R1, R2, R3, R4, R5, P_mpint
      };

      static const assh_bignum_op_t bytecode[] = {
        ASSH_BOP_SIZE(  P,      P_mpint                 ),
        ASSH_BOP_MOVE(  P,      P_mpint                 ),

        ASSH_BOP_SIZE(  A,      P                       ),
        ASSH_BOP_SIZE(  IA,     P                       ),
        ASSH_BOP_SIZE(  X,      P                       ),
        ASSH_BOP_SIZE(  E,      P                       ),
        ASSH_BOP_SIZE(  R1,     P                       ),
        ASSH_BOP_SIZE(  R2,     P                       ),
        ASSH_BOP_SIZE(  R3,     P                       ),
        ASSH_BOP_SIZE(  R4,     P                       ),
        ASSH_BOP_SIZE(  R5,     P                       ),

        ASSH_BOP_RAND(  A,      ASSH_BOP_NOREG, ASSH_BOP_NOREG,
                                ASSH_PRNG_QUALITY_WEAK  ),
        ASSH_BOP_MOD(   A,      A,      P               ),
        ASSH_BOP_RAND(  E,      ASSH_BOP_NOREG, ASSH_BOP_NOREG,
                                ASSH_PRNG_QUALITY_WEAK  ),
        ASSH_BOP_RAND(  X,      ASSH_BOP_NOREG, ASSH_BOP_NOREG,
                                ASSH_PRNG_QUALITY_WEAK  ),
        ASSH_BOP_INV(   IA,     A,      P               ),

        /* ((((a * x) % p)^e) % p) * ((inv(a)^e) % p) == x^e % p */
        ASSH_BOP_MULM(  R3,     A,      X,      P       ),
        ASSH_BOP_EXPM(  R2,     R3,     E,      P       ),
        ASSH_BOP_EXPM(  R1,     IA,     E,      P       ),
        ASSH_BOP_MULM(  R4,     R1,     R2,     P       ),
        ASSH_BOP_EXPM(  R5,     X,      E,      P       ),

     // ASSH_BOP_PRINT( R4,     'R4'                    ),
     // ASSH_BOP_PRINT( R5,     'R5'                    ),
        ASSH_BOP_CMPEQ( R4,     R5,     0               ),

        ASSH_BOP_END(),
      };

      ASSH_ERR_RET(assh_bignum_bytecode(&context, bytecode,
                                        "TTTTTTTTTTM", prime));
    }

  fprintf(stderr, "e");
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
  ASSH_ERR_RET(assh_context_prng(&context, NULL));

  test_shift();
  test_cmp();

  int i, count = 10;
  if (argc > 1)
    count = atoi(argv[1]);

  for (i = 0; count <= 0 || i < count; i++)
    {
      ASSH_ERR_RET(test_add_sub(0x100));
      ASSH_ERR_RET(test_div(0x100));
      ASSH_ERR_RET(test_convert(0x100));
      ASSH_ERR_RET(test_modinv(0x100));
      ASSH_ERR_RET(test_expmod(0x10));
    }

  fprintf(stderr, "\nDone\n");
  return 0;
}

