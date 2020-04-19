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


#include <assh/assh_bignum.h>
#include <assh/assh_packet.h>
#include <assh/assh_context.h>
#include <assh/assh_prng.h>

#include "prng_weak.h"
#include "test.h"
#include <stdlib.h>
#include <stdio.h>

 /* 1024 bits prime number */
static const uint8_t *prime1 = (const uint8_t*)"\x00\x00\x00\x81"
  "\x00\xff\xff\xff\xff\xff\xff\xff\xff\xc9\x0f\xda\xa2\x21\x68\xc2\x34"
  "\xc4\xc6\x62\x8b\x80\xdc\x1c\xd1\x29\x02\x4e\x08\x8a\x67\xcc\x74"
  "\x02\x0b\xbe\xa6\x3b\x13\x9b\x22\x51\x4a\x08\x79\x8e\x34\x04\xdd"
  "\xef\x95\x19\xb3\xcd\x3a\x43\x1b\x30\x2b\x0a\x6d\xf2\x5f\x14\x37"
  "\x4f\xe1\x35\x6d\x6d\x51\xc2\x45\xe4\x85\xb5\x76\x62\x5e\x7e\xc6"
  "\xf4\x4c\x42\xe9\xa6\x37\xed\x6b\x0b\xff\x5c\xb6\xf4\x06\xb7\xed"
  "\xee\x38\x6b\xfb\x5a\x89\x9f\xa5\xae\x9f\x24\x11\x7c\x4b\x1f\xe6"
  "\x49\x28\x66\x51\xec\xe6\x53\x81\xff\xff\xff\xff\xff\xff\xff\xff";

static const uint8_t *prime2 = (const uint8_t*)"\x00\x00\x00\x81"
  "\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x83";


struct assh_context_s context;

void test_convert()
{
  struct assh_bignum_s n, m;
  uint8_t buf[32];
  uint8_t *next;

  assh_bignum_init(&context, &n, 128);

  /********************/
  if (assh_bignum_convert(&context,
    ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE, "\x00\x00\x00\x01\x55", &n, NULL, 0))
    TEST_FAIL();

  memset(buf, 0xaa, sizeof(buf));
  if (assh_bignum_convert(&context,
    ASSH_BIGNUM_NATIVE, ASSH_BIGNUM_MPINT, &n, buf, &next, 0))
    TEST_FAIL();
  if (memcmp(buf, "\x00\x00\x00\x01\x55\xaa", 6) || next != buf + 5)
    TEST_FAIL();

  if (assh_bignum_convert(&context,
    ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE, "\x02\x01\x55", &n, NULL, 0))
    TEST_FAIL();

  memset(buf, 0xaa, sizeof(buf));
  if (assh_bignum_convert(&context,
    ASSH_BIGNUM_NATIVE, ASSH_BIGNUM_ASN1, &n, buf, &next, 0))
    TEST_FAIL();
  if (memcmp(buf, "\x02\x01\x55\xaa", 4) || next != buf + 3)
    TEST_FAIL();

  if (assh_bignum_convert(&context,
    ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE, "\x00\x00\x00\x02\x00\x85", &n, NULL, 0))
    TEST_FAIL();

  memset(buf, 0xaa, sizeof(buf));
  if (assh_bignum_convert(&context,
    ASSH_BIGNUM_NATIVE, ASSH_BIGNUM_MPINT, &n, buf, &next, 0))
    TEST_FAIL();
  if (memcmp(buf, "\x00\x00\x00\x02\x00\x85\xaa", 7) || next != buf + 6)
    TEST_FAIL();

  if (assh_bignum_convert(&context,
    ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE, "\x02\x02\x00\x85", &n, NULL, 0))
    TEST_FAIL();

  memset(buf, 0xaa, sizeof(buf));
  if (assh_bignum_convert(&context,
    ASSH_BIGNUM_NATIVE, ASSH_BIGNUM_ASN1, &n, buf, &next, 0))
    TEST_FAIL();
  ASSH_DEBUG_HEXDUMP("asn1", buf, 32);
  if (memcmp(buf, "\x02\x02\x00\x85\xaa", 5) || next != buf + 4)
    TEST_FAIL();

  if (assh_bignum_convert(&context,
    ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE, "\x00\x00\x00\x00", &n, NULL, 0))
    TEST_FAIL();

  memset(buf, 0xaa, sizeof(buf));
  if (assh_bignum_convert(&context,
    ASSH_BIGNUM_NATIVE, ASSH_BIGNUM_MPINT, &n, buf, &next, 0))
    TEST_FAIL();
  if (memcmp(buf, "\x00\x00\x00\x00\xaa", 5) || next != buf + 4)
    TEST_FAIL();

  if (assh_bignum_convert(&context,
    ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE, "\x02\x01\x00", &n, NULL, 0))
    TEST_FAIL();

  memset(buf, 0xaa, sizeof(buf));
  if (assh_bignum_convert(&context,
    ASSH_BIGNUM_NATIVE, ASSH_BIGNUM_ASN1, &n, buf, &next, 0))
    TEST_FAIL();
  ASSH_DEBUG_HEXDUMP("n", buf, 32);
  if (memcmp(buf, "\x02\x01\x00\xaa", 4) || next != buf + 3)
    TEST_FAIL();

  if (!assh_bignum_convert(&context,
    ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE, "\x00\x00\x00\x01\x85", &n, NULL, 0))
    TEST_FAIL();

  if (!assh_bignum_convert(&context,
    ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE, "\x00\x00\x00\x01\x00", &n, NULL, 0))
    TEST_FAIL();

  if (!assh_bignum_convert(&context,
    ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE, "\x00\x00\x00\x02\x00\x00", &n, NULL, 0))
    TEST_FAIL();

  if (!assh_bignum_convert(&context,
    ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE, "\x00\x00\x00\x02\x00\x10", &n, NULL, 0))
    TEST_FAIL();

  /********************/
  if (assh_bignum_convert(&context,
    ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE, "\x00\x00\x00\x11\x00\xf0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", &n, NULL, 0))
    TEST_FAIL();

  if (!assh_bignum_convert(&context,
    ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE, "\x00\x00\x00\x11\x01\xf0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", &n, NULL, 0))
    TEST_FAIL();

  assh_bignum_release(&context, &n);
  assh_bignum_init(&context, &n, 125);

  if (!assh_bignum_convert(&context,
    ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE, "\x00\x00\x00\x11\x00\xf0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", &n, NULL, 0))
    TEST_FAIL();
  if (!assh_bignum_convert(&context,
    ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE, "\x00\x00\x00\x10\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", &n, NULL, 0))
    TEST_FAIL();

  assh_bignum_release(&context, &n);
  assh_bignum_init(&context, &n, 117);

  if (assh_bignum_convert(&context,
    ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE, "\x00\x00\x00\x0f\x10\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04", &n, NULL, 0))
    TEST_FAIL();
  memset(buf, 0xaa, sizeof(buf));
  if (assh_bignum_convert(&context,
    ASSH_BIGNUM_NATIVE, ASSH_BIGNUM_MPINT, &n, buf, NULL, 0))
    TEST_FAIL();
  if (memcmp(buf, "\x00\x00\x00\x0f\x10\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\xaa", 20))
    TEST_FAIL();


  if (assh_bignum_convert(&context,
    ASSH_BIGNUM_MSB_RAW, ASSH_BIGNUM_NATIVE, "\x90\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04", &n, NULL, 0))
    TEST_FAIL();
  memset(buf, 0xaa, sizeof(buf));
  if (assh_bignum_convert(&context,
    ASSH_BIGNUM_NATIVE, ASSH_BIGNUM_MPINT, &n, buf, NULL, 0))
    TEST_FAIL();
  if (memcmp(buf, "\x00\x00\x00\x0f\x10\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\xaa", 20))
    TEST_FAIL();


  if (assh_bignum_convert(&context,
    ASSH_BIGNUM_LSB_RAW, ASSH_BIGNUM_NATIVE, "\x04\x00\x00\x00\x03\x00\x00\x00\x02\x00\x00\x00\x01\x00\x10", &n, NULL, 0))
    TEST_FAIL();
  memset(buf, 0xaa, sizeof(buf));
  if (assh_bignum_convert(&context,
    ASSH_BIGNUM_NATIVE, ASSH_BIGNUM_MPINT, &n, buf, NULL, 0))
    TEST_FAIL();
  if (memcmp(buf, "\x00\x00\x00\x0f\x10\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\xaa", 20))
    TEST_FAIL();

  memset(buf, 0xaa, sizeof(buf));
  if (assh_bignum_convert(&context,
    ASSH_BIGNUM_NATIVE, ASSH_BIGNUM_LSB_RAW, &n, buf, NULL, 0))
    TEST_FAIL();
  if (memcmp(buf, "\x04\x00\x00\x00\x03\x00\x00\x00\x02\x00\x00\x00\x01\x00\x10\xaa", 16))
    TEST_FAIL();

  memset(buf, 0xaa, sizeof(buf));
  if (assh_bignum_convert(&context,
    ASSH_BIGNUM_NATIVE, ASSH_BIGNUM_MSB_RAW, &n, buf, NULL, 0))
    TEST_FAIL();
  if (memcmp(buf, "\x10\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\xaa", 16))
    TEST_FAIL();

  /* value to large */
  assh_bignum_init(&context, &m, 64);
  if (!assh_bignum_convert(&context,
    ASSH_BIGNUM_NATIVE, ASSH_BIGNUM_NATIVE, &n, &m, NULL, 0))
    TEST_FAIL();

  if (assh_bignum_convert(&context,
    ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE, "\x00\x00\x00\x09\x01\xf0\x00\x00\x00\xf0\x00\x00\x00", &n, NULL, 0))
    TEST_FAIL();
  if (!assh_bignum_convert(&context,
    ASSH_BIGNUM_NATIVE, ASSH_BIGNUM_NATIVE, &n, &m, NULL, 0))
    TEST_FAIL();

  if (assh_bignum_convert(&context,
    ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE, "\x00\x00\x00\x09\x00\xf0\x00\x00\x00\xf0\x00\x00\x00", &n, NULL, 0))
    TEST_FAIL();
  if (assh_bignum_convert(&context,
    ASSH_BIGNUM_NATIVE, ASSH_BIGNUM_NATIVE, &n, &m, NULL, 0))
    TEST_FAIL();

  assh_bignum_release(&context, &m);
  assh_bignum_init(&context, &m, 60);

  if (!assh_bignum_convert(&context,
    ASSH_BIGNUM_NATIVE, ASSH_BIGNUM_NATIVE, &n, &m, NULL, 0))
    TEST_FAIL();

  if (assh_bignum_convert(&context,
    ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE, "\x00\x00\x00\x08\x0f\x00\x00\x00\xf0\x00\x00\x00", &n, NULL, 0))
    TEST_FAIL();
  if (assh_bignum_convert(&context,
    ASSH_BIGNUM_NATIVE, ASSH_BIGNUM_NATIVE, &n, &m, NULL, 0))
    TEST_FAIL();
  memset(buf, 0xaa, sizeof(buf));
  if (assh_bignum_convert(&context,
    ASSH_BIGNUM_NATIVE, ASSH_BIGNUM_MPINT, &n, buf, NULL, 0))
    TEST_FAIL();
  if (memcmp(buf, "\x00\x00\x00\x08\x0f\x00\x00\x00\xf0\x00\x00\x00\xaa", 9))
    TEST_FAIL();

  assh_bignum_release(&context, &n);
  assh_bignum_release(&context, &m);

  /********************/

  putchar('v');
}

#undef ASSH_BOP_PRINT
#define ASSH_BOP_PRINT(...) ASSH_BOP_NOP()

void test_ops()
{
  {
    struct op_test_s
    {
      size_t abits, bbits, rbits;
      assh_bool_t err;
      const assh_bignum_op_t *bytecode;
      const char *a, *b, *r, *m;
    };

    enum bytecode_args_e
    {
      A, B, R, M, T, A_mpint, B_mpint, R_mpint, M_mpint, MT, S
    };

    static const assh_bignum_op_t bytecode_cmp1[] = {
      ASSH_BOP_SIZE(	A,	S			),
      ASSH_BOP_SIZE(	B,	S			),

      ASSH_BOP_MOVE(	A,	A_mpint			),
      ASSH_BOP_MOVE(	B,	B_mpint			),

      ASSH_BOP_CMPEQ(     A,      B,	0        	),
      ASSH_BOP_CFAIL(     0,	0                       ),
      ASSH_BOP_CMPLT(     A,      B,	0      		),
      ASSH_BOP_CFAIL(     1,	0                       ),

      ASSH_BOP_UINT(      A,      16                      ),
      ASSH_BOP_CMPEQ(     A,      B,	0          	),
      ASSH_BOP_CFAIL(     1,	0                       ),
      ASSH_BOP_CMPLTEQ(   A,      B,	0           	),
      ASSH_BOP_CFAIL(     1,	0                       ),
      ASSH_BOP_CMPLTEQ(   B,      A,	0          	),
      ASSH_BOP_CFAIL(     1,	0                       ),

      ASSH_BOP_END(),
    };

    static const assh_bignum_op_t bytecode_cmp2[] = {
      ASSH_BOP_SIZE(	A,	S			),
      ASSH_BOP_SIZE(	B,	S			),

      ASSH_BOP_MOVE(	A,	A_mpint			),
      ASSH_BOP_MOVE(	B,	B_mpint			),

      ASSH_BOP_CMPEQ(     A,      B,	0     		),
      ASSH_BOP_CFAIL(     1,	0                       ),

      ASSH_BOP_END(),
    };

    static const assh_bignum_op_t bytecode_cmp3[] = {
      ASSH_BOP_SIZE(	A,	S			),
      ASSH_BOP_SIZE(	B,	S			),

      ASSH_BOP_MOVE(	A,	A_mpint			),
      ASSH_BOP_MOVE(	B,	B_mpint			),

      ASSH_BOP_CMPLT(     B,      A,	0      		),
      ASSH_BOP_CFAIL(     1,	0                       ),

      ASSH_BOP_END(),
    };

    static const assh_bignum_op_t bytecode_cmpeq[] = {
      ASSH_BOP_MOVE(	A,	A_mpint		),
      ASSH_BOP_MOVE(	B,	B_mpint		),
      ASSH_BOP_CMPEQ(	A,	B,	0	),
      ASSH_BOP_CFAIL(	1,	0		),
      ASSH_BOP_END(),
    };

    static const assh_bignum_op_t bytecode_cmplt[] = {
      ASSH_BOP_MOVE(	A,	A_mpint		),
      ASSH_BOP_MOVE(	B,	B_mpint		),
      ASSH_BOP_CMPLT(	A,	B,	0	),
      ASSH_BOP_CFAIL(	1,	0		),
      ASSH_BOP_END(),
    };

    static const assh_bignum_op_t bytecode_cmplteq[] = {
      ASSH_BOP_MOVE(	A,	A_mpint		),
      ASSH_BOP_MOVE(	B,	B_mpint		),
      ASSH_BOP_CMPLTEQ(	A,	B,	0	),
      ASSH_BOP_CFAIL(	1,	0		),
      ASSH_BOP_END(),
    };

    static const assh_bignum_op_t bytecode_shl[] = {
      ASSH_BOP_MOVE(	A,	A_mpint		),
      ASSH_BOP_MOVE(	B,	B_mpint		),
      ASSH_BOP_SHL(	R,	A,	0,	B	),
      ASSH_BOP_MOVE(	R_mpint,	R	),
      ASSH_BOP_END(),
    };

    static const assh_bignum_op_t bytecode_shr[] = {
      ASSH_BOP_MOVE(	A,	A_mpint		),
      ASSH_BOP_MOVE(	B,	B_mpint		),
      ASSH_BOP_SHR(	R,	A,	0,	B	),
      ASSH_BOP_MOVE(	R_mpint,	R	),
      ASSH_BOP_END(),
    };

    static const assh_bignum_op_t bytecode_add[] = {
      ASSH_BOP_MOVE(	A,	A_mpint		),
      ASSH_BOP_MOVE(	B,	B_mpint		),
      ASSH_BOP_ADD(	R,	A,	B	),
      ASSH_BOP_MOVE(	R_mpint,	R	),
      ASSH_BOP_END(),
    };

    static const assh_bignum_op_t bytecode_sub[] = {
      ASSH_BOP_MOVE(	A,	A_mpint		),
      ASSH_BOP_MOVE(	B,	B_mpint		),
      ASSH_BOP_SUB(	R,	A,	B	),
      ASSH_BOP_MOVE(	R_mpint,	R	),
      ASSH_BOP_END(),
    };

    static const assh_bignum_op_t bytecode_div[] = {
      ASSH_BOP_MOVE(	A,	A_mpint		),
      ASSH_BOP_MOVE(	B,	B_mpint		),
      ASSH_BOP_DIV(	R,	A,	B	),
      ASSH_BOP_MOVE(	R_mpint,	R	),
      ASSH_BOP_END(),
    };

    static const assh_bignum_op_t bytecode_mod[] = {
      ASSH_BOP_MOVE(	A,	A_mpint		),
      ASSH_BOP_MOVE(	B,	B_mpint		),
      ASSH_BOP_MOD(	R,	A,	B	),
      ASSH_BOP_MOVE(	R_mpint,	R	),
      ASSH_BOP_END(),
    };

    static const assh_bignum_op_t bytecode_addm[] = {
      ASSH_BOP_SIZE(	M,	R		),
      ASSH_BOP_SIZE(	MT,	R		),
      ASSH_BOP_MOVE(	A,	A_mpint		),
      ASSH_BOP_MOVE(	B,	B_mpint		),
      ASSH_BOP_MOVE(	M,	M_mpint		),
      ASSH_BOP_MTINIT(	MT,     M               ),
      ASSH_BOP_MTTO(    A,      A,      A,      MT      ),
      ASSH_BOP_MTTO(    B,      B,      B,      MT      ),
      ASSH_BOP_ADDM(	R,	A,	B,	MT	),
      ASSH_BOP_MTFROM(  R,      R,      R,      MT      ),
      ASSH_BOP_MOVE(	R_mpint,	R	),
      ASSH_BOP_END(),
    };

    static const assh_bignum_op_t bytecode_subm[] = {
      ASSH_BOP_SIZE(	M,	R		),
      ASSH_BOP_SIZE(	MT,	R		),
      ASSH_BOP_MOVE(	A,	A_mpint		),
      ASSH_BOP_MOVE(	B,	B_mpint		),
      ASSH_BOP_MOVE(	M,	M_mpint		),
      ASSH_BOP_MTINIT(	MT,     M               ),
      ASSH_BOP_MTTO(    A,      A,      A,      MT      ),
      ASSH_BOP_MTTO(    B,      B,      B,      MT      ),
      ASSH_BOP_SUBM(	R,	A,	B,	MT	),
      ASSH_BOP_MTFROM(  R,      R,      R,      MT      ),
      ASSH_BOP_MOVE(	R_mpint,	R	),
      ASSH_BOP_END(),
    };

    static const assh_bignum_op_t bytecode_mulm_mt[] = {
      ASSH_BOP_SIZE(	M,	R		),
      ASSH_BOP_SIZE(	MT,	R		),
      ASSH_BOP_MOVE(	A,	A_mpint		),
      ASSH_BOP_MOVE(	B,	B_mpint		),
      ASSH_BOP_MOVE(	M,	M_mpint		),
      ASSH_BOP_MTINIT(	MT,     M               ),
      ASSH_BOP_MTTO(    A,      A,      A,      MT      ),
      ASSH_BOP_MTTO(    B,      B,      B,      MT      ),
      ASSH_BOP_MOVE(	R,	A		),
      ASSH_BOP_MULM(	R,	R,	A,	MT	),
      ASSH_BOP_MTFROM(  R,      R,      R,      MT      ),
      ASSH_BOP_MOVE(	R_mpint,	R	),
      ASSH_BOP_PRINT(	R,	'R'		),
      ASSH_BOP_END(),
    };

    static const assh_bignum_op_t bytecode_modinv_mt[] = {
      ASSH_BOP_SIZE(	M,	R		),
      ASSH_BOP_SIZE(	MT,	R		),
      ASSH_BOP_MOVE(	A,	A_mpint		),
      ASSH_BOP_MOVE(	M,	M_mpint		),
      ASSH_BOP_MTINIT(	MT,     M               ),
      ASSH_BOP_MTTO(    A,      A,      A,      MT      ),
      ASSH_BOP_INV(	R,	A,	MT	),
      ASSH_BOP_MTFROM(  R,      R,      R,      MT      ),
      ASSH_BOP_MOVE(	R_mpint,	R	),
      ASSH_BOP_END(),
    };

    static const assh_bignum_op_t bytecode_isprime[] = {
      ASSH_BOP_MOVE(	A,	A_mpint		),
      ASSH_BOP_ISPRIME(	A,	10,	0	),
      ASSH_BOP_CFAIL(	1,	0		),
      ASSH_BOP_END(),
    };

    static const assh_bignum_op_t bytecode_istrivial[] = {
      ASSH_BOP_MOVE(	A,	A_mpint		),
      ASSH_BOP_ISTRIVIAL(	A,	0	),
      ASSH_BOP_CFAIL(	0,	0		),
      ASSH_BOP_END(),
    };

    static const assh_bignum_op_t bytecode_nextprime[] = {
      ASSH_BOP_SIZE(	M,	A		),
      ASSH_BOP_SIZE(	T,	A		),
      ASSH_BOP_UINT(	M,	0		),

      ASSH_BOP_UINT(	T,	1		),

      ASSH_BOP_MOVE(	A,	A_mpint		),
      ASSH_BOP_LADINIT( A			),

      ASSH_BOP_NEXTPRIME(	A,	ASSH_BOP_NOREG	),
      ASSH_BOP_PRINT(	A,	'A'		),
      ASSH_BOP_ADD(     A,	A,	T	),
      ASSH_BOP_ADD(     M,	M,	A	),
      ASSH_BOP_LADNEXT( 0			),
      ASSH_BOP_CJMP(	-6,	0,	0	),

      ASSH_BOP_PRINT(	M,	'R'		),
      ASSH_BOP_MOVE(	R_mpint,	M	),
      ASSH_BOP_END(),
    };

    static const assh_bignum_op_t bytecode_nextprime_step[] = {
      ASSH_BOP_SIZE(	M,	A		),
      ASSH_BOP_UINT(	M,	0		),

      ASSH_BOP_MOVE(	B,	B_mpint		),
      ASSH_BOP_NEXTPRIME(	B,	ASSH_BOP_NOREG	),
      ASSH_BOP_PRINT(	B,	'B'		),

      ASSH_BOP_MOVE(	A,	A_mpint		),
      ASSH_BOP_LADINIT( A			),

      ASSH_BOP_NEXTPRIME(	A,	B	),
      ASSH_BOP_PRINT(	A,	'A'		),
      ASSH_BOP_ADD(     A,	A,	B	),
      ASSH_BOP_ADD(     M,	M,	A	),
      ASSH_BOP_LADNEXT( 0			),
      ASSH_BOP_CJMP(	-6,	0,	0	),

      ASSH_BOP_PRINT(	M,	'R'		),
      ASSH_BOP_MOVE(	R_mpint,	M	),
      ASSH_BOP_END(),
    };

    static const struct op_test_s tests[] = {
      {
        64, 64, 0, 0, bytecode_cmp1,
        "\x00\x00\x00\x01\x01",
        "\x00\x00\x00\x01\x10"
      },

      {
        64, 64, 0, 1, bytecode_cmp2,
        "\x00\x00\x00\x01\x01",
        "\x00\x00\x00\x01\x10"
      },

      {
        64, 64, 0, 1, bytecode_cmp3,
        "\x00\x00\x00\x01\x01",
        "\x00\x00\x00\x01\x10"
      },

      {
	128, 128, 0, 0, bytecode_cmpeq,
	"\x00\x00\x00\x10\x1f\x23\x45\x67\x89\xab\xcd\x0e\xe0\xdc\xab\x98\x76\x54\x32\xf1",
	"\x00\x00\x00\x10\x1f\x23\x45\x67\x89\xab\xcd\x0e\xe0\xdc\xab\x98\x76\x54\x32\xf1",
      },

      {
	128, 128, 0, 1, bytecode_cmpeq,
	"\x00\x00\x00\x10\x1f\x23\x45\x67\x89\xab\xcd\x0e\xe0\xdc\xab\x98\x76\x54\x32\xf1",
	"\x00\x00\x00\x10\x1f\x23\x45\x67\x89\xab\xcd\x0e\xe0\xdc\xab\x98\x76\x54\x32\xf0",
      },

      {
	128, 128, 0, 1, bytecode_cmplt,
	"\x00\x00\x00\x10\x1f\x23\x45\x67\x89\xab\xcd\x0e\xe0\xdc\xab\x98\x76\x54\x32\xf1",
	"\x00\x00\x00\x08\x40\xdc\xab\x98\x76\x54\x32\xf0",
      },

      {
	128, 128, 0, 0, bytecode_cmplt,
	"\x00\x00\x00\x08\x40\xdc\xab\x98\x76\x54\x32\xf0",
	"\x00\x00\x00\x10\x1f\x23\x45\x67\x89\xab\xcd\x0e\xe0\xdc\xab\x98\x76\x54\x32\xf1",
      },

      {
	128, 64, 0, 1, bytecode_cmplt,
	"\x00\x00\x00\x10\x1f\x23\x45\x67\x89\xab\xcd\x0e\xe0\xdc\xab\x98\x76\x54\x32\xf1",
	"\x00\x00\x00\x08\x40\xdc\xab\x98\x76\x54\x32\xf0",
      },

      {
	64, 128, 0, 0, bytecode_cmplt,
	"\x00\x00\x00\x08\x40\xdc\xab\x98\x76\x54\x32\xf0",
	"\x00\x00\x00\x10\x1f\x23\x45\x67\x89\xab\xcd\x0e\xe0\xdc\xab\x98\x76\x54\x32\xf1",
      },

      {
	128, 128, 0, 0, bytecode_cmplteq,
	"\x00\x00\x00\x10\x1f\x23\x45\x67\x89\xab\xcd\x0e\xe0\xdc\xab\x98\x76\x54\x32\xf1",
	"\x00\x00\x00\x10\x1f\x23\x45\x67\x89\xab\xcd\x0e\xe0\xdc\xab\x98\x76\x54\x32\xf1",
      },

      {
	128, 128, 0, 0, bytecode_cmplteq,
	"\x00\x00\x00\x10\x1f\x23\x45\x67\x89\xab\xcd\x0e\xe0\xdc\xab\x98\x76\x54\x32\xf0",
	"\x00\x00\x00\x10\x1f\x23\x45\x67\x89\xab\xcd\x0e\xe0\xdc\xab\x98\x76\x54\x32\xf1",
      },

      {
	128, 128, 0, 1, bytecode_cmplteq,
	"\x00\x00\x00\x10\x1f\x23\x45\x67\x89\xab\xcd\x0e\xe0\xdc\xab\x98\x76\x54\x32\xf1",
	"\x00\x00\x00\x10\x1f\x23\x45\x67\x89\xab\xcd\x0e\xe0\xdc\xab\x98\x76\x54\x32\xf0",
      },

      {
	128, 32, 128, 0, bytecode_shr,
	"\x00\x00\x00\x10\x1f\x23\x45\x67\x89\xab\xcd\x0e\xe0\xdc\xab\x98\x76\x54\x32\xf1",
	"\x00\x00\x00\x00",
	"\x00\x00\x00\x0c\x1f\x23\x45\x67\x89\xab\xcd\x0e\xe0\xdc\xab\x98",
      },

      {
	128, 31, 128, 0, bytecode_shr,
	"\x00\x00\x00\x10\x1f\x23\x45\x67\x89\xab\xcd\x0e\xe0\xdc\xab\x98\x76\x54\x32\xf1",
	"\x00\x00\x00\x00",
	"\x00\x00\x00\x0c\x3e\x46\x8a\xcf\x13\x57\x9a\x1d\xc1\xb9\x57\x30",
      },

      {
	128, 101, 128, 0, bytecode_shr,
	"\x00\x00\x00\x10\x1f\x23\x45\x67\x89\xab\xcd\x0e\xe0\xdc\xab\x98\x76\x54\x32\xf1",
	"\x00\x00\x00\x00",
	"\x00\x00\x00\x04\x00\xf9\x1a\x2b",
      },

      {
	128, 5, 128, 0, bytecode_shr,
	"\x00\x00\x00\x10\x1f\x23\x45\x67\x89\xab\xcd\x0e\xe0\xdc\xab\x98\x76\x54\x32\xf1",
	"\x00\x00\x00\x00",
	"\x00\x00\x00\x10\x00\xf9\x1a\x2b\x3c\x4d\x5e\x68\x77\x06\xe5\x5c\xc3\xb2\xa1\x97",
      },

      {
	128, 0, 128, 0, bytecode_shr,
	"\x00\x00\x00\x10\x1f\x23\x45\x67\x89\xab\xcd\x0e\xe0\xdc\xab\x98\x76\x54\x32\xf1",
	"\x00\x00\x00\x00",
	"\x00\x00\x00\x10\x1f\x23\x45\x67\x89\xab\xcd\x0e\xe0\xdc\xab\x98\x76\x54\x32\xf1",
      },

      {
	128, 32, 128, 0, bytecode_shl,
	"\x00\x00\x00\x10\x1f\x23\x45\x67\x89\xab\xcd\x0e\xe0\xdc\xab\x98\x76\x54\x32\xf1",
	"\x00\x00\x00\x00",
	"\x00\x00\x00\x11\x00\x89\xab\xcd\x0e\xe0\xdc\xab\x98\x76\x54\x32\xf1\x00\x00\x00\x00",
      },

      {
	128, 31, 128, 0, bytecode_shl,
	"\x00\x00\x00\x10\x1f\x23\x45\x67\x89\xab\xcd\x0e\xe0\xdc\xab\x98\x76\x54\x32\xf1",
	"\x00\x00\x00\x00",
	"\x00\x00\x00\x11\x00\xc4\xd5\xe6\x87\x70\x6e\x55\xcc\x3b\x2a\x19\x78\x80\x00\x00\x00",
      },

      {
	128, 101, 128, 0, bytecode_shl,
	"\x00\x00\x00\x10\x1f\x23\x45\x67\x89\xab\xcd\x0e\xe0\xdc\xab\x98\x76\x54\x32\xf1",
	"\x00\x00\x00\x00",
	"\x00\x00\x00\x11\x00\xca\x86\x5e\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      },

      {
	128, 5, 128, 0, bytecode_shl,
	"\x00\x00\x00\x10\x1f\x23\x45\x67\x89\xab\xcd\x0e\xe0\xdc\xab\x98\x76\x54\x32\xf1",
	"\x00\x00\x00\x00",
	"\x00\x00\x00\x11\x00\xe4\x68\xac\xf1\x35\x79\xa1\xdc\x1b\x95\x73\x0e\xca\x86\x5e\x20",
      },

      {
	128, 0, 128, 0, bytecode_shl,
	"\x00\x00\x00\x10\x1f\x23\x45\x67\x89\xab\xcd\x0e\xe0\xdc\xab\x98\x76\x54\x32\xf1",
	"\x00\x00\x00\x00",
	"\x00\x00\x00\x10\x1f\x23\x45\x67\x89\xab\xcd\x0e\xe0\xdc\xab\x98\x76\x54\x32\xf1",
      },

      {
	128, 128, 128, 0, bytecode_add,
	"\x00\x00\x00\x00",
	"\x00\x00\x00\x00",
	"\x00\x00\x00\x00",
      },

      {
	8, 8, 8, 0, bytecode_add,
	"\x00\x00\x00\x01" "\x02",
	"\x00\x00\x00\x01" "\x03",
	"\x00\x00\x00\x01" "\x05",
      },
      {
	128, 128, 128, 0, bytecode_add,
	"\x00\x00\x00\x10" "\x00\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x10" "\x00\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x10" "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00",
      },
      {
	128, 128, 256, 0, bytecode_add,
	"\x00\x00\x00\x10" "\x00\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x10" "\x00\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x10" "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00",
      },
      {
	128, 128, 128, 1, bytecode_add, /* overflow */
	"\x00\x00\x00\x11" "\x00\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x11" "\x00\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
      },
      {
	128, 128, 129, 0, bytecode_add,
	"\x00\x00\x00\x11" "\x00\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x11" "\x00\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x11" "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00",
      },
      {
	127, 127, 128, 0, bytecode_add,
	"\x00\x00\x00\x10"     "\x40\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x10"     "\x40\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x11" "\x00\x81\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00",
      },
      {
	127, 127, 127, 1, bytecode_add, /* overflow */
	"\x00\x00\x00\x10" "\x40\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x10" "\x40\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
      },
      {
	64, 64, 128, 0, bytecode_add,
	"\x00\x00\x00\x09" "\x00\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x09" "\x00\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x09" "\x01\x01\x01\x01\x01\x01\x01\x01\x00",
      },

      {
	32, 64, 128, 0, bytecode_add,
	"\x00\x00\x00\x05" "\x00\xff\xff\xff\xff",
	"\x00\x00\x00\x09" "\x00\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x09" "\x00\x80\x80\x80\x81\x80\x80\x80\x7f",
      },

      {
	64, 32, 128, 0, bytecode_add,
	"\x00\x00\x00\x09" "\x00\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x05" "\x00\xff\xff\xff\xff",
	"\x00\x00\x00\x09" "\x00\x80\x80\x80\x81\x80\x80\x80\x7f",
      },

      {
	128, 128, 128, 0, bytecode_sub,
	"\x00\x00\x00\x00",
	"\x00\x00\x00\x00",
	"\x00\x00\x00\x00",
      },
      {
	8, 8, 8, 0, bytecode_sub,
	"\x00\x00\x00\x01" "\x05",
	"\x00\x00\x00\x01" "\x02",
	"\x00\x00\x00\x01" "\x03",
      },
      {
	8, 8, 8, 0, bytecode_sub,
	"\x00\x00\x00\x01" "\x05",
	"\x00\x00\x00\x01" "\x05",
	"\x00\x00\x00\x00",
      },
      {
	8, 8, 8, 1, bytecode_sub, /* overflow */
	"\x00\x00\x00\x01" "\x05",
	"\x00\x00\x00\x01" "\x06",
      },
      {
	128, 64, 128, 0, bytecode_sub,
	"\x00\x00\x00\x09" "\x00\x80\x80\x80\x81\x80\x80\x80\x7f",
	"\x00\x00\x00\x05" "\x00\xff\xff\xff\xff",
	"\x00\x00\x00\x09" "\x00\x80\x80\x80\x80\x80\x80\x80\x80",
      },
      {
	128, 64, 256, 0, bytecode_sub,
	"\x00\x00\x00\x09" "\x00\x80\x80\x80\x81\x80\x80\x80\x7f",
	"\x00\x00\x00\x05" "\x00\xff\xff\xff\xff",
	"\x00\x00\x00\x09" "\x00\x80\x80\x80\x80\x80\x80\x80\x80",
      },
      {
	64, 128, 128, 0, bytecode_sub,
	"\x00\x00\x00\x09" "\x00\x80\x80\x80\x81\x80\x80\x80\x7f",
	"\x00\x00\x00\x05" "\x00\xff\xff\xff\xff",
	"\x00\x00\x00\x09" "\x00\x80\x80\x80\x80\x80\x80\x80\x80",
      },
      {
	64, 128, 128, 1, bytecode_sub, /* overflow */
	"\x00\x00\x00\x05" "\x00\xff\xff\xff\xff",
	"\x00\x00\x00\x09" "\x00\x80\x80\x80\x81\x80\x80\x80\x7f",
	"\x00\x00\x00\x09" "\x00\x80\x80\x80\x80\x80\x80\x80\x80",
      },
      {
	128, 64, 128, 0, bytecode_sub,
	"\x00\x00\x00\x09" "\x00\x80\x80\x80\x81\x80\x80\x80\x7f",
	"\x00\x00\x00\x05" "\x00\xff\xff\xff\xff",
	"\x00\x00\x00\x09" "\x00\x80\x80\x80\x80\x80\x80\x80\x80",
      },
      {
	128, 64, 128, 1, bytecode_sub, /* overflow */
	"\x00\x00\x00\x05" "\x00\xff\xff\xff\xff",
	"\x00\x00\x00\x09" "\x00\x80\x80\x80\x81\x80\x80\x80\x7f",
	"\x00\x00\x00\x09" "\x00\x80\x80\x80\x80\x80\x80\x80\x80",
      },
      {
        256, 134, 256, 0, bytecode_div,
	"\x00\x00\x00\x21" "\x00\xf9\x5e\x33\xc9\x66\xa3\xa6\x4b\x96\x2d\x3a\xa6\x5a\x09\x93\x49\xe5\xcb\x20\x69\xd2\xa5\xd5\xab\x56\x22\x44\x1d\x3b\x76\x9b\x9c",
	"\x00\x00\x00\x11" "\x00\xab\xab\x5e\x9a\x21\xc9\x2f\x5e\x7e\x5f\xbe\x7d\x76\xf6\x1f\x3f",
	"\x00\x00\x00\x11" "\x01\x73\xdd\xf8\xa9\x07\x37\xdf\xce\xe1\xca\x82\xe7\xfb\x8b\x84\xef"
      },

      {
        256, 134, 256, 0, bytecode_mod,
	"\x00\x00\x00\x21" "\x00\xf9\x5e\x33\xc9\x66\xa3\xa6\x4b\x96\x2d\x3a\xa6\x5a\x09\x93\x49\xe5\xcb\x20\x69\xd2\xa5\xd5\xab\x56\x22\x44\x1d\x3b\x76\x9b\x9c",
	"\x00\x00\x00\x11" "\x00\xab\xab\x5e\x9a\x21\xc9\x2f\x5e\x7e\x5f\xbe\x7d\x76\xf6\x1f\x3f",
	"\x00\x00\x00\x10" "\x02\xa9\x9d\x18\x62\xb2\x96\x8c\x30\x19\xa3\x85\x87\x5d\xf3\xcb"
      },

      {
	128, 128, 128, 0, bytecode_addm, /* carry */
	"\x00\x00\x00\x11" "\x00\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x11" "\x00\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x10"     "\x0b\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab",
	"\x00\x00\x00\x11" "\x00\xf5\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55",
      },

      {
	128, 128, 128, 0, bytecode_addm, /* no carry */
	"\x00\x00\x00\x11" "\x00\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x11" "\x00\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x10"     "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01",
	"\x00\x00\x00\x10"     "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55",
      },

      {
	128, 128, 128, 0, bytecode_addm, /* no carry */
	"\x00\x00\x00\x11" "\x00\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x11" "\x00\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x0f"         "\x2b\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xac\x04",
	"\x00\x00\x00\x10"     "\x00\xf5\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55",
      },

      {
	128, 128, 128, 0, bytecode_subm, /* carry */
	"\x00\x00\x00\x10"     "\x40\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x11" "\x00\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x11" "\x00\xb5\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55",
	"\x00\x00\x00\x11" "\x00\xf5\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55",
      },

      {
	128, 128, 128, 0, bytecode_subm, /* no carry */
	"\x00\x00\x00\x11" "\x00\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x10"     "\x40\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x10"     "\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x00\x00\x00\x11" "\x00\xf5\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55",
      },

      {
	128, 128, 128, 0, bytecode_mulm_mt,
	"\x00\x00\x00\x11" "\x00\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x10"     "\x40\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x11" "\x00\xc4\x9d\x7e\xb8\xfe\x65\x30\x27\xa4\xb2\x72\x48\x61\x42\x7c\xc2",
	"\x00\x00\x00\x11" "\x00\xf5\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55",
      },

      {
	128, 128, 128, 0, bytecode_modinv_mt,
	"\x00\x00\x00\x10"     "\x40\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x00",
	"\x00\x00\x00\x10"     "\x14\xc5\x85\x54\x72\xa2\x41\x05\x69\xb3\x6c\x28\x83\x80\xe1\x4d",
	"\x00\x00\x00\x11" "\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1d",
      },

      {
	128, 128, 128, 0, bytecode_modinv_mt,
	"\x00\x00\x00\x10"     "\x40\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
	"\x00\x00\x00\x00",
	"\x00\x00\x00\x10"     "\x15\xae\x4d\x65\x16\xb5\x64\xda\xc8\x42\x79\x00\x39\xeb\xf3\xc8",
	"\x00\x00\x00\x11" "\x00\x98\xcc\x60\x26\xdc\x2d\xb6\x92\x2c\x5a\x00\x94\x00\x00\x00\x01",
      },

      {
	256, 0, 0, 0, bytecode_isprime,
	"\x00\x00\x00\x20"
        "\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xed"
      },

      {
	256, 0, 0, 0, bytecode_istrivial,
	"\x00\x00\x00\x20"
        "\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xed"
      },

      {
	32, 0, 0, 0, bytecode_isprime,
	"\x00\x00\x00\x05"
        "\x00\xff\xff\xff\xfb"
      },

      {
	32, 0, 0, 0, bytecode_istrivial,
	"\x00\x00\x00\x05"
        "\x00\xff\xff\xff\xfb"
      },

      {
	64, 0, 0, 1, bytecode_isprime,
	"\x00\x00\x00\x09"
        "\x00\xff\xff\xff\xfa\x00\x00\x00\x09"
      },

      {
	64, 0, 0, 0, bytecode_istrivial,
	"\x00\x00\x00\x09"
        "\x00\xff\xff\xff\xfa\x00\x00\x00\x09"
      },

      {
	256, 0, 0, 1, bytecode_isprime,
	"\x00\x00\x00\x20"
        "\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xeb"
      },

      {
	288, 0, 0, 1, bytecode_isprime,
	"\x00\x00\x00\x24"
        "\x7f\xff\xff\xfd\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xed"
	"\x00\x00\x00\x5f"
      },

      {
	256, 0, 256, 0, bytecode_nextprime,
	"\x00\x00\x00\x1f"
        "\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
	NULL,
	"\x00\x00\x00\x21\x00"
	"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x5c\x42\x94"
      },

      {
	256, 32, 256, 0, bytecode_nextprime_step,
	"\x00\x00\x00\x1e"
        "\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xf0\x0f\xff",
	"\x00\x00\x00\x05"
        "\x00\xff\xff\xf0\xfb",
	"\x00\x00\x00\x20"
	"\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x52\x88\xa9\x1b\x05\x67\x0a"
      },

      { 0 }
    };

    int i;
    for (i = 0; tests[i].abits; i++)
      {
	const struct op_test_s *t = &tests[i];
	size_t bytes = ASSH_ALIGN8(t->rbits) / 8;
	uint8_t buf[5 + bytes];

	struct assh_bignum_s a, b, r;
	assh_bignum_init(&context, &a, t->abits);
	assh_bignum_init(&context, &b, t->bbits);
	assh_bignum_init(&context, &r, t->rbits);

	memset(buf, 0, sizeof(buf));
	assh_status_t e = assh_bignum_bytecode(&context, 0, t->bytecode, "NNNTTMMMMms",
					      &a, &b, &r, t->a, t->b, buf, t->m, t->abits);

	if (t->err)
	  {
	    TEST_ASSERT(e);
	  }
	else
	  {
	    TEST_ASSERT(!e);
	    if (t->r)
	      {
		size_t s = 4 + assh_load_u32((const uint8_t*)t->r);
		if (memcmp(buf, t->r, s))
		  {
		    assh_hexdump(stderr, "result", buf, s);
		    assh_hexdump(stderr, "expected", t->r, s);
		    TEST_FAIL();
		  }
	      }
	  }

	assh_bignum_release(&context, &a);
	assh_bignum_release(&context, &b);
	assh_bignum_release(&context, &r);
      }

  }

  putchar('o');
}

void test_add_sub(unsigned int count)
{
  int i;

  for (i = 0; i < count; i++)
    {
      enum bytecode_args_e
      {
        A, B, C, D, S, L
      };

      size_t s = 27 + assh_prng_rand() % 100;
      size_t l = 3 + assh_prng_rand() % 12;

      static const assh_bignum_op_t bytecode[] = {
        ASSH_BOP_SIZE(  A,      S                       ),
        ASSH_BOP_SIZE(  B,      S                       ),
        ASSH_BOP_SIZE(  C,      S                       ),
        ASSH_BOP_SIZEM( D,      S,      0,      2       ),

        ASSH_BOP_RAND(  A,      ASSH_BOP_NOREG, ASSH_BOP_NOREG,
                                ASSH_PRNG_QUALITY_WEAK  ),
        ASSH_BOP_RAND(  B,      ASSH_BOP_NOREG, ASSH_BOP_NOREG,
                                ASSH_PRNG_QUALITY_WEAK  ),
        ASSH_BOP_PRINT( A,      'A'                     ),
        ASSH_BOP_SHR(   A,      A,      0,      L       ),
        ASSH_BOP_PRINT( A,      'A'                     ),
        ASSH_BOP_SHR(   B,      B,      0,      L       ),

        ASSH_BOP_MOVE(  C,      B                       ),
        ASSH_BOP_CMPEQ( C,      B,	0               ),
        ASSH_BOP_CFAIL( 1,	0                       ),

        ASSH_BOP_PRINT( A,      'A'                     ),
        ASSH_BOP_PRINT( B,      'B'                     ),

        ASSH_BOP_ADD(   B,      B,      A               ),
	ASSH_BOP_PRINT( B,      'B'                     ),
        ASSH_BOP_CMPEQ( C,      B,	0               ),
        ASSH_BOP_CFAIL( 0,	0                       ),

        ASSH_BOP_SUB(   B,      B,      A               ),
	ASSH_BOP_PRINT( B,      'B'                     ),
	ASSH_BOP_PRINT( C,      'C'                     ),
        ASSH_BOP_CMPEQ( C,      B,	0               ),
        ASSH_BOP_CFAIL( 1,	0                       ),

        ASSH_BOP_MOVE(  B,      A                       ),
        ASSH_BOP_ADD(   B,      A,      B               ),
        ASSH_BOP_ADD(   B,      B,      A               ),
        ASSH_BOP_ADD(   B,      A,      B               ),
        ASSH_BOP_ADD(   B,      B,      A               ),

        ASSH_BOP_UINT(  C,      5                       ),
        ASSH_BOP_MUL(   D,      A,      C               ),
	ASSH_BOP_PRINT( A,      'A'                     ),
	ASSH_BOP_PRINT( B,      'B'                     ),
	ASSH_BOP_PRINT( C,      'C'                     ),
	ASSH_BOP_PRINT( D,      'D'                     ),

        ASSH_BOP_CMPEQ( D,      B,	0               ),
        ASSH_BOP_CFAIL( 1,	0                       ),

        ASSH_BOP_END(),
      };

      if (assh_bignum_bytecode(&context, 0, bytecode, "TTTTss", s, l))
        TEST_FAIL();
    }

  putchar('a');
}

void test_div(unsigned int count)
{
  int i;

  for (i = 0; i < count; i++)
    {
      enum bytecode_args_e
      {
        A, B, C, D, E, S, Sb
      };

      static const assh_bignum_op_t bytecode[] = {
        ASSH_BOP_SIZE(  A,      S                       ),
        ASSH_BOP_SIZE(  B,      Sb                      ),
        ASSH_BOP_SIZE(  C,      S                       ),
        ASSH_BOP_SIZE(  D,      S                       ),
        ASSH_BOP_SIZEM( E,      S,      0,      2       ),

        /* test non constant time div */
        ASSH_BOP_RAND(  A,      ASSH_BOP_NOREG, ASSH_BOP_NOREG,
                                ASSH_PRNG_QUALITY_WEAK  ),
        ASSH_BOP_PRINT(	A,	'A'		),

        ASSH_BOP_RAND(  B,      ASSH_BOP_NOREG, ASSH_BOP_NOREG,
                                ASSH_PRNG_QUALITY_WEAK  ),
        ASSH_BOP_PRINT(	B,	'B'		),

        ASSH_BOP_DIVMOD(C,      D,      A,      B       ),
        ASSH_BOP_PRINT(	C,	'C'		),
        ASSH_BOP_PRINT(	D,	'D'		),

        ASSH_BOP_CMPLT( D,      B,	0               ),
        ASSH_BOP_CFAIL( 1,	0                       ),

        ASSH_BOP_MUL(   E,      B,      C               ),
        ASSH_BOP_ADD(   E,      E,      D               ),

        ASSH_BOP_CMPEQ( E,      A,	0               ),
        ASSH_BOP_CFAIL( 1,	0                       ),

        /* test constant time div with secret A */
        ASSH_BOP_RAND(  A,      ASSH_BOP_NOREG, ASSH_BOP_NOREG,
                                ASSH_PRNG_QUALITY_WEAK  ),
        ASSH_BOP_PRIVACY( A,    1,      0               ),
        ASSH_BOP_PRINT(	A,	'A'		),

        ASSH_BOP_RAND(  B,      ASSH_BOP_NOREG, ASSH_BOP_NOREG,
                                ASSH_PRNG_QUALITY_WEAK  ),
        ASSH_BOP_SET(B, 1, B, 1),
        ASSH_BOP_PRINT(	B,	'B'		),

        ASSH_BOP_DIVMOD(C,      D,      A,      B       ),

        ASSH_BOP_PRINT(	C,	'C'		),
        ASSH_BOP_PRINT(	D,	'D'		),

        ASSH_BOP_CMPLT( D,      B,	0               ),
        ASSH_BOP_CFAIL( 1,	0                       ),

        ASSH_BOP_MUL(   E,      B,      C               ),
        ASSH_BOP_ADD(   E,      E,      D               ),

        ASSH_BOP_CMPEQ( E,      A,	0               ),
        ASSH_BOP_CFAIL( 1,	0                       ),

        /* test constant time div with secret B */
        ASSH_BOP_RAND(  A,      ASSH_BOP_NOREG, ASSH_BOP_NOREG,
                                ASSH_PRNG_QUALITY_WEAK  ),
        ASSH_BOP_PRINT(	A,	'A'		),

        ASSH_BOP_RAND(  B,      ASSH_BOP_NOREG, ASSH_BOP_NOREG,
                                ASSH_PRNG_QUALITY_WEAK  ),
        ASSH_BOP_SET(B, 1, B, 1),
        ASSH_BOP_PRIVACY( B,    1,      0               ),
        ASSH_BOP_PRINT(	B,	'B'		),

        ASSH_BOP_DIVMOD(C,      D,      A,      B       ),

        ASSH_BOP_PRINT(	C,	'C'		),
        ASSH_BOP_PRINT(	D,	'D'		),

        ASSH_BOP_CMPLT( D,      B,	0               ),
        ASSH_BOP_CFAIL( 1,	0                       ),

        ASSH_BOP_MUL(   E,      B,      C               ),
        ASSH_BOP_ADD(   E,      E,      D               ),

        ASSH_BOP_CMPEQ( E,      A,	0               ),
        ASSH_BOP_CFAIL( 1,	0                       ),

        ASSH_BOP_END(),
      };

      size_t b_size = 100 + rand() % 128;
      size_t a_size = b_size + rand() % 128;

      if (assh_bignum_bytecode(&context, 2, bytecode, "TTTTTss",
                               a_size, b_size))
        TEST_FAIL();
    }

  putchar('d');
}

assh_status_t test_move(unsigned int count)
{
  assh_status_t err;
  int i;

  for (i = 0; i < count; i++)
    {
      enum bytecode_args_e
      {
        A, B, L,
        A_mpint, B_mpint
      };

      size_t s = 1 + assh_prng_rand() % 64;

      uint8_t mpa[s+4];
      uint8_t mpb[s+4];

      memset(mpa + 4, assh_prng_rand() & 127, s);

      if (mpa[4] == 0)
        s = 0;
      assh_store_u32(mpa, s);
      assh_store_u32(mpb, s);

      static const assh_bignum_op_t bytecode[] = {
        ASSH_BOP_SIZE(  A,      A_mpint                 ),

	ASSH_BOP_PRINT( A,      'A'                     ),

        ASSH_BOP_MOVE(  A,      A_mpint                 ),
	ASSH_BOP_PRINT( A,      'A'                     ),

        ASSH_BOP_MOVE(  B_mpint,        A               ),

        ASSH_BOP_END(),
      };

      TEST_ASSERT(!assh_bignum_bytecode(&context, 0, bytecode, "TTsMM",
                                        (size_t)256, mpa, mpb));

      ASSH_RET_IF_TRUE(memcmp(mpa, mpb, s+4), ASSH_ERR_BAD_DATA);
    }

  putchar('c');
  return ASSH_OK;
}

/* This test the modinv operation. lshift, mul and div ops are used. */
void test_modinv(unsigned int count)
{
  int i;

  for (i = 0; i < count; i++)
    {
      enum bytecode_args_e
      {
        P, B, C, D, S, P_mpint
      };

      static const assh_bignum_op_t bytecode[] = {

        ASSH_BOP_SIZE(  P,      P_mpint                 ),
        ASSH_BOP_SIZE(  B,      S                       ),
        ASSH_BOP_SIZE(  C,      P                       ),
        ASSH_BOP_SIZE(  D,      P                       ),

        ASSH_BOP_MOVE(  P,      P_mpint                 ),

        ASSH_BOP_RAND(  B,      ASSH_BOP_NOREG, ASSH_BOP_NOREG,
                                ASSH_PRNG_QUALITY_WEAK  ),

        ASSH_BOP_INV(   C,      B,      P               ),
        ASSH_BOP_CMPLT( C,      P,	0                       ),
        ASSH_BOP_CFAIL( 1,	0                               ),

        ASSH_BOP_MULM(  D,      B,      C,      P       ),

        ASSH_BOP_UINT(  P,      1                       ),
        ASSH_BOP_CMPEQ( P,      D,	0                       ),
        ASSH_BOP_CFAIL( 1,	0                               ),

        ASSH_BOP_END(),
      };

      if (assh_bignum_bytecode(&context, 0, bytecode, "TTTTsM",
                               (size_t)(assh_prng_rand() % 900 + 100),
                               i % 2 ? prime1 : prime2))
        TEST_FAIL();
    }

  putchar('i');
}


/* montgomery mul */
void test_mt(unsigned int count)
{
  int i;

  for (i = 0; i < count; i++)
    {

      enum bytecode_args_e
      {
        P, A, B, R, R2, MT, S, P_mpint
      };

      static const assh_bignum_op_t bytecode[] = {
        ASSH_BOP_SIZE(  P,      P_mpint                 ),
        ASSH_BOP_SIZE(	MT,	P               	),
        ASSH_BOP_SIZE(  A,      P                       ),
        ASSH_BOP_SIZE(  B,      P                       ),
        ASSH_BOP_SIZE(  R,      P                       ),
        ASSH_BOP_SIZE(  R2,     P                       ),

        ASSH_BOP_MOVE(  P,      P_mpint                 ),

        ASSH_BOP_RAND(  A,      ASSH_BOP_NOREG, ASSH_BOP_NOREG,
                                ASSH_PRNG_QUALITY_WEAK  ),
        ASSH_BOP_RAND(  B,      ASSH_BOP_NOREG, ASSH_BOP_NOREG,
                                ASSH_PRNG_QUALITY_WEAK  ),

        ASSH_BOP_MULM(  R2,      A,      B,      P      ),

        ASSH_BOP_MTINIT(MT,     P                       ),
        ASSH_BOP_MTTO(  A,      A,      A,      MT              ),
        ASSH_BOP_MTTO(  B,      B,      B,      MT              ),
        ASSH_BOP_MULM(  R,      A,      B,      MT      ),
        ASSH_BOP_MTFROM(R,      R,      R,      MT              ),

        ASSH_BOP_CMPEQ( R,      R2,	0                      ),
        ASSH_BOP_CFAIL( 1,	0                               ),

        ASSH_BOP_END(),
      };

      if (assh_bignum_bytecode(&context, 0, bytecode, "TTTTTmsM",
                               (size_t)1024 /*(assh_prng_rand() % 900 + 100)*/,
                               i % 2 ? prime1 : prime2))
        TEST_FAIL();
    }

  putchar('m');
}

/* test expmod. uses div, mul, modinv */
void test_expmod(unsigned int count)
{
  int i;

  for (i = 0; i < count; i++)
    {

      enum bytecode_args_e
      {
        P, A, IA, X, E, R1, R2, R3, R4, R5, P_mpint, MT
      };

      static const assh_bignum_op_t bytecode[] = {
        ASSH_BOP_SIZE(  P,      P_mpint                 ),
        ASSH_BOP_SIZE(  MT,     P                       ),
        ASSH_BOP_SIZE(  A,      P                       ),
        ASSH_BOP_SIZE(  IA,     P                       ),
        ASSH_BOP_SIZE(  X,      P                       ),
        ASSH_BOP_SIZE(  E,      P                       ),
        ASSH_BOP_SIZE(  R1,     P                       ),
        ASSH_BOP_SIZE(  R2,     P                       ),
        ASSH_BOP_SIZE(  R3,     P                       ),
        ASSH_BOP_SIZE(  R4,     P                       ),
        ASSH_BOP_SIZE(  R5,     P                       ),

        ASSH_BOP_MOVE(  P,      P_mpint                 ),
        ASSH_BOP_MTINIT(MT,     P                       ),

        ASSH_BOP_RAND(  A,      ASSH_BOP_NOREG, ASSH_BOP_NOREG,
                                ASSH_PRNG_QUALITY_WEAK  ),
        ASSH_BOP_MOD(   A,      A,      P               ),
        ASSH_BOP_RAND(  E,      ASSH_BOP_NOREG, ASSH_BOP_NOREG,
                                ASSH_PRNG_QUALITY_WEAK  ),
        ASSH_BOP_RAND(  X,      ASSH_BOP_NOREG, ASSH_BOP_NOREG,
                                ASSH_PRNG_QUALITY_WEAK  ),
        ASSH_BOP_INV(   IA,     A,      P               ),

        ASSH_BOP_PRINT( X,     'X'                    ),
        ASSH_BOP_PRINT( E,     'E'                    ),
        ASSH_BOP_PRINT( P,     'P'                    ),

        /* ((((a * x) % p)^e) % p) * ((inv(a)^e) % p) == x^e % p */
        ASSH_BOP_MULM(  R3,     A,      X,      P       ),
        ASSH_BOP_MTTO(  R3,     R3,     R3,     MT              ),
        ASSH_BOP_EXPM(  R2,     R3,     E,      MT      ),
        ASSH_BOP_MTTO(  IA,     IA,     IA,     MT              ),
        ASSH_BOP_EXPM(  R1,     IA,     E,      MT      ),
        ASSH_BOP_MULM(  R4,     R1,     R2,     MT      ),
        ASSH_BOP_MTTO(  X,      X,      X,      MT              ),
        ASSH_BOP_EXPM(  R5,     X,      E,      MT      ),

        ASSH_BOP_MTFROM(R4,     R4,     R4,     MT              ),
        ASSH_BOP_MTFROM(R5,     R5,     R5,     MT              ),
        ASSH_BOP_CMPEQ( R4,     R5,	0                      ),
        ASSH_BOP_CFAIL( 1,	0                               ),

        ASSH_BOP_PRINT( R4,     '4'                    ),
        ASSH_BOP_PRINT( R5,     '5'                    ),

        ASSH_BOP_END(),
      };

      TEST_ASSERT(!assh_bignum_bytecode(&context, 0, bytecode,
                                        "TTTTTTTTTTMm", prime1));
    }

  putchar('e');
}

int main(int argc, char **argv)
{
  setvbuf(stdout, NULL, _IONBF, 0);

  if (assh_deps_init())
    return -1;

  if (assh_context_init(&context, ASSH_CLIENT_SERVER,
                        NULL, NULL, &assh_prng_dummy, NULL))
    return -1;

  test_convert();
  test_ops();

  int i, count = 10;
  if (argc > 1)
    count = atoi(argv[1]);

  for (i = 0; count <= 0 || i < count; i++)
    {
      test_add_sub(0x100);
      test_div(0x100);
      test_move(0x100);
      test_modinv(0x1000);
      test_mt(0x1000);
      test_expmod(0x10);
    }

  assh_context_cleanup(&context);

  puts("\nTest passed");
  return 0;
}

