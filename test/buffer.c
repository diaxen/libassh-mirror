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
#include <assh/assh_bignum.h>
#include <assh/assh_buffer.h>
#include <assh/assh_context.h>

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "test.h"

struct assh_context_s context;

static void bignum_set(struct assh_bignum_s *bn, size_t bits, intptr_t x)
{
  assh_bignum_init(&context, bn, bits);

  static const assh_bignum_op_t bytecode[] = {
	ASSH_BOP_MOVE(  0,      1  ),
	ASSH_BOP_END(),
  };

  TEST_ASSERT(assh_bignum_bytecode(&context, 0, bytecode, "Ni", bn, x) == 0);
}

static assh_bool_t bignum_cmp(struct assh_bignum_s *bn, intptr_t x)
{
  static const assh_bignum_op_t bytecode[] = {
	ASSH_BOP_SIZE(   1,      2         ),
	ASSH_BOP_MOVE(   1,      2         ),
	ASSH_BOP_CMPEQ(  0,      1,	0  ),
	ASSH_BOP_CFAIL(  1,	 0	   ),
	ASSH_BOP_END(),
  };

  return assh_bignum_bytecode(&context, 0, bytecode, "NTi", bn, x) == 0;
}

assh_error_t
blob_write_alloc(const char *format, uint8_t **blob_, size_t *blob_len, ...)
{
  assh_error_t err;
  va_list ap;
  uint8_t *blob = NULL;

  va_start(ap, blob_len);
  err = assh_blob_write_va(format, blob, blob_len, ap);
  va_end(ap);

  if (err)
    return err;

  blob = malloc(*blob_len);
  if (!blob)
    TEST_FAIL("malloc");

  size_t len2 = *blob_len;
  va_start(ap, blob_len);
  err = assh_blob_write_va(format, blob, &len2, ap);
  va_end(ap);

  if (err)
    return err;

  ASSH_DEBUG_HEXDUMP(format, blob, len2);

  TEST_ASSERT(*blob_len >= len2);
  *blob_len = len2;

  *blob_ = blob;

  return 0;
}

static void test_write_ok()
{
  size_t blob_len;
  uint8_t *blob;

  {
    TEST_ASSERT(blob_write_alloc("Ds", &blob, &blob_len, "test", 4) == 0);
    TEST_ASSERT(blob_len == 8 &&
		!memcmp(blob, "\x00\x00\x00\x04\x74\x65\x73\x74", blob_len));
    free(blob);
  }

  {
    TEST_ASSERT(blob_write_alloc("Is", &blob, &blob_len, 42) == 0);
    TEST_ASSERT(blob_len == 8 &&
		!memcmp(blob, "\x00\x00\x00\x04\x00\x00\x00\x2a", blob_len));
    free(blob);
  }

  {
    TEST_ASSERT(blob_write_alloc("Irs", &blob, &blob_len, 42) == 0);
    TEST_ASSERT(blob_len == 8 &&
		!memcmp(blob, "\x00\x00\x00\x04\x2a\x00\x00\x00", blob_len));
    free(blob);
  }

  {
    TEST_ASSERT(blob_write_alloc("Ls", &blob, &blob_len, 42ULL) == 0);
    TEST_ASSERT(blob_len == 12 &&
		!memcmp(blob, "\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x2a", blob_len));
    free(blob);
  }

  {
    TEST_ASSERT(blob_write_alloc("DsIs", &blob, &blob_len, "test", 4, 1234) == 0);
    TEST_ASSERT(blob_len == 16 &&
		!memcmp(blob, "\x00\x00\x00\x04\x74\x65\x73\x74\x00\x00\x00\x04\x00\x00\x04\xd2", blob_len));
    free(blob);
  }

  {
    TEST_ASSERT(blob_write_alloc("ZsIs", &blob, &blob_len, "TEST", 1234) == 0);
    TEST_ASSERT(blob_len == 16 &&
		!memcmp(blob, "\x00\x00\x00\x04\x54\x45\x53\x54\x00\x00\x00\x04\x00\x00\x04\xd2", blob_len));
    free(blob);
  }

  {
    struct assh_cbuffer_s cbuf = { .str = "str", .len = 4 };

    TEST_ASSERT(blob_write_alloc("BsIs", &blob, &blob_len, &cbuf, 1234) == 0);
    TEST_ASSERT(blob_len == 16 &&
		!memcmp(blob, "\x00\x00\x00\x04\x73\x74\x72\x00\x00\x00\x00\x04\x00\x00\x04\xd2", blob_len));
    free(blob);
  }

  {
    struct assh_cbuffer_s cbuf = { .str = "str", .len = 4 };

    TEST_ASSERT(blob_write_alloc("E10;abcdefghijsBs", &blob, &blob_len, &cbuf) == 0);
    TEST_ASSERT(blob_len == 22 &&
		!memcmp(blob, "\x00\x00\x00\x0a\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x00\x00\x00\x04\x73\x74\x72\x00", blob_len));
    free(blob);
  }

  {
    struct assh_cbuffer_s cbuf = { .str = "str", .len = 4 };

    TEST_ASSERT(blob_write_alloc("Is (E3;STR s Bs)s", &blob, &blob_len, 42, &cbuf) == 0);
    TEST_ASSERT(blob_len == 27 &&
		!memcmp(blob, "\x00\x00\x00\x04\x00\x00\x00\x2a\x00\x00\x00\x0f\x00\x00\x00\x03\x53\x54\x52\x00\x00\x00\x04\x73\x74\x72\x00", blob_len));
    free(blob);
  }

  {
    struct assh_cbuffer_s cbuf = { .str = "str", .len = 4 };

    TEST_ASSERT(blob_write_alloc("Is (E3;STR s (Zs)s Bs)s Zb", &blob, &blob_len, 42, "in", &cbuf, "end") == 0);
    TEST_ASSERT(blob_len == 40 &&
		!memcmp(blob, "\x00\x00\x00\x04\x00\x00\x00\x2a\x00\x00\x00\x19\x00\x00\x00\x03\x53\x54\x52\x00\x00\x00\x06\x00\x00\x00\x02\x69\x6e\x00\x00\x00"
			"\x04\x73\x74\x72\x00\x65\x6e\x64", blob_len));
    free(blob);
  }

  {
    struct assh_cbuffer_s cbuf = { .str = "str", .len = 4 };

    TEST_ASSERT(blob_write_alloc("Is ((Zs)s Bs)a2 Zb", &blob, &blob_len, 42, "in", &cbuf, "end") == 0);
    TEST_ASSERT(blob_len == 31 &&
		!memcmp(blob, "\x00\x00\x00\x04\x00\x00\x00\x2a\x02\x12\x00\x00\x00\x06\x00\x00\x00\x02\x69\x6e\x00\x00\x00\x04\x73\x74\x72\x00\x65\x6e\x64", blob_len));
    free(blob);
  }

  {
    TEST_ASSERT(blob_write_alloc("Ib Z]6s Ib", &blob, &blob_len, 1234, "TEST", 4567) == 0);
    TEST_ASSERT(blob_len == 18 &&
		!memcmp(blob, "\x00\x00\x04\xd2\x00\x00\x00\x06\x54\x45\x53\x54\x00\x00\x00\x00\x11\xd7", blob_len));
    free(blob);
  }

  {
    TEST_ASSERT(blob_write_alloc("Ib Z[6s Ib", &blob, &blob_len, 1234, "TEST", 4567) == 0);
    TEST_ASSERT(blob_len == 18 &&
		!memcmp(blob, "\x00\x00\x04\xd2\x00\x00\x00\x06\x00\x00\x54\x45\x53\x54\x00\x00\x11\xd7", blob_len));
    free(blob);
  }

  {
    TEST_ASSERT(blob_write_alloc("Ib Z]2s Ib", &blob, &blob_len, 1234, "TEST", 4567) == 0);
    TEST_ASSERT(blob_len == 14 &&
		!memcmp(blob, "\x00\x00\x04\xd2\x00\x00\x00\x02\x54\x45\x00\x00\x11\xd7", blob_len));
    free(blob);
  }

  {
    TEST_ASSERT(blob_write_alloc("Ib Z[2s Ib", &blob, &blob_len, 1234, "TEST", 4567) == 0);
    TEST_ASSERT(blob_len == 14 &&
		!memcmp(blob, "\x00\x00\x04\xd2\x00\x00\x00\x02\x53\x54\x00\x00\x11\xd7", blob_len));
    free(blob);
  }

  {
    TEST_ASSERT(blob_write_alloc("Ib Z p0x5a [6 ]5 s Ib", &blob, &blob_len, 1234, "TEST", 4567) == 0);
    TEST_ASSERT(blob_len == 19 &&
		!memcmp(blob, "\x00\x00\x04\xd2\x00\x00\x00\x07\x5a\x5a\x54\x45\x53\x54\x5a\x00\x00\x11\xd7", blob_len));
    free(blob);
  }

  {
    struct assh_bignum_s a;
    bignum_set(&a, 80, 0x1234);

    TEST_ASSERT(blob_write_alloc("Gs", &blob, &blob_len, &a) == 0);
    TEST_ASSERT(blob_len == 6 &&
		!memcmp(blob, "\x00\x00\x00\x02\x12\x34", blob_len));
    assh_bignum_release(&context, &a);
    free(blob);
  }

  {
    struct assh_bignum_s a;
    bignum_set(&a, 80, 0xf234);

    TEST_ASSERT(blob_write_alloc("Gs", &blob, &blob_len, &a) == 0);
    TEST_ASSERT(blob_len == 7 &&
		!memcmp(blob, "\x00\x00\x00\x03\x00\xf2\x34", blob_len));
    assh_bignum_release(&context, &a);
    free(blob);
  }

  {
    struct assh_bignum_s a;
    bignum_set(&a, 80, 0x1234);

    TEST_ASSERT(blob_write_alloc("Ga", &blob, &blob_len, &a) == 0);
    TEST_ASSERT(blob_len == 4 &&
		!memcmp(blob, "\x02\x02\x12\x34", blob_len));
    assh_bignum_release(&context, &a);
    free(blob);
  }

  {
    struct assh_bignum_s a;
    bignum_set(&a, 80, 0x1234);

    TEST_ASSERT(blob_write_alloc("Gb", &blob, &blob_len, &a) == 0);
    TEST_ASSERT(blob_len == 10 &&
		!memcmp(blob, "\x00\x00\x00\x00\x00\x00\x00\x00\x12\x34", blob_len));
    assh_bignum_release(&context, &a);
    free(blob);
  }

  {
    struct assh_bignum_s a;
    bignum_set(&a, 80, 0x1234);

    TEST_ASSERT(blob_write_alloc("Grb", &blob, &blob_len, &a) == 0);
    TEST_ASSERT(blob_len == 10 &&
		!memcmp(blob, "\x34\x12\x00\x00\x00\x00\x00\x00\x00\x00", blob_len));
    assh_bignum_release(&context, &a);
    free(blob);
  }

  {
    struct assh_bignum_s a;
    bignum_set(&a, 80, 0xf234);

    TEST_ASSERT(blob_write_alloc("Zb (Gs Ga)s Zb", &blob, &blob_len, "A", &a, &a, "B") == 0);
    TEST_ASSERT(blob_len == 18 &&
		!memcmp(blob, "\x41\x00\x00\x00\x0c\x00\x00\x00\x03\x00\xf2\x34\x02\x03\x00\xf2\x34\x42", blob_len));
    assh_bignum_release(&context, &a);
    free(blob);
  }

}

static void test_write_error()
{
  size_t blob_len;
  uint8_t blob_[32], *blob = blob_;

  blob_len = 3;
  TEST_ASSERT(assh_blob_write("Zb", blob, &blob_len, "TEST") != 0);

  blob_len = 4;
  TEST_ASSERT(assh_blob_write("Zb", blob, &blob_len, "TEST") == 0);

  blob_len = 3;
  TEST_ASSERT(assh_blob_write("Zs", blob, &blob_len, "TEST") != 0);

  blob_len = 4;
  TEST_ASSERT(assh_blob_write("Zs", blob, &blob_len, "TEST") != 0);

  blob_len = 5;
  TEST_ASSERT(assh_blob_write("Zs", blob, &blob_len, "TEST") != 0);

  blob_len = 8;
  TEST_ASSERT(assh_blob_write("Zs", blob, &blob_len, "TEST") == 0);

  blob_len = 1;
  TEST_ASSERT(assh_blob_write("Za1", blob, &blob_len, "TEST") != 0);

  blob_len = 5;
  TEST_ASSERT(assh_blob_write("Za1", blob, &blob_len, "TEST") != 0);

  blob_len = 6;
  TEST_ASSERT(assh_blob_write("Za1", blob, &blob_len, "TEST") == 0);

  blob_len = 10;
  TEST_ASSERT(assh_blob_write("Zb (Zb)s", blob, &blob_len, "A", "TEST") == 0);

  blob_len = 9;
  TEST_ASSERT(assh_blob_write("Zb (Zb)s", blob, &blob_len, "A", "TEST") == 0);

  blob_len = 8;
  TEST_ASSERT(assh_blob_write("Zb (Zb)s", blob, &blob_len, "A", "TEST") != 0);

  blob_len = 7;
  TEST_ASSERT(assh_blob_write("Zb (Zb)s", blob, &blob_len, "A", "TEST") != 0);

  blob_len = 4;
  TEST_ASSERT(assh_blob_write("Zb (Zb)s", blob, &blob_len, "A", "TEST") != 0);

  blob_len = 4;
  TEST_ASSERT(assh_blob_write("Zb", blob, &blob_len, "TEST") == 0);

  blob_len = 4;
  TEST_ASSERT(assh_blob_write("Z>5b", blob, &blob_len, "TEST") != 0);

  blob_len = 4;
  TEST_ASSERT(assh_blob_write("Z<5b", blob, &blob_len, "TEST") != 0);
}

static void test_scan_ok()
{
  {
    static const uint8_t *blob = (const uint8_t *)"";
    size_t len = 0;
    TEST_ASSERT(assh_blob_scan(&context, "", &blob, &len) == 0);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"";
    size_t len = 0;
    TEST_ASSERT(assh_blob_scan(&context, "o", &blob, &len) == 0);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\xab\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "so", &blob, &len) == 0);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x01\x04\xab\xcd\xef\x91";
    size_t len = 6;
    TEST_ASSERT(assh_blob_scan(&context, "ao", &blob, &len) == 0);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x12\x34\x56";
    size_t len = 3;
    int x;
    TEST_ASSERT(assh_blob_scan(&context, "b3Io", &blob, &len, &x) == 0);
    TEST_ASSERT(x == 0x123456);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x12\x34\x56";
    size_t len = 3;
    int x;
    TEST_ASSERT(assh_blob_scan(&context, "b3Ir", &blob, &len, &x) == 0);
    TEST_ASSERT(x == 0x563412);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x12\x34\x56\x78";
    size_t len = 4;
    int x;
    TEST_ASSERT(assh_blob_scan(&context, "b4I", &blob, &len, &x) == 0);
    TEST_ASSERT(x == 0x12345678);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x12\x34\x56\x78";
    size_t len = 4;
    int x;
    TEST_ASSERT(assh_blob_scan(&context, "b4Ir", &blob, &len, &x) == 0);
    TEST_ASSERT(x == 0x78563412);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x12\x34\x56";
    size_t len = 3;
    long long int x;
    TEST_ASSERT(assh_blob_scan(&context, "b3L", &blob, &len, &x) == 0);
    TEST_ASSERT(x == 0x123456);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x12\x34\x56";
    size_t len = 3;
    long long int x;
    TEST_ASSERT(assh_blob_scan(&context, "b3Lr", &blob, &len, &x) == 0);
    TEST_ASSERT(x == 0x563412);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x12\x34\x56\x78\xab\xcd\xef\x91";
    size_t len = 8;
    long long int x;
    TEST_ASSERT(assh_blob_scan(&context, "b8L", &blob, &len, &x) == 0);
    TEST_ASSERT(x == 0x12345678abcdef91);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x12\x34\x56\x78\xab\xcd\xef\x91";
    size_t len = 8;
    long long int x;
    TEST_ASSERT(assh_blob_scan(&context, "b8Lr", &blob, &len, &x) == 0);
    TEST_ASSERT(x == 0x91efcdab78563412);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\xab\xcd\xef\x91";
    size_t len = 8, s = 1;
    TEST_ASSERT(assh_blob_scan(&context, "sT", &blob, &len, &s) == 0);
    TEST_ASSERT(s == 4);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\xab\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "st", &blob, &len, 4) == 0);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\xab\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "st>", &blob, &len, 3) == 0);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\xab\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "st<=", &blob, &len, 4) == 0);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\xab\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "st>=", &blob, &len, 4) == 0);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\xab\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "st4", &blob, &len) == 0);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\xab\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "st3>", &blob, &len) == 0);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\xab\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "st4<=", &blob, &len) == 0);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\xab\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "st4>=", &blob, &len) == 0);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\xab\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "st44!", &blob, &len) == 0);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\x1b\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "su29", &blob, &len) == 0);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\x00\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "su24", &blob, &len) == 0);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\x00\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "b8u35", &blob, &len) == 0);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\x00\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "b8u36!", &blob, &len) == 0);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\x00\xcd\xef\x91";
    size_t len = 8, l = 0;
    TEST_ASSERT(assh_blob_scan(&context, "b8J", &blob, &len, &l) == 0);
    TEST_ASSERT(l == 35);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\x00\xcd\xef\x91";
    size_t len = 8, l = 0;
    TEST_ASSERT(assh_blob_scan(&context, "sJ", &blob, &len, &l) == 0);
    TEST_ASSERT(l == 24);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x02\x03\x0d\xef\x91";
    size_t len = 5, l = 0;
    TEST_ASSERT(assh_blob_scan(&context, "aJ", &blob, &len, &l) == 0);
    TEST_ASSERT(l == 20);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"testbuffer";
    size_t len = 10;
    TEST_ASSERT(assh_blob_scan(&context, "b10 e0;4;test e4;6;buffer", &blob, &len) == 0);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"test buffer";
    size_t len = 11;
    TEST_ASSERT(assh_blob_scan(&context, "b11 e0;4;test e5;6;buffer", &blob, &len) == 0);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x02\xab\xcd\x00\x00\x00\x01\xef";
    size_t len = 11, lS0, lT0, lS1, lT1;
    const uint8_t *pH0, *pC0, *pN0, *pH1, *pC1, *pN1, *b = blob;
    TEST_ASSERT(assh_blob_scan(&context, "sHCNST sHCNST", &b, &len,
			       &pH0, &pC0, &pN0, &lS0, &lT0,
			       &pH1, &pC1, &pN1, &lS1, &lT1) == 0);

    TEST_ASSERT(lS0 == 6);
    TEST_ASSERT(lT0 == 2);
    TEST_ASSERT(lS1 == 5);
    TEST_ASSERT(lT1 == 1);

    TEST_ASSERT(pH0 == blob);
    TEST_ASSERT(pH1 == blob + 6);
    TEST_ASSERT(pC0 == blob + 4);
    TEST_ASSERT(pC1 == blob + 10);
    TEST_ASSERT(pN0 == blob + 6);
    TEST_ASSERT(pN1 == blob + 11);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x01\x02\xab\xcd\x02\x01\xef";
    size_t len = 7, lS0, lT0, lS1, lT1;
    const uint8_t *pH0, *pC0, *pN0, *pH1, *pC1, *pN1, *b = blob;
    TEST_ASSERT(assh_blob_scan(&context, "aHCNST a2HCNST", &b, &len,
			       &pH0, &pC0, &pN0, &lS0, &lT0,
			       &pH1, &pC1, &pN1, &lS1, &lT1) == 0);

    TEST_ASSERT(lS0 == 4);
    TEST_ASSERT(lT0 == 2);
    TEST_ASSERT(lS1 == 3);
    TEST_ASSERT(lT1 == 1);

    TEST_ASSERT(pH0 == blob);
    TEST_ASSERT(pH1 == blob + 4);
    TEST_ASSERT(pC0 == blob + 2);
    TEST_ASSERT(pC1 == blob + 6);
    TEST_ASSERT(pN0 == blob + 4);
    TEST_ASSERT(pN1 == blob + 7);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x02\xab\xcd\x00\x00\x00\x01\xef";
    struct assh_buffer_s b0, b1;
    size_t len = 11;
    const uint8_t *b = blob;
    TEST_ASSERT(assh_blob_scan(&context, "sB sB", &b, &len,
			       &b0, &b1) == 0);

    TEST_ASSERT(b0.size == 2);
    TEST_ASSERT(b0.data == blob + 4);

    TEST_ASSERT(b1.size == 1);
    TEST_ASSERT(b1.data == blob + 10);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x02\x4b\xcdtest";
    struct assh_bignum_s a;

    assh_bignum_init(&context, &a, 0);

    size_t len = 10;
    const uint8_t *b = blob;
    TEST_ASSERT(assh_blob_scan(&context, "sG b4e0;4;test", &b, &len, &a) == 0);

    TEST_ASSERT(a.bits == 15);
    TEST_ASSERT(!a.secret);

    TEST_ASSERT(bignum_cmp(&a, 0x4bcd));
    TEST_ASSERT(!bignum_cmp(&a, 0xcd4b));

    assh_bignum_release(&context, &a);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x02\x4b\xcdtest";
    struct assh_bignum_s a;

    assh_bignum_init(&context, &a, 256);

    size_t len = 10;
    const uint8_t *b = blob;
    TEST_ASSERT(assh_blob_scan(&context, "sG b4e0;4;test", &b, &len, &a) == 0);

    TEST_ASSERT(a.bits == 256);
    TEST_ASSERT(!a.secret);

    TEST_ASSERT(bignum_cmp(&a, 0x4bcd));
    TEST_ASSERT(!bignum_cmp(&a, 0xcd4b));

    assh_bignum_release(&context, &a);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x02\x4b\xcdtest";
    struct assh_bignum_s a;

    assh_bignum_init(&context, &a, 256);

    size_t len = 10;
    const uint8_t *b = blob;
    TEST_ASSERT(assh_blob_scan(&context, "sG! b4e0;4;test", &b, &len, &a) == 0);

    TEST_ASSERT(a.bits == 256);
    TEST_ASSERT(a.secret);

    TEST_ASSERT(bignum_cmp(&a, 0x4bcd));
    TEST_ASSERT(!bignum_cmp(&a, 0xcd4b));

    assh_bignum_release(&context, &a);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x4e\xcdtest";
    struct assh_bignum_s a;

    assh_bignum_init(&context, &a, 0);

    size_t len = 6;
    const uint8_t *b = blob;
    TEST_ASSERT(assh_blob_scan(&context, "b2G! b4e0;4;test", &b, &len, &a) == 0);

    TEST_ASSERT(a.bits == 15);
    TEST_ASSERT(a.secret);

    TEST_ASSERT(bignum_cmp(&a, 0x4ecd));
    TEST_ASSERT(!bignum_cmp(&a, 0xcd4e));

    assh_bignum_release(&context, &a);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x4e\xcdtest";
    struct assh_bignum_s a;

    assh_bignum_init(&context, &a, 0);

    size_t len = 6;
    const uint8_t *b = blob;
    TEST_ASSERT(assh_blob_scan(&context, "b2Gr! b4e0;4;test", &b, &len, &a) == 0);

    TEST_ASSERT(a.bits == 16);
    TEST_ASSERT(a.secret);

    TEST_ASSERT(!bignum_cmp(&a, 0x4ecd));
    TEST_ASSERT(bignum_cmp(&a, 0xcd4e));

    assh_bignum_release(&context, &a);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x12\x34\x56";
    size_t len = 3;
    int x = 0, y = 0;
    TEST_ASSERT(assh_blob_scan(&context, "(b3I)(b3Ir)", &blob, &len, &x, &y) == 0);
    TEST_ASSERT(x == 0x123456);
    TEST_ASSERT(y == 0x563412);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x12\x34\x56";
    size_t len = 3;
    int x = 0, y = 0;
    TEST_ASSERT(assh_blob_scan(&context, "((b3Io)(b3Ir))", &blob, &len, &x, &y) == 0);
    TEST_ASSERT(x == 0x123456);
    TEST_ASSERT(y == 0x563412);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x03\x12\x34\x56\x78";
    size_t len = 8;
    int x = 0, y = 0, z = 0;
    TEST_ASSERT(assh_blob_scan(&context, "s((b3I)(b3Ir))b1I", &blob, &len, &x, &y, &z) == 0);
    TEST_ASSERT(x == 0x123456);
    TEST_ASSERT(y == 0x563412);
    TEST_ASSERT(z == 0x78);
  }

#warning test ( )
}

static void test_scan_error()
{
  {
    static const uint8_t *blob = (const uint8_t *)"\x12\x34\x56";
    size_t len = 2;
    int x;
    TEST_ASSERT(assh_blob_scan(&context, "b3I", &blob, &len, &x)
		== ASSH_ERR_INPUT_OVERFLOW);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x05\xab\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "s", &blob, &len)
		== ASSH_ERR_INPUT_OVERFLOW);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x02\xab\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "so", &blob, &len)
		== ASSH_ERR_OUTPUT_OVERFLOW);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x01\x05\xab\xcd\xef\x91";
    size_t len = 6;
    TEST_ASSERT(assh_blob_scan(&context, "a", &blob, &len)
		== ASSH_ERR_INPUT_OVERFLOW);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\xab\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "st", &blob, &len, 7)
		== ASSH_ERR_BAD_DATA);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\xab\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "st", &blob, &len, 9)
		== ASSH_ERR_BAD_DATA);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\xab\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "st>", &blob, &len, 5)
		== ASSH_ERR_BAD_DATA);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\xab\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "st<", &blob, &len, 3)
		== ASSH_ERR_BAD_DATA);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\xab\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "st<", &blob, &len, 4)
		== ASSH_ERR_BAD_DATA);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\xab\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "st>", &blob, &len, 4)
		== ASSH_ERR_BAD_DATA);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\xab\xcd\xef\x91";
    size_t len = 8;
    long long int x;
    TEST_ASSERT(assh_blob_scan(&context, "st7", &blob, &len, &x)
		== ASSH_ERR_BAD_DATA);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\xab\xcd\xef\x91";
    size_t len = 8;
    long long int x;
    TEST_ASSERT(assh_blob_scan(&context, "st9", &blob, &len, &x)
		== ASSH_ERR_BAD_DATA);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\xab\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "st5>", &blob, &len)
		== ASSH_ERR_BAD_DATA);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\xab\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "st3<", &blob, &len)
		== ASSH_ERR_BAD_DATA);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\xab\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "st4<", &blob, &len)
		== ASSH_ERR_BAD_DATA);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\xab\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "st4>", &blob, &len)
		== ASSH_ERR_BAD_DATA);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\xab\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "st4!", &blob, &len)
		== ASSH_ERR_BAD_DATA);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x04\x00\xcd\xef\x91";
    size_t len = 8;
    TEST_ASSERT(assh_blob_scan(&context, "b8u35!=", &blob, &len)
		== ASSH_ERR_BAD_DATA);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"tEstbuffer";
    size_t len = 10;
    TEST_ASSERT(assh_blob_scan(&context, "b10 e0;4;test e4;6;buffer", &blob, &len)
		== ASSH_ERR_BAD_DATA);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"testbUffer";
    size_t len = 10;
    TEST_ASSERT(assh_blob_scan(&context, "b10 e0;4;test e4;6;buffer", &blob, &len)
		== ASSH_ERR_BAD_DATA);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"testbUffer";
    size_t len = 9;
    TEST_ASSERT(assh_blob_scan(&context, "b10 e0;4;test e4;6;buffer", &blob, &len)
		== ASSH_ERR_INPUT_OVERFLOW);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"testbUffer";
    size_t len = 10;
    TEST_ASSERT(assh_blob_scan(&context, "b9 e0;4;test e4;6;buffer", &blob, &len)
		== ASSH_ERR_INPUT_OVERFLOW);
  }

  {
    static const uint8_t *blob = (const uint8_t *)"\x00\x00\x00\x02\x4b\xcd";
    struct assh_bignum_s a;

    assh_bignum_init(&context, &a, 10);

    size_t len = 6;
    const uint8_t *b = blob;
    TEST_ASSERT(assh_blob_scan(&context, "sG", &b, &len, &a)
		== ASSH_ERR_OUTPUT_OVERFLOW);

    assh_bignum_release(&context, &a);
  }
}

int
main(int argc, char **argv)
{
  if (assh_deps_init())
    return -1;

  if (assh_context_init(&context, ASSH_CLIENT_SERVER,
			NULL, NULL, NULL, NULL))
    return -1;

  test_write_ok();
  test_write_error();
  test_scan_ok();
  test_scan_error();

  return 0;
}
