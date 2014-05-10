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

  Based on curve25519 ref10 implementation, rewritten for compactness.

*/

#include <assh/assh_25519num.h>

/*
  assh_25519num_t the field is \Z/(2^255-19).
  An element t, entries t[0]...t[9], represents the integer
  t[0] + 2^26*t[1] + 2^51*t[2] + 2^77*t[3] + 2^102*t[4] + ... + 2^230*t[9].
  Bounds on each t[i] vary depending on context.
*/

void assh_25519num_cst(assh_25519num_t h, unsigned int cst)
{
  unsigned int i;
  h[0] = cst;
  for (i = 1; i < 10; i++)
    h[i] = 0;
}

void assh_25519num_add(assh_25519num_t h, const assh_25519num_t f, const assh_25519num_t g)
{
  unsigned int i;
  for (i = 0; i < 10; i++)
    h[i] = f[i] + g[i];
}

void assh_25519num_sub(assh_25519num_t h, const assh_25519num_t f, const assh_25519num_t g)
{
  unsigned int i;
  for (i = 0; i < 10; i++)
    h[i] = f[i] - g[i];
}

void assh_25519num_neg(assh_25519num_t h, const assh_25519num_t f)
{
  unsigned int i;
  for (i = 0; i < 10; i++)
    h[i] = -f[i];
}

void assh_25519num_cmov(assh_25519num_t f, const assh_25519num_t g, unsigned int b)
{
  unsigned int i;
  b--;
  for (i = 0; i < 10; i++)
    f[i] = (g[i] & ~b) | (f[i] & b);
}

void assh_25519num_cswap(assh_25519num_t f, assh_25519num_t g, unsigned int b)
{
  unsigned int i;
  b = ~(b - 1);
  for (i = 0; i < 10; i++)
    {
      g[i] ^= f[i] & b;
      f[i] ^= g[i] & b;
      g[i] ^= f[i] & b;
    }
}

void assh_25519num_move(assh_25519num_t h, const assh_25519num_t f)
{
  unsigned int i;
  for (i = 0; i < 10; i++)
    h[i] = f[i];
}

assh_bool_t assh_25519num_isnonzero(const assh_25519num_t f)
{
  unsigned int i;
  int r = 0;
  for (i = 0; i < 10; i++)
    r |= f[i];
  return r;
}

void assh_25519num_mul(assh_25519num_t h, const assh_25519num_t f, const assh_25519num_t g)
{
  int32_t m[20];
  int64_t r[10];
  int64_t carry, t;
  uint_fast8_t i, j;

  /*
    r[0] = f0*g0 + f1*g9*38 + f2*g8*19 + f3*g7*38 + f4*g6*19 + f5*g5*38 + f6*g4*19 + f7*g3*38 + f8*g2*19 + f9*g1*38
    r[1] = f0*g1 + f1*g0    + f2*g9*19 + f3*g8*19 + f4*g7*19 + f5*g6*19 + f6*g5*19 + f7*g4*19 + f8*g3*19 + f9*g2*19
    r[2] = f0*g2 + f1*g1*2  + f2*g0    + f3*g9*38 + f4*g8*19 + f5*g7*38 + f6*g6*19 + f7*g5*38 + f8*g4*19 + f9*g3*38
    r[3] = f0*g3 + f1*g2    + f2*g1    + f3*g0    + f4*g9*19 + f5*g8*19 + f6*g7*19 + f7*g6*19 + f8*g5*19 + f9*g4*19
    r[4] = f0*g4 + f1*g3*2  + f2*g2    + f3*g1*2  + f4*g0    + f5*g9*38 + f6*g8*19 + f7*g7*38 + f8*g6*19 + f9*g5*38
    r[5] = f0*g5 + f1*g4    + f2*g3    + f3*g2    + f4*g1    + f5*g0    + f6*g9*19 + f7*g8*19 + f8*g7*19 + f9*g6*19
    r[6] = f0*g6 + f1*g5*2  + f2*g4    + f3*g3*2  + f4*g2    + f5*g1*2  + f6*g0    + f7*g9*38 + f8*g8*19 + f9*g7*38
    r[7] = f0*g7 + f1*g6    + f2*g5    + f3*g4    + f4*g3    + f5*g2    + f6*g1    + f7*g0    + f8*g9*19 + f9*g8*19
    r[8] = f0*g8 + f1*g7*2  + f2*g6    + f3*g5*2  + f4*g4    + f5*g3*2  + f6*g2    + f7*g1*2  + f8*g0    + f9*g9*38
    r[9] = f0*g9 + f1*g8    + f2*g7    + f3*g6    + f4*g5    + f5*g4    + f6*g3    + f7*g2    + f8*g1    + f9*g0
  */

  /* init */
  for (i = 0; i < 10; i++)
    {
      m[i] = g[i] * 19;
      m[i+10] = g[i];
      r[i] = 0;
    }

  /* multiply */
  for (i = 0; i < 10; i += 2)
    {
      for (j = 0; j < 10; j++)
	{
	  int64_t a = f[i    ] * (int64_t)m[10 + j - i];
	  int64_t b = f[i + 1] * (int64_t)m[9  + j - i];
	  if (!(j & 1))
	    b <<= 1;
	  r[j] += a + b;
	}
    }

  /* propagate carry */
  for (i = 0; ; i += 2)
    {
      carry = (r[i] + (1LL << 25)) >> 26;
      t = r[i+1] + carry;
      h[i] = r[i] -= carry << 26;
      carry = (t + (1LL << 24)) >> 25;
      h[i+1] = r[i+1] = t - (carry << 25);
      if (i == 8)
	break;
      r[i+2] += carry;
    }
  r[0] += carry * 19;

  carry = (r[0] + (1LL << 25)) >> 26;
  h[1] = r[1] + carry;
  h[0] = r[0] - (carry << 26);
}

void assh_25519num_bytecode(const uint16_t *ops, unsigned tmps_count,
			    unsigned int args_count, ...)
{
  int32_t *regs[tmps_count + args_count];
  assh_25519num_t tmps[tmps_count];
  unsigned int i;
  va_list ap;

  va_start(ap, args_count);
  for (i = 0; i < tmps_count; i++)
    regs[i] = tmps[i];
  for (; i < tmps_count + args_count; i++)
    regs[i] = va_arg(ap, int32_t *);
  va_end(ap);

  for (; *ops != 0; ops++) {
    unsigned int dst = *ops & 0x000f;
    unsigned int src1 = (*ops & 0x00f0) >> 4;
    unsigned int src2 = (*ops & 0x1f00) >> 8;
    unsigned int op = (*ops & 0xe000) >> 13;
    unsigned int i;

    switch (op)
      {
      case 0:
        /* square */
        assh_25519num_sq(regs[dst], regs[src1]);
        src2 = src2 & 0x10 ? (src2 << 4) & 0xf0 : src2;
        for (i = 1; i < src2; i++)
          assh_25519num_sq(regs[dst], regs[dst]);
        break;
      case 1:
        assh_25519num_add(regs[dst], regs[src1], regs[src2]);
        break;
      case 2:
        assh_25519num_sub(regs[dst], regs[src1], regs[src2]);
        break;
      case 3:
        assh_25519num_mul(regs[dst], regs[src1], regs[src2]);
        break;
      case 4:
        assh_25519num_move(regs[dst], regs[src1]);
        break;
      case 5:
        assh_25519num_cst(regs[dst], src1);
        break;
      }
  }
}

/** Invert macro instruction for the @ref assh_25519num_bytecode virtual machine */
#define ASSH_25519_OPS_INVERT(t0, t1, t2, t3, out, in)                          \
        ASSH_25519_OP_SQ(t0, in, 1),                                            \
        ASSH_25519_OP_SQ(t1, t0, 1),                                            \
        ASSH_25519_OP_SQ(t1, t1, 1),                                            \
        ASSH_25519_OP_MUL(t1, in, t1),                                          \
        ASSH_25519_OP_MUL(t0, t0, t1),                                          \
        ASSH_25519_OP_SQ(t2, t0, 1),                                            \
        ASSH_25519_OP_MUL(t1, t1, t2),                                          \
        ASSH_25519_OP_SQ(t2, t1, 1),                                            \
        ASSH_25519_OP_SQ(t2, t2, 4),                                            \
        ASSH_25519_OP_MUL(t1, t2, t1),                                          \
        ASSH_25519_OP_SQ(t2, t1, 1),                                            \
        ASSH_25519_OP_SQ(t2, t2, 9),                                            \
        ASSH_25519_OP_MUL(t2, t2, t1),                                          \
        ASSH_25519_OP_SQ(t3, t2, 1),                                            \
        ASSH_25519_OP_SQ(t3, t3, 0x11), ASSH_25519_OP_SQ(t3, t3, 0x03), /* 16 + 3 times */ \
        ASSH_25519_OP_MUL(t2, t3, t2),                                          \
        ASSH_25519_OP_SQ(t2, t2, 10),                                           \
        ASSH_25519_OP_MUL(t1, t2, t1),                                          \
        ASSH_25519_OP_SQ(t2, t1, 1),                                            \
        ASSH_25519_OP_SQ(t2, t2, 0x13), ASSH_25519_OP_SQ(t2, t2, 0x01), /* 48 + 1 times */ \
        ASSH_25519_OP_MUL(t2, t2, t1),                                          \
        ASSH_25519_OP_SQ(t3, t2, 1),                                            \
        ASSH_25519_OP_SQ(t3, t3, 0x16), ASSH_25519_OP_SQ(t3, t3, 0x03), /* 96 + 3 times */ \
        ASSH_25519_OP_MUL(t2, t3, t2),                                          \
        ASSH_25519_OP_SQ(t2, t2, 0x13), ASSH_25519_OP_SQ(t2, t2, 0x02), /* 48 + 2 times */ \
        ASSH_25519_OP_MUL(t1, t2, t1),                                          \
        ASSH_25519_OP_SQ(t1, t1, 5),                                            \
        ASSH_25519_OP_MUL(out, t1, t0)

void assh_25519num_invert(assh_25519num_t out, const assh_25519num_t z)
{
  static const uint16_t ops[] = {
    ASSH_25519_OPS_INVERT(0, 1, 2, 3, 4, 5),
    ASSH_25519_OP_END()
  };

  assh_25519num_bytecode(ops, 4, 2, out, z);
}

static inline uint32_t load_3(const uint8_t *in)
{
  uint32_t result;

  result = (uint32_t) in[0];
  result |= ((uint32_t) in[1]) << 8;
  result |= ((uint32_t) in[2]) << 16;

  return result;
}

static inline uint32_t load_4(const uint8_t *in)
{
  uint32_t result;

  result = (uint32_t) in[0];
  result |= ((uint32_t) in[1]) << 8;
  result |= ((uint32_t) in[2]) << 16;
  result |= ((uint32_t) in[3]) << 24;
  
  return result;
}

void assh_25519num_from_data(assh_25519num_t h, const uint8_t *s)
{
  h[0] = load_4(s);
  h[1] = load_3(s + 4) << 6;
  h[2] = load_3(s + 7) << 5;
  h[3] = load_3(s + 10) << 3;
  h[4] = load_3(s + 13) << 2;
  h[5] = load_4(s + 16);
  h[6] = load_3(s + 20) << 7;
  h[7] = load_3(s + 23) << 5;
  h[8] = load_3(s + 26) << 4;
  h[9] = (load_3(s + 29) & 0x7fffff) << 2;

  int64_t carry = (h[9] + (int64_t)(1 << 24)) >> 25;
  h[9] -= carry << 25;
  int64_t ca = (uint32_t)h[0] + carry * 19;

  unsigned int i, j;
  for (j = i = 1; i < 10; i++, j ^= 1) {
    carry = (ca + (int64_t)(1 << (24 + j))) >> (25 + j);
    h[i - 1] = ca - (carry << (25 + j));
    ca = (int64_t)(uint32_t)h[i] + carry;
  }
  h[9] = ca;
}

void assh_25519num_to_data(uint8_t *s, const assh_25519num_t h)
{
  assh_25519num_t t;
  int32_t carry;
  unsigned int i, j, k;

  assh_25519num_move(t, h);

  int32_t q = (19 * t[9] + (1 << 24)) >> 25;
  for (i = 0; i < 10; i++)
    q = (t[i] + q) >> (26 - (i & 1));

  t[0] += 19 * q;

  for (i = 0; i < 9; i++) 
    {
      carry = t[i] >> (26 - (i & 1));
      t[i + 1] += carry;
      t[i] -= carry << (26 - (i & 1));
    }
  carry = t[9] >> 25;
  t[9] -= carry << 25;

  uint64_t acc = 0;
  for (k = j = i = 0; i < 32; i++)
    {
      if (j < 8 && k < 10)
        {
          acc |= (uint64_t)t[k] << j;
          j += 26 - (k++ & 1);
        }
      s[i] = acc;
      acc >>= 8;
      j -= 8;
    }
}

assh_error_t assh_25519num_point_mul(assh_25519num_t result,
				     const assh_25519num_t basepoint,
				     const assh_25519key_t scalar)
{
  assh_error_t err;
  assh_25519num_t x1, x2, z2, x3, z3;
  unsigned int swap, b;
  int pos;

  ASSH_CHK_RET((scalar[0] & 0x07) != 0x00 ||
	       (scalar[31] & 0xc0) != 0x40, ASSH_ERR_NUM_OVERFLOW);

  assh_25519num_move(x1, basepoint);

  assh_25519num_cst(x2, 1);
  assh_25519num_cst(z2, 0);
  assh_25519num_move(x3, x1);
  assh_25519num_cst(z3, 1);

  swap = 0;
  for (pos = 254; pos >= 0; --pos)
    {
      static const assh_25519num_t c121666 = { 121666 };

      b = scalar[pos / 8] >> (pos & 7);
      b &= 1;
      swap ^= b;
      assh_25519num_cswap(x2, x3, swap);
      assh_25519num_cswap(z2, z3, swap);
      swap = b;

#define X1 2
#define X2 3
#define Z2 4
#define X3 5
#define Z3 6

      static const uint16_t ops2[] = {
	ASSH_25519_OP_SUB(	0,	X3,	Z3),
	ASSH_25519_OP_SUB(	1,	X2,	Z2),
	ASSH_25519_OP_ADD(	X2,	X2,	Z2),
	ASSH_25519_OP_ADD(	Z2,	X3,	Z3),
	ASSH_25519_OP_MUL(	Z3,	0,	X2),
	ASSH_25519_OP_MUL(	Z2,	Z2,	1),
	ASSH_25519_OP_SQ( 	 0,	1,	1),
	ASSH_25519_OP_SQ( 	 1,	X2,	1),
	ASSH_25519_OP_ADD(	X3,	Z3,	Z2),
	ASSH_25519_OP_SUB(	Z2,	Z3,	Z2),
	ASSH_25519_OP_MUL(	X2,	1,	0),
	ASSH_25519_OP_SUB(	 1,	1,	0),
	ASSH_25519_OP_SQ( 	Z2,	Z2,	1),
	ASSH_25519_OP_MUL(	Z3,	1,	7),
	ASSH_25519_OP_SQ( 	X3,	X3,	1),
	ASSH_25519_OP_ADD(	0,	0,	Z3),
	ASSH_25519_OP_MUL(	Z3,	X1,	Z2),
	ASSH_25519_OP_MUL(	Z2,	1,	0),
	ASSH_25519_OP_END()
      };

      assh_25519num_bytecode(ops2, 2, 6, x1, x2, z2, x3, z3, c121666);
    }

  assh_25519num_cswap(x2, x3, swap);
  assh_25519num_cswap(z2, z3, swap);

  assh_25519num_invert(z2, z2);
  assh_25519num_mul(result, x2, z2);

  return ASSH_OK;
}

