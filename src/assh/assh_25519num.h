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

#ifndef ASSH_25519NUM_H
#define ASSH_25519NUM_H

#include "assh_prng.h"

#include <stdarg.h>
#include <stdint.h>

typedef int32_t assh_25519num_t[10];

typedef uint8_t assh_25519key_t[32];

/** @This loads a constant in a field element */
void assh_25519num_cst(assh_25519num_t h, unsigned int cst);

/** @This initializes a field element from raw data */
void assh_25519num_from_data(assh_25519num_t h, const uint8_t *s);

/** @This initializes raw data from a field element */
void assh_25519num_to_data(uint8_t *s, const assh_25519num_t h);

/** @This copies a field element value */
void assh_25519num_move(assh_25519num_t h, const assh_25519num_t f);

/** @This tests is a field element is zero */
assh_bool_t assh_25519num_isnonzero(const assh_25519num_t f);

/** @This conditionally copies a field element */
void assh_25519num_cmov(assh_25519num_t f, const assh_25519num_t g, unsigned int b);

/** @This conditionally swaps a field element */
void assh_25519num_cswap(assh_25519num_t f, assh_25519num_t g, unsigned int b);

/** @This negates a field element */
void assh_25519num_neg(assh_25519num_t h, const assh_25519num_t f);

/** @This adds two field elements */
void assh_25519num_add(assh_25519num_t h, const assh_25519num_t f, const assh_25519num_t g);

/** @This subtracts two field elements */
void assh_25519num_sub(assh_25519num_t h, const assh_25519num_t f, const assh_25519num_t g);

/** @This compute the inverse of a field element */
void assh_25519num_invert(assh_25519num_t out, const assh_25519num_t z);

/** @This multiply two field elements */
void assh_25519num_mul(assh_25519num_t h, const assh_25519num_t f, const assh_25519num_t g);

/** @This square a field element */
static inline void assh_25519num_sq(assh_25519num_t h, const assh_25519num_t f)
{
  return assh_25519num_mul(h, f, f);
}

/** @This performs elliptic curve point multiplication */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_25519num_point_mul(assh_25519num_t result,
			const assh_25519num_t basepoint,
			const assh_25519key_t scalar);

/** Add opcode for the @ref assh_25519num_bytecode virtual machine */
#define ASSH_25519_OP_ADD(dst, src1, src2) ((dst) | ((src1) << 4) | ((src2) << 8) | 0x2000)
/** Subtract opcode for the @ref assh_25519num_bytecode virtual machine */
#define ASSH_25519_OP_SUB(dst, src1, src2) ((dst) | ((src1) << 4) | ((src2) << 8) | 0x4000)
/** Multiply opcode for the @ref assh_25519num_bytecode virtual machine */
#define ASSH_25519_OP_MUL(dst, src1, src2) ((dst) | ((src1) << 4) | ((src2) << 8) | 0x6000)
/** Square opcode for the @ref assh_25519num_bytecode virtual machine */
#define ASSH_25519_OP_SQ(dst, src1, cnt )  ((dst) | ((src1) << 4) | ((cnt) << 8) | 0x0000)
/** Move opcode for the @ref assh_25519num_bytecode virtual machine */
#define ASSH_25519_OP_MOVE(dst, src)       ((dst) | ((src) << 4) | 0x8000)
/** Constant load opcode for the @ref assh_25519num_bytecode virtual machine */
#define ASSH_25519_OP_SET(dst, cst)        ((dst) | ((cst) << 4) | 0xa000)
/** Bytecode end opcode for the @ref assh_25519num_bytecode virtual machine */
#define ASSH_25519_OP_END()                0x0000

/**

   Execute operations specified by the bytecode on provided @ref
   assh_25519num_t field element arguments and temporaries.

@code R
      op  src2  src1 dst
      xxx xxxxx xxxx xxxx
      |   |      |    |
      |   |      |    \------- destination value index
      |   |      |
      |   |      \------- source 1 value index
      |   |
      |   \------- source 2 value index / count
      |
      \---------- op
                  000: square(dst, src1, times)
                       if times < 16: count=times
                                else: count=(times % 16) * 16
                  001: add(dst, src1, src2)
                  010: sub(dst, src1, src2)
                  011: mul(dst, src1, src2)
		  100: move(dst, src1)
		  101: set(dst, cst) with cst in range [0,15]

      0000 is end of bytecode.
@end code

*/
void assh_25519num_bytecode(const uint16_t *ops, unsigned tmps_count,
                            unsigned int args_count, /* assh_25519num_t args */ ...);

#endif

