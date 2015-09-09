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

/**
   @file
   @short Big number engine module interface
   @internal

   The big number computations in libassh are expressed using a
   dedicated bytecode. A big number module is in charge of executing
   this bytecode.
*/

#ifndef ASSH_BIGNUM_H_
#define ASSH_BIGNUM_H_

#include "assh_context.h"

#include <stdarg.h>

/** @internal

    @This is the big number bytecode instruction word. The instruction
    binary formats is as follow:

    @code R
      op(6)                          d(6)
      xxxxxx                        xxxxxx

      op(6)                  c(8)    d(6)
      xxxxxx               xxxxxxxx xxxxxx

      op(6)          b(12)   c(8)    d(6)
      xxxxxx        xxxxxx xxxxxxxx xxxxxx

      op(6)   a(6)   b(6)    c(8)    d(6)
      xxxxxx xxxxxx xxxxxx xxxxxxxx xxxxxx
    @end code
    @see #ASSH_BOP_FMT1
    @see #ASSH_BOP_FMT2
    @see #ASSH_BOP_FMT3
    @see #ASSH_BOP_FMT4
*/
typedef uint32_t assh_bignum_op_t;

/** @internal @This generates bytecode instruction format 4 */
#define ASSH_BOP_FMT4(op, a, b, c, d) (((op) << 26) | ((a) << 20) | ((b) << 14) | ((c) << 6) | (d))
/** @internal @This generates bytecode instruction format 3 */
#define ASSH_BOP_FMT3(op, b, c, d)    (((op) << 26) | ((b) << 14) | ((c) << 6) | (d))
/** @internal @This generates bytecode instruction format 2 */
#define ASSH_BOP_FMT2(op, c, d)       (((op) << 26) | ((c) << 6) | (d))
/** @internal @This generates bytecode instruction format 1 */
#define ASSH_BOP_FMT1(op, d)          (((op) << 26) | (d))


/** @internal @This specifies various storage formats of big numbers. */
enum assh_bignum_fmt_e
{
  /** Native big number representation, stored as a
      @ref assh_bignum_s object. */
  ASSH_BIGNUM_NATIVE  = 'N',
  /** Same representation as @ref ASSH_BIGNUM_NATIVE, used as a
      temporary value during bytecode execution. */
  ASSH_BIGNUM_TEMP    = 'T',
  /** Secret temporary, @see ASSH_BIGNUM_TEMP. */
  ASSH_BIGNUM_STEMP   = 'X',
  /** SSH mpint representation. */
  ASSH_BIGNUM_MPINT   = 'M',
  /** ASN1 integer representation. */
  ASSH_BIGNUM_ASN1    = 'A',
  /** RAW MSB data embedded in a SSH string */
  ASSH_BIGNUM_STRING  = 'S',
  /** RAW MSB first data without header */
  ASSH_BIGNUM_MSB_RAW = 'D',
  /** RAW LSB first data without header */
  ASSH_BIGNUM_LSB_RAW = 'd',
  /** NUL terminated hexadecimal representation */
  ASSH_BIGNUM_HEX     = 'H',
  /** NUL terminated decimal string representation */
  ASSH_BIGNUM_DEC     = 'd',
  /** Intptr_t value interpreted as a number value. */
  ASSH_BIGNUM_INT     = 'i',
  /** Intptr_t value interpreted as a bit size. */
  ASSH_BIGNUM_SIZE    = 's',
  /** Temporary montgomery multiplication context. */
  ASSH_BIGNUM_MT      = 'm',
};

/** @internal @This represents a big number in native format. The
    number object is empty if no internal representation of the number
    is currently allocated (@ref n is @tt NULL). */
struct assh_bignum_s
{
  /** Bits size */
  uint16_t bits;
  /** Whether the number is secret */
  uint16_t secret:1;
  /** Whether the number is a montgomery modulus */
  uint16_t mt_mod:1;
  /** Whether the number is in montgomery representation */
  uint16_t mt_num:1;
  /** Associated montgomery context id */
  uint16_t mt_id:6;
  /** Number data */
  void *n;
};

/** @internal @see assh_bignum_bytecode_t */
#define ASSH_BIGNUM_BYTECODE_FCN(n)        \
  ASSH_WARN_UNUSED_RESULT assh_error_t \
  (n)(struct assh_context_s *c, uint8_t cond, \
      const assh_bignum_op_t *ops,     \
      const char *format, va_list ap)

/** @internal @This defines the function type for the byte code
    execution operation of the big number module interface. 
    @see assh_bignum_bytecode */
typedef ASSH_BIGNUM_BYTECODE_FCN(assh_bignum_bytecode_t);


/** @internal @see assh_bignum_convert_t */
#define ASSH_BIGNUM_CONVERT_FCN(n)            \
  ASSH_WARN_UNUSED_RESULT assh_error_t        \
  (n)(struct assh_context_s *c,           \
      enum assh_bignum_fmt_e srcfmt,      \
      enum assh_bignum_fmt_e dstfmt,      \
      const void *src, void *dst, assh_bool_t secret)

/** @internal @This defines the function type for the number
    conversion operation of the big number module interface.  @see
    assh_bignum_convert */
typedef ASSH_BIGNUM_CONVERT_FCN(assh_bignum_convert_t);


/** @internal @see assh_bignum_release_t */
#define ASSH_BIGNUM_RELEASE_FCN(n) \
  void (n)(struct assh_context_s *ctx, struct assh_bignum_s *bn)

/** @internal @This defines the function type for the release
    operation of the big number module interface.  @see
    assh_bignum_release */
typedef ASSH_BIGNUM_RELEASE_FCN(assh_bignum_release_t);

/** @internal @This is the big number engine module interface structure. */
struct assh_bignum_algo_s
{
  const char *name;
  assh_bignum_bytecode_t *f_bytecode;
  assh_bignum_convert_t *f_convert;
  assh_bignum_release_t *f_release;
};

/** @internal @This executes big number operations specified by the
    given bytecode. Operations are performed on arguments and
    temporarie values as specified by the @tt format argument.

    The format string indicates the types of arguments passed to the
    function and the number of temporary values. The format string is
    composed of characters defined in @ref assh_bignum_fmt_e. An extra
    argument must be passed to the function for each non-temporary
    entry in the format string.

    The @ref #ASSH_BOP_MOVE instruction can be used to convert between
    native big numbers (arguments or temporaries) and other types of
    arguments. Unless specified otherwise, all other instructions are
    designed to be used on native big numbers only.

    Native big number arguments are passed as pointers to @ref
    assh_bignum_s objects. The size of big numbers can only be changed
    by the @ref #ASSH_BOP_SIZE family of instructions. The destination
    big number used with other instructions must be large enough to
    store the result as the number will not be dynamically
    resized. Working on numbers with a predefined storage size helps
    with constant time execution.

    If @tt NULL is passed as argument following a mpint argument, the
    pointer will be set when the mpint is written. This allows storing
    contiguous numbers in mpint format whithout knowing the size of
    the encoded numbers.

    Resources used by temporary numbers are automatically released when
    the function returns. */
ASSH_INLINE ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_bytecode(struct assh_context_s *c, uint8_t cond,
                     const assh_bignum_op_t *ops,
                     const char *format, ...)
{
  va_list ap;
  assh_error_t err;
  va_start(ap, format);
  err = c->bignum->f_bytecode(c, cond, ops, format, ap);
  va_end(ap);
  return err;
}

/** @internal @This converts between a big number in @ref
    ASSH_BIGNUM_NATIVE format and a number in an alternate format. The
    native big number argument points to an @ref assh_bignum_s object.

    When converting to a native big number from a number in @ref
    ASSH_BIGNUM_STRING, @ref ASSH_BIGNUM_ASN1 or @ref
    ASSH_BIGNUM_MPINT format, the source number must have a properly
    initialized or checked size header. When converting from a source
    number in @ref ASSH_BIGNUM_MSB_RAW or @ref ASSH_BIGNUM_LSB_RAW
    format, the bit size of the destination number is used; leading
    bits in the most significant byte of the source are ignored.

    In all other cases, the buffer size is expected to be appropriate
    for the bits size of the native big number involved in the
    conversion, as returned by the @ref assh_bignum_size_of_bits and
    @ref assh_bignum_size_of_num functions.

    When converting between two native big numbers, the current bits
    size of the source might be larger than the size of the destination
    provided that the actual value fits in the destination. */
ASSH_INLINE ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_convert(struct assh_context_s *c,
                    enum assh_bignum_fmt_e src_fmt,
                    enum assh_bignum_fmt_e dst_fmt,
                    const void *src, void *dst,
                    assh_bool_t dst_secret)
{
  return c->bignum->f_convert(c, src_fmt, dst_fmt, src, dst, dst_secret);
}

/** @internal @This returns the byte size needed to store a big number
    of given bit size using the specified format. */
size_t assh_bignum_size_of_bits(enum assh_bignum_fmt_e dst_fmt, size_t bits);

/** @internal @This returns the byte size needed to store the given
    big number object. */
ASSH_INLINE size_t
assh_bignum_size_of_num(enum assh_bignum_fmt_e dst_fmt,
                        const struct assh_bignum_s *bn)
{
  return assh_bignum_size_of_bits(dst_fmt, bn->bits);
}

/** @internal @This evaluates the storage size in bytes, the actual
    embedded value size in bytes and the bit size of the big number
    value. The @tt fmt parameter indicates the input format of @tt data. No
    bound checking is performed, the buffer size of the input data
    must have been checked previously. Some value checks are performed
    on the format of the data.

    Either @tt size, @tt val_size or @tt bits may be @tt NULL. When
    the input format is either @ref ASSH_BIGNUM_MSB_RAW or
    @ref ASSH_BIGNUM_LSB_RAW, the @tt size parameter must be used to
    pass the bytes size of the buffer. */
assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_size_of_data(enum assh_bignum_fmt_e fmt,
                         const void *data, size_t *size,
                         size_t *val_size, size_t *bits);

/** @internal @This initializes a big number object. No buffer is
    allocated, the big number is left empty. */
ASSH_INLINE void
assh_bignum_init(struct assh_context_s *c,
                 struct assh_bignum_s  *bn,
                 size_t bits, assh_bool_t secret)
{
  bn->bits = bits;
  bn->secret = secret;
  bn->mt_mod = 0;
  bn->mt_num = 0;
  bn->n = NULL;
}

/** @internal @This returns the number of bits of a big number. */
ASSH_INLINE size_t
assh_bignum_bits(const struct assh_bignum_s  *bn)
{
  return bn->bits;
}

/** @internal @This test if a big number is actually stored in the
    object or if it's empty. */
ASSH_INLINE assh_bool_t
assh_bignum_isempty(const struct assh_bignum_s  *bn)
{
  return bn->n == NULL;
}

/** @internal @This releases the internal storage of a bignum. The big
    number object become empty as if the @ref assh_bignum_init
    function has just been called. */
ASSH_INLINE void
assh_bignum_release(struct assh_context_s *ctx,
                    struct assh_bignum_s  *bn)
{
  ctx->bignum->f_release(ctx, bn);
}

/** @internal */
enum assh_bignum_opcode_e
{
  ASSH_BIGNUM_OP_END,
  ASSH_BIGNUM_OP_MOVE,
  ASSH_BIGNUM_OP_SIZER,
  ASSH_BIGNUM_OP_SIZE,
  ASSH_BIGNUM_OP_ADD,
  ASSH_BIGNUM_OP_SUB,
  ASSH_BIGNUM_OP_MUL,
  ASSH_BIGNUM_OP_DIV,
  ASSH_BIGNUM_OP_GCD,
  ASSH_BIGNUM_OP_EXPM,
  ASSH_BIGNUM_OP_INV,
  ASSH_BIGNUM_OP_SHR,
  ASSH_BIGNUM_OP_SHL,
  ASSH_BIGNUM_OP_RAND,
  ASSH_BIGNUM_OP_CMP,
  ASSH_BIGNUM_OP_TEST,
  ASSH_BIGNUM_OP_UINT,
  ASSH_BIGNUM_OP_MTUINT,
  ASSH_BIGNUM_OP_JMP,
  ASSH_BIGNUM_OP_CFAIL,
  ASSH_BIGNUM_OP_LADINIT,
  ASSH_BIGNUM_OP_LADTEST,
  ASSH_BIGNUM_OP_LADNEXT,
  ASSH_BIGNUM_OP_CSWAP,
  ASSH_BIGNUM_OP_CMOVE,
  ASSH_BIGNUM_OP_MTINIT,
  ASSH_BIGNUM_OP_MTTO,
  ASSH_BIGNUM_OP_MTFROM,
  ASSH_BIGNUM_OP_PRIME,
  ASSH_BIGNUM_OP_ISPRIME,
  ASSH_BIGNUM_OP_BOOL,
  ASSH_BIGNUM_OP_PRIVACY,
  ASSH_BIGNUM_OP_PRINT,
  ASSH_BIGNUM_OP_TRACE,
};

/** @internal */
#define ASSH_BIGNUM_OP_NAMES {                  \
    "end", "move", "sizer", "size", "add",      \
    "sub", "mul", "div", "gcd",                 \
    "expm", "inv", "shr", "shl",                \
    "rand", "cmp", "test", "uint",              \
    "mtuint", "(c)jmp", "cfail",                \
    "ladinit", "ladtest", "ladnext", "cswap",   \
    "cmove", "mtinit", "mtto", "mtfrom",        \
    "prime", "isprime", "bool", "privacy",      \
    "print", "trace"                            \
}

/** @internal Reserved big number bytecode register id. */
#define ASSH_BOP_NOREG  63

/** @mgroup{Bytecode instructions}
    @internal This instruction terminates execution of the bytecode. */
#define ASSH_BOP_END() \
  ASSH_BOP_FMT3(ASSH_BIGNUM_OP_END, 0, 0, 0)

/** @mgroup{Bytecode instructions}
    @internal This instruction moves and converts values in various
    formats. It is equivalent to the @ref assh_bignum_convert_t function. */
#define ASSH_BOP_MOVE(dst, src) \
  ASSH_BOP_FMT3(ASSH_BIGNUM_OP_MOVE, 0, dst, src)

/** @mgroup{Bytecode instructions}
    @internal Same behavior as @ref #ASSH_BOP_MOVE, set the secret
    flag on destination. */
#define ASSH_BOP_MOVES(dst, src) \
  ASSH_BOP_FMT3(ASSH_BIGNUM_OP_MOVE, 1, dst, src)

/** @mgroup{Bytecode instructions}
    @internal This initializes a temporary montgomery multiplication
    context from a modulus number. The context is released at the end
    of the bytecode execution. */
#define ASSH_BOP_MTINIT(mt, mod) \
  ASSH_BOP_FMT2(ASSH_BIGNUM_OP_MTINIT, mt, mod)

/** @mgroup{Bytecode instructions}
    @internal This converts the source number to montgomery representation.

    The resulting value can be further processed by the @ref #ASSH_BOP_ADDM,
    @ref #ASSH_BOP_SUBM, @ref #ASSH_BOP_MULM, @ref #ASSH_BOP_EXPM,
    @ref #ASSH_BOP_INV, @ref #ASSH_BOP_MOD and @ref #ASSH_BOP_MTFROM instructions.
    The @tt mt operand is a montgomery context initialized from the modulus
    using the @ref #ASSH_BOP_MTINIT instruction. */
#define ASSH_BOP_MTTO(dst1, dst2, src, mt)         \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_MTTO, dst2 - dst1 + 1, dst1, src, mt)

/** @mgroup{Bytecode instructions}
    @internal This converts the source number from montgomery representation.
    The resulting number is reduced according to the modulus.
    @see #ASSH_BOP_MTTO */
#define ASSH_BOP_MTFROM(dst1, dst2, src, mt)       \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_MTFROM, dst2 - dst1 + 1, dst1, src, mt)

/** @mgroup{Bytecode instructions}
    @internal This instruction changes the bit size of a number. It is
    equivalent to a call to the @ref assh_bignum_init function on the
    destination, with the source operand being evaluated by a call to
    @ref assh_bignum_size_of_data. */
#define ASSH_BOP_SIZE(dst, src) \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_SIZE, dst, src, 0, 32)

/** @mgroup{Bytecode instructions}
    @internal This instruction has the same behavior as the @ref
    #ASSH_BOP_SIZE instruction with shift and offset of the source
    size value. */
#define ASSH_BOP_SIZEM(dst, src, cadd, cshift)         \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_SIZE, dst, src, cadd, cshift + 32)

/** @mgroup{Bytecode instructions}
    @internal This instruction has the same behavior as the @ref
    #ASSH_BOP_SIZE instruction applied to a range of destination
    registers. */
#define ASSH_BOP_SIZER(dst1, dst2, src)                      \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_SIZER, dst1, src, dst2, 0)

/** @mgroup{Bytecode instructions}
    @internal This instruction computes @tt {dst = (src1 + src2) %
    mod} in constant time. The bit size of the destination number must be
    @tt {max(bits(src1), bits(src2))} or larger. The @tt mod
    must be a montgomery context. */
#define ASSH_BOP_ADDM(dst, src1, src2, mod)                     \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_ADD, dst, src1, src2, mod)

/** @mgroup{Bytecode instructions}
    @internal This instruction computes @tt {dst = (src1 - src2) %
    mod}. Same behavior as @ref #ASSH_BOP_ADDM. */
#define ASSH_BOP_SUBM(dst, src1, src2, mod)                     \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_SUB, dst, src1, src2, mod)

/** @mgroup{Bytecode instructions}
    @internal This instruction computes @tt {dst = (src1 + src2)} in
    constant time. The bit size of the destination number must
    be @tt {max(bits(src1), bits(src2))} or larger. */
#define ASSH_BOP_ADD(dst, src1, src2)                           \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_ADD, dst, src1, src2, ASSH_BOP_NOREG)

/** @mgroup{Bytecode instructions}
    @internal This instruction computes @tt {dst = (src1 - src2) %
    mod}. Same behavior as @ref #ASSH_BOP_ADD */
#define ASSH_BOP_SUB(dst, src1, src2)                           \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_SUB, dst, src1, src2, ASSH_BOP_NOREG)

/** @mgroup{Bytecode instructions}
    @internal This instruction computes @tt {dst = (src1 * src2) %
    mod}. The bit size of the destination number must be
    @tt {bits(mod)} or larger. The @tt mod operand can be either a
    big number or a montgomery context. In the later case the bit
    size of all operands must match the size of the montgomery
    context and the operation is computed in constant time. */
#define ASSH_BOP_MULM(dst, src1, src2, mod)                     \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_MUL, dst, src1, src2, mod)

/** @mgroup{Bytecode instructions}
    @internal This instruction computes @tt {dst = (src1 * src2)} in
    constant time. The bit size of the destination number must
    be @tt {bits(src1) + bits(src2)} or larger.*/
#define ASSH_BOP_MUL(dst, src1, src2)                     \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_MUL, dst, src1, src2, ASSH_BOP_NOREG)

/** @mgroup{Bytecode instructions}
    @internal This instruction computes @tt {dst2 = src1 % src2} and
    @tt {dst1 = src1 / src2}. @see #ASSH_BOP_MOD  @see #ASSH_BOP_DIV */
#define ASSH_BOP_DIVMOD(dstq, dstr, src1, src2)                 \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_DIV, dstq, dstr, src1, src2)

/** @mgroup{Bytecode instructions}
    @internal This instruction computes @tt {dst2 = src1 % src2}.
    The @tt src2 operand can be either a big number or a montgomery context.
    @see #ASSH_BOP_DIVMOD */
#define ASSH_BOP_MOD(dst, src1, src2) \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_DIV, ASSH_BOP_NOREG, dst, src1, src2)

/** @mgroup{Bytecode instructions}
    @internal This instruction computes @tt {dst2 = src1 / src2}.
    @see #ASSH_BOP_DIVMOD */
#define ASSH_BOP_DIV(dst, src1, src2) \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_DIV, dst, ASSH_BOP_NOREG, src1, src2)

/** @mgroup{Bytecode instructions}
    @internal This instruction computes @tt {dst = gcd(src1, src2)}. */
#define ASSH_BOP_GCD(dst, src1, src2) \
  ASSH_BOP_FMT3(ASSH_BIGNUM_OP_GCD, dst, src1, src2)

/** @mgroup{Bytecode instructions}
    @internal This instruction computes @tt {dst = (src1 ^ src2) % mod}.
    The @tt mod operand must be a montgomery context. The @tt src1 and
    @tt dst operands are montgomery numbers and their bit size must
    match the size of the montgomery context.
    @see #ASSH_BOP_EXPM */
#define ASSH_BOP_EXPM(dst, src1, src2, mod) \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_EXPM, dst, src1, src2, mod)

/** @mgroup{Bytecode instructions}
    @internal This instruction computes @tt {dst = invmod(src1, src2)}.
    If @tt src2 is a montgomery context, the modulus must be prime as
    the operation is performed in constant time using the Fermat
    little theorem. */
#define ASSH_BOP_INV(dst, src1, src2)                \
  ASSH_BOP_FMT3(ASSH_BIGNUM_OP_INV, dst, src1, src2)

/** @mgroup{Bytecode instructions}
    @internal This instruction computes @tt {dst = shift_right(src1,
    val + size(src2))} in constant time. @tt val must be in range
    @tt{[-128, +127]} and @tt src2 can be @ref #ASSH_BOP_NOREG.
    The source and destination operands must have the same bit
    length and the shift amount must be less than the length. */
#define ASSH_BOP_SHR(dst, src, val, src2)              \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_SHR, dst, src, 128 + (val), src2)

/** @mgroup{Bytecode instructions}
    @internal This instruction is similar to @ref #ASSH_BOP_SHR but
    perform a left shift. */
#define ASSH_BOP_SHL(dst, src, val, src2)              \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_SHL, dst, src, 128 + (val), src2)

/** @mgroup{Bytecode instructions}
    @internal This instruction initializes a big number with random
    data. A new value is generated until it does fall in the specified
    range. The @tt min and @tt max bounds can be @ref #ASSH_BOP_NOREG.
    The quality operand is of type @ref assh_prng_quality_e. The result
    is flagged secret if the requested quality is not weak. */
#define ASSH_BOP_RAND(dst, min, max, quality)          \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_RAND, dst, min, max, quality)

/** @mgroup{Bytecode instructions}
    @internal This instruction performs a comparison in constant time
    and updates the condition flag.
    It can be used with values of different bit length. It is possible
    to test if an @ref assh_bignum_s object is empty by comparing
    against @ref #ASSH_BOP_NOREG. */
#define ASSH_BOP_CMPEQ(src1, src2, condid)                    \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_CMP, condid, src1, src2, 0)

/** @mgroup{Bytecode instructions}
    @internal This instruction is similar to @ref #ASSH_BOP_CMPEQ. */
#define ASSH_BOP_CMPLT(src1, src2, condid)                    \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_CMP, condid, src1, src2, 1)

/** @mgroup{Bytecode instructions}
    @internal This instruction is similar to @ref #ASSH_BOP_CMPEQ. */
#define ASSH_BOP_CMPGT(src1, src2, condid)                    \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_CMP, condid, src2, src1, 1)

/** @mgroup{Bytecode instructions}
    @internal This instruction is similar to @ref #ASSH_BOP_CMPEQ. */
#define ASSH_BOP_CMPLTEQ(src1, src2, condid)                  \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_CMP, condid, src1, src2, 2)

/** @mgroup{Bytecode instructions}
    @internal This instruction is similar to @ref #ASSH_BOP_CMPEQ. */
#define ASSH_BOP_CMPGTEQ(src1, src2, condid)                  \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_CMP, condid, src2, src1, 2)

/** @mgroup{Bytecode instructions}
    @internal This instruction jump to a different bytecode location. */
#define ASSH_BOP_JMP(pcdiff)                           \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_JMP, 0, 1, 128 + pcdiff, 0)

/** @mgroup{Bytecode instructions}
    @internal This instruction jump to a different bytecode location
    if the condition flag is different from inv. */
#define ASSH_BOP_CJMP(pcdiff, inv, condid)              \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_JMP, condid, 0, 128 + pcdiff, inv)

/** @mgroup{Bytecode instructions}
    @internal This instruction abort bytecode execution with an error
    if the condition flag is different from inv. */
#define ASSH_BOP_CFAIL(inv, condid)                 \
  ASSH_BOP_FMT2(ASSH_BIGNUM_OP_CFAIL, condid, inv)

/** @mgroup{Bytecode instructions}
    @internal This instruction tests a bit in @tt src1 and updates the
    condition flag. When the @tt
    src2 operand is @ref #ASSH_BOP_NOREG, the tested bit position is
    @tt{val}. In the other case, the tested bit position is @tt
    {size(src2) - val)}. @tt val must be in the range @tt{[0, 64]}. */
#define ASSH_BOP_TEST(src1, val, src2, condid)                 \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_TEST, condid, src1, val, src2)

/** @mgroup{Bytecode instructions}
    @internal This instruction initializes a big number from a 20 bits
    unsigned integer constant. */
#define ASSH_BOP_UINT(dst, value) \
  ASSH_BOP_FMT2(ASSH_BIGNUM_OP_UINT, value, dst)

/** @mgroup{Bytecode instructions}
    @internal This instruction initializes a big number from a 12 bits
    unsigned integer constant. The result is converted to montgomery form. */
#define ASSH_BOP_MTUINT(dst, value, mt)                    \
  ASSH_BOP_FMT3(ASSH_BIGNUM_OP_MTUINT, value, mt, dst)

/** @mgroup{Bytecode instructions}
    @internal This instruction performs a conditional swap in constant time
    between two values depending on the condition flag.  */
#define ASSH_BOP_CSWAP(src1, src2, inv, condid)                \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_CSWAP, condid, src1, src2, inv)

/** @mgroup{Bytecode instructions}
    @internal This instruction performs a conditional move in constant time
    depending on the condition flag.  */
#define ASSH_BOP_CMOVE(dst, src, inv, condid)                \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_CMOVE, condid, dst, src, inv)

/** @mgroup{Bytecode instructions}
    @internal This instruction initialize the ladder bit index to
    @em{bits(src)-1}. */
#define ASSH_BOP_LADINIT(src)                  \
  ASSH_BOP_FMT1(ASSH_BIGNUM_OP_LADINIT, src)

/** @mgroup{Bytecode instructions}
    @internal This instruction upadates the condition flag according to
    the bit in source number selected by the current ladder index. */
#define ASSH_BOP_LADTEST(src, condid)                  \
  ASSH_BOP_FMT2(ASSH_BIGNUM_OP_LADTEST, condid, src)

/** @mgroup{Bytecode instructions}
    @internal This instruction decrements the current ladder bit index
    and set the condition flag if the new index value is 0. */
#define ASSH_BOP_LADNEXT(condid)                    \
  ASSH_BOP_FMT1(ASSH_BIGNUM_OP_LADNEXT, condid)

/** @mgroup{Bytecode instructions}
    @internal This instruction generates a prime number in the range
    (min, max). If @tt min is @tt ASSH_BOP_NOREG, no lower bound is
    used. If @tt max is @tt ASSH_BOP_NOREG, the most significant bit
    of the destination will be set so that the bit size of the
    generated number is large. */
#define ASSH_BOP_PRIME(dst, min, max, quality)            \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_PRIME, dst, min, max, quality)

/** @mgroup{Bytecode instructions} @internal This instruction updates
    the condition flag. It is set if the number is a prime greater
    than 2. Seven miller rabin rounds are enough for values picked at
    random. The number of rounds for values of unknown origin is
    greater and depends on the required probability. */
#define ASSH_BOP_ISPRIME(src, rounds, condid)                  \
  ASSH_BOP_FMT3(ASSH_BIGNUM_OP_ISPRIME, condid, rounds, src)

/** specify boolean operations for use with @ref #ASSH_BOP_BOOL */
enum assh_bignum_bool_op
{
  ASSH_BOP_BOOL_AND,
  ASSH_BOP_BOOL_OR,
  ASSH_BOP_BOOL_XOR,
  ASSH_BOP_BOOL_ANDN,
  ASSH_BOP_BOOL_NAND,
  ASSH_BOP_BOOL_NOR,
  ASSH_BOP_BOOL_NXOR,
  ASSH_BOP_BOOL_NANDN,
};

/** @mgroup{Bytecode instructions}
    @internal This instructions performs the specified boolean
    operation on condition flags. @see assh_bignum_bool_op */
#define ASSH_BOP_BOOL(conddst, condsrc1, condsrc2, boolop)      \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_BOOL, conddst, condsrc1, condsrc2, boolop)

/** @mgroup{Bytecode instructions}
    @internal The secret flag is forwarded to results of operations
    on big numbers. This instruction can be used to change the secret
    flag of a value. */
#define ASSH_BOP_PRIVACY(src, secret) \
  ASSH_BOP_FMT2(ASSH_BIGNUM_OP_PRIVACY, secret, src)

/** @mgroup{Bytecode instructions}
    @internal This instruction prints a big number argument for
    debugging purpose. The id argument is an ASCII integer constant. */
#define ASSH_BOP_PRINT(src, id) \
  ASSH_BOP_FMT2(ASSH_BIGNUM_OP_PRINT, id, src)

#define ASSH_BOP_TRACE(mode) \
  ASSH_BOP_FMT1(ASSH_BIGNUM_OP_TRACE, mode)

/** @multiple @internal @This is a big number engine implementation
    descriptor. */
#ifdef CONFIG_ASSH_USE_GCRYPT_BIGNUM
extern const struct assh_bignum_algo_s assh_bignum_gcrypt;
#endif

extern const struct assh_bignum_algo_s assh_bignum_builtin;

#endif
