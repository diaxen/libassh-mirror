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


#ifndef ASSH_BIGNUM_H_
#define ASSH_BIGNUM_H_

#include "assh_context.h"

#include <stdarg.h>

/*
  Instruction binary formats:

      op(6)               c(26)
      xxxxxx    xxxxxxxxxxxxxxxxxxxxxxxxxx

      op(6)          c(20)           d(6)
      xxxxxx  xxxxxxxxxxxxxxxxxxxx  xxxxxx

      op(6)     b(12)       c(8)     d(6)
      xxxxxx  xxxxxxxxxxxx xxxxxxxx xxxxxx

      op(6)   a(6)   b(6)    c(8)    d(6)
      xxxxxx xxxxxx xxxxxx xxxxxxxx xxxxxx

*/
typedef uint32_t assh_bignum_op_t;

#define ASSH_BOP_FMT4(op, a, b, c, d) (((op) << 26) | ((a) << 20) | ((b) << 14) | ((c) << 6) | (d))
#define ASSH_BOP_FMT3(op, b, c, d)    (((op) << 26) | ((b) << 14) | ((c) << 6) | (d))
#define ASSH_BOP_FMT2(op, c, d)       (((op) << 26) | ((c) << 6) | (d))
#define ASSH_BOP_FMT1(op, d)          (((op) << 26) | (d))


/** @internal @This specifies various storage formats of big numbers. */
enum assh_bignum_fmt_e
{
  /** Native big number representation, stored as a @ref struct assh_bignum_s. */
  ASSH_BIGNUM_NATIVE  = 'N',
  /** Same representation as @ref ASSH_BIGNUM_NATIVE but used as a
      temporary value during bytecode execution. */
  ASSH_BIGNUM_TEMP    = 'T',
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
  /** pointer to intptr_t value */
  ASSH_BIGNUM_INTPTR  = 'I',
  /** intptr_t value interpreted as an integer value. */
  ASSH_BIGNUM_INT     = 'i',
  /** intptr_t value interpreted as a bit size. */
  ASSH_BIGNUM_SIZE    = 's',
  /** montgomery ladder object (@ref assh_bignum_mlad_s) */
  ASSH_BIGNUM_MLAD    = 'L',
};

/** @This represents a big number in native format. The number object
    is empty if no internal representation of the number is currently
    allocated (@tt n is @tt NULL). */
struct assh_bignum_s
{
  struct assh_context_s *ctx;
  size_t bits;
  /** pointer to native big number data */
  void *n;
};

/** @This contains a montgomery ladder state which can be used during
    bytecode execution */
struct assh_bignum_mlad_s
{
  const uint8_t *data;
  uint16_t count;
  assh_bool_t msbit_1st:1;
  assh_bool_t msbyte_1st:1;
};

/** @internal @see assh_bignum_bytecode_t */
#define ASSH_BIGNUM_BYTECODE_FCN(n)        \
  ASSH_WARN_UNUSED_RESULT assh_error_t \
  (n)(struct assh_context_s *c,        \
      const assh_bignum_op_t *ops,     \
      const char *format, va_list ap)

/**
   @internal @This executes big number operations specified by the
   given bytecode. Operations are performed on arguments and
   temporaries value as specified by the @tt format argument.

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
   by the @ref #ASSH_BOP_SIZE instruction. The destination big
   number use with other instructions must be large enough to store
   the result.

   Resources used by temporary numbers are automatically released when
   the function returns.
*/
typedef ASSH_BIGNUM_BYTECODE_FCN(assh_bignum_bytecode_t);


/** @internal @see assh_bignum_convert_t */
#define ASSH_BIGNUM_CONVERT_FCN(n)            \
  ASSH_WARN_UNUSED_RESULT assh_error_t        \
  (n)(struct assh_context_s *c,           \
      enum assh_bignum_fmt_e srcfmt,      \
      enum assh_bignum_fmt_e dstfmt,      \
      const void *src, void *dst)

/** @This converts between a big number in @ref ASSH_BIGNUM_NATIVE
    format and a number in an alternate format. The native big number
    argument points to an @ref assh_bignum_s object.

    When converting to a native big number from a number in @ref
    ASSH_BIGNUM_STRING, @ref ASSH_BIGNUM_ASN1 or @ref
    ASSH_BIGNUM_MPINT format, the source number must have a properly
    initialized size header.

    In all other cases, the buffer size is expected to be appropriate
    for the bits size of the native big number involved in the
    conversion, as returned by the @ref assh_bignum_size_of_bits
    function.

    When converting between two native big numbers, the current bits
    size of the source might be larger than the size of the destination
    provided that the actual value is fitting.
*/
typedef ASSH_BIGNUM_CONVERT_FCN(assh_bignum_convert_t);


/** @internal @see assh_bignum_release_fcn_t */
#define ASSH_BIGNUM_RELEASE_FCN(n) \
  void (n)(struct assh_bignum_s *bn)

/** @internal @This releases the internal representation of a big
    number unless it is already empty. */
typedef ASSH_BIGNUM_RELEASE_FCN(assh_bignum_release_t);


struct assh_bignum_algo_s
{
  const char *name;
  assh_bignum_bytecode_t *f_bytecode;
  assh_bignum_convert_t *f_convert;
  assh_bignum_release_t *f_release;
};

/** Convenience wrapper for @ref assh_bignum_bytecode_t */
static inline ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_bytecode(struct assh_context_s *c,
                     const assh_bignum_op_t *ops,
                     const char *format, ...)
{
  va_list ap;
  assh_error_t err;
  va_start(ap, format);
  err = c->bignum->f_bytecode(c, ops, format, ap);
  va_end(ap);
  return err;
}

/** Convenience wrapper for @ref assh_bignum_convert_t */
static inline ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_convert(struct assh_context_s *c,
                    enum assh_bignum_fmt_e src_fmt,
                    enum assh_bignum_fmt_e dst_fmt,
                    const void *src, void *dst)
{
  return c->bignum->f_convert(c, src_fmt, dst_fmt, src, dst);
}

/** @internal @This returns the bytes size needed to store a big number
    of given bit size using the specified format. */
size_t assh_bignum_size_of_bits(enum assh_bignum_fmt_e dst_fmt, size_t bits);

static inline size_t
assh_bignum_size_of_num(enum assh_bignum_fmt_e dst_fmt,
                        const struct assh_bignum_s *bn)
{
  return assh_bignum_size_of_bits(dst_fmt, bn->bits);
}

/** @internal @This evaluates the storage size in bytes, the actual
    embedded value size in bytes and the bit size of the big number
    value. The @tt fmt parameter indicates the input format of @tt data. No
    bound checking is performed, the buffer size of the input data
    must have been checked previously.

    Either @tt size, @tt val_size or @tt bits may be @tt NULL. When
    the input format is @ref ASSH_BIGNUM_MSB_RAW, the @tt size
    parameter must be used to pass the bytes size of the buffer. */
assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_size_of_data(enum assh_bignum_fmt_e fmt,
                         const void *data, size_t *size,
                         size_t *val_size, size_t *bits);

/** @This initializes the bignum as empty. */
static inline void
assh_bignum_init(struct assh_context_s *c,
                 struct assh_bignum_s  *bn,
		 size_t bits)
{
  bn->ctx = c;
  bn->bits = bits;
  bn->n = NULL;
}

/** @This returns the number of bits of a big number. */
static inline size_t
assh_bignum_bits(struct assh_bignum_s  *bn)
{
  return bn->bits;
}

static inline assh_bool_t
assh_bignum_isempty(struct assh_bignum_s  *bn)
{
  return bn->n == NULL;
}

/** Convenience wrapper for @ref assh_bignum_release_t */
static inline void
assh_bignum_release(struct assh_context_s *c,
                    struct assh_bignum_s  *bn)
{
  c->bignum->f_release(bn);
}

enum assh_bignum_opcode_e
  {
    ASSH_BIGNUM_OP_END,
    ASSH_BIGNUM_OP_MOVE,
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
    ASSH_BIGNUM_OP_AND,
    ASSH_BIGNUM_OP_OR,
    ASSH_BIGNUM_OP_NOT,
    ASSH_BIGNUM_OP_MASK,
    ASSH_BIGNUM_OP_RAND,
    ASSH_BIGNUM_OP_CMP,
    ASSH_BIGNUM_OP_UINT,
    ASSH_BIGNUM_OP_MLADSWAP,
    ASSH_BIGNUM_OP_MLADLOOP,
    ASSH_BIGNUM_OP_PRIME,
    ASSH_BIGNUM_OP_ISPRIM,
    ASSH_BIGNUM_OP_PRINT,
  };

#define ASSH_BIGNUM_OP_NAMES {                  \
    "end", "move", "size", "add",               \
    "sub", "mul", "div", "gcd",                 \
    "expm", "inv", "shr", "shl",                \
    "and", "or", "not", "mask",                 \
    "rand", "cmp", "uint",                      \
      "mladswap", "mladloop", "prime", "isprim", "print" \
}

#define ASSH_BOP_NOREG  63

/** This instruction terminates execution of the bytecode */
#define ASSH_BOP_END() \
  ASSH_BOP_FMT3(ASSH_BIGNUM_OP_END, 0, 0, 0)

/** This instruction moves and converts values in various formats. 
    It is implemented by calling @ref assh_bignum_convert_t. */
#define ASSH_BOP_MOVE(dst, src) \
  ASSH_BOP_FMT2(ASSH_BIGNUM_OP_MOVE, dst, src)

/** This instruction changes the bit size of a number. The initial bit
    size is set by the @ref assh_bignum_init function and can not be
    changed by an other instruction. If the source operand is not of
    type @ref ASSH_BIGNUM_SIZE, the bit size of the source value is
    used. */
#define ASSH_BOP_SIZE(dst, src) \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_SIZE, dst, src, 0, 32)

/** This instruction has the same behavior as the @ref #ASSH_BOP_SIZE
    instruction with shift and offset of the source size value. */
#define ASSH_BOP_SIZEM(dst, src, cadd, cshift)         \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_SIZE, dst, src, cadd, cshift + 32)

/** This instruction computes @tt {dst = (src1 + src2) % mod}. The
    bit size of the destination number must be at least
    max(bits(src1), bits(src2)). */
#define ASSH_BOP_ADDM(dst, src1, src2, mod)                     \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_ADD, dst, src1, src2, mod)

/** This instruction computes @tt {dst = (src1 - src2) % mod}. Same
    behavior as @ref #ASSH_BOP_ADDM. */
#define ASSH_BOP_SUBM(dst, src1, src2, mod)                     \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_SUB, dst, src1, src2, mod)

/** This instruction computes @tt {dst = (src1 + src2)}. The bit size
    of the destination number must be at least bits(mod). */
#define ASSH_BOP_ADD(dst, src1, src2)                           \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_ADD, dst, src1, src2, ASSH_BOP_NOREG)

/** This instruction computes @tt {dst = (src1 - src2) % mod}. Same
    behavior as @ref #ASSH_BOP_ADD */
#define ASSH_BOP_SUB(dst, src1, src2)                           \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_SUB, dst, src1, src2, ASSH_BOP_NOREG)

/** This instruction computes @tt {dst = (src1 * src2) % mod}. */
#define ASSH_BOP_MULM(dst, src1, src2, mod)                     \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_MUL, dst, src1, src2, mod)

/** This instruction computes @tt {dst = (src1 * src2)}. */
#define ASSH_BOP_MUL(dst, src1, src2)                     \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_MUL, dst, src1, src2, ASSH_BOP_NOREG)

/** This instruction computes @tt {dst2 = src1 % src2} and @tt{dst1 =
    src1 / src2}. Either @tt dst1 or @tt dst2 can be @ref #ASSH_BOP_NOREG. */
#define ASSH_BOP_DIVMOD(dstq, dstr, src1, src2)                 \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_DIV, dstq, dstr, src1, src2)

/** This instruction computes @tt {dst2 = src1 % src2}. */
#define ASSH_BOP_MOD(dst, src1, src2) \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_DIV, ASSH_BOP_NOREG, dst, src1, src2)

/** This instruction computes @tt {dst2 = src1 / src2}. */
#define ASSH_BOP_DIV(dst, src1, src2) \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_DIV, dst, ASSH_BOP_NOREG, src1, src2)

/** This instruction computes @tt {dst = gcd(src1, src2)}. */
#define ASSH_BOP_GCD(dst, src1, src2) \
  ASSH_BOP_FMT3(ASSH_BIGNUM_OP_GCD, dst, src1, src2)

/** This instruction computes @tt {dst = (src1 ** src2) % mod} */
#define ASSH_BOP_EXPM(dst, src1, src2, mod) \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_EXPM, dst, src1, src2, mod)

/** This instruction computes @tt {dst = (src1 ** src2) % mod}, in constant time */
#define ASSH_BOP_EXPM_C(dst, src1, src2, mod) \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_EXPM, dst, src1, src2, mod)

/** This instruction computes @tt {dst = invmod(src1, src2)} */
#define ASSH_BOP_INV(dst, src1, src2)                \
  ASSH_BOP_FMT3(ASSH_BIGNUM_OP_INV, dst, src1, src2)

/** This instruction computes @tt {dst = invmod(src1, src2)}, in constant time */
#define ASSH_BOP_INV_C(dst, src1, src2)              \
  ASSH_BOP_FMT3(ASSH_BIGNUM_OP_INV, dst, src1, src2)

/** This instruction computes @tt {dst = shift_right(src1, val +
    size(src2))}. @tt val must be in range [-128,+127] and @tt src2
    can be ASSH_BOP_NOREG. */
#define ASSH_BOP_SHR(dst, src, val, src2)              \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_SHR, dst, src, 128 + (val), src2)

/** This instruction is similar to @xref #ASSH_BOP_SHR. */
#define ASSH_BOP_SHL(dst, src, val, src2)              \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_SHL, dst, src, 128 + (val), src2)

/** This instruction initializes a big number with random data.
    The quality operand is of type @ref assh_prng_quality_e. */
#define ASSH_BOP_RAND(dst, min, max, quality)          \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_RAND, dst, min, max, quality)

/** This instruction changes the program counter if the two numbers
    are equal. The bytecode execution is aborted with the @ref
    ASSH_ERR_NUM_COMPARE_FAILED error if the condition is false and the
    value of @tt pcdiff is 0. */
#define ASSH_BOP_CMPEQ(src1, src2, pcdiff)                    \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_CMP, src1, src2, 128 + pcdiff, 0)
/** Same behavior as @ref #ASSH_BOP_CMPEQ. */
#define ASSH_BOP_CMPNE(src1, src2, pcdiff)                    \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_CMP, src1, src2, 128 + pcdiff, 1)
/** Same behavior as @ref #ASSH_BOP_CMPEQ. */
#define ASSH_BOP_CMPLT(src1, src2, pcdiff)                    \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_CMP, src1, src2, 128 + pcdiff, 2)
/** Same behavior as @ref #ASSH_BOP_CMPEQ. */
#define ASSH_BOP_CMPLTEQ(src1, src2, pcdiff)                  \
  ASSH_BOP_FMT4(ASSH_BIGNUM_OP_CMP, src1, src2, 128 + pcdiff, 3)

/** This instruction initializes a big number from a 20 bits
    unsigned integer constant. */
#define ASSH_BOP_UINT(dst, value) \
  ASSH_BOP_FMT2(ASSH_BIGNUM_OP_UINT, value, dst)

/** This instruction performs a conditional swap between two values
    depending on the current state of the the @ref assh_bignum_mlad_s
    struct argument. It is useful to implement a montgomery ladder.
    @see #ASSH_BOP_MLADLOOP */
#define ASSH_BOP_MLADSWAP(src1, src2, mlad)               \
  ASSH_BOP_FMT3(ASSH_BIGNUM_OP_MLADSWAP, src1, src2, mlad)

/** This instruction conditionally jump backward depending on the
    current state of the the @ref assh_bignum_mlad_s struct argument
    and advances the @ref assh_bignum_mlad_s state to the next bit. It
    is useful to implement a montgomery ladder.
    @see #ASSH_BOP_MLADSWAP */
#define ASSH_BOP_MLADLOOP(rel, mlad)                    \
  ASSH_BOP_FMT2(ASSH_BIGNUM_OP_MLADLOOP, rel, mlad)

/** This instruction generates a prime number in range (min, max). If
    @tt min is @tt ASSH_BOP_NOREG, no lower bound is used. If @tt max
    is @tt ASSH_BOP_NOREG, the most significant bit of the destination
    will be set. */
#define ASSH_BOP_PRIME(dst, min, max)                 \
  ASSH_BOP_FMT3(ASSH_BIGNUM_OP_PRIME, dst, min, max)

/** This instruction changes the program counter if the number is
    a prime greater than 2. The bytecode execution is aborted with the
    @ref ASSH_ERR_NUM_OVERFLOW error if the number is not prime and
    the value of @tt pcdiff is 0. */
#define ASSH_BOP_ISPRIM(src, pcdiff)                                   \
  ASSH_BOP_FMT3(ASSH_BIGNUM_OP_ISPRIM, 1, pcdiff + 128, src)

/** @see #ASSH_BOP_ISPRIM */
#define ASSH_BOP_ISNTPRIM(src, pcdiff)                                   \
  ASSH_BOP_FMT3(ASSH_BIGNUM_OP_ISPRIM, 0, pcdiff + 128, src)

/** This instruction print a big number argument for debugging
    purpose. The id argument is a 16 bits ASCII constant. */
#define ASSH_BOP_PRINT(src, id) \
  ASSH_BOP_FMT2(ASSH_BIGNUM_OP_PRINT, id, src)

extern const struct assh_bignum_algo_s assh_bignum_gcrypt;

#endif

