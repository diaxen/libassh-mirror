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

#include "assh_alloc.h"
#include "assh_prng.h"

#ifdef CONFIG_ASSH_USE_GCRYPT_BIGNUM

#include <gcrypt.h>

struct assh_bignum_s
{
  gcry_mpi_t n;
  unsigned int l;
};

static inline size_t
assh_bignum_sizeof(unsigned int bits)
{
  return sizeof(struct assh_bignum_s);
}

static inline void
assh_bignum_init(struct assh_context_s *c, struct assh_bignum_s *bn, unsigned int bits)
{
  bn->n = NULL;
  bn->l = bits;
}

static inline void
assh_bignum_cleanup(struct assh_context_s *c, struct assh_bignum_s *bn)
{
  if (bn->n != NULL)
    gcry_mpi_release(bn->n);
}

# define ASSH_BIGNUM_ALLOC(context, name, bits, sv, lbl)		\
  struct assh_bignum_s name##_, *name = &name##_;                       \
  assh_bignum_init(context, name, bits);

# define ASSH_BIGNUM_FREE(context, name)        \
  assh_bignum_cleanup(context, name);

static inline unsigned int
assh_bignum_bits(const struct assh_bignum_s *bn)
{
  return bn->l;
}

static inline ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_shrink(struct assh_bignum_s *bn,
                   unsigned int bits)
{
  bn->l = bits;
  return ASSH_OK;
}

#else

#if 0
typedef uint64_t assh_bnword_t;
typedef int64_t assh_bnsword_t;
typedef unsigned __int128 assh_bnlong_t;

#elif 1
typedef uint32_t assh_bnword_t;
typedef int32_t assh_bnsword_t;
typedef uint64_t assh_bnlong_t;

#elif 0
typedef uint16_t assh_bnword_t;
typedef int16_t assh_bnsword_t;
typedef uint32_t assh_bnlong_t;
#else

/* 8 bits big number word is useful for testing bignum algorithms
   because there are fewer possible word values, it will test more
   corner cases quickly. */
typedef uint8_t assh_bnword_t;
typedef int8_t assh_bnsword_t;
typedef uint16_t assh_bnlong_t;
#endif

/** Minimum number of words for karatsuba to switch to school mul. */
#define ASSH_BIGNUM_KARATSUBA_THRESHOLD 32

/** @This specifies the number of bits in a big number word. */
#define ASSH_BIGNUM_W (sizeof(assh_bnword_t) * 8)

/** @This holds a big number. */
struct assh_bignum_s
{
  struct assh_context_s *ctx;
  unsigned l;
  assh_bnword_t n[0];
};

/** @This computes the number of words needed to store a big number of
    specified bit length. */
#define ASSH_BIGNUM_WORDS(bits) (((((bits) - 1) | (ASSH_BIGNUM_W - 1)) + 1) / ASSH_BIGNUM_W)

/** @This returns the allocation size suitable to store a big number
    of the specified bit length. */
static inline size_t
assh_bignum_sizeof(unsigned int bits)
{
  size_t s = sizeof(struct assh_bignum_s)
    + ASSH_BIGNUM_WORDS(bits) * sizeof(assh_bnword_t);
  return ((s - 1) | (sizeof(void*) - 1)) + 1;
}

/** @This initializes a big number. */
static inline void
assh_bignum_init(struct assh_context_s *c, struct assh_bignum_s *bn, unsigned int bits)
{
  bn->ctx = c;
  bn->l = ASSH_BIGNUM_WORDS(bits);
}

/** @This release the resources used by a big number. */
static inline void
assh_bignum_cleanup(struct assh_context_s *c, struct assh_bignum_s *bn)
{
}

#ifdef CONFIG_ASSH_ALLOCA

# include <alloca.h>

/** @This declares a pointer to a big number, allocate the required
    storage using @ref alloca and initializes the number. */
# define ASSH_BIGNUM_ALLOC(context, name, bits, sv, lbl)                \
  size_t name##_l__ = ASSH_BIGNUM_WORDS(bits);                          \
  struct assh_bignum_s *name = alloca(sizeof(struct assh_bignum_s)      \
               + name##_l__ * sizeof(assh_bnword_t));                   \
  if (0)                                                                \
    goto lbl;                                                           \
  name->ctx = (context);						\
  name->l = name##_l__;

/** @This releases the big number allocated using @ref #ASSH_BIGNUM_ALLOC */
# define ASSH_BIGNUM_FREE(context, name)

#else

/** @This declares a pointer to a big number, allocate the required
    storage using the context allocator and initializes the number. */
# define ASSH_BIGNUM_ALLOC(context, name, bits, sv, lbl)                \
  size_t name##_l__ = ASSH_BIGNUM_WORDS(bits);                          \
  struct assh_bignum_s *name;                                           \
  ASSH_ERR_GTO(assh_alloc(context, sizeof(struct assh_bignum_s)         \
      + name##_l__ * sizeof(assh_bnword_t), ASSH_ALLOC_SCRATCH, (void**)&name) | sv, lbl); \
  name->ctx = (context);						\
  name->l = name##_l__;

/** @This releases the big number allocated using @ref #ASSH_BIGNUM_ALLOC */
# define ASSH_BIGNUM_FREE(context, name) \
  assh_free(context, name, ASSH_ALLOC_KEY);

#endif

/** @This returns the actual bit length of the big number. */
static inline unsigned int
assh_bignum_bits(const struct assh_bignum_s *bn)
{
  return bn->l * ASSH_BIGNUM_W;
}

/** This function reduces the bit length of a big number. */
static inline ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_shrink(struct assh_bignum_s *bn,
                   unsigned int bits)
{
  assh_error_t err;
  ASSH_CHK_RET(bits > bn->l * ASSH_BIGNUM_W, ASSH_ERR_NUM_OVERFLOW);
  bn->l = ASSH_BIGNUM_WORDS(bits);
  return ASSH_OK;
}

#endif

/** @This prints the big number in hexadecimal representation. */
void assh_bignum_print(FILE *out, const char *name,
		       const struct assh_bignum_s *bn);

/** @This initializes a big number and/or return the bit length of the
    number from a mpint buffer. The @tt mpint parameter must point to
    the string size header. Either the @tt bn or the @tt bits
    parameters may be @tt NULL.

    No pointer bound checking is performed, the mpint must have been
    checked previously using the @ref assh_check_string function. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_from_mpint(struct assh_bignum_s *bn, unsigned int *bits,
                       const uint8_t * __restrict__ mpint);

/** @This initializes a big number and/or return the bit length of the
    number from an asn1 integer value. The @tt integer parameter must
    point to the asn1 integer type identifier. Either the @tt bn or
    the @tt bits parameters may be @tt NULL.

    No pointer bound checking is performed, the value must have been
    checked previously using the @ref assh_check_asn1 function. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_from_asn1(struct assh_bignum_s *bn, unsigned int *bits,
                      const uint8_t * __restrict__ integer);

/** @This first skips the leading zero bytes of the buffer to evaluate
    the actual byte aligned big number size. It then initializes
    and/or return the bit length of the number. Either the @tt bn or the
    @tt bits parameters may be @tt NULL. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_from_bytes(struct assh_bignum_s *bn, unsigned int *bits,
                       const uint8_t * __restrict__ data, size_t data_len);

/** @This loads some raw data in a big number. Data are loaded as most
    significant byte first. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_from_data(struct assh_bignum_s *bn,
                      const uint8_t * __restrict__ data, size_t data_len);

/** @This initializes a big number using an hexadecimal string. If @tt
    bits is not @tt NULL, it will be set to the bit size of the hex
    string. If @tt hex_len is 0, @ref strlen is used to compute the
    string size. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_from_hex(struct assh_bignum_s *bn, unsigned int *bits,
		     const char * __restrict__ hex, size_t hex_len);

/** This function sets the number to the specified integer value. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_from_uint(struct assh_bignum_s *n,
		      unsigned int x);

/** @This converts a big number to the mpint format used in ssh
    packets. The mpint buffer must contain enough room for the mpint
    representation as returned by either the @ref
    assh_bignum_mpint_size or @ref assh_packet_mpint_size function.
    function. The actual number of bytes used by the mpint can be
    smaller. @see assh_packet_add_mpint */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_to_mpint(const struct assh_bignum_s *bn,
                     uint8_t * __restrict__ mpint);

/** @This returns the maximum number of bytes needed to store a big
    number in ssh mpint representation. The returned size includes the
    4 bytes header and may be slightly larger than actually
    needed. This value can be used to call the @ref the
    assh_packet_add_string function. @see assh_packet_add_mpint */
size_t assh_bignum_mpint_size(const struct assh_bignum_s *bn);

/** @This converts the big number to a string of bytes. Data are stored
    in most significant byte first order. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_msb_to_data(const struct assh_bignum_s *bn,
                        uint8_t * __restrict__ data, size_t data_len);

/** This function sets the number to a random value. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_rand(struct assh_context_s *c,
                 struct assh_bignum_s *n,
		 enum assh_prng_quality_e quality);

/** This function copy a big number. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_copy(struct assh_bignum_s *a,
                 const struct assh_bignum_s *b);

/** This function compares two big numbers. */
int assh_bignum_cmp(const struct assh_bignum_s *a,
		    const struct assh_bignum_s *b);

/** This function tests if a big numbers is zero. The processing time
    does not depend on the number value. */
assh_bool_t assh_bignum_cmpz(const struct assh_bignum_s *a);

/** This function compares a big number and an integer. */
int assh_bignum_cmp_uint(const struct assh_bignum_s *a, unsigned int x);

/** This function adds B to A. Any of the 3
    parameters can point to the same number. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_add(struct assh_bignum_s *r,
		const struct assh_bignum_s *a,
		const struct assh_bignum_s *b);

/** This function subtracts B from A. Any of the 3 parameters can
    point to the same number. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_sub(struct assh_bignum_s *r,
		const struct assh_bignum_s *a,
		const struct assh_bignum_s *b);

/** This multiply two big numbers. Multiplication involving numbers of
    the same even size in number of words will use the karatsuba algorithm. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_mul(struct assh_bignum_s *r,
                const struct assh_bignum_s *a,
                const struct assh_bignum_s *b);

/** This multiply two big numbers with modulo. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_mulmod(struct assh_bignum_s *r,
                   const struct assh_bignum_s *a,
                   const struct assh_bignum_s *b,
                   const struct assh_bignum_s *m);

/** This computes the modular multiplicative inverse of @em a modulo @em {m}. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_modinv(struct assh_bignum_s *r,
                   const struct assh_bignum_s *a,
                   const struct assh_bignum_s *m);

/** This computes the greatest common divisor of @em a and @em {b}. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_gcd(struct assh_bignum_s *r,
                const struct assh_bignum_s *a,
                const struct assh_bignum_s *b);

/** This function divides A by B. The remainder is stored in @tt r. The
    result is stored in @tt d unless it is a NULL pointer. The @tt a
    and @tt r parameters may point to the same number. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_div(struct assh_bignum_s *r,
                struct assh_bignum_s *d,
                const struct assh_bignum_s *a,
                const struct assh_bignum_s *b);

/** This function performs a logical right bit shift operation. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_rshift(struct assh_bignum_s *r,
                   const struct assh_bignum_s *a,
                   unsigned int n);

/** This function performs the modular exponentiation @em {x^e modulo m}. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_expmod(struct assh_bignum_s *r,
                   const struct assh_bignum_s *x,
                   const struct assh_bignum_s *e,
                   const struct assh_bignum_s *m);

typedef uint32_t assh_bignum_op_t;

/**

   Execute big number operations specified by the bytecode on provided
   arguments and temporaries.

   The format string indicates the types of arguments passed to the
   function and the number of temporary big numbers. The @tt move
   instruction can be used to convert between big numbers (argument or
   temporary) and other type of arguments. All other instructions are
   designed to be used on big numbers only.

   The format string pattern is @em{[NMSHDIT]+T*} :
   @list
     @item N: big number argument, pointer to number expected as va_arg
     @item M: mpint, pointer to mpint expected as va_arg
     @item S: ssh string, pointer to ssh string expected as va_arg
     @item H: nul terminated hex string, char * expected as va_arg
     @item D: bytes array, uint8_t * expected, deduce size from number argument
     @item I: integer, intptr_t * expected as va_arg
     @item T: big number temporary, bit size of number expected as va_arg
   @end list

   Opcodes:

@code R
      op       src2     src1     dst
      xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
      |        |        |        |
      |        |        |        \------- destination value index
      |        |        |
      |        |        \------- source 1 value index
      |        |
      |        \------ source 2 value index / count
      |
      \---------- op

		  00000000: move(dst, src1)
                  00000000: end()
                  00000001: add(dst, src1, src2)
                  00000010: sub(dst, src1, src2)
                  00000011: mul(dst, src1, src2)
                  00000100: div(dst, src1, src2)
                  00000111: mulmod(dst, src1, src2)
                  00001000: expmod(dst, src1, src2)
                  00001001: modinv(dst, src1, src2)
                  00001010: setmod(src1)
                  00001011: rand(dst, src1 = quality)

      op       src2     src1     cmpop
      xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
      |        |        |        |
      |        |        |        \------- comparison
      |        |        |
      |        |        \------- source 1 value index
      |        |
      |        \------ source 2 value index / count
      |
      \---------- op

                  00001100: cmp

      op       imm              dst
      xxxxxxxx xxxxxxxxxxxxxxxx xxxxxxxx
      |        |
      |        \------- value
      |
      \---------- op
                  00001101: repeat(count)
		  00001110: setuint(dst, value)
                  00001111: dump(src1)

@end code

*/
assh_error_t assh_bignum_bytecode(struct assh_context_s *c,
                                  const assh_bignum_op_t *ops,
                                  const char *format, ...);

#define ASSH_BIGNUM_BC_FMT1(op, a, b, c) (((op) << 24) | ((a) << 16) | ((b) << 8) | (c))
#define ASSH_BIGNUM_BC_FMT2(op, a, b)    (((op) << 24) | ((a) << 8) | (b))

/** This instruction terminates execution of the bytecode */
#define ASSH_BIGNUM_BC_END()                       ASSH_BIGNUM_BC_FMT1(0, 0, 0, 0)

/** This instruction moves between big numbers, or convert to/from
    other types of arguments. */
#define ASSH_BIGNUM_BC_MOVE(dst, src)              ASSH_BIGNUM_BC_FMT1(0, 0, src, dst)

/** This instruction computes dst = src1 + src2 */
#define ASSH_BIGNUM_BC_ADD(dst, src1, src2)        ASSH_BIGNUM_BC_FMT1(1, src2, src1, dst)

/** This instruction computes dst = src1 - src2 */
#define ASSH_BIGNUM_BC_SUB(dst, src1, src2)        ASSH_BIGNUM_BC_FMT1(2, src2, src1, dst)

/** This instruction computes dst = src1 * src2 */
#define ASSH_BIGNUM_BC_MUL(dst, src1, src2)        ASSH_BIGNUM_BC_FMT1(3, src2, src1, dst)

/** This instruction computes dst = dst % src2.
    It also computes src1 = dst / src2  if src1 != src2. */
#define ASSH_BIGNUM_BC_DIV(dst, src1, src2)        ASSH_BIGNUM_BC_FMT1(4, src2, src1, dst)

/** This instruction computes dst = gcd(src1, src2) */
#define ASSH_BIGNUM_BC_GCD(dst, src1, src2)     ASSH_BIGNUM_BC_FMT1(5, src2, src1, dst)

/** This instruction computes dst = (src1 * src2) % mod */
#define ASSH_BIGNUM_BC_MULMOD(dst, src1, src2)     ASSH_BIGNUM_BC_FMT1(7, src2, src1, dst)

/** This instruction computes dst = (src1 ** src2) % mod */
#define ASSH_BIGNUM_BC_EXPMOD(dst, src1, src2)     ASSH_BIGNUM_BC_FMT1(8, src2, src1, dst)

/** This instruction computes dst = invmod(src1, src2) */
#define ASSH_BIGNUM_BC_MODINV(dst, src1, src2)     ASSH_BIGNUM_BC_FMT1(9, src2, src1, dst)

/** This instruction sets the index of the modulus register used
    implicitly by some instructions. */
#define ASSH_BIGNUM_BC_SETMOD(src1)                ASSH_BIGNUM_BC_FMT1(10, 0, src1, 0)

/** This instruction initializes a big number with random data. The
    quality operand is of the type @ref assh_prng_quality_e. */
#define ASSH_BIGNUM_BC_RAND(dst, quality)          ASSH_BIGNUM_BC_FMT1(11, 0, quality, dst)

/** This instruction makes the @ref assh_bignum_bytecode function
    return an error if the two number are not equal. */
#define ASSH_BIGNUM_BC_CMPEQ(src1, src2)           ASSH_BIGNUM_BC_FMT1(12, src2, src1, 0)
/** This instruction makes the @ref assh_bignum_bytecode function
    return an error if the two number are equal. */
#define ASSH_BIGNUM_BC_CMPNE(src1, src2)           ASSH_BIGNUM_BC_FMT1(12, src2, src1, 1)
/** This instruction makes the @ref assh_bignum_bytecode function
    return an error if the first number is less than the second. */
#define ASSH_BIGNUM_BC_CMPLT(src1, src2)           ASSH_BIGNUM_BC_FMT1(12, src2, src1, 2)
/** This instruction makes the @ref assh_bignum_bytecode function
    return an error if the first number is less than or equal to the second. */
#define ASSH_BIGNUM_BC_CMPLTEQ(src1, src2)         ASSH_BIGNUM_BC_FMT1(12, src2, src1, 3)

/** This instruction makes the next instruction repeat a fixed number of times. */
#define ASSH_BIGNUM_BC_REPEAT(count)               ASSH_BIGNUM_BC_FMT2(13, count, 0)

/** This instruction initializes a big number with a constant unsigned integer value. */
#define ASSH_BIGNUM_BC_UINT(dst, value)         ASSH_BIGNUM_BC_FMT2(14, value, dst)

/** This instruction print a big number argument for debugging purpose. */
#define ASSH_BIGNUM_BC_BNDUMP(src)                   ASSH_BIGNUM_BC_FMT1(15, 0, src, 0)

#endif

