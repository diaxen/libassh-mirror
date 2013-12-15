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
#include "assh_prng.h"

#ifdef CONFIG_ASSH_USE_GCRYPT

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

static inline ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_init(struct assh_context_s *c, struct assh_bignum_s *bn, unsigned int bits)
{
  bn->n = NULL;
  bn->l = bits;
  return ASSH_OK;
}

static inline void
assh_bignum_cleanup(struct assh_context_s *c, struct assh_bignum_s *bn)
{
  if (bn->n != NULL)
    gcry_mpi_release(bn->n);
}

# define ASSH_BIGNUM_ALLOC(context, name, bits, lbl)                    \
  struct assh_bignum_s name##_, *name = &name##_;                       \
  ASSH_ERR_GTO(assh_bignum_init(context, name, bits), lbl);             \

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

/* 8 bits big number word is useful for testing algorithms because
   there are fewer possible word values, it will test more corner
   cases quickly. */
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
  return sizeof(struct assh_bignum_s)
    + ASSH_BIGNUM_WORDS(bits) * sizeof(assh_bnword_t);
}

/** @This initializes a big number. */
static inline ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_init(struct assh_context_s *c, struct assh_bignum_s *bn, unsigned int bits)
{
  bn->l = ASSH_BIGNUM_WORDS(bits);
  return ASSH_OK;
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
# define ASSH_BIGNUM_ALLOC(context, name, bits, lbl)                     \
  size_t name##_l__ = ASSH_BIGNUM_WORDS(bits);                          \
  struct assh_bignum_s *name = alloca(sizeof(struct assh_bignum_s)      \
               + name##_l__ * sizeof(assh_bnword_t));              \
  if (0)                                                                \
    goto lbl;                                                           \
  name->l = name##_l__;

/** @This releases the big number allocated using @ref #ASSH_BIGNUM_ALLOC */
# define ASSH_BIGNUM_FREE(context, name)

#else

/** @This declares a pointer to a big number, allocate the required
    storage using the context allocator and initializes the number. */
# define ASSH_BIGNUM_ALLOC(context, name, bits, lbl)                     \
  size_t name##_l__ = ASSH_BIGNUM_WORDS(bits);                          \
  struct assh_bignum_s *name;                                           \
  ASSH_ERR_GTO(assh_alloc(context, sizeof(struct assh_bignum_s)         \
      + name##_l__ * sizeof(assh_bnword_t), ASSH_ALLOC_KEY, (void**)&name), lbl); \
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
  ASSH_ERR_RET(bits > bn->l * ASSH_BIGNUM_W ? ASSH_ERR_OVERFLOW : 0);
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

/** @This initializes a big number using an hexadecimal string. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_from_hex(struct assh_bignum_s *bn, unsigned int *bits,
		     const char * __restrict__ hex, size_t hex_len);

/** @This converts a big number to the mpint format used in ssh
    packets. The mpint buffer must contain enough room for the mpint
    representation as returned by the @ref assh_bignum_mpint_size
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

/** This function sets the number to the specified integer value. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_uint(struct assh_bignum_s *n,
                 unsigned int x);

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

#endif

