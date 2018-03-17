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

#ifndef ASSH_BIGNUM_BUILTIN_H_
#define ASSH_BIGNUM_BUILTIN_H_

#include <assh/assh.h>
#include <assh/assh_bignum.h>
#include <assh/assh_prng.h>

#ifndef CONFIG_ASSH_BIGNUM_WORD
# define CONFIG_ASSH_BIGNUM_WORD 32
#endif

#if CONFIG_ASSH_BIGNUM_WORD == 8
/* 8 bits big number word is useful for testing bignum algorithms.
   Because there are fewer possible word values, it will test more
   corner cases in a short time. */
typedef uint8_t assh_bnword_t;
typedef int8_t assh_bnsword_t;
typedef uint16_t assh_bnlong_t;
typedef int16_t assh_bnslong_t;
#define ASSH_BN_FMT "%02x"
#define ASSH_BN_LFSR 0xb8
#define assh_bn_clz(x) assh_ct_clz8((assh_bnword_t)x)
#define assh_bn_ctz(x) assh_ct_ctz8((assh_bnword_t)x)

#elif CONFIG_ASSH_BIGNUM_WORD == 16
typedef uint16_t assh_bnword_t;
typedef int16_t assh_bnsword_t;
typedef uint32_t assh_bnlong_t;
typedef int32_t assh_bnslong_t;
#define ASSH_BN_FMT "%04x"
#define ASSH_BN_LFSR 0xb008
#define assh_bn_clz(x) assh_ct_clz16((assh_bnword_t)x)
#define assh_bn_ctz(x) assh_ct_ctz16((assh_bnword_t)x)

#elif CONFIG_ASSH_BIGNUM_WORD == 32
typedef uint32_t assh_bnword_t;
typedef int32_t assh_bnsword_t;
typedef uint64_t assh_bnlong_t;
typedef int64_t assh_bnslong_t;
#define ASSH_BN_FMT "%08x"
#define ASSH_BN_LFSR 0x80200003
#define assh_bn_clz(x) assh_ct_clz32((assh_bnword_t)x)
#define assh_bn_ctz(x) assh_ct_ctz32((assh_bnword_t)x)

#elif CONFIG_ASSH_BIGNUM_WORD == 64
typedef uint64_t assh_bnword_t;
typedef int64_t assh_bnsword_t;
typedef unsigned __int128 assh_bnlong_t;
typedef signed __int128 assh_bnslong_t;
#define ASSH_BN_FMT "%016llx"
#define ASSH_BN_LFSR 0xd800000000000000ULL
#define assh_bn_clz(x) assh_ct_clz64((assh_bnword_t)x)
#define assh_bn_ctz(x) assh_ct_ctz64((assh_bnword_t)x)

#endif

#define ASSH_BN_WORDMAX (assh_bnword_t)-1LL

/** Minimum number of words for karatsuba to switch to school mul. */
#define ASSH_BIGNUM_KARATSUBA_THRESHOLD 32

/** @This specifies the number of bits in a big number word. */
#define ASSH_BIGNUM_W (sizeof(assh_bnword_t) * 8)

struct assh_bignum_mt_s
{
  struct assh_bignum_s mod;
  assh_bnword_t n0;
  /* maximum bits */
  uint16_t max_bits;
};

ASSH_FIRST_FIELD_ASSERT(assh_bignum_mt_s, mod);

ASSH_INLINE assh_bnword_t assh_bignum_eqzero(assh_bnword_t a)
{
  /* return !a in constant time */
  return ((assh_bnword_t)(~a & (a - 1)) >> (ASSH_BIGNUM_W - 1)) & 1;
}

ASSH_INLINE assh_bnword_t assh_bignum_lt(assh_bnword_t a, assh_bnword_t b)
{
  /* return a < b in constant time */
  return (((assh_bnlong_t)a - (assh_bnlong_t)b) >> ASSH_BIGNUM_W) & 1;
}

ASSH_INLINE size_t
assh_bignum_words(size_t bits)
{
  return (((bits - 1) | (ASSH_BIGNUM_W - 1)) + 1) / ASSH_BIGNUM_W;
}

/****************************** bignum_builtin.c */

void
assh_bignum_dump(const assh_bnword_t *x, size_t l);

assh_bnword_t assh_bnword_egcd(assh_bnword_t a, assh_bnword_t b,
                               assh_bnword_t q);

ASSH_INLINE assh_bnword_t
assh_bnword_modinv(assh_bnword_t a, assh_bnword_t b)
{
  assh_bnword_t q = assh_bnword_egcd(a, b, 0);
  q += ((assh_bnsword_t)q >> 31) & b;
  return q;
}

ASSH_INLINE assh_bnword_t
assh_bnword_mt_modinv(assh_bnword_t a)
{
  assh_bnword_t b = 2 + a;

  b *= 2 + b * a;
  b *= 2 + b * a;
  if (ASSH_BIGNUM_W >= 16)
    b *= 2 + b * a;
  if (ASSH_BIGNUM_W >= 32)
    b *= 2 + b * a;
  if (ASSH_BIGNUM_W >= 64)
    b *= 2 + b * a;

  return -b;
}

void
assh_bignum_cmove(assh_bnword_t *a, const assh_bnword_t *b,
                  size_t l, assh_bool_t c);

void
assh_bignum_cswap(assh_bnword_t *an, assh_bnword_t *bn,
                  size_t l, assh_bool_t c);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_copy(struct assh_bignum_s *dst,
                 const struct assh_bignum_s *src);

void
assh_bignum_to_buffer(const struct assh_bignum_s *bn,
                      uint8_t *in, uint8_t **end,
                      enum assh_bignum_fmt_e format);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_from_buffer(struct assh_bignum_s *bn,
                        const uint8_t * __restrict__ data,
                        size_t data_len, enum assh_bignum_fmt_e format);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_from_uint(struct assh_bignum_s *bn,
                      uintptr_t x);

assh_bool_t assh_bignum_eq_uint(const assh_bnword_t a,
				const assh_bnword_t *b, size_t bl);

assh_bool_t assh_bignum_eq(const assh_bnword_t *a, size_t al,
			   const assh_bnword_t *b, size_t bl);

/** @This returns the effective bit length of the number. For secret
    numbers, the bit length of the container is returned instead. */
uint_fast32_t assh_bignum_bitlen(const struct assh_bignum_s *a);

enum assh_bignum_cmp_result_e {
  ASSH_BIGNUM_CMP_GT = 1,
  ASSH_BIGNUM_CMP_LT = 2,
};

enum assh_bignum_cmp_result_e
assh_bignum_cmp(const struct assh_bignum_s *a,
                const struct assh_bignum_s *b);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_rand(struct assh_context_s *c,
                 struct assh_bignum_s *bn,
                 const struct assh_bignum_s *min,
                 const struct assh_bignum_s *max,
                 enum assh_prng_quality_e quality);

/****************************** bignum_builtin_shift.c */

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_rshift(struct assh_bignum_s *dst,
                   const struct assh_bignum_s *src,
                   uint_fast32_t n);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_lshift(struct assh_bignum_s *dst,
                   const struct assh_bignum_s *src,
                   uint_fast32_t n);

/****************************** bignum_builtin_add.c */

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_addsub(struct assh_bignum_s *dst,
                   const struct assh_bignum_s *a,
                   const struct assh_bignum_s *b,
                   assh_bnword_t smask /* 0:add, -1:sub */);

/****************************** bignum_builtin_div.c */

assh_error_t
assh_bignum_div_euclidean(assh_bnword_t * __restrict__ rn,
                          uint_fast32_t r_len,
                          assh_bnword_t * __restrict__ dn,
                          uint_fast32_t d_len,
                          const assh_bnword_t * __restrict__ bn,
                          uint_fast32_t b_len,
                          assh_bool_t secret, int_fast32_t bitlen_diff);

size_t
assh_bignum_div_sc_size(const struct assh_bignum_s *r,
                        const struct assh_bignum_s *a);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_div(struct assh_context_s *ctx,
                assh_bnword_t *s,
                struct assh_bignum_s *r,
                struct assh_bignum_s *d,
                const struct assh_bignum_s *a,
                const struct assh_bignum_s *b);

size_t
assh_bignum_modinv_sc_size(const struct assh_bignum_s *m);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_modinv(struct assh_context_s *ctx,
                   assh_bnword_t *s,
                   struct assh_bignum_s *u,
                   const struct assh_bignum_s *a,
                   const struct assh_bignum_s *m);

size_t
assh_bignum_gcd_sc_size(const struct assh_bignum_s *a,
                        const struct assh_bignum_s *b);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_gcd(struct assh_context_s *ctx,
                assh_bnword_t *s,
                struct assh_bignum_s *g,
                const struct assh_bignum_s *a,
                const struct assh_bignum_s *b);

/****************************** bignum_builtin_mul.c */

size_t
assh_bignum_mul_sc_size(const struct assh_bignum_s *r,
                        const struct assh_bignum_s *a,
                        const struct assh_bignum_s *b);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_mul(struct assh_context_s *ctx,
                assh_bnword_t *s,
                struct assh_bignum_s *r,
                const struct assh_bignum_s *a,
                const struct assh_bignum_s *b);

size_t
assh_bignum_mul_mod_sc_size(const struct assh_bignum_s *a,
                            const struct assh_bignum_s *b);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_mul_mod(struct assh_context_s *ctx,
                    assh_bnword_t *s,
                    struct assh_bignum_s *r,
                    const struct assh_bignum_s *a,
                    const struct assh_bignum_s *b,
                    const struct assh_bignum_s *m);

/****************************** bignum_builtin_mt.c */

void
assh_bignum_mt_add(struct assh_bignum_s *dst,
                   const struct assh_bignum_s *a,
                   const struct assh_bignum_s *b,
                   const struct assh_bignum_s *mod);
void
assh_bignum_mt_sub(struct assh_bignum_s *dst,
                   const struct assh_bignum_s *a,
                   const struct assh_bignum_s *b,
                   const struct assh_bignum_s *mod);

void
assh_bignum_mt_mul(const struct assh_bignum_mt_s *mt,
                   assh_bnword_t * __restrict__ a,
                   const assh_bnword_t * __restrict__ x,
                   const assh_bnword_t * __restrict__ y);

void
assh_bignum_mt_reduce(const struct assh_bignum_mt_s *mt,
                      assh_bnword_t * __restrict__ a,
                      const assh_bnword_t * __restrict__ x);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_mt_init(struct assh_context_s *c,
                    struct assh_bignum_mt_s *mt,
                    const struct assh_bignum_s *mod);

size_t
assh_bignum_mt_to_sc_size(const struct assh_bignum_s *r,
                          const struct assh_bignum_s *a);

void
assh_bignum_mt_to(struct assh_context_s *ctx,
                  assh_bnword_t *s,
                  const struct assh_bignum_mt_s *mt,
                  struct assh_bignum_s *r,
                  const struct assh_bignum_s *a);

size_t
assh_bignum_mt_from_sc_size(const struct assh_bignum_s *r,
                            const struct assh_bignum_s *a);

void
assh_bignum_mt_from(struct assh_context_s *ctx,
                    assh_bnword_t *s,
                    const struct assh_bignum_mt_s *mt,
                    struct assh_bignum_s *r,
                    const struct assh_bignum_s *a);

size_t
assh_bignum_mul_mod_mt_sc_size(const struct assh_bignum_s *r,
                               const struct assh_bignum_s *a,
                               const struct assh_bignum_s *b);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_mul_mod_mt(struct assh_context_s *ctx,
                       assh_bnword_t *s,
                       struct assh_bignum_s *r,
                       const struct assh_bignum_s *a,
                       const struct assh_bignum_s *b,
                       const struct assh_bignum_mt_s *mt);

size_t
assh_bignum_expmod_mt_sc_size(const struct assh_bignum_mt_s *mt);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_expmod_mt(struct assh_context_s *ctx,
                      assh_bnword_t *s,
                      struct assh_bignum_s *r,
                      const struct assh_bignum_s *a,
                      const struct assh_bignum_s *b,
                      const struct assh_bignum_mt_s *mt);

size_t
assh_bignum_modinv_mt_sc_size(const struct assh_bignum_mt_s *mt);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_modinv_mt(struct assh_context_s *ctx,
                      assh_bnword_t *s,
                      struct assh_bignum_s *r,
                      const struct assh_bignum_s *a,
                      const struct assh_bignum_mt_s *mt);

/****************************** bignum_builtin_prime.c */

size_t
assh_bignum_prime_sc_size(const struct assh_bignum_s *bn);

assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_check_prime(struct assh_context_s *ctx,
                        assh_bnword_t *s,
                        const struct assh_bignum_s *bn,
                        size_t rounds, assh_bool_t *result);

assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_next_prime(struct assh_context_s *ctx,
                       assh_bnword_t *s,
                       struct assh_bignum_s *bn,
                       struct assh_bignum_s *step);

assh_error_t ASSH_WARN_UNUSED_RESULT
assh_bignum_gen_prime(struct assh_context_s *c,
                      assh_bnword_t *s,
                      struct assh_bignum_s *bn,
                      const struct assh_bignum_s *min,
                      const struct assh_bignum_s *max,
                      enum assh_prng_quality_e quality);

#endif
