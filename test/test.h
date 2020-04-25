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

#ifndef ASSH_TEST_H_
#define ASSH_TEST_H_

#include <stdlib.h>
#include <stdio.h>

#define TEST_LOC(lnum) __FILE__ ":" #lnum ":"
#define TEST_LOC_(x) TEST_LOC(x)

#define TEST_FAIL(...)				\
  do {						\
    fprintf(stderr, "FAIL " TEST_LOC_(__LINE__) __VA_ARGS__);	\
    exit(1);					\
  } while (0)

#define TEST_ASSERT(c)				\
  do {						\
    if (!(c)) TEST_FAIL( "failed: " #c);	\
  } while (0)

#include <assh/assh_algo.h>
#include <assh/assh_prng.h>

assh_status_t
test_algo_lookup(enum assh_algo_class_e cl, const char *name,
		 const char *variant, const char *implem,
		 const struct assh_algo_s **algo);

/** This swaps some bits with the given probability.
    The number of bits swpped is returned. */
unsigned
test_fuzz_mangle(uint8_t *data, size_t len, uint32_t ratio);

/* byte period of random bit error,
   no error is introduced when 0 */
extern uint32_t test_packet_fuzz;
extern unsigned long test_packet_fuzz_bits;

extern const struct assh_algo_cipher_s test_cipher_fuzz;

/* make a session use the fuzz cipher from start
   (before end of first key exchange) */
void test_cipher_fuzz_initreg(struct assh_context_s *c,
                              struct assh_session_s *s);



uint32_t test_prng_rand_seed(uint64_t *seed);

extern const uint32_t test_prng_rand_max;
extern uint64_t test_prng_seed;

static inline uint32_t test_prng_rand()
{
  return test_prng_rand_seed(&test_prng_seed);
}

static inline void test_prng_set_seed(uint64_t seed)
{
  if (!seed)
    seed++;
  test_prng_seed = seed;
}

extern const struct assh_prng_s test_prng_dummy;

#include <assh/assh_alloc.h>

extern size_t test_alloc_size;
extern uint32_t test_alloc_fuzz;
extern unsigned long test_alloc_fuzz_fails;

#define TEST_ALLOC_ALIGN 32

ASSH_ALLOCATOR(test_leaks_allocator);

#endif
