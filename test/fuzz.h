
#include <stdint.h>

#include "prng_weak.h"

static unsigned
aash_fuzz_mangle(uint8_t *data, size_t len, uint32_t ratio)
{
  uint64_t r = prng_rand_max / ratio;
  uint32_t i, j;

  for (i = j = 0; i < len * 8; i++)
    if (r > assh_prng_rand() * 8ULL)
      {
	data[i / 8] ^= 1 << (i % 8);
	j++;
      }

  return j;
}

