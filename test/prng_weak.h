
#ifndef ASSH_TEST_PRNG_WEAK_H_
#define ASSH_TEST_PRNG_WEAK_H_

#include <stdint.h>
#include <stdlib.h>
#include <assh/assh_prng.h>

static uint64_t prng_seed = 1;
static const uint32_t prng_rand_max = 0xffffffffULL;

uint32_t assh_prng_rand()
{
  /* 64 bits lfsr */
  prng_seed = (-(prng_seed & 1) & 0x81ec82f69eb5a9d3ULL)
            ^ (prng_seed >> 1);

  /* diffusion */
  uint64_t r = prng_seed;
  uint64_t c = 2466808117;
  r = ((uint32_t)r * c) ^ ((uint32_t)(r >> 32) * c);
  r = r ^ (r >> 32);

  return r;
}

void assh_prng_seed(uint64_t seed)
{
  if (!seed)
    seed++;
  prng_seed = seed;
}

static ASSH_PRNG_INIT_FCN(assh_prng_weak_init)
{
  return ASSH_OK;
}

static ASSH_PRNG_GET_FCN(assh_prng_weak_get)
{
  size_t i;
  for (i = 0; i < rdata_len; i++)
    rdata[i] = assh_prng_rand();

  return ASSH_OK;
}

static ASSH_PRNG_CLEANUP_FCN(assh_prng_weak_cleanup)
{
}

const struct assh_prng_s assh_prng_weak = 
{
  .f_init = assh_prng_weak_init,
  .f_get = assh_prng_weak_get,
  .f_cleanup = assh_prng_weak_cleanup,  
};

#endif
