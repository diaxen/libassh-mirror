
#include <stdlib.h>
#include <assh/assh_prng.h>

static ASSH_PRNG_INIT_FCN(assh_prng_weak_init)
{
  return ASSH_OK;
}

static ASSH_PRNG_GET_FCN(assh_prng_weak_get)
{
  size_t i;
  for (i = 0; i < rdata_len; i++)
    rdata[i] = rand();

  return ASSH_OK;
}

static ASSH_PRNG_CLEANUP_FCN(assh_prng_weak_cleanup)
{
}

static const struct assh_prng_s assh_prng_weak = 
{
  .f_init = assh_prng_weak_init,
  .f_get = assh_prng_weak_get,
  .f_cleanup = assh_prng_weak_cleanup,  
};

