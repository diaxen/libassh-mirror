
#include <assh/assh_cipher.h>

#include "fuzz.h"

/* byte period of random bit error,
   no error is introduced when 0 */
static uint32_t packet_fuzz = 0;
static unsigned long packet_fuzz_bits = 0;

static ASSH_CIPHER_INIT_FCN(assh_fuzz_init)
{
  return ASSH_OK;
}

static ASSH_CIPHER_PROCESS_FCN(assh_fuzz_process)
{
  if (packet_fuzz)
    packet_fuzz_bits += aash_fuzz_mangle(data, len, packet_fuzz);
  return ASSH_OK;
}

static ASSH_CIPHER_CLEANUP_FCN(assh_fuzz_cleanup)
{
}

const struct assh_algo_cipher_s assh_cipher_fuzz =
{
  ASSH_ALGO_BASE(CIPHER, "assh-test", 0, 99,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_ASSH,
                      "fuzz" })
  ),
  .ctx_size = 0,
  .block_size = 8,
  .head_size = 4,
  .f_init = assh_fuzz_init,
  .f_process = assh_fuzz_process,
  .f_cleanup = assh_fuzz_cleanup,
};

/* make a session use the fuzz cipher from start
   (before end of first key exchange) */
void assh_cipher_fuzz_initreg(struct assh_context_s *c,
                              struct assh_session_s *s)
{
  struct assh_kex_keys_s *keys;

  while (assh_alloc(c, sizeof(*keys), ASSH_ALLOC_INTERNAL, (void**)&keys))
    /* retry due to alloc fuzz */;

  keys->cipher = &assh_cipher_fuzz;
  keys->cipher_ctx = NULL;
  keys->mac = &assh_hmac_none;
  keys->mac_ctx = NULL;
  keys->cmp = &assh_compress_none;
  keys->cmp_ctx = NULL;
  s->cur_keys_out = keys;
}
