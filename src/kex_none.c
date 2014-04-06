
#include <assh/assh_kex.h>
#include <assh/assh_session.h>
#include <assh/hash_sha1.h>
#include <assh/assh_bignum.h>

static ASSH_KEX_PROCESS_FCN(assh_kex_none_process)
{
  assh_error_t err;

  assert(p == NULL);

  /* shared secret is 42 (64 bits) */
  ASSH_BIGNUM_ALLOC(s->ctx, kn, 64, ASSH_ERRSV_CONTINUE, err_);
  ASSH_ERR_GTO(assh_bignum_from_uint(kn, 42), err_k);

  /* exchange hash is zero (160 bits) */
  uint8_t ex_hash[20];
  memset(ex_hash, 0, sizeof(ex_hash));

  /* no packet exchange, setup new key */
  ASSH_ERR_GTO(assh_kex_new_keys(s, &assh_hash_sha1, ex_hash, kn), err_k);
  ASSH_ERR_GTO(assh_kex_end(s, 1), err_k);

  err = ASSH_OK;
 err_k:
  ASSH_BIGNUM_FREE(s->ctx, kn);
 err_:
  return err;
}

static ASSH_KEX_CLEANUP_FCN(assh_kex_none_cleanup)
{
}

static ASSH_KEX_INIT_FCN(assh_kex_none_init)
{
  return ASSH_OK;
}

struct assh_algo_kex_s assh_kex_none =
{
  .algo = { .name = "none@libassh.org", .class_ = ASSH_ALGO_KEX,
            .safety = 0, .speed = 99 },
  .f_init = assh_kex_none_init,
  .f_cleanup = assh_kex_none_cleanup,
  .f_process = assh_kex_none_process,
};

