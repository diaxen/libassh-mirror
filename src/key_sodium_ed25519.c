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

#include "key_sodium_ed25519.h"

#include <assh/assh_bignum.h>
#include <assh/assh_packet.h>
#include <assh/assh_buffer.h>
#include <assh/assh_alloc.h>
#include <assh/assh_prng.h>
#include <assh/assh_hash.h>
#include <assh/mod_sodium.h>

#include <sodium/crypto_sign_ed25519.h>
#include <string.h>

static ASSH_KEY_CMP_FCN(assh_key_ed25519_cmp)
{
  assert(key->algo == &assh_key_sodium_ed25519);

  if (key->algo != b->algo)
    return 0;

  struct assh_key_ed25519_s *k = (void*)key;
  struct assh_key_ed25519_s *l = (void*)b;

  if (!pub && (!k->key.private || !l->key.private ||
       (k->key.private && assh_memcmp(k->pv_key, l->pv_key, ASSH_ED25519_KSIZE))))
    return 0;

  return !assh_memcmp(k->pub_key, l->pub_key, ASSH_ED25519_KSIZE);
}

#ifdef CONFIG_ASSH_KEY_VALIDATE
static ASSH_KEY_VALIDATE_FCN(assh_key_ed25519_validate)
{
  *result = ASSH_KEY_NOT_CHECKED;
  return ASSH_OK;
}
#endif

static ASSH_KEY_CLEANUP_FCN(assh_key_ed25519_cleanup)
{
  struct assh_key_ed25519_s *k = (void*)key;

  assh_free(c, k);
}

static ASSH_KEY_OUTPUT_FCN(assh_key_ed25519_output)
{
  struct assh_key_ed25519_s *k = (void*)key;
  assh_status_t err;

  const char *algo_name = k->key.algo->name;

  assert(key->algo == &assh_key_sodium_ed25519);
  static const size_t n = ASSH_ED25519_KSIZE;

  switch (format)
    {
    case ASSH_KEY_FMT_PUB_RFC4253:
      ASSH_RETURN(assh_blob_write("Zs Ds", blob, blob_len,
                                  algo_name, k->pub_key, n));

    case ASSH_KEY_FMT_PV_OPENSSH_V1_KEY:
      ASSH_RET_IF_TRUE(!k->key.private, ASSH_ERR_MISSING_KEY);

      ASSH_RETURN(assh_blob_write("Zs Ds (Db Db)s", blob, blob_len, algo_name,
				  k->pub_key, n,
				  k->pv_key, n,
				  k->pub_key, n));

    default:
      ASSH_RETURN(ASSH_ERR_NOTSUP);
    }
}

static ASSH_KEY_LOAD_FCN(assh_key_ed25519_load)
{
  const uint8_t *blob = *blob_;
  assh_status_t err;

  /* allocate key structure */
  struct assh_key_ed25519_s *k = (void*)*key;

  if (k == NULL)
    {
      ASSH_RET_ON_ERR(assh_alloc(c, sizeof(struct assh_key_ed25519_s),
                                 ASSH_ALLOC_SECUR, (void**)&k));

      k->key.algo = algo;
      k->key.type = algo->name;
      k->key.safety = ASSH_ED25519_SAFETY;
      k->key.private = 0;
    }

  static const size_t n = ASSH_ED25519_KSIZE;

  /* parse the key blob */
  switch (format)
    {
    case ASSH_KEY_FMT_PUB_RFC4253:

      ASSH_JMP_ON_ERR(assh_blob_scan(c,
                                /*  name pub */
                                     "sz stD $",
                                     &blob, &blob_len,
                                     algo->name, n, k->pub_key), err_);
      break;

    case ASSH_KEY_FMT_PV_OPENSSH_V1_KEY:
      k->key.private = 1;

      ASSH_JMP_ON_ERR(assh_blob_scan(c,
                                 /* name pub  (pv pub) */
                                     "sz st st(bD bD $)",
                                     &blob, &blob_len,
                                     algo->name, n, 2 * n,
                                     n, k->pv_key, n, k->pub_key), err_);
      break;

    default:
      ASSH_JMP_ON_ERR(ASSH_ERR_NOTSUP, err_);
    }

  *key = &k->key;
  *blob_ = blob;
  return ASSH_OK;

 err_:
  assh_key_ed25519_cleanup(c, &k->key);
  return err;
}

#ifdef CONFIG_ASSH_KEY_CREATE
static ASSH_KEY_CREATE_FCN(assh_key_ed25519_create)
{
  assh_status_t err;
  struct assh_key_ed25519_s *k;

  ASSH_RET_ON_ERR(assh_alloc(c, sizeof(struct assh_key_ed25519_s),
                          ASSH_ALLOC_SECUR, (void**)&k));

  k->key.algo = algo;
  k->key.type = algo->name;
  k->key.safety = ASSH_ED25519_SAFETY;
  k->key.private = 1;

  /* XXX the seed and the private key are the same thing, however the
     libsodium API forces us to use a separate temporary buffer that
     we have to allocate in secure memory. */
  ASSH_SCRATCH_ALLOC(c, uint8_t, seed, ASSH_ED25519_KSIZE,
		     ASSH_ERRSV_CONTINUE, err_key);

  ASSH_JMP_ON_ERR(assh_prng_get(c, seed, ASSH_ED25519_KSIZE,
                 ASSH_PRNG_QUALITY_LONGTERM_KEY), err_sc);

  crypto_sign_ed25519_seed_keypair(k->pub_key, k->keypair, seed);
  ASSH_SCRATCH_FREE(c, seed);

  *key = &k->key;

  return ASSH_OK;

 err_sc:
  ASSH_SCRATCH_FREE(c, seed);
 err_key:
  assh_free(c, k);
  return err;
}
#endif

const struct assh_key_algo_s assh_key_sodium_ed25519 =
{
  .name = "ssh-ed25519",
  .implem = "assh-sodium",
  .min_bits = 255,
  .bits = 255,
  .max_bits = 255,

  .formats = (enum assh_key_format_e[]){
    ASSH_KEY_FMT_PV_OPENSSH_V1,
    ASSH_KEY_FMT_PUB_RFC4716,
    ASSH_KEY_FMT_PUB_RFC4253,
    ASSH_KEY_FMT_PUB_OPENSSH,
    ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB,
    ASSH_KEY_FMT_PV_OPENSSH_V1_KEY,
    0,
  },

  .f_output = assh_key_ed25519_output,
#ifdef CONFIG_ASSH_KEY_CREATE
  .f_create = assh_key_ed25519_create,
#endif
  .f_load = assh_key_ed25519_load,
#ifdef CONFIG_ASSH_KEY_VALIDATE
  .f_validate = assh_key_ed25519_validate,
#endif
  .f_cmp = assh_key_ed25519_cmp,
  .f_cleanup = assh_key_ed25519_cleanup,
};
