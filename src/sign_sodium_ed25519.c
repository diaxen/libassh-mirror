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

#define ASSH_PV

#include <assh/assh_buffer.h>
#include <assh/assh_bignum.h>
#include <assh/assh_sign.h>
#include <assh/assh_hash.h>
#include <assh/assh_alloc.h>
#include <assh/mod_sodium.h>

#include "key_sodium_ed25519.h"
#include <sodium/crypto_sign_ed25519.h>

#include <string.h>

static ASSH_SIGN_GENERATE_FCN(assh_sign_ed25519_generate)
{
  const struct assh_key_ed25519_s *k = (const void*)key;
  assh_status_t err = ASSH_OK;

  size_t tlen = strlen(k->key.algo->name);
  size_t len = 4 + tlen + 4 + 2 * ASSH_ED25519_KSIZE;

  /* check/return signature length */
  if (sign == NULL)
    {
      *sign_len = len;
      return ASSH_OK;
    }

  ASSH_RET_IF_TRUE(*sign_len < len, ASSH_ERR_OUTPUT_OVERFLOW);
  *sign_len = len;

  assh_store_u32(sign, tlen);
  memcpy(sign + 4, k->key.algo->name, tlen);
  assh_store_u32(sign + 4 + tlen, 2 * ASSH_ED25519_KSIZE);

  uint8_t *r_str = sign + 4 + tlen + 4;

  /* XXX the libsodium API does not support split message hashing, so we
     have to copy the message parts to a single temporary buffer. */
  switch (data_count)
    {
    case 0:
      crypto_sign_ed25519_detached(r_str, NULL, r_str, 0, k->keypair);
      break;

    case 1:
      crypto_sign_ed25519_detached(r_str, NULL, data[0].data, data[0].len, k->keypair);
      break;

    default: {
      size_t mlen = 0;
      uint_fast8_t i;
      for (i = 0; i < data_count; i++)
	mlen += data[i].len;

      ASSH_RET_IF_TRUE(mlen > 0x10000, ASSH_ERR_INPUT_OVERFLOW);
      ASSH_SCRATCH_ALLOC(c, uint8_t, sc, mlen, ASSH_ERRSV_CONTINUE, err_);
      uint8_t *s = sc;

      for (i = 0; i < data_count; i++)
	{
	  size_t len = data[i].len;
	  memcpy(s, data[i].data, len);
	  s += len;
	}

      crypto_sign_ed25519_detached(r_str, NULL, sc, mlen, k->keypair);
      ASSH_SCRATCH_FREE(c, sc);
    }
    }

 err_:
  return err;
}

static ASSH_SIGN_CHECK_FCN(assh_sign_ed25519_check)
{
  const struct assh_key_ed25519_s *k = (const void*)key;
  assh_status_t err = ASSH_OK;

  size_t tlen = strlen(k->key.algo->name);

  ASSH_RET_IF_TRUE(sign_len != 4 + tlen + 4 + 2 * ASSH_ED25519_KSIZE, ASSH_ERR_INPUT_OVERFLOW);

  ASSH_RET_IF_TRUE(tlen != assh_load_u32(sign), ASSH_ERR_BAD_DATA);
  ASSH_RET_IF_TRUE(memcmp(sign + 4, k->key.algo->name, tlen), ASSH_ERR_BAD_DATA);

  uint8_t *rs_str = (uint8_t*)sign + 4 + tlen;
  ASSH_RET_IF_TRUE(assh_load_u32(rs_str) != ASSH_ED25519_KSIZE * 2, ASSH_ERR_INPUT_OVERFLOW);

  uint8_t *sig = rs_str + 4;
  int result;

  /* XXX the libsodium API does not support split message hashing, so we
     have to copy the message parts to a single temporary buffer. */
  switch (data_count)
    {
    case 0:
      result = crypto_sign_ed25519_verify_detached(sig, sig, 0, k->pub_key);
      break;

    case 1:
      result = crypto_sign_ed25519_verify_detached(sig, data[0].data, data[0].len, k->pub_key);
      break;

    default: {
      size_t mlen = 0;
      uint_fast8_t i;
      for (i = 0; i < data_count; i++)
	mlen += data[i].len;

      ASSH_RET_IF_TRUE(mlen > 0x10000, ASSH_ERR_INPUT_OVERFLOW);
      ASSH_SCRATCH_ALLOC(c, uint8_t, sc, mlen, ASSH_ERRSV_CONTINUE, err_);
      uint8_t *s = sc;

      for (i = 0; i < data_count; i++)
	{
	  size_t len = data[i].len;
	  memcpy(s, data[i].data, len);
	  s += len;
	}

      result = crypto_sign_ed25519_verify_detached(sig, sc, mlen, k->pub_key);
      ASSH_SCRATCH_FREE(c, sc);
    }
    }

  ASSH_RET_IF_TRUE(result, ASSH_ERR_NUM_COMPARE_FAILED);

 err_:
  return err;
}

static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_ed25519_suitable_key)
{
  if (key == NULL)
    return c->type == ASSH_SERVER;
  return key->algo == &assh_key_sodium_ed25519;
}

const struct assh_algo_sign_s assh_sign_sodium_ed25519 =
{
  .algo_wk = {
    ASSH_ALGO_BASE(SIGN, "assh-sodium", 50, 157,
      ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_COMMON,
                        "ssh-ed25519" }),
    ),
    .f_suitable_key = assh_sign_ed25519_suitable_key,
    .key_algo = &assh_key_sodium_ed25519,
  },
  .f_generate = assh_sign_ed25519_generate,
  .f_check = assh_sign_ed25519_check,
};
