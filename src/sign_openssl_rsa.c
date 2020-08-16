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
#include <assh/mod_openssl.h>
#include <assh/assh_hash.h>
#include <assh/assh_prng.h>
#include <assh/assh_alloc.h>

#include "key_openssl_rsa.h"
#include "sign_rsa.h"

#include <string.h>

static ASSH_WARN_UNUSED_RESULT assh_status_t
assh_sign_rsa_generate(struct assh_context_s *c,
                       const struct assh_key_s *key,
                       size_t data_count,
                       const struct assh_cbuffer_s data[],
                       uint8_t *sign, size_t *sign_len,
                       enum assh_rsa_digest_e digest_id,
                       const char *algo_id)
{
  const struct assh_key_rsa_s *k = (const void*)key;
  assh_status_t err;

  size_t n = RSA_size(k->rsa);

  /* check/return signature length */
  size_t id_len = 4 + assh_load_u32((const uint8_t*)algo_id);
  size_t len = id_len + 4 + n;

  if (sign == NULL)
    {
      *sign_len = len;
      return ASSH_OK;
    }

  assert(key->algo == &assh_key_openssl_rsa);

  ASSH_RET_IF_TRUE(*sign_len < len, ASSH_ERR_OUTPUT_OVERFLOW);
  *sign_len = len;

  const struct assh_rsa_digest_s *digest = assh_rsa_digests + digest_id;
  ASSH_RET_IF_TRUE(digest->algo == NULL, ASSH_ERR_NOTSUP);

  ASSH_SCRATCH_ALLOC(c, uint8_t, scratch,
                     digest->algo->ctx_size +
		     digest->oid_len + digest->algo->hash_size,
                     ASSH_ERRSV_CONTINUE, err_);

  void *hash_ctx = scratch;
  uint8_t *em = scratch + digest->algo->ctx_size;

  memcpy(em, digest->oid, digest->oid_len);

  ASSH_JMP_ON_ERR(assh_hash_init(c, hash_ctx, digest->algo), err_scratch);

  uint_fast8_t i;
  for (i = 0; i < data_count; i++)
    assh_hash_update(hash_ctx, data[i].data, data[i].len);
  assh_hash_final(hash_ctx, em + digest->oid_len, digest->algo->hash_size);
  assh_hash_cleanup(hash_ctx);

  memcpy(sign, algo_id, id_len);
  assh_store_u32(sign + id_len, n);
  uint8_t *to = sign + id_len + 4;

  ASSH_JMP_IF_TRUE(RSA_private_encrypt(digest->oid_len + digest->algo->hash_size,
		     em, to, k->rsa, RSA_PKCS1_PADDING) != n, ASSH_ERR_CRYPTO, err_scratch);

  err = ASSH_OK;

 err_scratch:
  ASSH_SCRATCH_FREE(c, scratch);
 err_:
  return err;
}

static ASSH_WARN_UNUSED_RESULT assh_status_t
assh_sign_rsa_check(struct assh_context_s *c,
                     const struct assh_key_s *key, size_t data_count,
                     const struct assh_cbuffer_s data[],
                     const uint8_t *sign, size_t sign_len, assh_safety_t *safety,
                     uint8_t digest_mask, const char *algo_id)
{
  const struct assh_key_rsa_s *k = (const void*)key;
  assh_status_t err;

  assert(key->algo == &assh_key_openssl_rsa);

  size_t id_len = 4 + assh_load_u32((const uint8_t*)algo_id);
  size_t n = RSA_size(k->rsa);

  ASSH_RET_IF_TRUE(sign_len != id_len + 4 + n, ASSH_ERR_INPUT_OVERFLOW);

  ASSH_RET_IF_TRUE(memcmp(sign, algo_id, id_len), ASSH_ERR_BAD_DATA);

  uint8_t *c_str = (uint8_t*)sign + id_len;
  ASSH_RET_IF_TRUE(assh_load_u32(c_str) != n, ASSH_ERR_INPUT_OVERFLOW);

  ASSH_SCRATCH_ALLOC(c, uint8_t, em, n, ASSH_ERRSV_CONTINUE, err_);

  int r = RSA_public_decrypt(n, c_str + 4, em, k->rsa, RSA_PKCS1_PADDING);
  ASSH_JMP_IF_TRUE(r < 0, ASSH_ERR_CRYPTO, err_em);

#ifdef CONFIG_ASSH_DEBUG_SIGN
  ASSH_DEBUG_HEXDUMP("rsa check em", em, n);
#endif

  /* lookup digest algorithm in use */
  const struct assh_rsa_digest_s *digest;
  uint_fast8_t i;
  for (i = 0; i < RSA_DIGEST_count; i++)
    {
      digest = assh_rsa_digests + i;
      if (digest->algo == NULL)
        continue;
      if (digest->oid_len + digest->algo->hash_size != r)
        continue;
      if (!memcmp(digest->oid, em, digest->oid_len))
        break;
    }

  ASSH_JMP_IF_TRUE(i == RSA_DIGEST_count, ASSH_ERR_NOTSUP, err_em);
  ASSH_JMP_IF_TRUE(!((digest_mask >> i) & 1), ASSH_ERR_WEAK_ALGORITHM, err_em);

#ifdef CONFIG_ASSH_DEBUG_SIGN
  ASSH_DEBUG("rsa digest %s\n", digest->algo->name);
#endif

  /* compute message hash */
  ASSH_SCRATCH_ALLOC(c, void, hash_ctx, digest->algo->ctx_size +
                     digest->algo->hash_size,
                     ASSH_ERRSV_CONTINUE, err_em);

  uint8_t *hash = hash_ctx + digest->algo->ctx_size;

  ASSH_JMP_ON_ERR(assh_hash_init(c, hash_ctx, digest->algo), err_hash);
  for (i = 0; i < data_count; i++)
    assh_hash_update(hash_ctx, data[i].data, data[i].len);
  assh_hash_final(hash_ctx, hash, digest->algo->hash_size);
  assh_hash_cleanup(hash_ctx);

  *safety = assh_min_uint(*safety, digest->algo->sign_safety);

  ASSH_JMP_IF_TRUE(assh_memcmp(hash, em + digest->oid_len,
			       digest->algo->hash_size),
               ASSH_ERR_NUM_COMPARE_FAILED, err_hash);

  err = ASSH_OK;

 err_hash:
  ASSH_SCRATCH_FREE(c, hash_ctx);
 err_em:
  ASSH_SCRATCH_FREE(c, em);
 err_:
  return err;
}

static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_rsa_suitable_key_768)
{
  if (key == NULL)
    return c->type == ASSH_SERVER;
  if (key->algo != &assh_key_openssl_rsa || key->role != ASSH_ALGO_SIGN)
    return 0;
  const struct assh_key_rsa_s *k = (const void*)key;
  return RSA_bits(k->rsa) >= 768;
}

static ASSH_SIGN_CHECK_FCN(assh_sign_rsa_check_sha1_md5)
{
  return assh_sign_rsa_check(c, key, data_count, data,
                              sign, sign_len, safety,
                                (1 << RSA_DIGEST_SHA1)
                              | (1 << RSA_DIGEST_MD5)
                              | (1 << RSA_DIGEST_SHA256)
                              | (1 << RSA_DIGEST_SHA384)
                              | (1 << RSA_DIGEST_SHA512), ASSH_RSA_ID);
}

static ASSH_SIGN_GENERATE_FCN(assh_sign_rsa_generate_sha1)
{
  return assh_sign_rsa_generate(c, key, data_count, data,
                      sign, sign_len, RSA_DIGEST_SHA1, ASSH_RSA_ID);
}

const struct assh_algo_sign_s assh_sign_openssl_rsa_sha1_md5 =
{
  .algo_wk = {
    ASSH_ALGO_BASE(SIGN, "assh-openssl", 15, 126,
      ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "ssh-rsa" }),
      ASSH_ALGO_VARIANT(0, "sha*, md5, key >= 768" ),
    ),
    .key_algo = &assh_key_openssl_rsa,
    .f_suitable_key = assh_sign_rsa_suitable_key_768,
  },
  .f_generate = assh_sign_rsa_generate_sha1,
  .f_check = assh_sign_rsa_check_sha1_md5,
};



static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_rsa_suitable_key_1024)
{
  if (key == NULL)
    return c->type == ASSH_SERVER;
  if (key->algo != &assh_key_openssl_rsa || key->role != ASSH_ALGO_SIGN)
    return 0;
  const struct assh_key_rsa_s *k = (const void*)key;
  return RSA_bits(k->rsa) >= 1024;
}

static ASSH_SIGN_CHECK_FCN(assh_sign_rsa_check_sha1)
{
  return assh_sign_rsa_check(c, key, data_count, data,
                              sign, sign_len, safety,
                                (1 << RSA_DIGEST_SHA1)
                              | (1 << RSA_DIGEST_SHA256)
                              | (1 << RSA_DIGEST_SHA384)
                              | (1 << RSA_DIGEST_SHA512), ASSH_RSA_ID);
}

const struct assh_algo_sign_s assh_sign_openssl_rsa_sha1 =
{
  .algo_wk = {
    ASSH_ALGO_BASE(SIGN, "assh-openssl", 20, 126,
      ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "ssh-rsa" }),
      ASSH_ALGO_VARIANT(0, "sha*, key >= 1024" ),
    ),
    .f_suitable_key = assh_sign_rsa_suitable_key_1024,
    .key_algo = &assh_key_openssl_rsa,
  },
  .f_generate = assh_sign_rsa_generate_sha1,
  .f_check = assh_sign_rsa_check_sha1,
};



static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_rsa_suitable_key_2048)
{
  if (key == NULL)
    return c->type == ASSH_SERVER;
  if (key->algo != &assh_key_openssl_rsa || key->role != ASSH_ALGO_SIGN)
    return 0;
  const struct assh_key_rsa_s *k = (const void*)key;
  return RSA_bits(k->rsa) >= 2048;
}

const struct assh_algo_sign_s assh_sign_openssl_rsa_sha1_2048 =
{
  .algo_wk = {
    ASSH_ALGO_BASE(SIGN, "assh-openssl", 25, 32,
      ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "ssh-rsa" }),
      ASSH_ALGO_VARIANT(0, "sha*, key >= 2048" ),
    ),
    .f_suitable_key = assh_sign_rsa_suitable_key_2048,
    .key_algo = &assh_key_openssl_rsa,
  },
  .f_generate = assh_sign_rsa_generate_sha1,
  .f_check = assh_sign_rsa_check_sha1,
};



static ASSH_SIGN_CHECK_FCN(assh_sign_rsa_check_sha256)
{
  return assh_sign_rsa_check(c, key, data_count, data,
                             sign, sign_len, safety,
                             (1 << RSA_DIGEST_SHA256),
                             ASSH_RSA_SHA256_ID);
}

static ASSH_SIGN_GENERATE_FCN(assh_sign_rsa_generate_sha256)
{
  return assh_sign_rsa_generate(c, key, data_count, data,
                                sign, sign_len, RSA_DIGEST_SHA256,
                                ASSH_RSA_SHA256_ID);
}

const struct assh_algo_sign_s assh_sign_openssl_rsa_sha256 =
{
  .algo_wk = {
    ASSH_ALGO_BASE(SIGN, "assh-openssl", 40, 32,
      ASSH_ALGO_NAMES({ ASSH_ALGO_STD_DRAFT | ASSH_ALGO_ASSH,
                        "rsa-sha2-256" }),
    ),
    .f_suitable_key = assh_sign_rsa_suitable_key_2048,
    .key_algo = &assh_key_openssl_rsa,
  },
  .groups = 1,
  .f_generate = assh_sign_rsa_generate_sha256,
  .f_check = assh_sign_rsa_check_sha256,
};


static ASSH_SIGN_CHECK_FCN(assh_sign_rsa_check_sha512)
{
  return assh_sign_rsa_check(c, key, data_count, data,
                             sign, sign_len, safety,
                             (1 << RSA_DIGEST_SHA512),
                             ASSH_RSA_SHA512_ID);
}

static ASSH_SIGN_GENERATE_FCN(assh_sign_rsa_generate_sha512)
{
  return assh_sign_rsa_generate(c, key, data_count, data,
                                sign, sign_len, RSA_DIGEST_SHA512,
                                ASSH_RSA_SHA512_ID);
}

const struct assh_algo_sign_s assh_sign_openssl_rsa_sha512 =
{
  .algo_wk = {
    ASSH_ALGO_BASE(SIGN, "assh-openssl", 45, 32,
      ASSH_ALGO_NAMES({ ASSH_ALGO_STD_DRAFT | ASSH_ALGO_ASSH,
                        "rsa-sha2-512" }),
    ),
    .f_suitable_key = assh_sign_rsa_suitable_key_2048,
    .key_algo = &assh_key_openssl_rsa,
  },
  .groups = 1,
  .f_generate = assh_sign_rsa_generate_sha512,
  .f_check = assh_sign_rsa_check_sha512,
};
