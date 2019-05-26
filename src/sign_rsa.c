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

#include <assh/assh_buffer.h>
#include <assh/assh_bignum.h>
#include <assh/assh_sign.h>
#include <assh/key_rsa.h>
#include <assh/assh_hash.h>
#include <assh/assh_prng.h>
#include <assh/assh_alloc.h>

#include <string.h>

enum assh_rsa_digest_e
{
  RSA_DIGEST_MD2,
  RSA_DIGEST_MD5,
  RSA_DIGEST_SHA1,
  RSA_DIGEST_SHA256,
  RSA_DIGEST_SHA384,
  RSA_DIGEST_SHA512,
  RSA_DIGEST_count,
};

struct assh_rsa_digest_s
{
  /* asn1 DER digest algorithm identifier */
  uint_fast8_t oid_len;
  const char *oid;

  const struct assh_hash_algo_s *algo;
};

static const struct assh_rsa_digest_s assh_rsa_digests[RSA_DIGEST_count] =
{
 /* len   DigestInfo header */
  { 18, "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x02\x05\x00\x04\x10",
    NULL /* md2 */ },
  { 18, "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10",
    &assh_hash_md5 },
  { 15, "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14",
    &assh_hash_sha1 },
  { 19, "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20",
    &assh_hash_sha256 },
  { 19, "\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30",
    &assh_hash_sha384 },
  { 19, "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40",
    &assh_hash_sha512 },
};

#define ASSH_RSA_SHA256_ID "\x00\x00\x00\x0crsa-sha2-256"
#define ASSH_RSA_SHA512_ID "\x00\x00\x00\x0crsa-sha2-512"

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_sign_rsa_generate(struct assh_context_s *c,
                       const struct assh_key_s *key,
                       size_t data_count,
                       const struct assh_cbuffer_s data[],
                       uint8_t *sign, size_t *sign_len,
                       enum assh_rsa_digest_e digest_id,
                       const char *algo_id)
{
  const struct assh_key_rsa_s *k = (const void*)key;
  assh_error_t err;

  assert(key->algo == &assh_key_rsa);

  size_t n = ASSH_ALIGN8(assh_bignum_bits(&k->nn)) / 8;

  /* check/return signature length */
  size_t id_len = 4 + assh_load_u32((const uint8_t*)algo_id);
  size_t len = id_len + 4 + n;

  if (sign == NULL)
    {
      *sign_len = len;
      return ASSH_OK;
    }

  /* check availability of the private key */
  ASSH_RET_IF_TRUE(assh_bignum_isempty(&k->dn), ASSH_ERR_MISSING_KEY);

  ASSH_RET_IF_TRUE(*sign_len < len, ASSH_ERR_OUTPUT_OVERFLOW);
  *sign_len = len;

  const struct assh_rsa_digest_s *digest = assh_rsa_digests + digest_id;
  ASSH_RET_IF_TRUE(digest->algo == NULL, ASSH_ERR_NOTSUP);

  /* build encoded message buffer */
  size_t ps_len = n - 3 - digest->oid_len - digest->algo->hash_size;

  ASSH_RET_IF_TRUE(ps_len < 8, ASSH_ERR_BAD_DATA);

  ASSH_SCRATCH_ALLOC(c, uint8_t, scratch,
                     digest->algo->ctx_size + n,
                     ASSH_ERRSV_CONTINUE, err_);

  uint8_t *em_buf = scratch + digest->algo->ctx_size;
  uint8_t *em = em_buf;

  *em++ = 0x00;
  *em++ = 0x01;
  memset(em, 0xff, ps_len);
  em += ps_len;
  *em++ = 0x00;
  memcpy(em, digest->oid, digest->oid_len);
  em += digest->oid_len;

  uint_fast16_t i;
  void *hash_ctx = scratch;

  ASSH_JMP_ON_ERR(assh_hash_init(c, hash_ctx, digest->algo), err_scratch);
  for (i = 0; i < data_count; i++)
    assh_hash_update(hash_ctx, data[i].data, data[i].len);
  assh_hash_final(hash_ctx, em, digest->algo->hash_size);

  assh_hash_cleanup(hash_ctx);

  /* build signature blob */
  memcpy(sign, algo_id, id_len);
  assh_store_u32(sign + id_len, n);
  uint8_t *c_str = sign + id_len + 4;

#ifdef CONFIG_ASSH_DEBUG_SIGN
  ASSH_DEBUG_HEXDUMP("rsa generate em", em_buf, n);
#endif

  /* use Chinese Remainder */
  enum bytecode_args_e
  {
    C_data, EM_data,            /* data buffers */
    Q, P, DP, DQ, I, N,         /* big number inputs */
    M2, EM, T3, T0, T1, T2,     /* big number temporaries */
    MT, PQ_size
  };

  static const assh_bignum_op_t bytecode[] = {
    ASSH_BOP_SIZER(     M2,     EM,     N		),
    ASSH_BOP_SIZER(     T0,     MT,     PQ_size		),
    ASSH_BOP_SIZEM(     T3,     PQ_size, 0, 1		),

    ASSH_BOP_MOVE(      EM,     EM_data			),

    /* m2 = em^dq % q */
    ASSH_BOP_MOVE(      T2,     Q			),
    ASSH_BOP_MOD(       T0,     EM,     T2              ),
    ASSH_BOP_MTINIT(    MT,     T2                      ),
    ASSH_BOP_MTTO(      T0,     T0,     T0,     MT      ),
    ASSH_BOP_EXPM(      T0,     T0,     DQ,	MT	),
    ASSH_BOP_MTFROM(    T0,     T0,     T0,     MT      ),
    ASSH_BOP_MOVE(      M2,     T0			),

    /* m1 = em^dp % p */
    ASSH_BOP_MOVE(      T2,     P			),
    ASSH_BOP_MOD(       T1,     EM,     T2              ),
    ASSH_BOP_MTINIT(    MT,     T2                      ),
    ASSH_BOP_MTTO(      T1,     T1,     T1,     MT      ),
    ASSH_BOP_EXPM(      T1,     T1,     DP,	MT	),

    /* h = i * (m1 - m2) */
    ASSH_BOP_MTTO(      T0,     T0,     T0,     MT      ),
    ASSH_BOP_SUBM(      T1,     T1,     T0,     MT      ),
    ASSH_BOP_MOVE(      T2,     I			),
    ASSH_BOP_MTTO(      T2,     T2,     T2,     MT      ),
    ASSH_BOP_MULM(      T0,     T1,     T2,     MT      ),
    ASSH_BOP_MTFROM(    T1,     T1,     T0,     MT      ),

    /* m = m2 + h * q */
    ASSH_BOP_MUL(       T3,     T1,     Q               ),
    ASSH_BOP_ADD(       M2,     M2,     T3              ),

    ASSH_BOP_MOVE(      C_data, M2			),
    ASSH_BOP_END(),
  };

  intptr_t pqsize = ASSH_MAX(assh_bignum_bits(&k->pn),
			     assh_bignum_bits(&k->qn));

  ASSH_JMP_ON_ERR(assh_bignum_bytecode(c, 0, bytecode, "DDNNNNNNTTTTTTms",
                   /* Data */ c_str, em_buf,
                   /* Num  */ &k->qn, &k->pn, &k->dpn, &k->dqn,
                              &k->in, &k->nn, pqsize), err_scratch);

  err = ASSH_OK;

 err_scratch:
  ASSH_SCRATCH_FREE(c, scratch);
 err_:
  return err;
}

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_sign_rsa_check(struct assh_context_s *c,
                     const struct assh_key_s *key, size_t data_count,
                     const struct assh_cbuffer_s data[],
                     const uint8_t *sign, size_t sign_len, assh_safety_t *safety,
                     uint8_t digest_mask, const char *algo_id)
{
  const struct assh_key_rsa_s *k = (const void*)key;
  assh_error_t err;

  assert(key->algo == &assh_key_rsa);

  size_t id_len = 4 + assh_load_u32((const uint8_t*)algo_id);
  size_t n = ASSH_ALIGN8(assh_bignum_bits(&k->nn)) / 8;

  ASSH_RET_IF_TRUE(sign_len != id_len + 4 + n, ASSH_ERR_INPUT_OVERFLOW);

  ASSH_RET_IF_TRUE(memcmp(sign, algo_id, id_len), ASSH_ERR_BAD_DATA);

  uint8_t *c_str = (uint8_t*)sign + id_len;
  ASSH_RET_IF_TRUE(assh_load_u32(c_str) != n, ASSH_ERR_INPUT_OVERFLOW);

  ASSH_SCRATCH_ALLOC(c, uint8_t, em_buf, n, ASSH_ERRSV_CONTINUE, err_);
  uint8_t *em = em_buf;

  enum bytecode_args_e
  {
    C_data, EM_data,            /* data buffers */
    N, E,                       /* big number inputs */
    C, EM,                      /* big number temporaries */
    MT
  };

  static const assh_bignum_op_t bytecode[] = {
    ASSH_BOP_SIZER(     C,      MT,     N		),
    ASSH_BOP_MTINIT(    MT,     N                       ),

    ASSH_BOP_MOVE(      C,      C_data                  ),
    ASSH_BOP_MTTO(      C,      C,      C,      MT      ),
    ASSH_BOP_EXPM(      EM,     C,      E,	MT	),
    ASSH_BOP_MTFROM(    EM,     EM,     EM,     MT      ),

    ASSH_BOP_MOVE(      EM_data, EM                     ),
    ASSH_BOP_END(),
  };

  ASSH_JMP_ON_ERR(assh_bignum_bytecode(c, 0, bytecode, "DDNNTTm",
                   /* Data */ c_str + 4, em,
                   /* Nun  */ &k->nn, &k->en), err_em);

#ifdef CONFIG_ASSH_DEBUG_SIGN
  ASSH_DEBUG_HEXDUMP("rsa check em", em, n);
#endif

  uint8_t *em_end = em + n;
  uint_fast16_t i;

  /* check padding */
  ASSH_JMP_IF_TRUE(*em++ != 0x00, ASSH_ERR_BAD_DATA, err_em);
  ASSH_JMP_IF_TRUE(*em++ != 0x01, ASSH_ERR_BAD_DATA, err_em);
  for (i = 0; em + 1 < em_end && *em == 0xff; em++)
    i++;
  ASSH_JMP_IF_TRUE(i < 8, ASSH_ERR_BAD_DATA, err_em);
  ASSH_JMP_IF_TRUE(*em++ != 0x00, ASSH_ERR_BAD_DATA, err_em);

  /* lookup digest algorithm in use */
  const struct assh_rsa_digest_s *digest;
  for (i = 0; i < RSA_DIGEST_count; i++)
    {
      digest = assh_rsa_digests + i;
      if (digest->algo == NULL)
        continue;
      if (digest->oid_len + digest->algo->hash_size != em_end - em)
        continue;
      if (!memcmp(digest->oid, em, digest->oid_len))
        break;
    }

  ASSH_JMP_IF_TRUE(i == RSA_DIGEST_count, ASSH_ERR_NOTSUP, err_em);
  ASSH_JMP_IF_TRUE(!((digest_mask >> i) & 1), ASSH_ERR_WEAK_ALGORITHM, err_em);

  /* compute message hash */
  em += digest->oid_len;
  ASSH_SCRATCH_ALLOC(c, void, hash_ctx, digest->algo->ctx_size +
                     digest->algo->hash_size,
                     ASSH_ERRSV_CONTINUE, err_em);

  uint8_t *hash = hash_ctx + digest->algo->ctx_size;

  ASSH_JMP_ON_ERR(assh_hash_init(c, hash_ctx, digest->algo), err_hash);
  for (i = 0; i < data_count; i++)
    assh_hash_update(hash_ctx, data[i].data, data[i].len);
  assh_hash_final(hash_ctx, hash, digest->algo->hash_size);
  assh_hash_cleanup(hash_ctx);

#ifdef CONFIG_ASSH_DEBUG_SIGN
  ASSH_DEBUG_HEXDUMP("rsa check hash", hash, digest->algo->hash_size);
#endif

  *safety = ASSH_MIN(*safety, digest->algo->safety);

  ASSH_JMP_IF_TRUE(assh_memcmp(hash, em, digest->algo->hash_size),
               ASSH_ERR_NUM_COMPARE_FAILED, err_hash);

  err = ASSH_OK;

 err_hash:
  ASSH_SCRATCH_FREE(c, hash_ctx);
 err_em:
  ASSH_SCRATCH_FREE(c, em_buf);
 err_:
  return err;
}

static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_rsa_suitable_key_768)
{
  if (key == NULL)
    return c->type == ASSH_SERVER;
  if (key->algo != &assh_key_rsa || key->role != ASSH_ALGO_SIGN)
    return 0;
  const struct assh_key_rsa_s *k = (const void*)key;
  return assh_bignum_bits(&k->nn) >= 768;
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

const struct assh_algo_sign_s assh_sign_rsa_sha1_md5 =
{
  ASSH_ALGO_BASE(SIGN, 15, 40,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "ssh-rsa" }),
    ASSH_ALGO_VARIANT( 2, "sha*, md5, 768+ bits keys" ),
    .f_suitable_key = assh_sign_rsa_suitable_key_768,
    .key = &assh_key_rsa,
  ),
  .f_generate = assh_sign_rsa_generate_sha1,
  .f_check = assh_sign_rsa_check_sha1_md5,
};



static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_rsa_suitable_key_1024)
{
  if (key == NULL)
    return c->type == ASSH_SERVER;
  if (key->algo != &assh_key_rsa || key->role != ASSH_ALGO_SIGN)
    return 0;
  const struct assh_key_rsa_s *k = (const void*)key;
  return assh_bignum_bits(&k->nn) >= 1024;
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

const struct assh_algo_sign_s assh_sign_rsa_sha1 =
{
  ASSH_ALGO_BASE(SIGN, 20, 40,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "ssh-rsa" }),
    ASSH_ALGO_VARIANT( 1, "sha*, 1024+ bits keys" ),
    .f_suitable_key = assh_sign_rsa_suitable_key_1024,
    .key = &assh_key_rsa,
  ),
  .f_generate = assh_sign_rsa_generate_sha1,
  .f_check = assh_sign_rsa_check_sha1,
};



static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_rsa_suitable_key_2048)
{
  if (key == NULL)
    return c->type == ASSH_SERVER;
  if (key->algo != &assh_key_rsa || key->role != ASSH_ALGO_SIGN)
    return 0;
  const struct assh_key_rsa_s *k = (const void*)key;
  return assh_bignum_bits(&k->nn) >= 2048;
}

const struct assh_algo_sign_s assh_sign_rsa_sha1_2048 =
{
  ASSH_ALGO_BASE(SIGN, 25, 30,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "ssh-rsa" }),
    ASSH_ALGO_VARIANT( 0, "sha*, 2048+ bits keys" ),
    .f_suitable_key = assh_sign_rsa_suitable_key_2048,
    .key = &assh_key_rsa,
  ),
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

const struct assh_algo_sign_s assh_sign_rsa_sha256 =
{
  ASSH_ALGO_BASE(SIGN, 40, 30,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_DRAFT | ASSH_ALGO_ASSH,
                      "rsa-sha2-256" }),
    .f_suitable_key = assh_sign_rsa_suitable_key_2048,
    .key = &assh_key_rsa,
  ),
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

const struct assh_algo_sign_s assh_sign_rsa_sha512 =
{
  ASSH_ALGO_BASE(SIGN, 45, 30,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_DRAFT | ASSH_ALGO_ASSH,
                      "rsa-sha2-512" }),
    .f_suitable_key = assh_sign_rsa_suitable_key_2048,
    .key = &assh_key_rsa,
  ),
  .groups = 1,
  .f_generate = assh_sign_rsa_generate_sha512,
  .f_check = assh_sign_rsa_check_sha512,
};

