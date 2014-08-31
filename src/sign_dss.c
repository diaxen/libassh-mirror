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

#include <assh/assh_packet.h>
#include <assh/assh_bignum.h>
#include <assh/assh_sign.h>
#include <assh/key_dsa.h>
#include <assh/assh_hash.h>
#include <assh/assh_prng.h>
#include <assh/assh_alloc.h>

#include <string.h>

static assh_error_t
assh_sign_dss_hash_algo(const struct assh_hash_algo_s **algo, unsigned int n)
{
  assh_error_t err;

  switch (n)
    {
    case 160:
      *algo = &assh_hash_sha1;
      break;
    case 224:
      *algo = &assh_hash_sha224;
      break;
    case 256:
      *algo = &assh_hash_sha256;
      break;
    default:
      ASSH_ERR_RET(ASSH_ERR_NOTSUP);
    }

  return ASSH_OK;
}

static ASSH_SIGN_GENERATE_FCN(assh_sign_dss_generate)
{
  struct assh_key_dsa_s *k = (void*)key;
  assh_error_t err;

  /* check availability of the private key */
  ASSH_CHK_RET(assh_bignum_isempty(&k->xn), ASSH_ERR_MISSING_KEY);

  //  unsigned int l = assh_bignum_bits(&k->pn);
  unsigned int n = assh_bignum_bits(&k->qn);

  /* check/return signature length */
  size_t len = assh_dss_id_len + 4 + n * 2 / 8;

  const struct assh_hash_algo_s *algo;
  ASSH_ERR_RET(assh_sign_dss_hash_algo(&algo, n));
  assert(algo->hash_size == n / 8);

  if (sign == NULL)
    {
      *sign_len = len;
      return ASSH_OK;
    }

  ASSH_CHK_RET(*sign_len < len, ASSH_ERR_OUTPUT_OVERFLOW);
  *sign_len = len;

  memcpy(sign, assh_dss_id, assh_dss_id_len);
  assh_store_u32(sign + assh_dss_id_len, n * 2 / 8);
  uint8_t *r_str = sign + assh_dss_id_len + 4;
  uint8_t *s_str = r_str + n / 8;

  ASSH_SCRATCH_ALLOC(c, uint8_t, scratch,
		     algo->ctx_size
                     + /* sizeof nonce[] */ n / 8 
                     + /* sizeof msgh[] */ n / 8,
		     ASSH_ERRSV_CONTINUE, err_);

  void *hash_ctx = (void*)scratch;
  uint8_t *nonce = scratch + algo->ctx_size;
  uint8_t *msgh = nonce + n / 8;
  unsigned int i;

  /* message hash */
  ASSH_ERR_GTO(assh_hash_init(c, hash_ctx, algo), err_scratch);
  for (i = 0; i < data_count; i++)
    assh_hash_update(hash_ctx, data[i], data_len[i]);
  assh_hash_final(hash_ctx, msgh);

  /* Do not use the prng output directly as the DSA nonce in order to
     avoid leaking key bits in case of a weak prng. Random data is
     hashed with the private key and the message data. */
  ASSH_ERR_GTO(c->prng->f_get(c, nonce, n / 8, ASSH_PRNG_QUALITY_NONCE), err_scratch);
  ASSH_ERR_GTO(assh_hash_init(c, hash_ctx, algo), err_scratch);
  assh_hash_update(hash_ctx, nonce, n / 8);
  for (i = 0; i < data_count; i++)
    assh_hash_update(hash_ctx, data[i], data_len[i]);
  ASSH_ERR_GTO(assh_hash_bignum(c, hash_ctx, &k->xn), err_hash);
  assh_hash_final(hash_ctx, nonce);

  enum bytecode_args_e
  {
    K_data, R_data, S_data, M_data,    /* data buffers */
    P, Q, G, X,                        /* big number inputs */
    K, R, M, S, R1, R2, R3             /* big number temporaries */
  };

  static const assh_bignum_op_t bytecode[] = {
    ASSH_BOP_SIZE(      K,      Q                       ),
    ASSH_BOP_SIZE(      R,      Q                       ),
    ASSH_BOP_SIZE(      M,      Q                       ),
    ASSH_BOP_SIZE(      S,      Q                       ),
    ASSH_BOP_SIZE(      R1,     Q                       ),
    ASSH_BOP_SIZE(      R2,     Q                       ),
    ASSH_BOP_SIZE(      R3,     P                       ),

    ASSH_BOP_MOVE(      K,      K_data                  ),
    ASSH_BOP_MOVE(      M,      M_data                  ),

#ifdef CONFIG_ASSH_DEBUG_SIGN
    ASSH_BOP_PRINT(     K,      'K'                     ),
    ASSH_BOP_PRINT(     M,      'M'                     ),
#endif

    ASSH_BOP_MOD(       K,      K,      Q               ),
    /* g^k mod p */
    ASSH_BOP_EXPM(      R3,     G,      K,      P       ),
    /* r = (g^k mod p) mod q */
    ASSH_BOP_MOD(       R,      R3,     Q               ),
    ASSH_BOP_MOVE(      R_data, R                       ),
    /* (x * r) mod q */
    ASSH_BOP_MULM(      R1,     X,      R,      Q       ),
    /* sha(m) + (x * r) */
    ASSH_BOP_ADDM(      R2,     M,      R1,     Q       ),
    /* k^-1 */
    ASSH_BOP_INV(       R1,     K,      Q               ),
    /* s = k^-1 * (sha(m) + (x * r)) mod q */
    ASSH_BOP_MULM(      S,      R1,     R2,     Q       ),
    ASSH_BOP_MOVE(      S_data, S                       ),

#ifdef CONFIG_ASSH_DEBUG_SIGN
    ASSH_BOP_PRINT(     R,      'R'                     ),
    ASSH_BOP_PRINT(     S,      'S'                     ),
#endif

    ASSH_BOP_END(),
  };

  ASSH_ERR_GTO(assh_bignum_bytecode(c, bytecode, "DDDDNNNNTTTTTTT",
                  /* D */ nonce, r_str, s_str, msgh,
                  /* N */ &k->pn, &k->qn, &k->gn, &k->xn), err_scratch);

  ASSH_SCRATCH_FREE(c, scratch);
  return ASSH_OK;

 err_hash:
  assh_hash_final(hash_ctx, NULL);
 err_scratch:
  ASSH_SCRATCH_FREE(c, scratch);
 err_:
  return err;
}

static ASSH_SIGN_VERIFY_FCN(assh_sign_dss_verify)
{
  struct assh_key_dsa_s *k = (void*)key;
  assh_error_t err;

  //  unsigned int l = assh_bignum_bits(&k->pn);
  unsigned int n = assh_bignum_bits(&k->qn);

  ASSH_CHK_RET(sign_len != assh_dss_id_len + 4 + n * 2 / 8, ASSH_ERR_INPUT_OVERFLOW);

  ASSH_CHK_RET(memcmp(sign, assh_dss_id, assh_dss_id_len), ASSH_ERR_BAD_DATA);

  const struct assh_hash_algo_s *algo;
  ASSH_ERR_RET(assh_sign_dss_hash_algo(&algo, n));

  /* check signature blob size */
  uint8_t *rs_str = (uint8_t*)sign + assh_dss_id_len;
  ASSH_CHK_RET(assh_load_u32(rs_str) != n * 2 / 8, ASSH_ERR_INPUT_OVERFLOW);

  ASSH_SCRATCH_ALLOC(c, uint8_t, scratch,
		     algo->ctx_size
                     + /* sizeof msgh[] */ n / 8,
		     ASSH_ERRSV_CONTINUE, err_);

  /* message hash */
  void *hash_ctx = (void*)scratch;
  uint8_t *msgh = scratch + algo->ctx_size;
  unsigned int i;

  ASSH_ERR_GTO(assh_hash_init(c, hash_ctx, algo), err_scratch);
  for (i = 0; i < data_count; i++)
    assh_hash_update(hash_ctx, data[i], data_len[i]);
  assh_hash_final(hash_ctx, msgh);

  enum bytecode_args_e
  {
    R_data, S_data, M_data,     /* data buffers */
    P, Q, G, Y,                 /* big number inputs */
    M, R, S, W, U1, V1, U2, V2, V  /* big number temporaries */
  };

  static const assh_bignum_op_t bytecode[] = {
    ASSH_BOP_SIZE(      M,      Q                       ),
    ASSH_BOP_SIZE(      R,      Q                       ),
    ASSH_BOP_SIZE(      S,      Q                       ),
    ASSH_BOP_SIZE(      W,      Q                       ),
    ASSH_BOP_SIZE(      U1,     Q                       ),
    ASSH_BOP_SIZE(      V1,     P                       ),
    ASSH_BOP_SIZE(      U2,     Q                       ),
    ASSH_BOP_SIZE(      V2,     P                       ),
    ASSH_BOP_SIZE(      V,      P                       ),

    ASSH_BOP_MOVE(      R,      R_data                  ),
    ASSH_BOP_MOVE(      S,      S_data                  ),
    ASSH_BOP_MOVE(      M,      M_data                  ),

#ifdef CONFIG_ASSH_DEBUG_SIGN
    ASSH_BOP_PRINT(     M,      'M'                     ),
    ASSH_BOP_PRINT(     R,      'R'                     ),
    ASSH_BOP_PRINT(     S,      'S'                     ),
#endif

    ASSH_BOP_INV(       W,      S,      Q               ),
    /* (sha(m) * w) mod q */
    ASSH_BOP_MULM(      U1,     M,      W,      Q       ),
    /* g^u1 */
    ASSH_BOP_EXPM(      V1,     G,      U1,     P       ),
    /* r * w mod q */
    ASSH_BOP_MULM(      U2,     R,      W,      Q       ),
    /* y^u2 */
    ASSH_BOP_EXPM(      V2,     Y,      U2,     P       ),
    /* (g^u1 * y^u2) mod p */
    ASSH_BOP_MULM(      V,      V1,     V2,     P       ),
    /* v = (g^u1 * y^u2) mod p mod q */
    ASSH_BOP_MOD(       V,      V,      Q               ),

    ASSH_BOP_CMPEQ(     V,      R,      0               ),

#ifdef CONFIG_ASSH_DEBUG_SIGN
    ASSH_BOP_PRINT(     V,      'V'                     ),
#endif

    ASSH_BOP_END(),
  };

  ASSH_ERR_GTO(assh_bignum_bytecode(c, bytecode, "DDDNNNNTTTTTTTTT",
                                    /* D */ rs_str + 4, rs_str + 4 + n / 8, msgh,
                                    /* N */ &k->pn, &k->qn, &k->gn, &k->yn), err_scratch);

  err = ASSH_OK;

 err_scratch:
  ASSH_SCRATCH_FREE(c, scratch);
 err_:
  return err;
}

static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_dss_suitable_key)
{
  if (key->algo != &assh_key_dsa)
    return 0;
  struct assh_key_dsa_s *k = (void*)key;
  return assh_bignum_bits(&k->qn) == 160 &&
         assh_bignum_bits(&k->pn) == 1024;
}

struct assh_algo_sign_s assh_sign_dss =
{
  .algo = {
    .name = "ssh-dss", .class_ = ASSH_ALGO_SIGN,
    .safety = 20, .speed = 40,
    .f_suitable_key = assh_sign_dss_suitable_key,
    .key = &assh_key_dsa,
  },
  .f_generate = assh_sign_dss_generate,
  .f_verify = assh_sign_dss_verify,
};

static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_dss_suitable_key_2048_224)
{
  if (key->algo != &assh_key_dsa)
    return 0;
  struct assh_key_dsa_s *k = (void*)key;
  return assh_bignum_bits(&k->qn) == 224 &&
         assh_bignum_bits(&k->pn) >= 2048;
}

struct assh_algo_sign_s assh_sign_dsa2048_sha224 =
{
  .algo = {
    .name = "dsa2048-sha224@libassh.org", .class_ = ASSH_ALGO_SIGN,
    .safety = 35, .speed = 30,
    .f_suitable_key = assh_sign_dss_suitable_key_2048_224,
    .key = &assh_key_dsa,
  },
  .f_generate = assh_sign_dss_generate,
  .f_verify = assh_sign_dss_verify,
};

static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_dss_suitable_key_2048_256)
{
  if (key->algo != &assh_key_dsa)
    return 0;
  struct assh_key_dsa_s *k = (void*)key;
  return assh_bignum_bits(&k->qn) == 256 &&
         assh_bignum_bits(&k->pn) >= 2048;
}

struct assh_algo_sign_s assh_sign_dsa2048_sha256 =
{
  .algo = {
    .name = "dsa2048-sha256@libassh.org", .class_ = ASSH_ALGO_SIGN,
    .safety = 40, .speed = 30,
    .f_suitable_key = assh_sign_dss_suitable_key_2048_256,
    .key = &assh_key_dsa,
  },
  .f_generate = assh_sign_dss_generate,
  .f_verify = assh_sign_dss_verify,
};

static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_dss_suitable_key_3072_256)
{
  if (key->algo != &assh_key_dsa)
    return 0;
  struct assh_key_dsa_s *k = (void*)key;
  return assh_bignum_bits(&k->qn) == 256 &&
         assh_bignum_bits(&k->pn) >= 3072;
}

struct assh_algo_sign_s assh_sign_dsa3072_sha256 =
{
  .algo = {
    .name = "dsa3072-sha256@libassh.org", .class_ = ASSH_ALGO_SIGN,
    .safety = 50, .speed = 30,
    .f_suitable_key = assh_sign_dss_suitable_key_3072_256,
    .key = &assh_key_dsa,
  },
  .f_generate = assh_sign_dss_generate,
  .f_verify = assh_sign_dss_verify,
};

