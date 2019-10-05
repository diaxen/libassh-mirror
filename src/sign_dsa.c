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

static assh_status_t
assh_sign_dsa_hash_algo(const struct assh_hash_algo_s **algo, uint_fast16_t n)
{
  assh_status_t err;

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
      ASSH_RETURN(ASSH_ERR_NOTSUP);
    }

  return ASSH_OK;
}

static ASSH_SIGN_GENERATE_FCN(assh_sign_dsa_generate)
{
  const struct assh_key_dsa_s *k = (const void*)key;
  assh_status_t err;

  //  uint_fast16_t l = assh_bignum_bits(&k->pn);
  uint_fast16_t n = assh_bignum_bits(&k->qn);

  const struct assh_hash_algo_s *algo;
  ASSH_RET_ON_ERR(assh_sign_dsa_hash_algo(&algo, n));
  n /= 8;

  /* check/return signature length */
  size_t len = ASSH_DSA_ID_LEN + 4 + n * 2;

  if (sign == NULL)
    {
      *sign_len = len;
      return ASSH_OK;
    }

  /* check availability of the private key */
  ASSH_RET_IF_TRUE(assh_bignum_isempty(&k->xn), ASSH_ERR_MISSING_KEY);

  ASSH_RET_IF_TRUE(*sign_len < len, ASSH_ERR_OUTPUT_OVERFLOW);
  *sign_len = len;

  memcpy(sign, ASSH_DSA_ID, ASSH_DSA_ID_LEN);
  assh_store_u32(sign + ASSH_DSA_ID_LEN, n * 2);
  uint8_t *r_str = sign + ASSH_DSA_ID_LEN + 4;
  uint8_t *s_str = r_str + n;

  ASSH_SCRATCH_ALLOC(c, uint8_t, scratch,
		     algo->ctx_size * 2
                     + /* sizeof nonce[] */ n * 2
                     + /* sizeof msgh[] */ n,
		     ASSH_ERRSV_CONTINUE, err_);

  void *hash_ctx1 = scratch;
  void *hash_ctx2 = scratch + algo->ctx_size;
  uint8_t *nonce = scratch + algo->ctx_size * 2;
  uint8_t *msgh = nonce + n * 2;
  uint_fast8_t i;

  /* message hash */
  ASSH_JMP_ON_ERR(assh_hash_init(c, hash_ctx1, algo), err_scratch);
  for (i = 0; i < data_count; i++)
    assh_hash_update(hash_ctx1, data[i].data, data[i].len);
  assh_hash_final(hash_ctx1, msgh, n);
  assh_hash_cleanup(hash_ctx1);

  /* Do not rely on prng, avoid leaking key bits.
     Use expand(hash(key|msgh) % q as nonce. */
  ASSH_JMP_ON_ERR(assh_hash_init(c, hash_ctx1, algo), err_scratch);
  ASSH_JMP_ON_ERR(assh_hash_bignum(c, hash_ctx1, &k->xn), err_hash);
  assh_hash_update(hash_ctx1, msgh, n);

  ASSH_JMP_ON_ERR(assh_hash_copy(hash_ctx2, hash_ctx1), err_hash);
  assh_hash_update(hash_ctx1, "A", 1); /* first half */
  assh_hash_final(hash_ctx1, nonce, n);
  assh_hash_update(hash_ctx2, "B", 1); /* second half */
  assh_hash_final(hash_ctx2, nonce + n, n);
  assh_hash_cleanup(hash_ctx2);
  assh_hash_cleanup(hash_ctx1);

  enum bytecode_args_e
  {
    K_data, R_data, S_data, M_data,    /* data buffers */
    P, Q, G, X,                        /* big number inputs */
    K, R, M, S, R1, R2, R3, R4,        /* big number temporaries */
    MT
  };

  static const assh_bignum_op_t bytecode[] = {
    ASSH_BOP_SIZEM(     K,      Q,      0,      1       ),
    ASSH_BOP_SIZER(     R,      R2,     Q               ),
    ASSH_BOP_SIZER(     R3,     MT,     P               ),

    /* k = k % q */
    ASSH_BOP_MOVES(     K,      K_data                  ),
    ASSH_BOP_MOD(       K,      K,      Q               ),
    ASSH_BOP_SHRINK(    K,      Q                       ),

    ASSH_BOP_MOVE(      M,      M_data                  ),

#ifdef CONFIG_ASSH_DEBUG_SIGN
    ASSH_BOP_PRINT(     K,      'K'                     ),
    ASSH_BOP_PRINT(     M,      'M'                     ),
#endif

    ASSH_BOP_MTINIT(	MT,	P			),
    /* g^k mod p */
    ASSH_BOP_MTTO(      R3,	R3,     G,	MT	),
    ASSH_BOP_EXPM(      R3,     R3,     K,      MT      ),
    ASSH_BOP_MTFROM(    R3,	R3,	R3,	MT	),
    /* r = (g^k mod p) mod q */
    ASSH_BOP_MOVE(      R4,     Q                       ),
    ASSH_BOP_MTINIT(	MT,	R4			),
    ASSH_BOP_MTTO(      R3,	R3,	R3,	MT	),
    ASSH_BOP_MOD(       R3,     R3,             MT      ),
    ASSH_BOP_MTFROM(    R3,	R3,	R3,	MT	),
    ASSH_BOP_MOVE(      R,      R3                      ),
    /* (x * r) mod q */
    ASSH_BOP_MTINIT(	MT,	Q			),
    ASSH_BOP_MTTO(      R2,	R2,	R,	MT	),
    ASSH_BOP_MTTO(      S,	S,	X,	MT	),
    ASSH_BOP_MTTO(      M,	M,	M,	MT	),
    ASSH_BOP_MULM(      R1,     S,      R2,     MT      ),
    /* sha(m) + (x * r) */
    ASSH_BOP_ADDM(      R2,     M,      R1,     MT      ),
    /* k^-1 */
    ASSH_BOP_MTTO(      M,	M,	K,	MT	),
    ASSH_BOP_INV(       R1,     M,      MT              ),
    /* s = k^-1 * (sha(m) + (x * r)) mod q */
    ASSH_BOP_MULM(      S,      R1,     R2,     MT      ),
    ASSH_BOP_MTFROM(    S,	S,	S,	MT	),

    ASSH_BOP_MOVE(      R_data, R                       ),
    ASSH_BOP_MOVE(      S_data, S                       ),

#ifdef CONFIG_ASSH_DEBUG_SIGN
    ASSH_BOP_PRINT(     R,      'R'                     ),
    ASSH_BOP_PRINT(     S,      'S'                     ),
#endif

    ASSH_BOP_END(),
  };

  ASSH_JMP_ON_ERR(assh_bignum_bytecode(c, 0, bytecode, "DDDDNNNNTTTTTTTTm",
                  /* D */ nonce, r_str, s_str, msgh,
                  /* N */ &k->pn, &k->qn, &k->gn, &k->xn), err_scratch);

  ASSH_SCRATCH_FREE(c, scratch);
  return ASSH_OK;

 err_hash:
  assh_hash_cleanup(hash_ctx1);
 err_scratch:
  ASSH_SCRATCH_FREE(c, scratch);
 err_:
  return err;
}

static ASSH_SIGN_CHECK_FCN(assh_sign_dsa_check)
{
  const struct assh_key_dsa_s *k = (const void*)key;
  assh_status_t err;

  //  uint_fast16_t l = assh_bignum_bits(&k->pn);
  uint_fast16_t n = assh_bignum_bits(&k->qn);

  const struct assh_hash_algo_s *algo;
  ASSH_RET_ON_ERR(assh_sign_dsa_hash_algo(&algo, n));
  n /= 8;

  ASSH_RET_IF_TRUE(sign_len != ASSH_DSA_ID_LEN + 4 + n * 2, ASSH_ERR_INPUT_OVERFLOW);

  ASSH_RET_IF_TRUE(memcmp(sign, ASSH_DSA_ID, ASSH_DSA_ID_LEN), ASSH_ERR_BAD_DATA);

  /* check signature blob size */
  uint8_t *rs_str = (uint8_t*)sign + ASSH_DSA_ID_LEN;
  ASSH_RET_IF_TRUE(assh_load_u32(rs_str) != n * 2, ASSH_ERR_INPUT_OVERFLOW);

  ASSH_SCRATCH_ALLOC(c, uint8_t, scratch,
		     algo->ctx_size
                     + /* sizeof msgh[] */ n,
		     ASSH_ERRSV_CONTINUE, err_);

  /* message hash */
  void *hash_ctx = (void*)scratch;
  uint8_t *msgh = scratch + algo->ctx_size;
  uint_fast8_t i;

  ASSH_JMP_ON_ERR(assh_hash_init(c, hash_ctx, algo), err_scratch);
  for (i = 0; i < data_count; i++)
    assh_hash_update(hash_ctx, data[i].data, data[i].len);
  assh_hash_final(hash_ctx, msgh, n);
  assh_hash_cleanup(hash_ctx);

  enum bytecode_args_e
  {
    R_data, S_data, M_data,     /* data buffers */
    P, Q, G, Y,                 /* big number inputs */
    M, R, S, W, U1, U2, V1, V2, V,  /* big number temporaries */
    MT
  };

  static const assh_bignum_op_t bytecode[] = {
    ASSH_BOP_SIZER(     M,      U2,     Q               ),
    ASSH_BOP_SIZER(     V1,     MT,     P               ),

    ASSH_BOP_MOVE(      R,      R_data                  ),
    ASSH_BOP_MOVE(      S,      S_data                  ),
    ASSH_BOP_MOVE(      M,      M_data                  ),

#ifdef CONFIG_ASSH_DEBUG_SIGN
    ASSH_BOP_PRINT(     M,      'M'                     ),
    ASSH_BOP_PRINT(     R,      'R'                     ),
    ASSH_BOP_PRINT(     S,      'S'                     ),
#endif

    /* check r and s ranges */
    ASSH_BOP_UINT(      U1,     0               	),

    ASSH_BOP_CMPGT(     S,      U1,     0 /* s > 0 */   ),
    ASSH_BOP_CFAIL(     1,      0                       ),
    ASSH_BOP_CMPLT(     S,      Q,      0 /* s < n */   ),
    ASSH_BOP_CFAIL(     1,      0                       ),

    ASSH_BOP_CMPGT(     R,      U1,     0 /* r > 0 */   ),
    ASSH_BOP_CFAIL(     1,      0                       ),
    ASSH_BOP_CMPLT(     R,      Q,      0 /* r < n */   ),
    ASSH_BOP_CFAIL(     1,      0                       ),

    ASSH_BOP_INV(       W,      S,      Q               ),
    /* r * w mod q */
    ASSH_BOP_MULM(      U2,     R,      W,      Q       ),
    /* (sha(m) * w) mod q */
    ASSH_BOP_MULM(      U1,     M,      W,      Q       ),
    /* g^u1 */
    ASSH_BOP_MTINIT(	MT,	P			),
    ASSH_BOP_MTTO(      V1,	V1,	G,	MT	),
    ASSH_BOP_EXPM(      V1,     V1,     U1,     MT      ),
    /* y^u2 */
    ASSH_BOP_MTTO(      V2,	V2,	Y,	MT	),
    ASSH_BOP_EXPM(      V2,     V2,     U2,     MT      ),
    /* (g^u1 * y^u2) mod p */
    ASSH_BOP_MULM(      V1,     V1,     V2,     MT      ),
    /* v = (g^u1 * y^u2) mod p mod q */
    ASSH_BOP_MTFROM(    V1,	V1,	V1,	MT	),
    ASSH_BOP_MOD(       V,      V1,     Q               ),

#ifdef CONFIG_ASSH_DEBUG_SIGN
    ASSH_BOP_PRINT(     V,      'V'                     ),
#endif

    ASSH_BOP_CMPEQ(     V,      R,      0               ),
    ASSH_BOP_CFAIL(     1,      0                       ),

    ASSH_BOP_END(),
  };

  ASSH_JMP_ON_ERR(assh_bignum_bytecode(c, 0, bytecode, "DDDNNNNTTTTTTTTTm",
                 /* D */ rs_str + 4, rs_str + 4 + n, msgh,
                 /* N */ &k->pn, &k->qn, &k->gn, &k->yn), err_scratch);

  *safety = ASSH_MIN(*safety, algo->safety);

  err = ASSH_OK;

 err_scratch:
  ASSH_SCRATCH_FREE(c, scratch);
 err_:
  return err;
}

static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_dsa_suitable_key_768)
{
  if (key == NULL)
    return c->type == ASSH_SERVER;
  if (key->algo != &assh_key_dsa)
    return 0;
  const struct assh_key_dsa_s *k = (const void*)key;
  return assh_bignum_bits(&k->qn) == 160 &&
         assh_bignum_bits(&k->pn) >= 768;
}

const struct assh_algo_sign_s assh_sign_dsa768 =
{
  ASSH_ALGO_BASE(SIGN, "assh-builtin", 15, 40,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "ssh-dss" }),
    ASSH_ALGO_VARIANT( 2, "768+ bits keys" ),
    .f_suitable_key = assh_sign_dsa_suitable_key_768,
    .key = &assh_key_dsa,
  ),
  .f_generate = assh_sign_dsa_generate,
  .f_check = assh_sign_dsa_check,
};

static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_dsa_suitable_key_1024)
{
  if (key == NULL)
    return c->type == ASSH_SERVER;
  if (key->algo != &assh_key_dsa)
    return 0;
  const struct assh_key_dsa_s *k = (const void*)key;
  return assh_bignum_bits(&k->qn) >= 160 &&
         assh_bignum_bits(&k->pn) >= 1024;
}

const struct assh_algo_sign_s assh_sign_dsa1024 =
{
  ASSH_ALGO_BASE(SIGN, "assh-builtin", 20, 40,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "ssh-dss" }),
    ASSH_ALGO_VARIANT( 2, "1024+ bits keys" ),
    .f_suitable_key = assh_sign_dsa_suitable_key_1024,
    .key = &assh_key_dsa,
  ),
  .f_generate = assh_sign_dsa_generate,
  .f_check = assh_sign_dsa_check,
};

static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_dsa_suitable_key_2048_224)
{
  if (key == NULL)
    return c->type == ASSH_SERVER;
  if (key->algo != &assh_key_dsa)
    return 0;
  const struct assh_key_dsa_s *k = (const void*)key;
  return assh_bignum_bits(&k->qn) == 224 &&
         assh_bignum_bits(&k->pn) >= 2048;
}

const struct assh_algo_sign_s assh_sign_dsa2048_sha224 =
{
  ASSH_ALGO_BASE(SIGN, "assh-builtin", 35, 30,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_ASSH,
	              "dsa2048-sha224@libassh.org" }),
    .f_suitable_key = assh_sign_dsa_suitable_key_2048_224,
    .key = &assh_key_dsa,
  ),
  .groups = 1,
  .f_generate = assh_sign_dsa_generate,
  .f_check = assh_sign_dsa_check,
};

static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_dsa_suitable_key_2048_256)
{
  if (key == NULL)
    return c->type == ASSH_SERVER;
  if (key->algo != &assh_key_dsa)
    return 0;
  const struct assh_key_dsa_s *k = (const void*)key;
  return assh_bignum_bits(&k->qn) == 256 &&
         assh_bignum_bits(&k->pn) >= 2048;
}

const struct assh_algo_sign_s assh_sign_dsa2048_sha256 =
{
  ASSH_ALGO_BASE(SIGN, "assh-builtin", 40, 30,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_ASSH,
	              "dsa2048-sha256@libassh.org" }),
    .f_suitable_key = assh_sign_dsa_suitable_key_2048_256,
    .key = &assh_key_dsa,
  ),
  .groups = 1,
  .f_generate = assh_sign_dsa_generate,
  .f_check = assh_sign_dsa_check,
};

static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_dsa_suitable_key_3072_256)
{
  if (key == NULL)
    return c->type == ASSH_SERVER;
  if (key->algo != &assh_key_dsa)
    return 0;
  const struct assh_key_dsa_s *k = (const void*)key;
  return assh_bignum_bits(&k->qn) == 256 &&
         assh_bignum_bits(&k->pn) >= 3072;
}

const struct assh_algo_sign_s assh_sign_dsa3072_sha256 =
{
  ASSH_ALGO_BASE(SIGN, "assh-builtin", 50, 30,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_ASSH,
	              "dsa3072-sha256@libassh.org" }),
    .f_suitable_key = assh_sign_dsa_suitable_key_3072_256,
    .key = &assh_key_dsa,
  ),
  .groups = 1,
  .f_generate = assh_sign_dsa_generate,
  .f_check = assh_sign_dsa_check,
};

