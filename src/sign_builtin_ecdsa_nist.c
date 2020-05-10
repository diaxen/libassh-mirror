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

#include <assh/assh_packet.h>
#include <assh/assh_bignum.h>
#include <assh/assh_sign.h>
#include <assh/mod_builtin.h>
#include <assh/assh_hash.h>
#include <assh/assh_prng.h>
#include <assh/assh_alloc.h>

#include "key_builtin_ecdsa_nist.h"
#include "ecc_weierstrass.h"

#include <string.h>

static ASSH_SIGN_GENERATE_FCN(assh_sign_ecdsa_generate)
{
  const struct assh_key_ecdsa_s *k = (const void*)key;
  assh_status_t err;

  const struct assh_weierstrass_curve_s *curve = k->id->curve;
  const struct assh_hash_algo_s *hash = k->id->hash;

  size_t n = ASSH_ALIGN8(curve->bits) / 8;
  size_t tlen = strlen(k->id->name);
  size_t maxlen = 4 + tlen + 4 + 2 * (/* mpint */ (4 + 1 + n));

  /* check/return signature length */
  if (sign == NULL)
    {
      *sign_len = maxlen;
      return ASSH_OK;
    }

  assert(!assh_bignum_isempty(&k->sn));

  ASSH_RET_IF_TRUE(*sign_len < maxlen, ASSH_ERR_OUTPUT_OVERFLOW);

  assh_store_u32(sign, tlen);
  memcpy(sign + 4, k->id->name, tlen);
  uint8_t *rs_str = sign + 4 + tlen + 4;

  /* hash function output size */
  size_t hsize = hash->hash_size ? hash->hash_size : n;
  /* size of message hash */
  size_t nhsize = n > hsize ? n : hsize;

  ASSH_SCRATCH_ALLOC(c, uint8_t, sc,
    hash->ctx_size * 2 + /* hm */ nhsize
                   + /* k */ hsize * 2, ASSH_ERRSV_CONTINUE, err_);

  void    *hash_ctx1 = sc;
  void    *hash_ctx2 = sc + hash->ctx_size;
  uint8_t *hm = sc + hash->ctx_size * 2;
  uint8_t *k_ = hm + nhsize;

  uint_fast8_t i;

  /* message hash */
  ASSH_JMP_ON_ERR(assh_hash_init(c, hash_ctx1, hash), err_scratch);
  for (i = 0; i < data_count; i++)
    assh_hash_update(hash_ctx1, data[i].data, data[i].len);
  assh_hash_final(hash_ctx1, hm + nhsize - hsize, hsize);
  assh_hash_cleanup(hash_ctx1);
  memset(hm, 0, nhsize - hsize);    /* padding */

  /* Do not rely on prng, use expand(hash(hm|key)) % p as nonce.
     see Suite B implementer's guide to FIPS 186-3 (ECDSA) section A.2.1 */
  assert(hsize * 2 >= n + 8);

  ASSH_JMP_ON_ERR(assh_hash_init(c, hash_ctx1, hash), err_scratch);
  assh_hash_update(hash_ctx1, hm, nhsize);
  ASSH_JMP_ON_ERR(assh_hash_bignum(c, hash_ctx1, &k->sn), err_hash);

  if (hash->hash_size)
    {
      /* 2 * fixed size output hash */
      ASSH_JMP_ON_ERR(assh_hash_copy(hash_ctx2, hash_ctx1), err_hash);
      assh_hash_update(hash_ctx1, "A", 1); /* first half */
      assh_hash_final(hash_ctx1, k_, hsize);
      assh_hash_update(hash_ctx2, "B", 1); /* second half */
      assh_hash_final(hash_ctx2, k_ + hsize, hsize);
      assh_hash_cleanup(hash_ctx2);
    }
  else
    {
      /* variable output hash */
      assh_hash_final(hash_ctx1, k_, hsize * 2);
    }

  assh_hash_cleanup(hash_ctx1);

  enum {
    X_raw, Y_raw, P_raw, N_raw, M_raw, K_raw, D, R_mpint, S_mpint,
    X1, Y1, Z1, X2, Y2, Z2, X3, Y3, Z3, T0, T1, T2, T3, MT,
    K, S, Sh
  };

  static const assh_bignum_op_t bytecode[] = {

    /* reduce k */
    ASSH_BOP_SIZE(      K,      Sh                      ),
    ASSH_BOP_SIZER(     X1,     MT,    S                ),

    ASSH_BOP_MOVE(      T3,     P_raw                   ),
    ASSH_BOP_MOVES(     K,      K_raw                   ),
    ASSH_BOP_MOD(       K,      K,     T3               ),
    ASSH_BOP_SHRINK(    K,      S                       ),

    /* compute ephemeral key pair (k, R) */
    ASSH_BOP_MTINIT(	MT,     T3                      ),

    ASSH_BOP_MOVE(      X1,     X_raw                   ),
    ASSH_BOP_MOVE(      Y1,     Y_raw                   ),
    ASSH_BOP_MTTO(      X1,     Y1,     X1,     MT      ),

    ASSH_BOP_WS_SCMUL2(X3, Y3, Z3, X2, Y2, Z2, X1, Y1, Z1,
                       T0, T1, T2, T3, K, MT),

    ASSH_BOP_MTFROM(	X2,     X2,     X2,     MT      ),

    ASSH_BOP_MOVE(      T0,     N_raw                   ),
    ASSH_BOP_MTINIT(	MT,     T0                      ),

    /* r = xr % n */
    ASSH_BOP_MTTO(      X2,     X2,     X2,     MT      ),
    ASSH_BOP_MOD(       X2,     X2,     MT		),

    /* k^-1 */
    ASSH_BOP_MTTO(      T1,     T1,     K,      MT      ),
    ASSH_BOP_INV(       T0,     T1,     MT              ),

    /* E */
    ASSH_BOP_MOVE(      T2,     M_raw                   ),
    ASSH_BOP_MTTO(      T3,     T3,     T2,     MT      ),

    /* d */
    ASSH_BOP_MTTO(      T1,     T1,     D,      MT      ),

    /* s = k^-1 * (E + r * d) */
    ASSH_BOP_MULM(      Y2,     T1,     X2,	MT	),
    ASSH_BOP_ADDM(      Y2,     Y2,     T3,	MT	),
    ASSH_BOP_MULM(      Y2,     Y2,     T0,	MT	),

    ASSH_BOP_MTFROM(    T0,     T1,     X2,     MT      ),

    /* sanity check */
    ASSH_BOP_UINT(      T2,     0			),
    ASSH_BOP_CMPEQ(     K,      T2,      0              ),
    ASSH_BOP_CFAIL(     0,      0                       ),
    ASSH_BOP_CMPEQ(     T1,     T2,      0              ),
    ASSH_BOP_CFAIL(     0,      0                       ),
    ASSH_BOP_CMPEQ(     T0,     T2,      0              ),
    ASSH_BOP_CFAIL(     0,      0                       ),

#ifdef CONFIG_ASSH_DEBUG_SIGN
    ASSH_BOP_PRINT(     T0,    'R'                      ),
    ASSH_BOP_PRINT(     T1,    'S'                      ),
#endif

    ASSH_BOP_MOVEA(     R_mpint,	T0              ),
    ASSH_BOP_MOVE(      S_mpint,	T1              ),

    ASSH_BOP_END(),
  };

  ASSH_JMP_ON_ERR(assh_bignum_bytecode(c, 0, bytecode, "DDDDDDNMMTTTTTTTTTTTTTmTss",
	    curve->gx, curve->gy, curve->p, curve->n,
            hm, k_, &k->sn, rs_str, NULL, (size_t)curve->bits, (size_t)(hsize * 8 * 2)), err_scratch);

  size_t rlen = 4 + assh_load_u32(rs_str);
  size_t slen = 4 + assh_load_u32(rs_str + rlen);

  /* adjust signature blob length and signature len */
  assh_store_u32(rs_str - 4, rlen + slen);
  *sign_len = 4 + tlen + 4 + rlen + slen;

  ASSH_SCRATCH_FREE(c, sc);
  return ASSH_OK;

 err_hash:
  assh_hash_cleanup(hash_ctx1);
 err_scratch:
  ASSH_SCRATCH_FREE(c, sc);
 err_:
  return err;
}

static ASSH_SIGN_CHECK_FCN(assh_sign_ecdsa_check)
{
  const struct assh_key_ecdsa_s *k = (const void*)key;
  assh_status_t err;

  const struct assh_weierstrass_curve_s *curve = k->id->curve;
  const struct assh_hash_algo_s *hash = k->id->hash;

  size_t n = ASSH_ALIGN8(curve->bits) / 8;
  size_t tlen = strlen(k->id->name);
  size_t minlen = 4 + tlen + 4 + 2 * (/* mpint */ 4);

  ASSH_RET_IF_TRUE(sign_len < minlen, ASSH_ERR_INPUT_OVERFLOW);

  ASSH_RET_IF_TRUE(tlen != assh_load_u32(sign), ASSH_ERR_BAD_DATA);
  ASSH_RET_IF_TRUE(memcmp(sign + 4, k->id->name, tlen), ASSH_ERR_BAD_DATA);

  const uint8_t *rs_str = (uint8_t*)sign + 4 + tlen;
  const uint8_t *r_mpint = rs_str + 4;
  const uint8_t *s_mpint, *s_end, *rs_end;

  ASSH_RET_ON_ERR(assh_check_string(sign, sign_len, rs_str, &rs_end));
  ASSH_RET_ON_ERR(assh_check_string(sign, sign_len, r_mpint, &s_mpint));
  ASSH_RET_ON_ERR(assh_check_string(sign, sign_len, s_mpint, &s_end));

  ASSH_RET_IF_TRUE(rs_end != sign + sign_len, ASSH_ERR_INPUT_OVERFLOW);
  ASSH_RET_IF_TRUE(s_end != sign + sign_len, ASSH_ERR_INPUT_OVERFLOW);

  /* hash function output size */
  size_t hsize = hash->hash_size ? hash->hash_size : n;
  /* size of message hash */
  size_t nhsize = n > hsize ? n : hsize;

  ASSH_SCRATCH_ALLOC(c, uint8_t, sc,
    hash->ctx_size + /* hm */ nhsize, ASSH_ERRSV_CONTINUE, err_);

  void *hash_ctx = sc;
  uint8_t *hm = sc + hash->ctx_size;
  uint_fast8_t i;

  ASSH_JMP_ON_ERR(assh_hash_init(c, hash_ctx, hash), err_scratch);
  for (i = 0; i < data_count; i++)
    assh_hash_update(hash_ctx, data[i].data, data[i].len);
  assh_hash_final(hash_ctx, hm + nhsize - hsize, hsize);
  assh_hash_cleanup(hash_ctx);
  memset(hm, 0, nhsize - hsize);    /* padding */

  enum {
    GX_raw, GY_raw, QX, QY, P_raw, N_raw, M_raw, R_mpint, S_mpint,
    X1, Y1, Z1, X2, Y2, Z2, X3, Y3, Z3, X4, Y4, Z4, T0, T1, T2, T3, U1, U2,
    MT, S
  };

  static const assh_bignum_op_t bytecode[] = {

    ASSH_BOP_SIZER(     X1,     MT,    S                ),

    ASSH_BOP_MOVE(      T2,     N_raw                   ),
    ASSH_BOP_UINT(      T3,     0               	),

    /* check r and s ranges */
    ASSH_BOP_MOVE(      T0,     S_mpint                 ),
    ASSH_BOP_CMPGT(     T0,     T3,     0 /* s > 0 */   ),
    ASSH_BOP_CFAIL(     1,      0                       ),
    ASSH_BOP_CMPLT(     T0,     T2,     0 /* s < n */   ),
    ASSH_BOP_CFAIL(     1,      0                       ),

    ASSH_BOP_MOVE(      T1,     R_mpint                 ),
    ASSH_BOP_CMPGT(     T1,     T3,     0 /* r > 0 */   ),
    ASSH_BOP_CFAIL(     1,      0                       ),
    ASSH_BOP_CMPLT(     T1,     T2,     0 /* r < n */   ),
    ASSH_BOP_CFAIL(     1,      0                       ),

    ASSH_BOP_MTINIT(	MT,     T2                      ),
    ASSH_BOP_MTTO(      T0,     T1,     T0,     MT      ),

    /* w = s^-1 */
    ASSH_BOP_INV(       T3,     T0,     MT              ),

    /* u1 = e * w */
    ASSH_BOP_MOVE(      T2,     M_raw                   ),
    ASSH_BOP_MTTO(      T2,     T2,     T2,     MT      ),
    ASSH_BOP_MULM(      U1,     T3,     T2,	MT	),

    /* u2 = r * w */
    ASSH_BOP_MULM(      U2,     T3,     T1,	MT	),

    ASSH_BOP_MTFROM(    U1,     U2,     U1,     MT      ),

    ASSH_BOP_MOVE(      T2,     P_raw                   ),
    ASSH_BOP_MTINIT(	MT,     T2                      ),

    /* u1 . G */
    ASSH_BOP_MOVE(      X1,     GX_raw                  ),
    ASSH_BOP_MOVE(      Y1,     GY_raw                  ),
    ASSH_BOP_MTTO(      X1,     Y1,     X1,     MT      ),

    ASSH_BOP_WS_SCMUL3(X3, Y3, Z3, X2, Y2, Z2, X1, Y1, Z1,
                       T0, T1, T2, T3, U1, MT),

    ASSH_BOP_MTTO(      X1,     Y1,     QX,     MT      ),

    /* u2 . Q */
    ASSH_BOP_WS_SCMUL3(X3, Y3, Z3, X4, Y4, Z4, X1, Y1, Z1,
                       T0, T1, T2, T3, U2, MT),

    /* R = u1 . G + u2 . Q */
    ASSH_BOP_WS_PADD(X3, Y3, Z3, X2, Y2, Z2, X4, Y4, Z4,
                     T0, T1, T2, T3, MT),

    /* check that R is not at infinity */
    ASSH_BOP_MTFROM(	T0,     T0,     Z3,     MT      ),
    ASSH_BOP_UINT(      T1,     0                       ),
    ASSH_BOP_CMPEQ(     T1,     T0,     0               ),
    ASSH_BOP_CFAIL(     0,      0                       ),

    /* Rx */
    ASSH_BOP_INV(       T0,     Z3,             MT      ),
    ASSH_BOP_MULM(      X3,     X3,     T0,     MT      ),
    ASSH_BOP_MTFROM(	T0,     T0,     X3,     MT      ),

    /* test Rx % n == r */
    ASSH_BOP_MOVE(      T2,     N_raw                   ),
    ASSH_BOP_MOD(	T1,     T0,     T2              ),
    ASSH_BOP_MOVE(      T3,     R_mpint                 ),
#ifdef CONFIG_ASSH_DEBUG_SIGN
    ASSH_BOP_PRINT(     T1,    'x'                      ),
    ASSH_BOP_PRINT(     T3,    'r'                      ),
#endif
    ASSH_BOP_CMPEQ(     T3,     T1,     0               ),
    ASSH_BOP_CFAIL(     1,      0                       ),

    ASSH_BOP_END(),
  };

  ASSH_JMP_ON_ERR(assh_bignum_bytecode(c, 0, bytecode, "DDNNDDDMMTTTTTTTTTTTTTTTTTTms",
            curve->gx, curve->gy, &k->xn, &k->yn, curve->p, curve->n,
            hm, r_mpint, s_mpint, (size_t)curve->bits), err_scratch);

  err = ASSH_OK;

 err_scratch:
  ASSH_SCRATCH_FREE(c, sc);
 err_:

  return err;
}


static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_nistp256_suitable_key)
{
  if (key == NULL)
    return c->type == ASSH_SERVER;
  struct assh_key_ecdsa_s *k = (void*)key;
  return key->algo == &assh_key_builtin_ecdsa_nist &&
    k->id->curve == &assh_nistp256_curve &&
    k->id->hash == &assh_hash_sha256;
}

const struct assh_algo_sign_s assh_sign_builtin_nistp256 =
{
  .algo_wk = {
     ASSH_ALGO_BASE(SIGN, "assh-builtin", ASSH_NISTP256_SAFETY, 90,
       ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
   	              "ecdsa-sha2-nistp256" }),
     ),
     .f_suitable_key = assh_sign_nistp256_suitable_key,
     .key_algo = &assh_key_builtin_ecdsa_nist,
  },
  .f_generate = assh_sign_ecdsa_generate,
  .f_check = assh_sign_ecdsa_check,
};


static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_nistp384_suitable_key)
{
  if (key == NULL)
    return c->type == ASSH_SERVER;
  struct assh_key_ecdsa_s *k = (void*)key;
  return key->algo == &assh_key_builtin_ecdsa_nist &&
    k->id->curve == &assh_nistp384_curve &&
    k->id->hash == &assh_hash_sha384;
}

const struct assh_algo_sign_s assh_sign_builtin_nistp384 =
{
  .algo_wk = {
     ASSH_ALGO_BASE(SIGN, "assh-builtin", ASSH_NISTP384_SAFETY, 80,
       ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
   	              "ecdsa-sha2-nistp384" }),
     ),
     .f_suitable_key = assh_sign_nistp384_suitable_key,
     .key_algo = &assh_key_builtin_ecdsa_nist,
  },
  .f_generate = assh_sign_ecdsa_generate,
  .f_check = assh_sign_ecdsa_check,
};


static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_nistp521_suitable_key)
{
  if (key == NULL)
    return c->type == ASSH_SERVER;
  struct assh_key_ecdsa_s *k = (void*)key;
  return key->algo == &assh_key_builtin_ecdsa_nist &&
    k->id->curve == &assh_nistp521_curve &&
    k->id->hash == &assh_hash_sha512;
}

const struct assh_algo_sign_s assh_sign_builtin_nistp521 =
{
  .algo_wk = {
    ASSH_ALGO_BASE(SIGN, "assh-builtin", ASSH_NISTP521_SAFETY, 70,
      ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
                        "ecdsa-sha2-nistp521" }),
    ),
    .f_suitable_key = assh_sign_nistp521_suitable_key,
    .key_algo = &assh_key_builtin_ecdsa_nist,
  },
  .f_generate = assh_sign_ecdsa_generate,
  .f_check = assh_sign_ecdsa_check,
};

