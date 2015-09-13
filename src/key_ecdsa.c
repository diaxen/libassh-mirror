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

#include <assh/key_ecdsa.h>
#include <assh/assh_bignum.h>
#include <assh/assh_packet.h>
#include <assh/assh_alloc.h>
#include <assh/assh_prng.h>
#include <assh/assh_hash.h>

#include "ecc_weierstrass.h"

#include <string.h>

static ASSH_KEY_OUTPUT_FCN(assh_key_ecdsa_output)
{
  struct assh_key_ecdsa_s *k = (void*)key;

  assert(key->algo == &assh_key_ecdsa_nistp256 ||
         key->algo == &assh_key_ecdsa_nistp384 ||
         key->algo == &assh_key_ecdsa_nistp521);

  const struct assh_weierstrass_curve_s *curve = k->curve;
  assh_error_t err;

  size_t n = ASSH_ALIGN8(curve->bits) / 8;
  size_t tlen = strlen(k->key.algo->type);
  size_t dlen = strlen(curve->name);
  size_t pub_len = /* algo id*/ 4 + tlen
    + /* curve id */ 4 + dlen
    + /* curve point */ 4 + 1 + 2 * n;

  switch (format)
    {
    case ASSH_KEY_FMT_PUB_RFC4253_6_6: {
      assert(curve->bits == assh_bignum_bits(&k->xn));
      assert(curve->bits == assh_bignum_bits(&k->yn));

      if (blob != NULL)
        {
          ASSH_CHK_RET(pub_len > *blob_len, ASSH_ERR_OUTPUT_OVERFLOW);

          assh_store_u32(blob, tlen);
          memcpy(blob + 4, k->key.algo->type, tlen);
          blob += 4 + tlen;

          assh_store_u32(blob, dlen);
          memcpy(blob + 4, curve->name, dlen);
          blob += 4 + dlen;

          assh_store_u32(blob, 1 + 2 * n);
          blob[4] = 0x4;
          uint8_t *rx = blob + 4 + 1;
          uint8_t *ry = rx + n;
          ASSH_ERR_RET(assh_bignum_convert(c, ASSH_BIGNUM_NATIVE,
                                           ASSH_BIGNUM_MSB_RAW, &k->xn, rx, 0));
          ASSH_ERR_RET(assh_bignum_convert(c, ASSH_BIGNUM_NATIVE,
                                           ASSH_BIGNUM_MSB_RAW, &k->yn, ry, 0));
        }

      *blob_len = pub_len;

      return ASSH_OK;
    }

    case ASSH_KEY_FMT_PV_OPENSSH_V1_KEY: {
      assert(curve->bits == assh_bignum_bits(&k->xn));
      assert(curve->bits == assh_bignum_bits(&k->yn));
      ASSH_CHK_RET(assh_bignum_isempty(&k->sn), ASSH_ERR_NOTSUP);
      assert(curve->bits == assh_bignum_bits(&k->sn));

      size_t len = pub_len + /* mpint scalar */ 4 + 1 + n;

      if (blob != NULL)
        {
          ASSH_CHK_RET(len > *blob_len, ASSH_ERR_OUTPUT_OVERFLOW);

          assh_store_u32(blob, tlen);
          memcpy(blob + 4, k->key.algo->type, tlen);
          blob += 4 + tlen;

          assh_store_u32(blob, dlen);
          memcpy(blob + 4, curve->name, dlen);
          blob += 4 + dlen;

          assh_store_u32(blob, 1 + 2 * n);
          blob[4] = 0x4;
          uint8_t *rx = blob + 4 + 1;
          uint8_t *ry = rx + n;
          uint8_t *sc = ry + n;
          ASSH_ERR_RET(assh_bignum_convert(c, ASSH_BIGNUM_NATIVE,
                                           ASSH_BIGNUM_MSB_RAW, &k->xn, rx, 0));
          ASSH_ERR_RET(assh_bignum_convert(c, ASSH_BIGNUM_NATIVE,
                                           ASSH_BIGNUM_MSB_RAW, &k->yn, ry, 0));
          ASSH_ERR_RET(assh_bignum_convert(c, ASSH_BIGNUM_NATIVE,
                                           ASSH_BIGNUM_MPINT, &k->sn, sc, 1));
          len = pub_len + 4 + assh_load_u32(sc);
        }

      *blob_len = len;

      return ASSH_OK;
    }

#if 0
    case ASSH_KEY_FMT_PV_PEM_ASN1: {
      ASSH_CHK_RET(!k->private, ASSH_ERR_NOTSUP);
      return ASSH_OK;
    }
#endif

    default:
      ASSH_ERR_RET(ASSH_ERR_NOTSUP);
    }

  return ASSH_OK;
}

static ASSH_KEY_CMP_FCN(assh_key_ecdsa_cmp)
{
  assert(key->algo == &assh_key_ecdsa_nistp256 ||
         key->algo == &assh_key_ecdsa_nistp384 ||
         key->algo == &assh_key_ecdsa_nistp521);

  if (key->algo != b->algo)
    return 0;

  struct assh_key_ecdsa_s *k = (void*)key;
  struct assh_key_ecdsa_s *l = (void*)b;

  enum bytecode_args_e
  {
    X0, X1, Y0, Y1, S0, S1
  };

  static const assh_bignum_op_t bytecode[] = {
    ASSH_BOP_CJMP(      2,      0,       0       ),
    ASSH_BOP_CMPEQ(     S1,     S0,      0       ),
    ASSH_BOP_CFAIL(     1,      0                ),

    ASSH_BOP_CMPEQ(     X1,     X0,      0       ),
    ASSH_BOP_CFAIL(     1,      0                ),
    ASSH_BOP_CMPEQ(     Y1,     Y0,      0       ),
    ASSH_BOP_CFAIL(     1,      0                ),
    ASSH_BOP_END(),
  };

  if (!pub)
    {
      if (assh_bignum_isempty(&k->xn) != assh_bignum_isempty(&l->xn))
        return 0;
      if (assh_bignum_isempty(&l->xn))
        pub = 1;
    }

  return assh_bignum_bytecode(c, !!pub, bytecode, "NNNNNN",
    &k->xn, &l->xn, &k->yn, &l->yn, &k->sn, &l->sn) == 0;
}

static assh_error_t
assh_key_ecdsa_create(struct assh_context_s *c,
                      const struct assh_key_ops_s *algo,
                      struct assh_key_s **key,
                      const struct assh_weierstrass_curve_s *curve,
                      const struct assh_hash_algo_s *hash)
{
  assh_error_t err;
  struct assh_key_ecdsa_s *k;

  ASSH_ERR_RET(assh_alloc(c, sizeof(struct assh_key_ecdsa_s),
                          ASSH_ALLOC_INTERNAL, (void**)&k));

  k->key.algo = algo;
  k->curve = curve;
  k->hash = hash;

  assh_bignum_init(c, &k->xn, curve->bits);
  assh_bignum_init(c, &k->yn, curve->bits);
  assh_bignum_init(c, &k->sn, curve->bits);

  assert(curve->cofactor == 1); /* more checks needed if != 1 */

  enum {
    X_raw, Y_raw, P_raw, N_raw,
    X2, Y2, SC, X1, Y1, Z1, Z2, X3, Y3, Z3, T0, T1, T2, T3,
    MT
  };

  static const assh_bignum_op_t bytecode[] = {

    ASSH_BOP_SIZER(     X1,     T3,    SC               ),

    ASSH_BOP_UINT(      T0,     1                       ),
    ASSH_BOP_MOVE(      T1,     N_raw                   ),
    ASSH_BOP_SUB(       T1,     T1,     T0              ),
    ASSH_BOP_RAND(      SC,     T0,     T1,
                        ASSH_PRNG_QUALITY_LONGTERM_KEY  ),

    ASSH_BOP_MOVE(      T0,     P_raw                   ),
    ASSH_BOP_MTINIT(	MT,     T0                      ),

    ASSH_BOP_MOVE(      X1,     X_raw                   ),
    ASSH_BOP_MOVE(      Y1,     Y_raw                   ),
    ASSH_BOP_MTTO(      X1,     Y1,     X1,     MT      ),

    ASSH_BOP_WS_SCMUL2(X3, Y3, Z3, X2, Y2, Z2, X1, Y1, Z1,
                       T0, T1, T2, T3, SC, MT),

    ASSH_BOP_MTFROM(	X2,     Y2,     X2,     MT      ),

    ASSH_BOP_PRIVACY(   X2,     0,      0		),
    ASSH_BOP_PRIVACY(   Y2,     0,      0		),

#ifdef CONFIG_ASSH_DEBUG_KEX
    ASSH_BOP_PRINT(     X2,    'X'                      ),
    ASSH_BOP_PRINT(     Y2,    'Y'                      ),
#endif

    ASSH_BOP_END(),
  };

  ASSH_ERR_GTO(assh_bignum_bytecode(c, 0, bytecode, "DDDDNNNTTTTTTTTTTTm",
               curve->gx, curve->gy, curve->p, curve->n,
               &k->xn, &k->yn, &k->sn), err_key);

  assert(k->sn.secret);

  *key = &k->key;

  return ASSH_OK;

 err_key:
  assh_free(c, k);
  return err;
}

static ASSH_KEY_VALIDATE_FCN(assh_key_ecdsa_validate)
{
  assh_error_t err;
  struct assh_key_ecdsa_s *k = (void*)key;
  const struct assh_weierstrass_curve_s *curve = k->curve;

  assert(key->algo == &assh_key_ecdsa_nistp256 ||
         key->algo == &assh_key_ecdsa_nistp384 ||
         key->algo == &assh_key_ecdsa_nistp521);

  ASSH_CHK_RET(curve->bits != assh_bignum_bits(&k->xn) ||
               curve->bits != assh_bignum_bits(&k->yn),
               ASSH_ERR_OUTPUT_OVERFLOW);

  assert(curve->cofactor == 1); /* more checks needed if != 1 */

  enum {
    P_raw, B_raw,
    X, Y, X1, Y1, Z1, T0, T1, T2,
    MT
  };

  static const assh_bignum_op_t bytecode[] = {

    ASSH_BOP_SIZER(     X1,     T2,    X                ),

    /* init */
    ASSH_BOP_MOVE(      T0,     P_raw                   ),
    ASSH_BOP_MTINIT(	MT,     T0                      ),

    ASSH_BOP_MOVE(      T2,     B_raw                   ),
    ASSH_BOP_MTTO(      X1,     Y1,     X,      MT      ),

    ASSH_BOP_WS_POINTONCURVE(X1, Y1, T0, T1, T2, MT),

    ASSH_BOP_END(),
  };

  ASSH_ERR_RET(assh_bignum_bytecode(c, 0, bytecode, "DDNNTTTTTTm",
                 curve->p, curve->b, &k->xn, &k->yn));

  return ASSH_OK;
}

static assh_error_t
assh_key_ecdsa_load(struct assh_context_s *c,
                    const struct assh_key_ops_s *algo,
                    const uint8_t *blob, size_t blob_len,
                    struct assh_key_s **key,
                    enum assh_key_format_e format,
                    const struct assh_weierstrass_curve_s *curve,
                    const struct assh_hash_algo_s *hash)
{
  assh_error_t err;

  size_t n = ASSH_ALIGN8(curve->bits) / 8;
  size_t tlen = strlen(algo->type);
  size_t dlen = strlen(curve->name);
  size_t kp_len = 1 + 2 * n;

  const uint8_t *x_str, *y_str, *s_str = NULL;

  /* parse the key blob */
  switch (format)
    {
    case ASSH_KEY_FMT_PUB_RFC4253_6_6: {
      size_t len = /* algo id*/ 4 + tlen
        + /* curve id */ 4 + dlen
        + /* curve point */ 4 + kp_len;

      ASSH_CHK_RET(blob_len < len, ASSH_ERR_INPUT_OVERFLOW);

      ASSH_CHK_RET(assh_load_u32(blob) != tlen, ASSH_ERR_BAD_DATA);
      ASSH_CHK_RET(memcmp(algo->type, blob + 4, tlen), ASSH_ERR_BAD_DATA);
      blob += 4 + tlen;

      ASSH_CHK_RET(assh_load_u32(blob) != dlen, ASSH_ERR_BAD_DATA);
      ASSH_CHK_RET(memcmp(curve->name, blob + 4, dlen), ASSH_ERR_BAD_DATA);
      blob += 4 + dlen;

      ASSH_CHK_RET(assh_load_u32(blob) != kp_len, ASSH_ERR_BAD_DATA);
      /* point compression not supported */
      ASSH_CHK_RET(blob[4] != 4, ASSH_ERR_NOTSUP);
      x_str = blob + 4 + 1;
      y_str = blob + 4 + 1 + n;
      break;
    }

    case ASSH_KEY_FMT_PV_OPENSSH_V1_KEY: {
      size_t min_len = /* algo id*/ 4 + tlen
        + /* curve id */ 4 + dlen
        + /* curve point */ 4 + kp_len
        + /* scalar mpint */ 4;
      size_t max_len = min_len + 4 + 1 + n;

      ASSH_CHK_RET(blob_len < min_len || blob_len > max_len,
                   ASSH_ERR_INPUT_OVERFLOW);

      ASSH_CHK_RET(assh_load_u32(blob) != tlen, ASSH_ERR_BAD_DATA);
      ASSH_CHK_RET(memcmp(algo->type, blob + 4, tlen), ASSH_ERR_BAD_DATA);
      blob += 4 + tlen;
      blob_len -= 4 + tlen;

      ASSH_CHK_RET(assh_load_u32(blob) != dlen, ASSH_ERR_BAD_DATA);
      ASSH_CHK_RET(memcmp(curve->name, blob + 4, dlen), ASSH_ERR_BAD_DATA);
      blob += 4 + dlen;
      blob_len -= 4 + dlen;

      ASSH_CHK_RET(assh_load_u32(blob) != kp_len, ASSH_ERR_BAD_DATA);
      /* point compression not supported */
      ASSH_CHK_RET(blob[4] != 4, ASSH_ERR_NOTSUP);
      x_str = blob + 4 + 1;
      y_str = blob + 4 + 1 + n;
      s_str = blob + 4 + kp_len;
      ASSH_ERR_RET(assh_check_string(blob, blob_len, s_str, NULL));
      break;
    }

    case ASSH_KEY_FMT_PV_PEM_ASN1: {
      uint8_t *seq, *seq_end, *val, *tmp, *next;
      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, blob, &seq, &seq_end,
                                   /* seq */ 0x30));

      /* version */
      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, seq, &val, &next,
                                   /* integer */ 0x02));
      ASSH_CHK_RET(val + 1 != next || val[0] != 1, ASSH_ERR_BAD_DATA);

      /* private key */
      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, next, &s_str, &next,
                                   /* octet string */ 0x04));
      ASSH_CHK_RET(s_str + n != next, ASSH_ERR_BAD_DATA);

      tmp = next;
      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, next, &val, &next, 0));
      if (tmp[0] == 0xa0)       /* optional domain parameters */
        {
          tmp = next;
          ASSH_ERR_RET(assh_check_asn1(blob, blob_len, next, &val, NULL, 0));
        }

      ASSH_CHK_RET(tmp[0] != /* optional public key */ 0xa1, ASSH_ERR_BAD_DATA);
      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, val, &x_str, &next, 0x03));

      ASSH_CHK_RET(x_str + 2 + 2 * n != next, ASSH_ERR_BAD_DATA);
      ASSH_CHK_RET(x_str[1] != 0x04 /* no point compression */, ASSH_ERR_BAD_DATA);
      x_str += 2;
      y_str = x_str + n;

      break;
    }

    default:
      ASSH_ERR_RET(ASSH_ERR_NOTSUP);
    }

  /* allocate key structure */
  struct assh_key_ecdsa_s *k;

  ASSH_ERR_RET(assh_alloc(c, sizeof(struct assh_key_ecdsa_s),
                          ASSH_ALLOC_INTERNAL, (void**)&k));

  assh_bignum_init(c, &k->xn, curve->bits);
  assh_bignum_init(c, &k->yn, curve->bits);
  assh_bignum_init(c, &k->sn, curve->bits);

  switch (format)
    {
    case ASSH_KEY_FMT_PV_OPENSSH_V1_KEY:
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE,
                                       s_str, &k->sn, 1), err_key);
    case ASSH_KEY_FMT_PUB_RFC4253_6_6:
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_MSB_RAW, ASSH_BIGNUM_NATIVE,
                                       x_str, &k->xn, 0), err_key);
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_MSB_RAW, ASSH_BIGNUM_NATIVE,
                                       y_str, &k->yn, 0), err_key);
      break;

    case ASSH_KEY_FMT_PV_PEM_ASN1:
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_MSB_RAW, ASSH_BIGNUM_NATIVE,
                                       s_str, &k->sn, 1), err_key);
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_MSB_RAW, ASSH_BIGNUM_NATIVE,
                                       x_str, &k->xn, 0), err_key);
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_MSB_RAW, ASSH_BIGNUM_NATIVE,
                                       y_str, &k->yn, 0), err_key);
      break;

    default:
      break;
    }

  k->key.algo = algo;
  k->curve = curve;
  k->hash = hash;

  *key = &k->key;

  return ASSH_OK;

 err_key:
  assh_bignum_release(c, &k->sn);
  assh_bignum_release(c, &k->xn);
  assh_bignum_release(c, &k->yn);
  assh_free(c, k);
  return err;
}

static ASSH_KEY_CLEANUP_FCN(assh_key_ecdsa_cleanup)
{
  struct assh_key_ecdsa_s *k = (void*)key;

  assh_bignum_release(c, &k->sn);
  assh_bignum_release(c, &k->xn);
  assh_bignum_release(c, &k->yn);
  assh_free(c, k);
}

static ASSH_KEY_LOAD_FCN(assh_key_ecdsa_nistp256_load)
{
  return assh_key_ecdsa_load(c, algo, blob, blob_len, key, format,
                             &assh_nistp256_curve, &assh_hash_sha256);
}

static ASSH_KEY_CREATE_FCN(assh_key_ecdsa_nistp256_create)
{
  return assh_key_ecdsa_create(c, algo, key,
                               &assh_nistp256_curve, &assh_hash_sha256);
}

const struct assh_key_ops_s assh_key_ecdsa_nistp256 =
{
  .type = "ecdsa-sha2-nistp256",
  .f_output = assh_key_ecdsa_output,
  .f_create = assh_key_ecdsa_nistp256_create,
  .f_load = assh_key_ecdsa_nistp256_load,
  .f_validate = assh_key_ecdsa_validate,
  .f_cmp = assh_key_ecdsa_cmp,
  .f_cleanup = assh_key_ecdsa_cleanup,
};

static ASSH_KEY_LOAD_FCN(assh_key_ecdsa_nistp384_load)
{
  return assh_key_ecdsa_load(c, algo, blob, blob_len, key, format,
                             &assh_nistp384_curve, &assh_hash_sha384);
}

static ASSH_KEY_CREATE_FCN(assh_key_ecdsa_nistp384_create)
{
  return assh_key_ecdsa_create(c, algo, key,
                               &assh_nistp384_curve, &assh_hash_sha384);
}

const struct assh_key_ops_s assh_key_ecdsa_nistp384 =
{
  .type = "ecdsa-sha2-nistp384",
  .f_output = assh_key_ecdsa_output,
  .f_create = assh_key_ecdsa_nistp384_create,
  .f_load = assh_key_ecdsa_nistp384_load,
  .f_validate = assh_key_ecdsa_validate,
  .f_cmp = assh_key_ecdsa_cmp,
  .f_cleanup = assh_key_ecdsa_cleanup,
};

static ASSH_KEY_LOAD_FCN(assh_key_ecdsa_nistp521_load)
{
  return assh_key_ecdsa_load(c, algo, blob, blob_len, key, format,
                             &assh_nistp521_curve, &assh_hash_sha512);
}

static ASSH_KEY_CREATE_FCN(assh_key_ecdsa_nistp521_create)
{
  return assh_key_ecdsa_create(c, algo, key,
                               &assh_nistp521_curve, &assh_hash_sha512);
}

const struct assh_key_ops_s assh_key_ecdsa_nistp521 =
{
  .type = "ecdsa-sha2-nistp521",
  .f_output = assh_key_ecdsa_output,
  .f_create = assh_key_ecdsa_nistp521_create,
  .f_load = assh_key_ecdsa_nistp521_load,
  .f_validate = assh_key_ecdsa_validate,
  .f_cmp = assh_key_ecdsa_cmp,
  .f_cleanup = assh_key_ecdsa_cleanup,
};

