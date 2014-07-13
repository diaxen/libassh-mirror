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
#include <assh/assh_hash.h>
#include <assh/assh_prng.h>
#include <assh/assh_alloc.h>

#include <string.h>

/************************************************************ dss key */

struct assh_sign_dss_key_s
{
  struct assh_key_s key;

  /** public p */
  struct assh_bignum_s pn;
  /** public q */
  struct assh_bignum_s qn;
  /** public g */
  struct assh_bignum_s gn;
  /** public y */
  struct assh_bignum_s yn;
  /** private x, may be null */
  struct assh_bignum_s xn;
};

static const char *assh_dss_id = "\x00\x00\x00\x07ssh-dss";
static const size_t assh_dss_id_len = 4 + 7;

static ASSH_KEY_CLEANUP_FCN(assh_sign_dss_key_cleanup)
{
  struct assh_sign_dss_key_s *k = (void*)key;

  assh_bignum_release(c, &k->xn);
  assh_bignum_release(c, &k->yn);
  assh_bignum_release(c, &k->gn);
  assh_bignum_release(c, &k->qn);
  assh_bignum_release(c, &k->pn);
  assh_free(c, k, ASSH_ALLOC_KEY);
}

static ASSH_KEY_OUTPUT_FCN(assh_sign_dss_key_output)
{
  struct assh_sign_dss_key_s *k = (void*)key;
  assh_error_t err;

  assert(!strcmp(key->type, "ssh-dss"));

  struct assh_bignum_s *bn_[6] = { &k->pn, &k->qn, &k->gn, &k->yn, NULL, NULL };

  switch (format)
    {
    case ASSH_KEY_FMT_PUB_RFC4253_6_6: {
      /* add algo identifier */
      size_t l = assh_dss_id_len;
      if (blob != NULL)
        {
          ASSH_CHK_RET(assh_dss_id_len > *blob_len, ASSH_ERR_OUTPUT_OVERFLOW);
          memcpy(blob, assh_dss_id, assh_dss_id_len);
          *blob_len -= assh_dss_id_len;
          blob += assh_dss_id_len;
        }

      /* add key integers */
      struct assh_bignum_s **bn = bn_;
      for (bn = bn_; *bn != NULL; bn++)
        {
          size_t s = assh_bignum_size_of_num(ASSH_BIGNUM_MPINT, *bn);
          if (blob != NULL)
            {
              ASSH_CHK_RET(s > *blob_len, ASSH_ERR_OUTPUT_OVERFLOW);
              ASSH_ERR_RET(assh_bignum_convert(c, ASSH_BIGNUM_NATIVE,
                             ASSH_BIGNUM_MPINT, *bn, blob));
              s = assh_load_u32(blob) + 4;
              *blob_len -= s;
              blob += s;
            }
          l += s;
        }
      *blob_len = l;
      return ASSH_OK;
    }

#if 0
    case ASSH_KEY_FMT_PV_PEM_ASN1: {
      ASSH_CHK_RET(assh_bignum_isempty(&k->xn), ASSH_ERR_NOTSUP);
      bn_[4] = k->xn;
      return ASSH_OK;
    }
#endif

    default:
      ASSH_ERR_RET(ASSH_ERR_NOTSUP);
    }

  return ASSH_OK;
}

static ASSH_KEY_CMP_FCN(assh_sign_dss_key_cmp)
{
  assert(!strcmp(key->type, "ssh-dss"));

  if (strcmp(key->type, b->type))
    return 0;

  struct assh_sign_dss_key_s *k = (void*)key;
  struct assh_sign_dss_key_s *l = (void*)b;

  enum bytecode_args_e
  {
    P0, P1, Q0, Q1, G0, G1, Y0, Y1, X0, X1
  };

  static const assh_bignum_op_t *bc, bytecode[] = {
    ASSH_BOP_CMPEQ(     X1,     X0       ),
    ASSH_BOP_CMPEQ(     P1,     P0       ),
    ASSH_BOP_CMPEQ(     Q1,     Q0       ),
    ASSH_BOP_CMPEQ(     G1,     G0       ),
    ASSH_BOP_CMPEQ(     Y1,     Y0       ),
    ASSH_BOP_END(),
  };

  bc = bytecode;

  if (pub)
    {
      /* skip compare of X */
      bc++;
    }
  else
    {
      if (assh_bignum_isempty(&k->xn) != 
          assh_bignum_isempty(&l->xn))
        return 0;
      if (assh_bignum_isempty(&l->xn))
        bc++;
    }

  return assh_bignum_bytecode(c, bc, "NNNNNNNN",
    &k->pn, &l->pn, &k->qn, &l->qn, &k->gn, &l->gn, &k->yn, &l->yn) == 0;
}

static ASSH_KEY_VALIDATE_FCN(assh_sign_dss_key_validate)
{
  struct assh_sign_dss_key_s *k = (void*)key;
  assh_error_t err = ASSH_OK;

  /*
   * FIPS 186-4 Appendix A2.2
   * SP 800-89 section 5.3.1
   */

  unsigned int l = assh_bignum_bits(&k->pn);
  unsigned int n = assh_bignum_bits(&k->qn);

  /* check key size */
  if (l < 1024 || n < 160 || l > 4096 || n > 256 || l % 8 || n % 8)
    return ASSH_OK;

  enum bytecode_args_e
  {
    P, Q, G, Y, T1, T2
  };

  static const assh_bignum_op_t bytecode1[] = {
    ASSH_BOP_SIZE(      T1,     P                       ),
    ASSH_BOP_SIZE(      T2,     P                       ),

    ASSH_BOP_UINT(      T1,     1                       ),

    /* check generator range */
    ASSH_BOP_CMPLT(     T1,     G                       ), /* g > 1 */
    ASSH_BOP_CMPLT(     G,      P                       ), /* g < p */

    /* check generator order in the group */
    ASSH_BOP_EXPM(      T2,     G,      Q,      P       ),
    ASSH_BOP_CMPEQ(     T1,     T2                      ),

    /* check public key range */
    ASSH_BOP_CMPLT(     T1,     Y                       ), /* y > 1 */
    ASSH_BOP_SUB(       T2,     P,      T1              ),
    ASSH_BOP_CMPLT(     Y,      T2                      ), /* y < p-1 */

    /* check public key order in the group */
    ASSH_BOP_EXPM(      T2,     Y,      Q,      P       ),
    ASSH_BOP_CMPEQ(     T1,     T2                      ),

    ASSH_BOP_END(),
  };

  ASSH_ERR_RET(assh_bignum_bytecode(c, bytecode1, "NNNNTT",
                                    &k->pn, &k->qn, &k->gn, &k->yn));

  /* check that the private part match the public part of the key */
  if (!assh_bignum_isempty(&k->xn))
    {
      enum bytecode_args_e
      {
        P, G, Y, X, T1
      };

      static const assh_bignum_op_t bytecode2[] = {

        ASSH_BOP_SIZE(  T1,     P                       ),
        ASSH_BOP_EXPM(  T1,     G,      X,      P       ),
        ASSH_BOP_CMPEQ( T1,     Y                       ),

        ASSH_BOP_END(),
      };

      ASSH_ERR_RET(assh_bignum_bytecode(c, bytecode2, "NNNNT",
                                        &k->pn, &k->gn, &k->yn, &k->xn));
    }

  return ASSH_OK;
}

static ASSH_KEY_LOAD_FCN(assh_sign_dss_key_load)
{
  assh_error_t err;

  unsigned int l, n;
  uint8_t *p_str, *q_str, *g_str, *y_str, *x_str;

  /* parse the key blob */
  switch (format)
    {
    case ASSH_KEY_FMT_PUB_RFC4253_6_6: {

      ASSH_CHK_RET(blob_len < assh_dss_id_len, ASSH_ERR_INPUT_OVERFLOW);
      ASSH_CHK_RET(memcmp(assh_dss_id, blob, assh_dss_id_len), ASSH_ERR_BAD_DATA);

      p_str = (uint8_t*)blob + assh_dss_id_len;
      ASSH_ERR_RET(assh_check_string(blob, blob_len, p_str, &q_str));
      l = (assh_load_u32(p_str) * 8) & 0xfffffc00;
      ASSH_ERR_RET(assh_check_string(blob, blob_len, q_str, &g_str));
      n = (assh_load_u32(q_str) * 8) & 0xffffffe0;
      ASSH_ERR_RET(assh_check_string(blob, blob_len, g_str, &y_str));
      ASSH_ERR_RET(assh_check_string(blob, blob_len, y_str, NULL));
      x_str = NULL;
      break;
    }

    case ASSH_KEY_FMT_PV_PEM_ASN1: {
      uint8_t *seq, *seq_end, *val;
      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, blob, &seq, &seq_end));

      /* sequence type */
      ASSH_CHK_RET(blob[0] != 0x30, ASSH_ERR_BAD_DATA);

      /* skip first value */
      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, seq, NULL, &p_str));

      /* parse p, q, g, y, x */
      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, p_str, &val, &q_str));
      l = ((q_str - val) * 8) & 0xfffffc00;
      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, q_str, &val, &g_str));
      n = ((g_str - val) * 8) & 0xffffffe0;
      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, g_str, NULL, &y_str));
      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, y_str, NULL, &x_str));
      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, x_str, NULL, NULL));
      break;
    }

    default:
      ASSH_ERR_RET(ASSH_ERR_NOTSUP);
    }

  /* allocate key structure */
  ASSH_CHK_RET(l < 1024 || n < 160 || l % 8 || n % 8, ASSH_ERR_BAD_DATA);
  ASSH_CHK_RET(l > 4096 || n > 256, ASSH_ERR_NOTSUP);

  ASSH_ERR_RET(assh_alloc(c, sizeof(struct assh_sign_dss_key_s),
                          ASSH_ALLOC_KEY, (void**)key));
  struct assh_sign_dss_key_s *k = (void*)*key;

  k->key.type = "ssh-dss";
  k->key.f_output = assh_sign_dss_key_output;
  k->key.f_validate = assh_sign_dss_key_validate;
  k->key.f_cmp = assh_sign_dss_key_cmp;
  k->key.f_cleanup = assh_sign_dss_key_cleanup;

  /* init numbers */
  assh_bignum_init(c, &k->pn, l);
  assh_bignum_init(c, &k->qn, n);
  assh_bignum_init(c, &k->gn, l);
  assh_bignum_init(c, &k->yn, l);
  assh_bignum_init(c, &k->xn, n);

  /* convert numbers from blob representation */
  switch (format)
    {
    case ASSH_KEY_FMT_PUB_RFC4253_6_6:
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE,
                                       p_str, &k->pn), err_xn);
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE,
                                       q_str, &k->qn), err_xn);
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE,
                                       g_str, &k->gn), err_xn);
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE,
                                       y_str, &k->yn), err_xn);
      break;

    case ASSH_KEY_FMT_PV_PEM_ASN1:
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE,
                                       p_str, &k->pn), err_xn);
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE,
                                       q_str, &k->qn), err_xn);
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE,
                                       g_str, &k->gn), err_xn);
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE,
                                       y_str, &k->yn), err_xn);
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE,
                                       x_str, &k->xn), err_xn);
    default:
      break;
    }

  return ASSH_OK;

 err_xn:
  assh_bignum_release(c, &k->xn);
  assh_bignum_release(c, &k->yn);
  assh_bignum_release(c, &k->gn);
  assh_bignum_release(c, &k->qn);
  assh_bignum_release(c, &k->pn);
  assh_free(c, k, ASSH_ALLOC_KEY);
  return err;
}

/************************************************************ dss sign algo */

static assh_error_t
assh_sign_dss_hash_algo(const struct assh_hash_s **algo, unsigned int n)
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
  struct assh_sign_dss_key_s *k = (void*)key;
  assh_error_t err;

  /* check availability of the private key */
  ASSH_CHK_RET(assh_bignum_isempty(&k->xn), ASSH_ERR_MISSING_KEY);

  //  unsigned int l = assh_bignum_bits(&k->pn);
  unsigned int n = assh_bignum_bits(&k->qn);

  /* check/return signature length */
  size_t len = assh_dss_id_len + 4 + n * 2 / 8;

  const struct assh_hash_s *algo;
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
  ASSH_ERR_GTO(algo->f_init(hash_ctx), err_scratch);
  for (i = 0; i < data_count; i++)
    algo->f_update(hash_ctx, data[i], data_len[i]);
  algo->f_final(hash_ctx, msgh);

  /* Do not use the prng output directly as the DSA nonce in order to
     avoid leaking key bits in case of a weak prng. Random data is
     hashed with the private key and the message data. */
  ASSH_ERR_GTO(c->prng->f_get(c, nonce, n / 8, ASSH_PRNG_QUALITY_NONCE), err_scratch);
  ASSH_ERR_GTO(algo->f_init(hash_ctx), err_scratch);
  algo->f_update(hash_ctx, nonce, n / 8);
  for (i = 0; i < data_count; i++)
    algo->f_update(hash_ctx, data[i], data_len[i]);
  ASSH_ERR_GTO(assh_hash_bignum(c, hash_ctx, algo->f_update, &k->xn), err_hash);
  algo->f_final(hash_ctx, nonce);

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
  algo->f_final(hash_ctx, NULL);
 err_scratch:
  ASSH_SCRATCH_FREE(c, scratch);
 err_:
  return err;
}

static ASSH_SIGN_VERIFY_FCN(assh_sign_dss_verify)
{
  struct assh_sign_dss_key_s *k = (void*)key;
  assh_error_t err;

  //  unsigned int l = assh_bignum_bits(&k->pn);
  unsigned int n = assh_bignum_bits(&k->qn);

  ASSH_CHK_RET(sign_len != assh_dss_id_len + 4 + n * 2 / 8, ASSH_ERR_INPUT_OVERFLOW);

  ASSH_CHK_RET(memcmp(sign, assh_dss_id, assh_dss_id_len), ASSH_ERR_BAD_DATA);

  const struct assh_hash_s *algo;
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

  ASSH_ERR_GTO(algo->f_init(hash_ctx), err_scratch);
  for (i = 0; i < data_count; i++)
    algo->f_update(hash_ctx, data[i], data_len[i]);
  algo->f_final(hash_ctx, msgh);

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

    ASSH_BOP_CMPEQ(     V,      R                       ),

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
  if (strcmp(key->type, "ssh-dss"))
    return 0;
  struct assh_sign_dss_key_s *k = (void*)key;
  return assh_bignum_bits(&k->qn) == 160 &&
         assh_bignum_bits(&k->pn) == 1024;
}

struct assh_algo_sign_s assh_sign_dss =
{
  .algo = {
    .name = "ssh-dss", .class_ = ASSH_ALGO_SIGN,
    .safety = 20, .speed = 40,
    .f_suitable_key = assh_sign_dss_suitable_key,
  },
  .key_type = "ssh-dss",
  .f_key_load = assh_sign_dss_key_load,
  .f_generate = assh_sign_dss_generate,
  .f_verify = assh_sign_dss_verify,
};

static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_dss_suitable_key_2048_224)
{
  if (strcmp(key->type, "ssh-dss"))
    return 0;
  struct assh_sign_dss_key_s *k = (void*)key;
  return assh_bignum_bits(&k->qn) == 224 &&
         assh_bignum_bits(&k->pn) >= 2048;
}

struct assh_algo_sign_s assh_sign_dsa2048_sha224 =
{
  .algo = {
    .name = "dsa2048-sha224@libassh.org", .class_ = ASSH_ALGO_SIGN,
    .safety = 35, .speed = 30,
    .f_suitable_key = assh_sign_dss_suitable_key_2048_224,
  },
  .key_type = "ssh-dss",
  .f_key_load = assh_sign_dss_key_load,
  .f_generate = assh_sign_dss_generate,
  .f_verify = assh_sign_dss_verify,
};

static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_dss_suitable_key_2048_256)
{
  if (strcmp(key->type, "ssh-dss"))
    return 0;
  struct assh_sign_dss_key_s *k = (void*)key;
  return assh_bignum_bits(&k->qn) == 256 &&
         assh_bignum_bits(&k->pn) >= 2048;
}

struct assh_algo_sign_s assh_sign_dsa2048_sha256 =
{
  .algo = {
    .name = "dsa2048-sha256@libassh.org", .class_ = ASSH_ALGO_SIGN,
    .safety = 40, .speed = 30,
    .f_suitable_key = assh_sign_dss_suitable_key_2048_256,
  },
  .key_type = "ssh-dss",
  .f_key_load = assh_sign_dss_key_load,
  .f_generate = assh_sign_dss_generate,
  .f_verify = assh_sign_dss_verify,
};

static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_dss_suitable_key_3072_256)
{
  if (strcmp(key->type, "ssh-dss"))
    return 0;
  struct assh_sign_dss_key_s *k = (void*)key;
  return assh_bignum_bits(&k->qn) == 256 &&
         assh_bignum_bits(&k->pn) >= 3072;
}

struct assh_algo_sign_s assh_sign_dsa3072_sha256 =
{
  .algo = {
    .name = "dsa3072-sha256@libassh.org", .class_ = ASSH_ALGO_SIGN,
    .safety = 50, .speed = 30,
    .f_suitable_key = assh_sign_dss_suitable_key_3072_256,
  },
  .key_type = "ssh-dss",
  .f_key_load = assh_sign_dss_key_load,
  .f_generate = assh_sign_dss_generate,
  .f_verify = assh_sign_dss_verify,
};

