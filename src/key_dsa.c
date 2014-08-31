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

#include <assh/key_dsa.h>
#include <assh/assh_bignum.h>
#include <assh/assh_packet.h>
#include <assh/assh_alloc.h>
#include <assh/assh_prng.h>

#include <string.h>

static ASSH_KEY_OUTPUT_FCN(assh_key_dsa_output)
{
  struct assh_key_dsa_s *k = (void*)key;
  assh_error_t err;

  assert(key->algo == &assh_key_dsa);

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

static ASSH_KEY_CMP_FCN(assh_key_dsa_cmp)
{
  assert(key->algo == &assh_key_dsa);

  if (key->algo != b->algo)
    return 0;

  struct assh_key_dsa_s *k = (void*)key;
  struct assh_key_dsa_s *l = (void*)b;

  enum bytecode_args_e
  {
    P0, P1, Q0, Q1, G0, G1, Y0, Y1, X0, X1
  };

  static const assh_bignum_op_t *bc, bytecode[] = {
    ASSH_BOP_CMPEQ(     X1,     X0,	0       ),
    ASSH_BOP_CMPEQ(     P1,     P0,	0       ),
    ASSH_BOP_CMPEQ(     Q1,     Q0,	0       ),
    ASSH_BOP_CMPEQ(     G1,     G0,	0       ),
    ASSH_BOP_CMPEQ(     Y1,     Y0,	0       ),
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

static ASSH_KEY_CREATE_FCN(assh_key_dsa_create)
{
  assh_error_t err;

  ASSH_CHK_RET(bits < 1024, ASSH_ERR_NOTSUP);

  size_t l = bits;
  size_t n = l > 1024 ? 256 : 160;

  struct assh_key_dsa_s *k;

  ASSH_ERR_RET(assh_alloc(c, sizeof(struct assh_key_dsa_s),
                          ASSH_ALLOC_KEY, (void**)&k));

  k->key.algo = &assh_key_dsa;

  /* init numbers */
  assh_bignum_init(c, &k->pn, l);
  assh_bignum_init(c, &k->qn, n);
  assh_bignum_init(c, &k->gn, l);
  assh_bignum_init(c, &k->yn, l);
  assh_bignum_init(c, &k->xn, n);

  enum bytecode_args_e
  {
    P, Q, G, Y, X,
    T0, T1, H, S
  };

  static const assh_bignum_op_t bytecode[] = {

    ASSH_BOP_SIZE(      T0,     S                               ),
    ASSH_BOP_SIZE(      T1,     P                               ),

    /* generate DSA parameters */
    ASSH_BOP_PRIME(     Q,      ASSH_BOP_NOREG, ASSH_BOP_NOREG  ),

    ASSH_BOP_UINT(      T1,     1                               ),

    ASSH_BOP_RAND(      T0,     ASSH_BOP_NOREG, ASSH_BOP_NOREG,
                        ASSH_PRNG_QUALITY_EPHEMERAL_KEY ),
    ASSH_BOP_MUL(       P,      T0,     Q                       ),
    ASSH_BOP_ADD(       P,      P,      T1                      ),

    ASSH_BOP_ADD(       T0,     T0,     T1 /* T0 = (p-1)/q */   ),
    ASSH_BOP_ADD(       P,      P,      Q                       ),
    ASSH_BOP_ISNTPRIM(  P,      -3                              ),

#warning FIXME range
    ASSH_BOP_RAND(      H,      ASSH_BOP_NOREG, ASSH_BOP_NOREG,
                        ASSH_PRNG_QUALITY_WEAK          ),
    ASSH_BOP_EXPM(      G,      H,      T0,     P               ),
    ASSH_BOP_CMPEQ(     G,      T1,     -3                      ),

    /* generate key pair */
#warning FIXME range
    ASSH_BOP_RAND(      X,      ASSH_BOP_NOREG, Q,
                        ASSH_PRNG_QUALITY_LONGTERM_KEY  ),
    ASSH_BOP_EXPM(      Y,      G,      X,      P               ),

    ASSH_BOP_END(),
  };

  ASSH_ERR_GTO(assh_bignum_bytecode(c, bytecode, "NNNNNTTTs",
                 &k->pn, &k->qn, &k->gn, &k->yn, &k->xn, l - n), err_key);

  *key = &k->key;
  return ASSH_OK;
 err_key:
  assh_free(c, k, ASSH_ALLOC_KEY);
  return err;
}

static ASSH_KEY_VALIDATE_FCN(assh_key_dsa_validate)
{
  struct assh_key_dsa_s *k = (void*)key;
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
    ASSH_BOP_CMPLT(     T1,     G,      0 /* g > 1 */   ),
    ASSH_BOP_CMPLT(     G,      P,      0 /* g < p */   ),

    /* check generator order in the group */
    ASSH_BOP_EXPM(      T2,     G,      Q,      P       ),
    ASSH_BOP_CMPEQ(     T1,     T2,     0               ),

    /* check public key range */
    ASSH_BOP_CMPLT(     T1,     Y,      0  /* y > 1 */  ),
    ASSH_BOP_SUB(       T2,     P,      T1              ),
    ASSH_BOP_CMPLT(     Y,      T2,     0 /* y < p-1 */ ),

    /* check public key order in the group */
    ASSH_BOP_EXPM(      T2,     Y,      Q,      P       ),
    ASSH_BOP_CMPEQ(     T1,     T2,     0               ),

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
        ASSH_BOP_EXPM_C(T1,     G,      X,      P       ),
        ASSH_BOP_CMPEQ( T1,     Y,      0               ),

        ASSH_BOP_END(),
      };

      ASSH_ERR_RET(assh_bignum_bytecode(c, bytecode2, "NNNNT",
                                        &k->pn, &k->gn, &k->yn, &k->xn));
    }

  return ASSH_OK;
}

static ASSH_KEY_LOAD_FCN(assh_key_dsa_load)
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

  struct assh_key_dsa_s *k = (void*)*key;

  ASSH_ERR_RET(assh_alloc(c, sizeof(struct assh_key_dsa_s),
                          ASSH_ALLOC_KEY, (void**)&k));

  k->key.algo = &assh_key_dsa;

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

  *key = &k->key;
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

static ASSH_KEY_CLEANUP_FCN(assh_key_dsa_cleanup)
{
  struct assh_key_dsa_s *k = (void*)key;

  assh_bignum_release(c, &k->xn);
  assh_bignum_release(c, &k->yn);
  assh_bignum_release(c, &k->gn);
  assh_bignum_release(c, &k->qn);
  assh_bignum_release(c, &k->pn);
  assh_free(c, k, ASSH_ALLOC_KEY);
}

const struct assh_algo_key_s assh_key_dsa =
{
  .type = "ssh-dss",
  .f_output = assh_key_dsa_output,
  .f_create = assh_key_dsa_create,
  .f_validate = assh_key_dsa_validate,
  .f_cmp = assh_key_dsa_cmp,
  .f_load = assh_key_dsa_load,
  .f_cleanup = assh_key_dsa_cleanup,
};

