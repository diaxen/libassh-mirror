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
#include <assh/assh_buffer.h>
#include <assh/assh_alloc.h>
#include <assh/assh_prng.h>

#include <string.h>

#define ASSH_DSA_SAFETY(l, n)                           \
  ASSH_MIN(ASSH_SAFETY_PRIMEFIELD(l),                   \
           99 * (n) / 512)

static ASSH_KEY_OUTPUT_FCN(assh_key_dsa_output)
{
  struct assh_key_dsa_s *k = (void*)key;
  assh_error_t err;

  assert(key->algo == &assh_key_dsa);

  struct assh_bignum_s *bn_[6] = { &k->pn, &k->qn, &k->gn, &k->yn, NULL, NULL };

  switch (format)
    {
    case ASSH_KEY_FMT_PV_OPENSSH_V1_KEY:
      ASSH_RET_IF_TRUE(assh_bignum_isempty(&k->xn), ASSH_ERR_MISSING_KEY);
      bn_[4] = &k->xn;
    case ASSH_KEY_FMT_PUB_RFC4253: {
      /* add algo identifier */
      size_t l = ASSH_DSA_ID_LEN;
      if (blob != NULL)
        {
          memcpy(blob, ASSH_DSA_ID, ASSH_DSA_ID_LEN);
          blob += ASSH_DSA_ID_LEN;
        }

      /* add key integers */
      struct assh_bignum_s **bn = bn_;
      if (blob == NULL)
        {
          for (bn = bn_; *bn != NULL; bn++)
            l += assh_bignum_size_of_num(ASSH_BIGNUM_MPINT, *bn);
        }
      else
        {
          uint8_t *b = blob;
          for (bn = bn_; *bn != NULL; bn++)
              ASSH_RET_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_NATIVE,
                             ASSH_BIGNUM_MPINT, *bn, b, &b, 0));
          l += b - blob;
        }
      *blob_len = l;
      return ASSH_OK;
    }

    case ASSH_KEY_FMT_PV_PEM_ASN1: {
      ASSH_RET_IF_TRUE(assh_bignum_isempty(&k->xn), ASSH_ERR_MISSING_KEY);
      bn_[4] = &k->xn;
      uint8_t *b = blob + 4;
      uint8_t *s = b;
      size_t l = /* seq */ 4 + /* version */ 3;

      /* version */
      if (blob != NULL)
        {
          *b++ = 0x02;
          *b++ = 0x01;
          *b++ = 0x00;
        }

      struct assh_bignum_s **bn = bn_;
      if (blob == NULL)
        {
          for (bn = bn_; *bn != NULL; bn++)
            l += assh_bignum_size_of_num(ASSH_BIGNUM_ASN1, *bn);
        }
      else
        {
          /* add key integers */
          for (bn = bn_; *bn != NULL; bn++)
              ASSH_RET_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_NATIVE,
                             ASSH_BIGNUM_ASN1, *bn, b, &b, 0));
          l = b - s;
          /* sequence header */
          b = blob;
          assh_append_asn1(&b, 0x30, l);
          if (b < s)
            memmove(b, s, l);
          l += b - blob;
        }
      *blob_len = l;

      return ASSH_OK;
    }

    default:
      ASSH_RETURN(ASSH_ERR_NOTSUP);
    }
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

  static const assh_bignum_op_t bytecode[] = {
    ASSH_BOP_CJMP(      2,      0,       0       ),
    ASSH_BOP_CMPEQ(     X1,     X0,      0       ),
    ASSH_BOP_CFAIL(     1,      0                ),

    ASSH_BOP_CMPEQ(     P1,     P0,      0       ),
    ASSH_BOP_CFAIL(     1,      0                ),
    ASSH_BOP_CMPEQ(     Q1,     Q0,      0       ),
    ASSH_BOP_CFAIL(     1,      0                ),
    ASSH_BOP_CMPEQ(     G1,     G0,      0       ),
    ASSH_BOP_CFAIL(     1,      0                ),
    ASSH_BOP_CMPEQ(     Y1,     Y0,      0       ),
    ASSH_BOP_CFAIL(     1,      0                ),
    ASSH_BOP_END(),
  };

  if (!pub)
    {
      if (assh_bignum_isempty(&k->xn) !=
          assh_bignum_isempty(&l->xn))
        return 0;
      if (assh_bignum_isempty(&l->xn))
        pub = 1;
    }

  return assh_bignum_bytecode(c, pub, bytecode, "NNNNNNNNNN",
                              &k->pn, &l->pn, &k->qn, &l->qn, &k->gn, &l->gn,
                              &k->yn, &l->yn, &k->xn, &l->xn) == 0;
}

static ASSH_KEY_CLEANUP_FCN(assh_key_dsa_cleanup)
{
  struct assh_key_dsa_s *k = (void*)key;

  assh_bignum_release(c, &k->xn);
  assh_bignum_release(c, &k->yn);
  assh_bignum_release(c, &k->gn);
  assh_bignum_release(c, &k->qn);
  assh_bignum_release(c, &k->pn);
  assh_free(c, k);
}

static ASSH_KEY_CREATE_FCN(assh_key_dsa_create)
{
  assh_error_t err;

  ASSH_RET_IF_TRUE(bits < 1024 || bits > 4096, ASSH_ERR_NOTSUP);

  size_t l = ASSH_ALIGN8(bits);
  size_t n;

  if (l == 1024)
    n = 160;
  else if (l < 2048)
    n = 224;
  else
    n = 256;

  struct assh_key_dsa_s *k;

  ASSH_RET_ON_ERR(assh_alloc(c, sizeof(struct assh_key_dsa_s),
                          ASSH_ALLOC_INTERNAL, (void**)&k));

  k->key.algo = &assh_key_dsa;
  k->key.type = "ssh-dss";
  k->key.safety = ASSH_DSA_SAFETY(l, n);
  k->key.private = 1;

  /* init numbers */
  assh_bignum_init(c, &k->pn, l);
  assh_bignum_init(c, &k->qn, n);
  assh_bignum_init(c, &k->gn, l);
  assh_bignum_init(c, &k->yn, l);
  assh_bignum_init(c, &k->xn, n);

  enum bytecode_args_e
  {
    P, Q, G, Y, X,
    T0, T1, T2, T3, MT,
  };

  static const assh_bignum_op_t bytecode[] = {
    ASSH_BOP_SIZE(      T0,     Q                       ),
    ASSH_BOP_SIZER(     T1,     MT,     P               ),

    /* generate Q */
    ASSH_BOP_UINT(      T0,     1                       ),
    ASSH_BOP_SHL(       T0,     T0,     -1,     Q       ),
    ASSH_BOP_PRIME(     Q,      T0,     ASSH_BOP_NOREG,
                        ASSH_PRNG_QUALITY_PUBLIC        ),

    /* generate P */
    ASSH_BOP_UINT(      T1,     1                       ),
    ASSH_BOP_SHL(       T1,     T1,     -1,     P       ),
    ASSH_BOP_RAND(      P,      T1,     ASSH_BOP_NOREG,
                        ASSH_PRNG_QUALITY_PUBLIC        ),

    ASSH_BOP_MOD(       T1,     P,      Q               ),
    ASSH_BOP_SUB(       P,      P,      T1              ),

    ASSH_BOP_UINT(      T0,     1                       ),
    ASSH_BOP_ADD(       P,      P,      T0              ),
    ASSH_BOP_NEXTPRIME( P,      Q                       ),

    /* find suitable G */
    ASSH_BOP_SUB(       T1,     P,      T0              ),
    ASSH_BOP_DIV(       T2,     T1,     Q               ),

    ASSH_BOP_MTINIT(    MT,     P                       ),
    ASSH_BOP_RAND(      G,      ASSH_BOP_NOREG,     T1,
                        ASSH_PRNG_QUALITY_PUBLIC        ),
    ASSH_BOP_MTTO(      G,      G,      G,      MT      ),
    ASSH_BOP_EXPM(      G,      G,      T2,     MT      ),
    ASSH_BOP_MTFROM(    T3,     T3,     G,      MT      ),
    ASSH_BOP_CMPEQ(     T0,     T3,     0               ),
    ASSH_BOP_CJMP(      -6,     0,      0               ),

#ifdef CONFIG_ASSH_DEBUG_SIGN
    ASSH_BOP_PRINT(     P,      'P'                     ),
    ASSH_BOP_PRINT(     Q,      'Q'                     ),
    ASSH_BOP_PRINT(     G,      'G'                     ),
#endif

    /* generate key pair X, Y */
    ASSH_BOP_RAND(      X,      T0,     Q,
                        ASSH_PRNG_QUALITY_LONGTERM_KEY  ),
    ASSH_BOP_EXPM(    Y,      G,      X,      MT        ),
    ASSH_BOP_PRIVACY( Y,      0,      0			),
    ASSH_BOP_MTFROM(  Y,      Y,      Y,      MT        ),

    ASSH_BOP_MOVE(    G,      T3                        ),

#ifdef CONFIG_ASSH_DEBUG_SIGN
    ASSH_BOP_PRINT(     Y,      'Y'                     ),
    ASSH_BOP_PRINT(     X,      'X'                     ),
#endif

    ASSH_BOP_END(),
  };

  ASSH_JMP_ON_ERR(assh_bignum_bytecode(c, 0, bytecode, "NNNNNTTTTm",
                 &k->pn, &k->qn, &k->gn, &k->yn, &k->xn), err_key);

  assert(!k->pn.secret && !k->qn.secret &&
         !k->gn.secret && !k->yn.secret && k->xn.secret);

  *key = &k->key;
  return ASSH_OK;

 err_key:
  assh_key_dsa_cleanup(c, &k->key);
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

  uint_fast16_t l = assh_bignum_bits(&k->pn);
  uint_fast16_t n = assh_bignum_bits(&k->qn);

  /* check key size */
  ASSH_RET_IF_TRUE(l < 768 || n < 160 || l > 4096 || n > 256 || l % 8 || n % 8,
               ASSH_ERR_BAD_DATA);

  enum bytecode_args_e
  {
    P, Q, G, X, Y, T1, T2, MT
  };

  static const assh_bignum_op_t bytecode1[] = {
    ASSH_BOP_SIZER(     T1,     MT,     P               ),

    /* check q prime with probability 1e-6 */
    ASSH_BOP_TEST(      Q,      1,      Q,      0       ),
    ASSH_BOP_CFAIL(     1,      0                       ),
    ASSH_BOP_ISPRIME(   Q,      10,     0               ),
    ASSH_BOP_CFAIL(     1,      0                       ),

    /* check p prime with probability 1e-6 */
    ASSH_BOP_TEST(      P,      1,      P,      0       ),
    ASSH_BOP_CFAIL(     1,      0                       ),
    ASSH_BOP_ISPRIME(   P,      10,     0               ),
    ASSH_BOP_CFAIL(     1,      0                       ),

    /* check (p-1)%q < 1 */
    ASSH_BOP_UINT(      T1,     1                       ),
    ASSH_BOP_SUB(       T2,     P,      T1              ),
    ASSH_BOP_MOD(       T2,     T2,     Q               ),
    ASSH_BOP_CMPLT(     T2,     T1,      0              ),
    ASSH_BOP_CFAIL(     1,      0                       ),

    /* check generator range */
    ASSH_BOP_CMPLT(     T1,     G,      0 /* g > 1 */   ),
    ASSH_BOP_CFAIL(     1,      0                       ),
    ASSH_BOP_CMPLT(     G,      P,      0 /* g < p */   ),
    ASSH_BOP_CFAIL(     1,      0                       ),

    ASSH_BOP_MTINIT(    MT,     P                       ),

    /* check generator order in the group */
    ASSH_BOP_MTTO(      T2,     T2,     G,      MT      ),
    ASSH_BOP_EXPM(      T2,     T2,     Q,      MT      ),
    ASSH_BOP_MTFROM(    T2,     T2,     T2,     MT      ),
    ASSH_BOP_CMPEQ(     T1,     T2,      0              ),
    ASSH_BOP_CFAIL(     1,      0                       ),

    /* check public key range */
    ASSH_BOP_CMPLT(     T1,     Y,      0  /* y > 1 */  ),
    ASSH_BOP_CFAIL(     1,      0                       ),
    ASSH_BOP_SUB(       T2,     P,      T1              ),
    ASSH_BOP_CMPLT(     Y,      T2,      0/* y < p-1 */ ),
    ASSH_BOP_CFAIL(     1,      0                       ),

    /* check public key order in the group */
    ASSH_BOP_MTTO(      T2,     T2,     Y,      MT      ),
    ASSH_BOP_EXPM(      T2,     T2,     Q,      MT      ),
    ASSH_BOP_MTFROM(    T2,     T2,     T2,     MT      ),
    ASSH_BOP_CMPEQ(     T1,     T2,      0              ),
    ASSH_BOP_CFAIL(     1,      0                       ),

    /* check private key */
    ASSH_BOP_CMPEQ(     X,      ASSH_BOP_NOREG,      0  ),
    ASSH_BOP_CJMP(      4,      0,      0               ),
    ASSH_BOP_MTTO(      T2,     T2,     G,      MT      ),
    ASSH_BOP_EXPM(      T2,     T2,     X,      MT      ),
    ASSH_BOP_MTFROM(    T2,     T2,     T2,     MT      ),
    ASSH_BOP_CMPEQ(     T2,     Y,      0               ),
    ASSH_BOP_CFAIL(     1,      0                       ),

    ASSH_BOP_END(),
  };

  ASSH_RETURN(assh_bignum_bytecode(c, 0, bytecode1, "NNNNNTTm",
                             &k->pn, &k->qn, &k->gn, &k->xn, &k->yn));
}

static ASSH_KEY_LOAD_FCN(assh_key_dsa_load)
{
  const uint8_t *blob = *blob_;
  assh_error_t err;

  size_t l, n;
  const uint8_t *p_str, *q_str, *g_str, *y_str, *x_str;

  /* parse the key blob */
  switch (format)
    {
    case ASSH_KEY_FMT_PV_OPENSSH_V1_KEY:
    case ASSH_KEY_FMT_PUB_RFC4253: {

      ASSH_RET_IF_TRUE(blob_len < ASSH_DSA_ID_LEN, ASSH_ERR_INPUT_OVERFLOW);
      ASSH_RET_IF_TRUE(memcmp(ASSH_DSA_ID, blob, ASSH_DSA_ID_LEN), ASSH_ERR_BAD_DATA);

      p_str = blob + ASSH_DSA_ID_LEN;
      ASSH_RET_ON_ERR(assh_check_string(blob, blob_len, p_str, &q_str));
      ASSH_RET_ON_ERR(assh_bignum_size_of_data(ASSH_BIGNUM_MPINT, p_str, NULL, NULL, &l));
      ASSH_RET_ON_ERR(assh_check_string(blob, blob_len, q_str, &g_str));
      ASSH_RET_ON_ERR(assh_bignum_size_of_data(ASSH_BIGNUM_MPINT, q_str, NULL, NULL, &n));
      ASSH_RET_ON_ERR(assh_check_string(blob, blob_len, g_str, &y_str));
      ASSH_RET_ON_ERR(assh_check_string(blob, blob_len, y_str, &x_str));

      if (format != ASSH_KEY_FMT_PV_OPENSSH_V1_KEY)
        {
          *blob_ = x_str;
          x_str = NULL;
          break;
        }

      ASSH_RET_ON_ERR(assh_check_string(blob, blob_len, x_str, blob_));
      break;
    }

    case ASSH_KEY_FMT_PV_PEM_ASN1: {
      const uint8_t *seq, *seq_end;
      ASSH_RET_ON_ERR(assh_check_asn1(blob, blob_len, blob, &seq, &seq_end,
                                   /* seq */ 0x30));

      /* skip first value */
      ASSH_RET_ON_ERR(assh_check_asn1(blob, blob_len, seq, NULL, &p_str, 0x02));

      /* parse p, q, g, y, x */
      ASSH_RET_ON_ERR(assh_check_asn1(blob, blob_len, p_str, NULL, &q_str, 0x02));
      ASSH_RET_ON_ERR(assh_bignum_size_of_data(ASSH_BIGNUM_ASN1, p_str, NULL, NULL, &l));
      ASSH_RET_ON_ERR(assh_check_asn1(blob, blob_len, q_str, NULL, &g_str, 0x02));
      ASSH_RET_ON_ERR(assh_bignum_size_of_data(ASSH_BIGNUM_ASN1, q_str, NULL, NULL, &n));
      ASSH_RET_ON_ERR(assh_check_asn1(blob, blob_len, g_str, NULL, &y_str, 0x02));
      ASSH_RET_ON_ERR(assh_check_asn1(blob, blob_len, y_str, NULL, &x_str, 0x02));
      ASSH_RET_ON_ERR(assh_check_asn1(blob, blob_len, x_str, NULL, blob_, 0x02));
      break;
    }

    default:
      ASSH_RETURN(ASSH_ERR_NOTSUP);
    }

  /* allocate key structure */
  ASSH_RET_IF_TRUE(l < 768 || n < 160 || l % 8 || n % 8, ASSH_ERR_BAD_DATA);
  ASSH_RET_IF_TRUE(l > 4096 || n > 256, ASSH_ERR_NOTSUP);

  struct assh_key_dsa_s *k = (void*)*key;

  ASSH_RET_ON_ERR(assh_alloc(c, sizeof(struct assh_key_dsa_s),
                          ASSH_ALLOC_INTERNAL, (void**)&k));

  k->key.algo = &assh_key_dsa;
  k->key.type = "ssh-dss";
  k->key.safety = ASSH_DSA_SAFETY(l, n);
  k->key.private = 0;

  /* init numbers */
  assh_bignum_init(c, &k->pn, l);
  assh_bignum_init(c, &k->qn, n);
  assh_bignum_init(c, &k->gn, l);
  assh_bignum_init(c, &k->yn, l);
  assh_bignum_init(c, &k->xn, n);

  /* convert numbers from blob representation */
  switch (format)
    {
    case ASSH_KEY_FMT_PV_OPENSSH_V1_KEY:
      k->key.private = 1;
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE,
                                       x_str, &k->xn, NULL, 0), err_xn);
    case ASSH_KEY_FMT_PUB_RFC4253:
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE,
                                       p_str, &k->pn, NULL, 0), err_xn);
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE,
                                       q_str, &k->qn, NULL, 0), err_xn);
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE,
                                       g_str, &k->gn, NULL, 0), err_xn);
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE,
                                       y_str, &k->yn, NULL, 0), err_xn);
      break;

    case ASSH_KEY_FMT_PV_PEM_ASN1:
      k->key.private = 1;
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE,
                                       p_str, &k->pn, NULL, 0), err_xn);
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE,
                                       q_str, &k->qn, NULL, 0), err_xn);
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE,
                                       g_str, &k->gn, NULL, 0), err_xn);
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE,
                                       y_str, &k->yn, NULL, 0), err_xn);
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE,
                                       x_str, &k->xn, NULL, 1), err_xn);
    default:
      break;
    }

  *key = &k->key;
  return ASSH_OK;

 err_xn:
  assh_key_dsa_cleanup(c, &k->key);
  return err;
}

const struct assh_key_ops_s assh_key_dsa =
{
  .type = "ssh-dss",
  .f_output = assh_key_dsa_output,
  .f_create = assh_key_dsa_create,
  .f_validate = assh_key_dsa_validate,
  .f_cmp = assh_key_dsa_cmp,
  .f_load = assh_key_dsa_load,
  .f_cleanup = assh_key_dsa_cleanup,
};

