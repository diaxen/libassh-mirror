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

#include <assh/key_rsa.h>
#include <assh/assh_packet.h>
#include <assh/assh_alloc.h>
#include <assh/assh_prng.h>

#include <string.h>

static ASSH_KEY_OUTPUT_FCN(assh_key_rsa_output)
{
  struct assh_key_rsa_s *k = (void*)key;
  assh_error_t err;

  assert(key->algo == &assh_key_rsa);

  struct assh_bignum_s *bn_[9];
  bn_[2] = NULL;

  switch (format)
    {
    case ASSH_KEY_FMT_PV_OPENSSH_V1_KEY:
      ASSH_CHK_RET(assh_bignum_isempty(&k->dn), ASSH_ERR_MISSING_KEY);
      bn_[0] = &k->nn;
      bn_[1] = &k->en;
      bn_[2] = &k->dn;
      bn_[3] = &k->in;
      bn_[4] = &k->pn;
      bn_[5] = &k->qn;
      bn_[6] = NULL;
      goto mpint_key;

    case ASSH_KEY_FMT_PUB_RFC4253:
      bn_[0] = &k->en;
      bn_[1] = &k->nn;
    mpint_key: {
      /* add algo identifier */
      size_t l = ASSH_RSA_ID_LEN;
      if (blob != NULL)
        {
          memcpy(blob, ASSH_RSA_ID, ASSH_RSA_ID_LEN);
          blob += ASSH_RSA_ID_LEN;
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
              ASSH_ERR_RET(assh_bignum_convert(c, ASSH_BIGNUM_NATIVE,
                             ASSH_BIGNUM_MPINT, *bn, b, &b, 0));
          l += b - blob;
        }
      *blob_len = l;
      return ASSH_OK;
    }

    case ASSH_KEY_FMT_PV_PEM_ASN1: {
      ASSH_CHK_RET(assh_bignum_isempty(&k->dn), ASSH_ERR_MISSING_KEY);

      enum bytecode_args_e { D, P, Q, DP, DQ, T0, T1 };

      static const assh_bignum_op_t bytecode[] = {
        ASSH_BOP_SIZER(  T0,    T1,     P               ),
        ASSH_BOP_PRIVACY(DP,    0,      1               ),
        ASSH_BOP_PRIVACY(DQ,    0,      1               ),
        ASSH_BOP_PRIVACY(D,     0,      1               ),
        ASSH_BOP_UINT(   T0,    1                       ),
        ASSH_BOP_SUB(    T1,    P,      T0              ),
        ASSH_BOP_PRIVACY(T1,    0,      1               ),
        ASSH_BOP_MOD(    DP,    D,      T1              ),
        ASSH_BOP_SUB(    T1,    Q,      T0              ),
        ASSH_BOP_PRIVACY(T1,    0,      1               ),
        ASSH_BOP_MOD(    DQ,    D,      T1              ),
        ASSH_BOP_PRIVACY(D,     1,      0               ),
        ASSH_BOP_PRIVACY(DP,    1,      0               ),
        ASSH_BOP_PRIVACY(DQ,    1,      0               ),
        ASSH_BOP_END(),
      };

      /* Compute dq and dp values if missing. This involves non
         constant time operations on secret values. We do not want
         to perform this computation every time a key is loaded. */
      if (assh_bignum_isempty(&k->dpn))
        ASSH_ERR_RET(assh_bignum_bytecode(c, 0, bytecode, "NNNNNTT",
                       &k->dn, &k->pn, &k->qn, &k->dpn, &k->dqn));

      bn_[2] = &k->dn;
      bn_[3] = &k->pn;
      bn_[4] = &k->qn;
      bn_[5] = &k->dpn;
      bn_[6] = &k->dqn;
      bn_[7] = &k->in;
      bn_[8] = NULL;
    }

    case ASSH_KEY_FMT_PUB_PEM_ASN1: {
      bn_[0] = &k->nn;
      bn_[1] = &k->en;
      uint8_t *b = blob + 4;
      uint8_t *s = b;
      size_t l = /* seq */ 4;

      if (format == ASSH_KEY_FMT_PV_PEM_ASN1)
        {
          /* version */
          if (blob != NULL)
            {
              *b++ = 0x02;
              *b++ = 0x01;
              *b++ = 0x00;
            }
          l += 3;
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
              ASSH_ERR_RET(assh_bignum_convert(c, ASSH_BIGNUM_NATIVE,
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
      ASSH_ERR_RET(ASSH_ERR_NOTSUP);
    }
}

static ASSH_KEY_CMP_FCN(assh_key_rsa_cmp)
{
  assert(key->algo == &assh_key_rsa);

  if (key->algo != b->algo)
    return 0;

  struct assh_key_rsa_s *k = (void*)key;
  struct assh_key_rsa_s *l = (void*)b;

  enum bytecode_args_e
  {
    N0, N1, E0, E1, D0, D1
  };

  static const assh_bignum_op_t bytecode[] = {
    ASSH_BOP_CJMP(      2,      0,       0              ),
    ASSH_BOP_CMPEQ(     D1,     D0,      0              ),
    ASSH_BOP_CFAIL(     1,      0                       ),

    ASSH_BOP_CMPEQ(     E1,     E0,      0              ),
    ASSH_BOP_CFAIL(     1,      0                       ),
    ASSH_BOP_CMPEQ(     N1,     N0,      0              ),
    ASSH_BOP_CFAIL(     1,      0                       ),
    ASSH_BOP_END(),
  };

  if (!pub)
    {
      if (assh_bignum_isempty(&k->dn) !=
          assh_bignum_isempty(&l->dn))
        return 0;
      if (assh_bignum_isempty(&l->dn))
        pub = 1;
    }

  return assh_bignum_bytecode(c, pub, bytecode, "NNNNNN",
    &k->nn, &l->nn, &k->en, &l->en, &k->dn, &l->dn) == 0;
}

static ASSH_KEY_CREATE_FCN(assh_key_rsa_create)
{
  assh_error_t err;

  ASSH_CHK_RET(bits < 1024, ASSH_ERR_NOTSUP);
  bits += bits & 1;

  struct assh_key_rsa_s *k;

  ASSH_ERR_RET(assh_alloc(c, sizeof(struct assh_key_rsa_s),
                          ASSH_ALLOC_INTERNAL, (void**)&k));

  k->key.algo = &assh_key_rsa;
  k->key.type = "ssh-rsa";
  k->key.safety = ASSH_SAFETY_PRIMEFIELD(bits);

  /* init numbers */
  assh_bignum_init(c, &k->nn, bits);
  assh_bignum_init(c, &k->dn, bits);
  assh_bignum_init(c, &k->en, 17);
  assh_bignum_init(c, &k->pn, bits / 2);
  assh_bignum_init(c, &k->qn, bits / 2);
  assh_bignum_init(c, &k->in, bits / 2);
  assh_bignum_init(c, &k->dpn, bits / 2);
  assh_bignum_init(c, &k->dqn, bits / 2);

  enum bytecode_args_e
  {
    N, D, E, P, Q, I, DP, DQ,
    T0, T1, MT
  };

  static const assh_bignum_op_t bytecode[] = {

    ASSH_BOP_SIZEM(     P,      N,      0,      -1      ),
    ASSH_BOP_SIZER(     Q,      T0,     P               ),
    ASSH_BOP_SIZE(      T1,     N                       ),

    /* generate 2 prime numbers with the 2 most significant bits set */
    ASSH_BOP_UINT(      T0,     3                       ),
    ASSH_BOP_SHL(       T0,     T0,     -2,     P       ),
    ASSH_BOP_PRIME(     P,      T0,     ASSH_BOP_NOREG,
                        ASSH_PRNG_QUALITY_LONGTERM_KEY  ),
    ASSH_BOP_PRIME(     Q,      T0,     ASSH_BOP_NOREG,
                        ASSH_PRNG_QUALITY_LONGTERM_KEY  ),
    /* sanity check */
    ASSH_BOP_CMPEQ(     P,      Q,      0               ),
    ASSH_BOP_CFAIL(     0,      0                       ),

    ASSH_BOP_MUL(       N,      P,      Q               ),
    ASSH_BOP_PRIVACY(   N,      0,      0               ),

    // FIXME could use T1 = N - (P + Q -1)
    ASSH_BOP_UINT(      T0,     1                       ),
    ASSH_BOP_SUB(       DP,     P,      T0              ),
    ASSH_BOP_SUB(       DQ,     Q,      T0              ),
    ASSH_BOP_MUL(       T1,     DP,     DQ              ),

    ASSH_BOP_PRIVACY(   T1,     0,      1               ),
    ASSH_BOP_PRIVACY(   D,      0,      1               ),
    ASSH_BOP_UINT(      E,      65537                   ),
    ASSH_BOP_INV(       D,      E,      T1              ),

    ASSH_BOP_PRIVACY(   DP,     0,      1               ),
    ASSH_BOP_PRIVACY(   DQ,     0,      1               ),
    ASSH_BOP_MOD(       T1,     D,      DP              ),
    ASSH_BOP_MOVE(      DP,     T1                      ),
    ASSH_BOP_MOD(       T1,     D,      DQ              ),
    ASSH_BOP_MOVE(      DQ,     T1                      ),

    ASSH_BOP_PRIVACY(   P,      0,      1               ),
    ASSH_BOP_PRIVACY(   Q,      0,      1               ),
    ASSH_BOP_PRIVACY(   I,      0,      1               ),
    ASSH_BOP_INV(       I,      Q,      P               ),

    ASSH_BOP_PRIVACY(   P,      1,      0               ),
    ASSH_BOP_PRIVACY(   Q,      1,      0               ),
    ASSH_BOP_PRIVACY(   I,      1,      0               ),
    ASSH_BOP_PRIVACY(   D,      1,      0               ),
    ASSH_BOP_PRIVACY(   DP,     1,      0               ),
    ASSH_BOP_PRIVACY(   DQ,     1,      0               ),
    ASSH_BOP_END(),
  };

  ASSH_ERR_GTO(assh_bignum_bytecode(c, 0, bytecode, "NNNNNNNNTTm",
                 &k->nn, &k->dn, &k->en, &k->pn, &k->qn,
                 &k->in, &k->dpn, &k->dqn), err_key);

  assert(!k->nn.secret && !k->en.secret && k->dn.secret &&
         k->pn.secret && k->qn.secret && k->in.secret &&
         k->dpn.secret && k->dqn.secret);

  *key = &k->key;
  return ASSH_OK;
 err_key:
  assh_free(c, k);
  return err;
}

static ASSH_KEY_VALIDATE_FCN(assh_key_rsa_validate)
{
  struct assh_key_rsa_s *k = (void*)key;
  assh_error_t err = ASSH_OK;

  unsigned int n = assh_bignum_bits(&k->nn);

  /* check key size */
  ASSH_CHK_RET(n < 768 || n > 8192, ASSH_ERR_BAD_DATA);

  enum bytecode_args_e
  {
    N, D, E, T0
  };

  /* FIXME add constant time private key validation  */

  static const assh_bignum_op_t bytecode[] = {
    ASSH_BOP_SIZE(      T0,     N                       ),

    /* check N */
    ASSH_BOP_TEST(      N,      1,      N,      0       ),
    ASSH_BOP_CFAIL(     1,      0                       ),
    ASSH_BOP_TEST(      N,      0, ASSH_BOP_NOREG, 0    ),
    ASSH_BOP_CFAIL(     1,      0                       ),

    /* check E */
    ASSH_BOP_TEST(      E,      0, ASSH_BOP_NOREG, 0    ),
    ASSH_BOP_CFAIL(     1,      0                       ),
    ASSH_BOP_UINT(      T0,     2                       ),
    ASSH_BOP_CMPLTEQ(   E,      T0,     0               ),
    ASSH_BOP_CFAIL(     0,      0                       ),

    ASSH_BOP_END(),
  };

  ASSH_ERR_RET(assh_bignum_bytecode(c, 0, bytecode, "NNNT",
                                    &k->nn, &k->dn, &k->en));

  return ASSH_OK;
}

static ASSH_KEY_LOAD_FCN(assh_key_rsa_load)
{
  const uint8_t *blob = *blob_;
  assh_error_t err;

  size_t n_len, e_len, d_len = 0, p_len = 0, q_len = 0;
  const uint8_t *n_str, *e_str, *d_str,
    *p_str, *q_str, *i_str, *dp_str, *dq_str;

  /* parse the key blob */
  switch (format)
    {
    case ASSH_KEY_FMT_PUB_RFC4253:

      ASSH_CHK_RET(blob_len < ASSH_RSA_ID_LEN, ASSH_ERR_INPUT_OVERFLOW);
      ASSH_CHK_RET(memcmp(ASSH_RSA_ID, blob, ASSH_RSA_ID_LEN), ASSH_ERR_BAD_DATA);

      e_str = blob + ASSH_RSA_ID_LEN;
      ASSH_ERR_RET(assh_check_string(blob, blob_len, e_str, &n_str));
      ASSH_ERR_RET(assh_bignum_size_of_data(ASSH_BIGNUM_MPINT, e_str, NULL, NULL, &e_len));
      ASSH_ERR_RET(assh_check_string(blob, blob_len, n_str, blob_));
      ASSH_ERR_RET(assh_bignum_size_of_data(ASSH_BIGNUM_MPINT, n_str, NULL, NULL, &n_len));
      d_str = NULL;
      break;

    case ASSH_KEY_FMT_PUB_PEM_ASN1: {
      const uint8_t *seq_end, *val;
      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, blob, &n_str, &seq_end, /* seq */ 0x30));
      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, n_str, NULL, &e_str, 0x02));
      ASSH_ERR_RET(assh_bignum_size_of_data(ASSH_BIGNUM_ASN1, n_str, NULL, NULL, &n_len));
      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, e_str, &val, blob_, 0x02));
      ASSH_ERR_RET(assh_bignum_size_of_data(ASSH_BIGNUM_ASN1, e_str, NULL, NULL, &e_len));
      d_str = NULL;
      break;
    }

    case ASSH_KEY_FMT_PV_OPENSSH_V1_KEY:
      ASSH_CHK_RET(blob_len < ASSH_RSA_ID_LEN, ASSH_ERR_INPUT_OVERFLOW);
      ASSH_CHK_RET(memcmp(ASSH_RSA_ID, blob, ASSH_RSA_ID_LEN), ASSH_ERR_BAD_DATA);

      n_str = blob + ASSH_RSA_ID_LEN;
      ASSH_ERR_RET(assh_check_string(blob, blob_len, n_str, &e_str));
      ASSH_ERR_RET(assh_bignum_size_of_data(ASSH_BIGNUM_MPINT, n_str, NULL, NULL, &n_len));
      ASSH_ERR_RET(assh_check_string(blob, blob_len, e_str, &d_str));
      ASSH_ERR_RET(assh_bignum_size_of_data(ASSH_BIGNUM_MPINT, e_str, NULL, NULL, &e_len));
      ASSH_ERR_RET(assh_check_string(blob, blob_len, d_str, &i_str));
      ASSH_ERR_RET(assh_bignum_size_of_data(ASSH_BIGNUM_MPINT, d_str, NULL, NULL, &d_len));
      ASSH_ERR_RET(assh_check_string(blob, blob_len, i_str, &p_str));
      ASSH_ERR_RET(assh_check_string(blob, blob_len, p_str, &q_str));
      ASSH_ERR_RET(assh_bignum_size_of_data(ASSH_BIGNUM_MPINT, p_str, NULL, NULL, &p_len));
      ASSH_ERR_RET(assh_check_string(blob, blob_len, q_str, blob_));
      ASSH_ERR_RET(assh_bignum_size_of_data(ASSH_BIGNUM_MPINT, q_str, NULL, NULL, &q_len));
      break;

    case ASSH_KEY_FMT_PV_PEM_ASN1: {
      const uint8_t *seq, *seq_end, *version, *val;
      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, blob, &seq, &seq_end, /* seq */ 0x30));
      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, seq, &version, &n_str, /* integer */ 0x02));
      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, n_str, NULL, &e_str, 0x02));
      ASSH_ERR_RET(assh_bignum_size_of_data(ASSH_BIGNUM_ASN1, n_str, NULL, NULL, &n_len));
      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, e_str, &val, &d_str, 0x02));
      ASSH_ERR_RET(assh_bignum_size_of_data(ASSH_BIGNUM_ASN1, e_str, NULL, NULL, &e_len));
      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, d_str, NULL, &p_str, 0x02));
      ASSH_ERR_RET(assh_bignum_size_of_data(ASSH_BIGNUM_ASN1, d_str, NULL, NULL, &d_len));
      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, p_str, NULL, &q_str, 0x02));
      ASSH_ERR_RET(assh_bignum_size_of_data(ASSH_BIGNUM_ASN1, p_str, NULL, NULL, &p_len));
      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, q_str, NULL, &dp_str, 0x02));
      ASSH_ERR_RET(assh_bignum_size_of_data(ASSH_BIGNUM_ASN1, q_str, NULL, NULL, &q_len));
      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, dp_str, NULL, &dq_str, 0x02));
      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, dq_str, NULL, &i_str, 0x02));
      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, i_str, NULL, blob_, 0x02));
      break;
    }

    default:
      ASSH_ERR_RET(ASSH_ERR_NOTSUP);
    }

  /* allocate key structure */
  ASSH_CHK_RET(n_len < 768 || n_len > 8192, ASSH_ERR_NOTSUP);
  ASSH_CHK_RET(e_len < 1 || e_len > 32, ASSH_ERR_NOTSUP);
  ASSH_CHK_RET(d_str != NULL && (d_len < 768 || d_len > 8192), ASSH_ERR_NOTSUP);

  struct assh_key_rsa_s *k;

  ASSH_ERR_RET(assh_alloc(c, sizeof(struct assh_key_rsa_s),
                          ASSH_ALLOC_INTERNAL, (void**)&k));

  k->key.algo = &assh_key_rsa;
  k->key.type = "ssh-rsa";
  k->key.safety = ASSH_SAFETY_PRIMEFIELD(n_len);

  /* init numbers */
  assh_bignum_init(c, &k->nn, n_len);
  assh_bignum_init(c, &k->en, e_len);
  assh_bignum_init(c, &k->dn, d_len);
  assh_bignum_init(c, &k->pn, p_len);
  assh_bignum_init(c, &k->qn, q_len);
  assh_bignum_init(c, &k->in, p_len);
  assh_bignum_init(c, &k->dpn, p_len);
  assh_bignum_init(c, &k->dqn, q_len);

  /* convert numbers from blob representation */
  switch (format)
    {
    case ASSH_KEY_FMT_PV_OPENSSH_V1_KEY:
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE,
                                       d_str, &k->dn, NULL, 1), err_num);
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE,
                                       p_str, &k->pn, NULL, 1), err_num);
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE,
                                       q_str, &k->qn, NULL, 1), err_num);
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE,
                                       i_str, &k->in, NULL, 1), err_num);
    case ASSH_KEY_FMT_PUB_RFC4253:
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE,
                                       n_str, &k->nn, NULL, 0), err_num);
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE,
                                       e_str, &k->en, NULL, 0), err_num);
      break;

    case ASSH_KEY_FMT_PV_PEM_ASN1:
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE,
                                       d_str, &k->dn, NULL, 1), err_num);
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE,
                                       p_str, &k->pn, NULL, 1), err_num);
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE,
                                       q_str, &k->qn, NULL, 1), err_num);
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE,
                                       dp_str, &k->dpn, NULL, 1), err_num);
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE,
                                       dq_str, &k->dqn, NULL, 1), err_num);
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE,
                                       i_str, &k->in, NULL, 1), err_num);
    case ASSH_KEY_FMT_PUB_PEM_ASN1:
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE,
                                       n_str, &k->nn, NULL, 0), err_num);
      ASSH_ERR_GTO(assh_bignum_convert(c, ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE,
                                       e_str, &k->en, NULL, 0), err_num);
     default:
      break;
    }

  *key = &k->key;
  return ASSH_OK;

 err_num:
  assh_bignum_release(c, &k->nn);
  assh_bignum_release(c, &k->en);
  assh_bignum_release(c, &k->dn);
  assh_bignum_release(c, &k->pn);
  assh_bignum_release(c, &k->qn);
  assh_bignum_release(c, &k->in);
  assh_bignum_release(c, &k->dpn);
  assh_bignum_release(c, &k->dqn);
  assh_free(c, k);
  return err;
}

static ASSH_KEY_CLEANUP_FCN(assh_key_rsa_cleanup)
{
  struct assh_key_rsa_s *k = (void*)key;

  assh_bignum_release(c, &k->nn);
  assh_bignum_release(c, &k->en);
  assh_bignum_release(c, &k->dn);
  assh_bignum_release(c, &k->pn);
  assh_bignum_release(c, &k->qn);
  assh_bignum_release(c, &k->in);
  assh_bignum_release(c, &k->dpn);
  assh_bignum_release(c, &k->dqn);
  assh_free(c, k);
}

const struct assh_key_ops_s assh_key_rsa =
{
  .type = "ssh-rsa",
  .f_output = assh_key_rsa_output,
  .f_create = assh_key_rsa_create,
  .f_validate = assh_key_rsa_validate,
  .f_cmp = assh_key_rsa_cmp,
  .f_load = assh_key_rsa_load,
  .f_cleanup = assh_key_rsa_cleanup,
};

