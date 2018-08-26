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
#include <assh/assh_buffer.h>
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
      ASSH_RET_IF_TRUE(assh_bignum_isempty(&k->dn), ASSH_ERR_MISSING_KEY);
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
              ASSH_RET_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_NATIVE,
                             ASSH_BIGNUM_MPINT, *bn, b, &b, 0));
          l += b - blob;
        }
      *blob_len = l;
      return ASSH_OK;
    }

    case ASSH_KEY_FMT_PV_PEM_ASN1: {
      ASSH_RET_IF_TRUE(assh_bignum_isempty(&k->dn), ASSH_ERR_MISSING_KEY);

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

  ASSH_UNREACHABLE();
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

#ifdef CONFIG_ASSH_KEY_CREATE
static ASSH_KEY_CREATE_FCN(assh_key_rsa_create)
{
  assh_error_t err;

  ASSH_RET_IF_TRUE(bits < 1024, ASSH_ERR_NOTSUP);
  bits += bits & 1;

  struct assh_key_rsa_s *k;

  ASSH_RET_ON_ERR(assh_alloc(c, sizeof(struct assh_key_rsa_s),
                          ASSH_ALLOC_INTERNAL, (void**)&k));

  k->key.algo = &assh_key_rsa;
  k->key.type = "ssh-rsa";
  k->key.safety = ASSH_SAFETY_PRIMEFIELD(bits);
  k->key.private = 1;

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
    ASSH_BOP_UINT(      I,      3                       ),
    ASSH_BOP_SHL(       I,      I,      -2,     P       ),
    ASSH_BOP_PRIME(     P,      I,      ASSH_BOP_NOREG,
                        ASSH_PRNG_QUALITY_LONGTERM_KEY  ),
    ASSH_BOP_PRIME(     Q,      I,      ASSH_BOP_NOREG,
                        ASSH_PRNG_QUALITY_LONGTERM_KEY  ),
    /* sanity check */
    ASSH_BOP_CMPEQ(     P,      Q,      0               ),
    ASSH_BOP_CFAIL(     0,      0                       ),

    /* N */
    ASSH_BOP_MUL(       N,      P,      Q               ),
    ASSH_BOP_PRIVACY(   N,      0,      0               ),

    ASSH_BOP_UINT(      T0,     1                       ),

    /* phi(N) */
    ASSH_BOP_SUB(       T1,     N,      P               ),
    ASSH_BOP_SUB(       T1,     T1,     Q               ),
    ASSH_BOP_ADD(       T1,     T1,     T0              ),

    /* E, D */
    ASSH_BOP_PRIVACY(   T1,     0,      1               ),
    ASSH_BOP_PRIVACY(   D,      0,      1               ),
    ASSH_BOP_UINT(      E,      65537                   ),
    ASSH_BOP_INV(       D,      E,      T1              ),

    /* choose P & Q again if phi(N) and E are not coprimes */
    ASSH_BOP_CMPEQ(     D,      T0,      0              ),
    ASSH_BOP_CJMP(      -16,    0,       0              ),

    /* DP */
    ASSH_BOP_SUB(       DP,     P,      T0              ),
    ASSH_BOP_MOD(       T1,     D,      DP              ),
    ASSH_BOP_MOVE(      DP,     T1                      ),

    /* DQ */
    ASSH_BOP_SUB(       DQ,     Q,      T0              ),
    ASSH_BOP_MOD(       T1,     D,      DQ              ),
    ASSH_BOP_MOVE(      DQ,     T1                      ),

    /* I */
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

  ASSH_JMP_ON_ERR(assh_bignum_bytecode(c, 0, bytecode, "NNNNNNNNTTm",
                 &k->nn, &k->dn, &k->en, &k->pn, &k->qn,
                 &k->in, &k->dpn, &k->dqn), err_key);

  assert(!k->nn.secret && !k->en.secret && k->dn.secret &&
         k->pn.secret && k->qn.secret && k->in.secret &&
         k->dpn.secret && k->dqn.secret);

  *key = &k->key;
  return ASSH_OK;
 err_key:
  assh_key_rsa_cleanup(c, &k->key);
  return err;
}
#endif

#ifdef CONFIG_ASSH_KEY_VALIDATE
static ASSH_KEY_VALIDATE_FCN(assh_key_rsa_validate)
{
  struct assh_key_rsa_s *k = (void*)key;
  assh_error_t err;

  enum bytecode_args_e
  {
    N, D, E, P, Q, DP, DQ, I,
    T0, T1, T2
  };

  assh_bool_t public = assh_bignum_isempty(&k->pn);

  static const assh_bignum_op_t bytecode[] = {
    ASSH_BOP_SIZE(      T0,     N                       ),
    ASSH_BOP_SIZER(     T1,     T2,     P               ),

    /* check range of N */
    ASSH_BOP_TEST(      N,      1,      N,      0       ),
    ASSH_BOP_CFAIL(     1,      0                       ),
    ASSH_BOP_TEST(      N,      0, ASSH_BOP_NOREG, 0    ),
    ASSH_BOP_CFAIL(     1,      0                       ),

    /* check range of E */
    ASSH_BOP_TEST(      E,      0, ASSH_BOP_NOREG, 0    ),
    ASSH_BOP_CFAIL(     1,      0                       ),
    ASSH_BOP_UINT(      T0,     2                       ),
    ASSH_BOP_CMPLTEQ(   E,      T0,     0               ),
    ASSH_BOP_CFAIL(     0,      0                       ),

    /* private key ? */
    ASSH_BOP_CJMP(      3,      1,      1               ),

    /* check for small factors in N */
    ASSH_BOP_ISTRIVIAL( N,      0                       ),
    ASSH_BOP_CFAIL(     0,      0                       ),

    ASSH_BOP_JMP(       27 /* goto to end */            ),

    /* check P != Q */
    ASSH_BOP_CMPEQ(     Q,      P,     0                ),
    ASSH_BOP_CFAIL(     0,      0                       ),

    /* check P prime */
    ASSH_BOP_ISPRIME(   P,      20,      0              ),
    ASSH_BOP_CFAIL(     1,      0                       ),

    /* check Q prime */
    ASSH_BOP_ISPRIME(   Q,      20,      0              ),
    ASSH_BOP_CFAIL(     1,      0                       ),

    /* check Q*I % P == 1 */
    ASSH_BOP_MULM(      T2,     Q,      I,     P       ),
    ASSH_BOP_UINT(      T1,     1                       ),
    ASSH_BOP_CMPEQ(     T2,     T1,     0               ),
    ASSH_BOP_CFAIL(     1,      0                       ),

    /* check N == P * Q */
    ASSH_BOP_MUL(       T0,     P,      Q               ),
    ASSH_BOP_CMPEQ(     T0,     N,      0               ),
    ASSH_BOP_CFAIL(     1,      0                       ),

    /* check D*E % phi(N) == 1 */
    ASSH_BOP_SUB(       T0,     N,      P               ),
    ASSH_BOP_SUB(       T0,     T0,     Q               ),
    ASSH_BOP_ADD(       T0,     T0,     T1              ),
    ASSH_BOP_MULM(      T0,     D,      E,      T0      ),
    ASSH_BOP_CMPEQ(     T0,     T1,     0               ),
    ASSH_BOP_CFAIL(     1,      0                       ),

    /* check DP == D % P */
    ASSH_BOP_SUB(       T2,     P,      T1              ),
    ASSH_BOP_MOD(       T0,     D,      T2              ),
    ASSH_BOP_CMPEQ(     T0,     DP,     0               ),
    ASSH_BOP_CFAIL(     1,      0                       ),

    /* check DQ == D % Q */
    ASSH_BOP_SUB(       T2,     Q,      T1              ),
    ASSH_BOP_MOD(       T0,     D,      T2              ),
    ASSH_BOP_CMPEQ(     T0,     DQ,     0               ),
    ASSH_BOP_CFAIL(     1,      0                       ),

    ASSH_BOP_END(),
  };

  err = assh_bignum_bytecode(c, public << 1, bytecode, "NNNNNNNNTTT",
                             &k->nn, &k->dn, &k->en, &k->pn,
                             &k->qn, &k->dpn, &k->dqn, &k->in);

  switch (ASSH_ERR_ERROR(err))
    {
    case ASSH_ERR_NUM_COMPARE_FAILED:
    case ASSH_ERR_NUM_OVERFLOW:
      return ASSH_OK;

    case ASSH_OK:
      if (public)
        *result = ASSH_KEY_PARTIALLY_CHECKED;
      else
        *result = ASSH_KEY_GOOD;
      return ASSH_OK;

    default:
      ASSH_RETURN(err);
    }
}
#endif

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
      d_str = NULL;
      ASSH_RET_ON_ERR(assh_scan_blob("s H7 E;7;ssh-rsa sPB sPB", &blob, &blob_len,
                                      &e_str, &e_len, &n_str, &n_len));
      break;

    case ASSH_KEY_FMT_PUB_PEM_ASN1: {
      d_str = NULL;
      ASSH_RET_ON_ERR(assh_scan_blob("a48(a2PB a2PB)", &blob, &blob_len,
                                      &n_str, &n_len, &e_str, &e_len));
      break;
    }

    case ASSH_KEY_FMT_PV_OPENSSH_V1_KEY:
      ASSH_RET_ON_ERR(assh_scan_blob("s H7 E;7;ssh-rsa sPB sPB sPB sP sPB sPB", &blob, &blob_len,
                                      &n_str, &n_len, &e_str, &e_len,
                                      &d_str, &d_len, &i_str,
                                      &p_str, &p_len, &q_str, &q_len));
      break;

    case ASSH_KEY_FMT_PV_PEM_ASN1: {
      ASSH_RET_ON_ERR(assh_scan_blob("a48(a2 a2PB a2PB a2PB a2PB a2PB a2P a2P a2P)", &blob, &blob_len,
                                      &n_str, &n_len, &e_str, &e_len,
                                      &d_str, &d_len, &p_str, &p_len,
                                      &q_str, &q_len, &dp_str, &dq_str, &i_str));
      break;
    }

    default:
      ASSH_RETURN(ASSH_ERR_NOTSUP);
    }

  /* allocate key structure */
  ASSH_RET_IF_TRUE(n_len < 768 || n_len > 8192, ASSH_ERR_NOTSUP);
  ASSH_RET_IF_TRUE(e_len < 1 || e_len > 32, ASSH_ERR_NOTSUP);

  if (d_str != NULL)
    {
      ASSH_RET_IF_TRUE(d_len < 768 || d_len > 8192, ASSH_ERR_NOTSUP);
      ASSH_RET_IF_TRUE(n_len != p_len * 2 || n_len != q_len * 2, ASSH_ERR_NOTSUP);
    }

  struct assh_key_rsa_s *k;

  ASSH_RET_ON_ERR(assh_alloc(c, sizeof(struct assh_key_rsa_s),
                          ASSH_ALLOC_INTERNAL, (void**)&k));

  k->key.algo = &assh_key_rsa;
  k->key.type = "ssh-rsa";
  k->key.safety = ASSH_SAFETY_PRIMEFIELD(n_len);
  k->key.private = 0;

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
      k->key.private = 1;
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE,
                                       d_str, &k->dn, NULL, 1), err_num);
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE,
                                       p_str, &k->pn, NULL, 1), err_num);
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE,
                                       q_str, &k->qn, NULL, 1), err_num);
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE,
                                       i_str, &k->in, NULL, 1), err_num);
    case ASSH_KEY_FMT_PUB_RFC4253:
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE,
                                       n_str, &k->nn, NULL, 0), err_num);
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE,
                                       e_str, &k->en, NULL, 0), err_num);
      break;

    case ASSH_KEY_FMT_PV_PEM_ASN1:
      k->key.private = 1;
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE,
                                       d_str, &k->dn, NULL, 1), err_num);
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE,
                                       p_str, &k->pn, NULL, 1), err_num);
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE,
                                       q_str, &k->qn, NULL, 1), err_num);
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE,
                                       dp_str, &k->dpn, NULL, 1), err_num);
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE,
                                       dq_str, &k->dqn, NULL, 1), err_num);
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE,
                                       i_str, &k->in, NULL, 1), err_num);
    case ASSH_KEY_FMT_PUB_PEM_ASN1:
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE,
                                       n_str, &k->nn, NULL, 0), err_num);
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE,
                                       e_str, &k->en, NULL, 0), err_num);
     default:
      break;
    }

  if (k->key.private)
    {
      enum bytecode_args_e
      {
        D, P, Q, DP, DQ, T0, T1
      };

      static const assh_bignum_op_t bytecode[] = {
        ASSH_BOP_SIZER(  T0,    T1,     P               ),

        /* check that msb of P and Q are set */
        ASSH_BOP_TEST(   P,      1,      P,      0      ),
        ASSH_BOP_TEST(   Q,      1,      Q,      1      ),
        ASSH_BOP_BOOL(   0,      1,      0,      ASSH_BOP_BOOL_AND ),
        ASSH_BOP_CFAIL(  1,      0                      ),

        /* Compute missing dq and dp values */
        ASSH_BOP_UINT(   T0,    1                       ),

        ASSH_BOP_CMPEQ(  DP,     ASSH_BOP_NOREG, 0      ),
        ASSH_BOP_CJMP(   2,      1,      0              ),
        ASSH_BOP_SUB(    T1,    P,      T0              ),
        ASSH_BOP_MOD(    DP,    D,      T1              ),

        ASSH_BOP_CMPEQ(  DQ,     ASSH_BOP_NOREG, 0      ),
        ASSH_BOP_CJMP(   2,      1,      0              ),
        ASSH_BOP_SUB(    T1,    Q,      T0              ),
        ASSH_BOP_MOD(    DQ,    D,      T1              ),

        ASSH_BOP_END(),
      };

      ASSH_JMP_ON_ERR(assh_bignum_bytecode(c, 0, bytecode, "NNNNNTT",
                     &k->dn, &k->pn, &k->qn, &k->dpn, &k->dqn), err_num);
    }

  *key = &k->key;
  *blob_ = blob;
  return ASSH_OK;

 err_num:
  assh_key_rsa_cleanup(c, &k->key);
  return err;
}

const struct assh_key_algo_s assh_key_rsa =
{
  .name = "ssh-rsa",
  .min_bits = 1024,
  .bits = 2048,
  .max_bits = 8192,

  .formats = (enum assh_key_format_e[]){
    ASSH_KEY_FMT_PV_PEM,
    ASSH_KEY_FMT_PUB_RFC4716,
    ASSH_KEY_FMT_PUB_RFC4253,
    ASSH_KEY_FMT_PUB_OPENSSH,
    ASSH_KEY_FMT_PUB_PEM,
    ASSH_KEY_FMT_PUB_PEM_ASN1,
    ASSH_KEY_FMT_PV_OPENSSH_V1,
    ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB,
    ASSH_KEY_FMT_PV_OPENSSH_V1_KEY,
    ASSH_KEY_FMT_PV_PEM_ASN1,
    0,
  },

  .f_output = assh_key_rsa_output,
#ifdef CONFIG_ASSH_KEY_CREATE
  .f_create = assh_key_rsa_create,
#endif
#ifdef CONFIG_ASSH_KEY_VALIDATE
  .f_validate = assh_key_rsa_validate,
#endif
  .f_cmp = assh_key_rsa_cmp,
  .f_load = assh_key_rsa_load,
  .f_cleanup = assh_key_rsa_cleanup,
};

