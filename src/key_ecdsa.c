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
#include <assh/assh_buffer.h>
#include <assh/assh_alloc.h>
#include <assh/assh_prng.h>
#include <assh/assh_hash.h>

#include "ecc_weierstrass.h"

#include <string.h>

static const struct assh_key_ecdsa_id_s assh_key_ecdsa_id[] = {
  { "ecdsa-sha2-nistp256",
    (const uint8_t*)"\x08" "\x2a\x86\x48\xce\x3d\x03\x01\x07",
    &assh_nistp256_curve, &assh_hash_sha256 },
  { "ecdsa-sha2-nistp384",
    (const uint8_t*)"\x05" "\x2b\x81\x04\x00\x22",
    &assh_nistp384_curve, &assh_hash_sha384 },
  { "ecdsa-sha2-nistp521",
    (const uint8_t*)"\x05" "\x2b\x81\x04\x00\x23",
    &assh_nistp521_curve, &assh_hash_sha512 },
  { NULL }
};

static const struct assh_key_ecdsa_id_s *
assh_key_ecdsa_lookup_name(const char *name, size_t name_len)
{
  const struct assh_key_ecdsa_id_s *n;
  for (n = assh_key_ecdsa_id; n->name != NULL; n++)
    if (name_len == strlen(n->name) && !strcmp(name, n->name))
      return n;
  return NULL;
};

static const struct assh_key_ecdsa_id_s *
assh_key_ecdsa_lookup_oid(const uint8_t *id, size_t id_len)
{
  const struct assh_key_ecdsa_id_s *n;
  for (n = assh_key_ecdsa_id; n->name != NULL; n++)
    if (id_len == n->oid[0] && !memcmp(id, n->oid + 1, id_len))
      return n;
  return NULL;
};

static const struct assh_key_ecdsa_id_s *
assh_key_ecdsa_lookup_bits(size_t bits)
{
  const struct assh_key_ecdsa_id_s *n;
  for (n = assh_key_ecdsa_id; n->name != NULL; n++)
    if (bits == n->curve->bits)
      return n;
  return NULL;
};

static ASSH_KEY_OUTPUT_FCN(assh_key_ecdsa_output)
{
  struct assh_key_ecdsa_s *k = (void*)key;

  assert(key->algo == &assh_key_ecdsa_nistp);

  const struct assh_weierstrass_curve_s *curve = k->id->curve;
  assh_error_t err;

  assert(curve->bits == assh_bignum_bits(&k->xn));
  assert(curve->bits == assh_bignum_bits(&k->yn));
  size_t n = ASSH_ALIGN8(curve->bits) / 8;
  size_t len = 0;

  switch (format)
    {
    case ASSH_KEY_FMT_PV_OPENSSH_V1_KEY:
      ASSH_RET_IF_TRUE(!k->key.private, ASSH_ERR_MISSING_KEY);
      len = /* mpint scalar */ 4 + 1 + n;
    case ASSH_KEY_FMT_PUB_RFC4253: {
      size_t tlen = strlen(k->id->name);
      size_t dlen = strlen(curve->name);

      len += /* algo id*/ 4 + tlen
          + /* curve id */ 4 + dlen
          + /* curve point */ 4 + 1 + 2 * n;

      assert(curve->bits == assh_bignum_bits(&k->sn));

      if (blob != NULL)
        {
          uint8_t *b = blob;

          assh_store_u32(b, tlen);
          memcpy(b + 4, k->id->name, tlen);
          b += 4 + tlen;

          assh_store_u32(b, dlen);
          memcpy(b + 4, curve->name, dlen);
          b += 4 + dlen;

          assh_store_u32(b, 1 + 2 * n);
          b[4] = 0x4;
          b += 5;
          ASSH_RET_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_NATIVE,
                         ASSH_BIGNUM_MSB_RAW, &k->xn, b, &b, 0));
          ASSH_RET_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_NATIVE,
                         ASSH_BIGNUM_MSB_RAW, &k->yn, b, &b, 0));

          if (format == ASSH_KEY_FMT_PV_OPENSSH_V1_KEY)
            ASSH_RET_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_NATIVE,
                           ASSH_BIGNUM_MPINT, &k->sn, b, &b, 1));

          len = b - blob;
        }

      *blob_len = len;
      return ASSH_OK;
    }

    case ASSH_KEY_FMT_PV_PEM_ASN1: {
      ASSH_RET_IF_TRUE(!k->key.private, ASSH_ERR_MISSING_KEY);
      assert(curve->bits == assh_bignum_bits(&k->sn));

      size_t pub_len = 2 + 2 * n;
      size_t oid_len = k->id->oid[0];
      size_t oid_clen = assh_asn1_headlen(oid_len) + oid_len;
      size_t pub_clen = assh_asn1_headlen(pub_len) + pub_len;
      size_t pem_clen = /* version */ 3 +
        /* pvkey */ assh_asn1_headlen(n) + n +
        /* oid */ assh_asn1_headlen(oid_clen) + oid_clen +
        /* pubkey */ assh_asn1_headlen(pub_clen) + pub_clen;
      size_t pem_len = assh_asn1_headlen(pem_clen) + pem_clen;

      if (blob != NULL)
        {
          uint8_t *b = blob;

          /* sequence */
          assh_append_asn1(&b, 0x30, pem_clen);
          /* version */
          *b++ = 0x02;
          *b++ = 0x01;
          *b++ = 0x01;
          /* pvkey */
          assh_append_asn1(&b, 0x04, n);
          ASSH_RET_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_NATIVE,
                         ASSH_BIGNUM_MSB_RAW, &k->sn, b, &b, 0));
          /* oid */
          assh_append_asn1(&b, 0xa0, oid_clen);
          assh_append_asn1(&b, 0x06, oid_len);
          memcpy(b, k->id->oid + 1, oid_len);
          b += oid_len;
          /* pubkey */
          assh_append_asn1(&b, 0xa1, pub_clen);
          assh_append_asn1(&b, 0x03, pub_len);
          *b++ = 0x00;
          *b++ = 0x04;
          ASSH_RET_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_NATIVE,
                         ASSH_BIGNUM_MSB_RAW, &k->xn, b, &b, 0));
          ASSH_RET_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_NATIVE,
                         ASSH_BIGNUM_MSB_RAW, &k->yn, b, &b, 0));
        }

      *blob_len = pem_len;
      return ASSH_OK;
    }

    default:
      ASSH_RETURN(ASSH_ERR_NOTSUP);
    }

  ASSH_UNREACHABLE();
}

static ASSH_KEY_CMP_FCN(assh_key_ecdsa_cmp)
{
  assert(key->algo == &assh_key_ecdsa_nistp);

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
      if (k->key.private != l->key.private)
        return 0;
      if (!l->key.private)
        pub = 1;
    }

  return assh_bignum_bytecode(c, !!pub, bytecode, "NNNNNN",
    &k->xn, &l->xn, &k->yn, &l->yn, &k->sn, &l->sn) == 0;
}

static ASSH_KEY_CLEANUP_FCN(assh_key_ecdsa_cleanup)
{
  struct assh_key_ecdsa_s *k = (void*)key;

  assh_bignum_release(c, &k->sn);
  assh_bignum_release(c, &k->xn);
  assh_bignum_release(c, &k->yn);
  assh_free(c, k);
}

#ifdef CONFIG_ASSH_KEY_CREATE
static assh_error_t
assh_key_ecdsa_create(struct assh_context_s *c,
                      const struct assh_key_algo_s *algo,
                      struct assh_key_s **key,
                      const struct assh_key_ecdsa_id_s *id)
{
  assh_error_t err;
  struct assh_key_ecdsa_s *k;
  const struct assh_weierstrass_curve_s *curve = id->curve;

  ASSH_RET_ON_ERR(assh_alloc(c, sizeof(struct assh_key_ecdsa_s),
                          ASSH_ALLOC_INTERNAL, (void**)&k));

  k->key.type = id->name;
  k->key.algo = algo;
  k->key.safety = id->curve->safety;
  k->key.private = 1;
  k->id = id;

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

    ASSH_BOP_SIZER(     X1,     MT,    SC               ),

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

  ASSH_JMP_ON_ERR(assh_bignum_bytecode(c, 0, bytecode, "DDDDNNNTTTTTTTTTTTm",
               curve->gx, curve->gy, curve->p, curve->n,
               &k->xn, &k->yn, &k->sn), err_key);

  assert(k->sn.secret);

  *key = &k->key;

  return ASSH_OK;

 err_key:
  assh_key_ecdsa_cleanup(c, &k->key);
  return err;
}
#endif

#ifdef CONFIG_ASSH_KEY_VALIDATE
static ASSH_KEY_VALIDATE_FCN(assh_key_ecdsa_validate)
{
  assh_error_t err;
  struct assh_key_ecdsa_s *k = (void*)key;
  const struct assh_weierstrass_curve_s *curve = k->id->curve;

  assert(key->algo == &assh_key_ecdsa_nistp);

  if (curve->bits != assh_bignum_bits(&k->xn) ||
      curve->bits != assh_bignum_bits(&k->yn))
    return ASSH_OK;             /* *result is BAD */

  assert(curve->cofactor == 1); /* more checks needed if != 1 */

  enum {
    P_raw, B_raw,
    X, Y, X1, Y1, Z1, T0, T1, T2,
    MT
  };

  static const assh_bignum_op_t bytecode[] = {

    ASSH_BOP_SIZER(     X1,     MT,    X                ),

    /* init */
    ASSH_BOP_MOVE(      T0,     P_raw                   ),
    ASSH_BOP_MTINIT(	MT,     T0                      ),

    ASSH_BOP_MOVE(      T2,     B_raw                   ),
    ASSH_BOP_MTTO(      X1,     Y1,     X,      MT      ),

    ASSH_BOP_WS_POINTONCURVE(X1, Y1, T0, T1, T2, MT),

    ASSH_BOP_END(),
  };

  err = assh_bignum_bytecode(c, 0, bytecode, "DDNNTTTTTTm",
                             curve->p, curve->b, &k->xn, &k->yn);

  switch (ASSH_ERR_ERROR(err))
    {
    case ASSH_ERR_NUM_COMPARE_FAILED:
    case ASSH_ERR_NUM_OVERFLOW:
      return ASSH_OK;

    case ASSH_OK:
      *result = ASSH_KEY_PARTIALLY_CHECKED;
      return ASSH_OK;

    default:
      ASSH_RETURN(err);
    }
}
#endif

static ASSH_KEY_LOAD_FCN(assh_key_ecdsa_load)
{
  assh_error_t err;
  const struct assh_key_ecdsa_id_s *id = NULL;
  const uint8_t *x_str, *y_str, *s_str = NULL;
  const uint8_t *blob = *blob_;
  struct assh_key_ecdsa_s *k = (void*)*key;

  /* parse the key blob */
  switch (format)
    {
    case ASSH_KEY_FMT_PUB_RFC4253:
    case ASSH_KEY_FMT_PV_OPENSSH_V1_KEY: {
      ASSH_RET_IF_TRUE(k != NULL, ASSH_ERR_BAD_ARG);

      /* lookup key type */
      size_t id_len;
      const char *id_str;
      ASSH_RET_ON_ERR(assh_scan_blob("sRL", &blob, &blob_len,
                                      &id_str, &id_len));

      id = assh_key_ecdsa_lookup_name(id_str, id_len);
      ASSH_RET_IF_TRUE(id == NULL, ASSH_ERR_NOTSUP);

      size_t n = ASSH_ALIGN8(id->curve->bits) / 8;
      size_t kp_len = 1 + 2 * n;

      ASSH_RET_ON_ERR(assh_scan_blob(/* curve name */ "sQ"
                                     /* pub blob */ "sT("
                                       /* encoding */ "l1 E;1;\x04"
                                       /* X */ "lR"
                                       /* Y */ "lR"
                                     ")", &blob, &blob_len,
                                      id->curve->name, kp_len,
                                      n, &x_str, n, &y_str));

      if (format == ASSH_KEY_FMT_PV_OPENSSH_V1_KEY)
        ASSH_RET_ON_ERR(assh_scan_blob("sP", &blob, &blob_len, &s_str));

      break;
    }

    case ASSH_KEY_FMT_PV_PEM_ASN1: {
      ASSH_RET_IF_TRUE(k != NULL, ASSH_ERR_BAD_ARG);

      const uint8_t *id_str, *pub_str;
      size_t id_len, pub_len;

      ASSH_RET_ON_ERR(assh_scan_blob("a48(" /* version */ "a2 H1 E;1;\x01"
                                            /* pv key */ "a4P"
                                            /* curve name */ "a160(a6RL)"
                                            /* pub key */ "a161(a3RL E1;1;\x04))",
                                     &blob, &blob_len,
                                     &s_str, &id_str, &id_len, &pub_str, &pub_len));

      id = assh_key_ecdsa_lookup_oid(id_str, id_len);
      ASSH_RET_IF_TRUE(id == NULL, ASSH_ERR_NOTSUP);
      size_t n = ASSH_ALIGN8(id->curve->bits) / 8;

      ASSH_RET_IF_TRUE(pub_len != 2 + 2 * n, ASSH_ERR_BAD_DATA);

      x_str = pub_str + 2;
      y_str = x_str + n;

      break;
    }

    default:
      ASSH_RETURN(ASSH_ERR_NOTSUP);
    }

  /* allocate key structure */
  if (k == NULL)
    {
      ASSH_RET_ON_ERR(assh_alloc(c, sizeof(struct assh_key_ecdsa_s),
                                 ASSH_ALLOC_INTERNAL, (void**)&k));

      k->key.private = 0;
      k->key.type = id->name;
      k->key.algo = algo;
      k->key.safety = id->curve->safety;
      k->id = id;

      size_t bits = id->curve->bits;
      assh_bignum_init(c, &k->xn, bits);
      assh_bignum_init(c, &k->yn, bits);
      assh_bignum_init(c, &k->sn, bits);
    }

  switch (format)
    {
    case ASSH_KEY_FMT_PV_PEM_ASN1:
      k->key.private = 1;
      /* Some buggy implementations skip leading zero bytes in the
         fixed size ASN1 octet string, so we load it as an ASN1 number instead. */
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_ASN1, ASSH_BIGNUM_NATIVE,
                                       s_str, &k->sn, NULL, 1), err_key);
      goto pub;

    case ASSH_KEY_FMT_PV_OPENSSH_V1_KEY:
      k->key.private = 1;
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_MPINT, ASSH_BIGNUM_NATIVE,
                                       s_str, &k->sn, NULL, 1), err_key);

    case ASSH_KEY_FMT_PUB_RFC4253:
    pub:
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_MSB_RAW, ASSH_BIGNUM_NATIVE,
                                       x_str, &k->xn, NULL, 0), err_key);
      ASSH_JMP_ON_ERR(assh_bignum_convert(c, ASSH_BIGNUM_MSB_RAW, ASSH_BIGNUM_NATIVE,
                                       y_str, &k->yn, NULL, 0), err_key);
      break;

    default:
      ASSH_UNREACHABLE();
    }

  *key = &k->key;
  *blob_ = blob;
  return ASSH_OK;

 err_key:

  switch (format)
    {
    case ASSH_KEY_FMT_PV_PEM_ASN1:
    case ASSH_KEY_FMT_PV_OPENSSH_V1_KEY:
      assh_bignum_release(c, &k->sn);
    case ASSH_KEY_FMT_PUB_RFC4253:
      assh_bignum_release(c, &k->xn);
      assh_bignum_release(c, &k->yn);
      assh_free(c, k);
      break;
    default:
      ASSH_UNREACHABLE();
    }

  return err;
}

#ifdef CONFIG_ASSH_KEY_CREATE
static ASSH_KEY_CREATE_FCN(assh_key_ecdsa_nistp_create)
{
  assh_error_t err;
  const struct assh_key_ecdsa_id_s *id = assh_key_ecdsa_lookup_bits(bits);
  ASSH_RET_IF_TRUE(id == NULL, ASSH_ERR_NOTSUP);
  ASSH_RETURN(assh_key_ecdsa_create(c, algo, key, id));
}
#endif

const struct assh_key_algo_s assh_key_ecdsa_nistp =
{
  .name = "ecdsa-sha2-nist",
  .min_bits = 256,
  .bits = 256,
  .max_bits = 521,

  .formats = (enum assh_key_format_e[]){
    ASSH_KEY_FMT_PV_PEM,
    ASSH_KEY_FMT_PUB_RFC4716,
    ASSH_KEY_FMT_PUB_RFC4253,
    ASSH_KEY_FMT_PUB_OPENSSH,
    ASSH_KEY_FMT_PV_OPENSSH_V1,
    ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB,
    ASSH_KEY_FMT_PV_OPENSSH_V1_KEY,
    ASSH_KEY_FMT_PV_PEM_ASN1,
    0,
  },

  .f_output = assh_key_ecdsa_output,
#ifdef CONFIG_ASSH_KEY_CREATE
  .f_create = assh_key_ecdsa_nistp_create,
#endif
  .f_load = assh_key_ecdsa_load,
#ifdef CONFIG_ASSH_KEY_VALIDATE
  .f_validate = assh_key_ecdsa_validate,
#endif
  .f_cmp = assh_key_ecdsa_cmp,
  .f_cleanup = assh_key_ecdsa_cleanup,
};

