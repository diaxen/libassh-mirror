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
#include <assh/hash_sha1.h>
#include <assh/assh_prng.h>
#include <assh/assh_alloc.h>

#include <string.h>

/************************************************************ dss key */

struct assh_sign_dss_key_s
{
  struct assh_key_s key;

  /** public p */
  struct assh_bignum_s *pn;
  /** public q */
  struct assh_bignum_s *qn;
  /** public g */
  struct assh_bignum_s *gn;
  /** public y */
  struct assh_bignum_s *yn;
  /** private x, may be null */
  struct assh_bignum_s *xn;
};

static const char *assh_dss_id = "\x00\x00\x00\x07ssh-dss";
static const size_t assh_dss_id_len = 4 + 7;

static ASSH_KEY_CLEANUP_FCN(assh_sign_dss_key_cleanup)
{
  struct assh_sign_dss_key_s *k = (void*)key;

  if (k->xn != NULL)
    assh_bignum_cleanup(c, k->xn);
  assh_bignum_cleanup(c, k->yn);
  assh_bignum_cleanup(c, k->gn);
  assh_bignum_cleanup(c, k->qn);
  assh_bignum_cleanup(c, k->pn);
  assh_free(c, k, ASSH_ALLOC_KEY);
}

static ASSH_KEY_OUTPUT_FCN(assh_sign_dss_key_output)
{
  struct assh_sign_dss_key_s *k = (void*)key;
  assh_error_t err;

  assert((void*)key->algo == (void*)&assh_sign_dss);

  struct assh_bignum_s *bn_[6] = { k->pn, k->qn, k->gn, k->yn, NULL, NULL };

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
          size_t s = assh_bignum_mpint_size(*bn);
          if (blob != NULL)
            {
              ASSH_CHK_RET(s > *blob_len, ASSH_ERR_OUTPUT_OVERFLOW);
              ASSH_ERR_RET(assh_bignum_to_mpint(*bn, blob));
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
      ASSH_CHK_RET(k->xn == NULL, ASSH_ERR_NOTSUP);
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
  assert((void*)key->algo == (void*)&assh_sign_dss);

  if (key->algo != b->algo)
    return 0;

  struct assh_sign_dss_key_s *k = (void*)key;
  struct assh_sign_dss_key_s *l = (void*)b;

  return (!assh_bignum_cmp(k->pn, l->pn) &&
          !assh_bignum_cmp(k->qn, l->qn) && 
          !assh_bignum_cmp(k->gn, l->gn) && 
          !assh_bignum_cmp(k->yn, l->yn) && 
          (pub || (k->xn == NULL && l->xn == NULL) ||
           (k->xn != NULL && l->xn != NULL && !assh_bignum_cmp(k->xn, l->xn))));
}

static ASSH_KEY_VALIDATE_FCN(assh_sign_dss_key_validate)
{
  struct assh_sign_dss_key_s *k = (void*)key;
  assh_error_t err = ASSH_OK;

  /*
   * FIPS 186-4 Appendix A2.2
   * SP 800-89 section 5.3.1
   */

  unsigned int l = assh_bignum_bits(k->pn);
  unsigned int n = assh_bignum_bits(k->qn);

  /* check key size */
  if (l < 1024 || n < 160 || l > 8192 || n > 512 || l % 8 || n % 8)
    goto err_;

  enum bytecode_args_e
  {
    P, Q, G, Y, T1, T2
  };

  assh_bignum_op_t bytecode[] = {
    ASSH_BIGNUM_BC_UINT(        T1,     1               ),

    /* check generator range */
    ASSH_BIGNUM_BC_CMPLT(       T1,     G               ), /* g > 1 */
    ASSH_BIGNUM_BC_CMPLT(       G,      P               ), /* g < p */

    /* check generator order in the group */
    ASSH_BIGNUM_BC_SETMOD(      P                       ),
    ASSH_BIGNUM_BC_EXPMOD(      T2,     G,      Q       ),
    ASSH_BIGNUM_BC_CMPEQ(       T1,     T2              ),

    /* check public key range */
    ASSH_BIGNUM_BC_CMPLT(       T1,     G               ), /* y > 1 */
    ASSH_BIGNUM_BC_EXPMOD(      T2,     P,      T1      ),
    ASSH_BIGNUM_BC_CMPLT(       Y,      T2              ), /* y < p-1 */

    /* check public key order in the group */
    ASSH_BIGNUM_BC_EXPMOD(      T2,     Y,      Q       ),
    ASSH_BIGNUM_BC_CMPEQ(       T1,     T2              ),

    ASSH_BIGNUM_BC_END(),
  };

  err = assh_bignum_bytecode(c, bytecode, "NNNNTT",
                             k->pn, k->qn, k->gn, k->yn, l, l);

  if (err != ASSH_ERR_NUM_COMPARE_FAILED)
    ASSH_ERR_RET(err);

  *valid = (err == ASSH_OK);

 err_:
  return err;
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
  ASSH_CHK_RET(l > 8192 || n > 512, ASSH_ERR_NOTSUP);

  size_t size = sizeof(struct assh_sign_dss_key_s)
    + assh_bignum_sizeof(l)  /* p */
    + assh_bignum_sizeof(n)  /* q */
    + assh_bignum_sizeof(l)  /* g */
    + assh_bignum_sizeof(l); /* y */

  if (x_str != NULL)
    size += assh_bignum_sizeof(n); /* x */

  ASSH_ERR_RET(assh_alloc(c, size, ASSH_ALLOC_KEY, (void**)key));
  struct assh_sign_dss_key_s *k = (void*)*key;

  k->key.f_output = assh_sign_dss_key_output;
  k->key.f_validate = assh_sign_dss_key_validate;
  k->key.f_cmp = assh_sign_dss_key_cmp;
  k->key.f_cleanup = assh_sign_dss_key_cleanup;

  /* init key structure */
  k->pn = (struct assh_bignum_s*)(k + 1);
  k->qn = (struct assh_bignum_s*)((uint8_t*)k->pn + assh_bignum_sizeof(l));
  k->gn = (struct assh_bignum_s*)((uint8_t*)k->qn + assh_bignum_sizeof(n));
  k->yn = (struct assh_bignum_s*)((uint8_t*)k->gn + assh_bignum_sizeof(l));
  k->xn = (struct assh_bignum_s*)((x_str != NULL) ? (uint8_t*)k->yn + assh_bignum_sizeof(l) : NULL);

  /* init numbers */
  assh_bignum_init(c, k->pn, l);
  assh_bignum_init(c, k->qn, n);
  assh_bignum_init(c, k->gn, l);
  assh_bignum_init(c, k->yn, l);

  if (x_str != NULL)
    assh_bignum_init(c, k->xn, n);

  /* convert numbers from blob representation */
  switch (format)
    {
    case ASSH_KEY_FMT_PUB_RFC4253_6_6:
      ASSH_ERR_GTO(assh_bignum_from_mpint(k->pn, NULL, p_str), err_xn);
      ASSH_ERR_GTO(assh_bignum_from_mpint(k->qn, NULL, q_str), err_xn);
      ASSH_ERR_GTO(assh_bignum_from_mpint(k->gn, NULL, g_str), err_xn);
      ASSH_ERR_GTO(assh_bignum_from_mpint(k->yn, NULL, y_str), err_xn);
      break;

    case ASSH_KEY_FMT_PV_PEM_ASN1:
      ASSH_ERR_GTO(assh_bignum_from_asn1(k->pn, NULL, p_str), err_xn);
      ASSH_ERR_GTO(assh_bignum_from_asn1(k->qn, NULL, q_str), err_xn);
      ASSH_ERR_GTO(assh_bignum_from_asn1(k->gn, NULL, g_str), err_xn);
      ASSH_ERR_GTO(assh_bignum_from_asn1(k->yn, NULL, y_str), err_xn);
      ASSH_ERR_GTO(assh_bignum_from_asn1(k->xn, NULL, x_str), err_xn);
    default:
      break;
    }

#ifdef CONFIG_ASSH_DEBUG_SIGN
  assh_bignum_print(stderr, "dss key p", k->pn);
  assh_bignum_print(stderr, "dss key q", k->qn);
  assh_bignum_print(stderr, "dss key g", k->gn);
  assh_bignum_print(stderr, "dss key y", k->yn);
  if (k->xn != NULL)
    assh_bignum_print(stderr, "dss key x", k->xn);
#endif

  return ASSH_OK;

 err_xn:
  if (k->xn != NULL)
    assh_bignum_cleanup(c, k->xn);
  assh_bignum_cleanup(c, k->yn);
  assh_bignum_cleanup(c, k->gn);
  assh_bignum_cleanup(c, k->qn);
  assh_bignum_cleanup(c, k->pn);
  assh_free(c, k, ASSH_ALLOC_KEY);
  return err;
}

/************************************************************ dss sign algo */

static assh_error_t
assh_sign_dss_hash(struct assh_context_s *c, size_t data_count,
		   const uint8_t * const data[],
		   const size_t data_len[],
		   unsigned int n, struct assh_bignum_s *bn)
{
  assh_error_t err;
  unsigned int i;

  switch (n)
    {
    case 160: {
      ASSH_SCRATCH_ALLOC(c, uint8_t, scratch,
			 sizeof(struct assh_hash_sha1_context_s) + n / 8,
			 ASSH_ERRSV_CONTINUE, err);

      struct assh_hash_sha1_context_s *sha1 = (void*)scratch;
      uint8_t *hash = scratch + sizeof(*sha1);

      assh_sha1_init(sha1);
      for (i = 0; i < data_count; i++)
        assh_sha1_update(sha1, data[i], data_len[i]);
      assh_sha1_final(sha1, hash);

      ASSH_ERR_GTO(assh_bignum_from_data(bn, hash, n / 8), err);

      err = ASSH_OK;
     err:
      ASSH_SCRATCH_FREE(c, scratch);
      return err;
    }
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
  ASSH_CHK_RET(k->xn == NULL, ASSH_ERR_MISSING_KEY);

  unsigned int l = assh_bignum_bits(k->pn);
  unsigned int n = assh_bignum_bits(k->qn);

#ifdef CONFIG_ASSH_DEBUG_SIGN
  ASSH_DEBUG("N=%u L=%u\n", n, l);
#endif

  /* check/return signature length */
  size_t len = assh_dss_id_len + 4 + n * 2 / 8;

  if (sign == NULL)
    {
      *sign_len = len;
      return ASSH_OK;
    }

  ASSH_CHK_RET(*sign_len < len, ASSH_ERR_OUTPUT_OVERFLOW);
  *sign_len = len;

  /* message hash */
  ASSH_BIGNUM_ALLOC(c, mn, n, ASSH_ERRSV_CONTINUE, err_);
  ASSH_ERR_GTO(assh_sign_dss_hash(c, data_count, data, data_len, n, mn), err_mn);

  memcpy(sign, assh_dss_id, assh_dss_id_len);
  assh_store_u32(sign + assh_dss_id_len, n * 2 / 8);
  uint8_t *r_str = sign + assh_dss_id_len + 4;
  uint8_t *s_str = r_str + n / 8;

  /* Do not use the prng output directly as the DSA nonce in order to
     avoid leaking key bits in case of a weak prng. Random data is
     hashed with the private key and the message data. */
  ASSH_SCRATCH_ALLOC(c, uint8_t, scratch,
		     sizeof(struct assh_hash_sha1_context_s)
		     + /* sizeof rnd[] */ n / 8 + 20,
		     ASSH_ERRSV_CONTINUE, err_mn);

  struct assh_hash_sha1_context_s *sha1 = (void*)scratch;
  uint8_t *rnd = scratch + sizeof(*sha1);

  unsigned int i;

  ASSH_ERR_GTO(c->prng->f_get(c, rnd, n / 8, ASSH_PRNG_QUALITY_NONCE), err_scratch);
  assh_sha1_init(sha1);
  for (i = 0; i < data_count; i++)
    assh_sha1_update(sha1, data[i], data_len[i]);
  ASSH_ERR_GTO(assh_hash_bignum(c, sha1, &assh_sha1_update, k->xn), err_scratch);
  for (i = 0; ; )
    {
      assh_sha1_update(sha1, rnd, n / 8);
      assh_sha1_final(sha1, rnd + i);
      if ((i += 20) >= n / 8)
	break;
      assh_sha1_init(sha1);
    }

  enum bytecode_args_e
  {
    K_data, R_data, S_data,     /* data buffers */
    P, Q, G, X, M,              /* big number inputs */
    K, R, S, R1, R2, R3         /* big number temporaries */
  };

  assh_bignum_op_t bytecode[] = {
    ASSH_BIGNUM_BC_MOVE(        K,      K_data          ),

    /* g^k mod p */
    ASSH_BIGNUM_BC_SETMOD(      P                       ),
    ASSH_BIGNUM_BC_EXPMOD(      R3,     G,      K       ),

    /* r = (g^k mod p) mod q */
    ASSH_BIGNUM_BC_DIV(         R3,     Q,      Q       ),
    ASSH_BIGNUM_BC_MOVE(        R,      R3              ),
    ASSH_BIGNUM_BC_MOVE(        R_data, R               ),

    /* (x * r) mod q */
    ASSH_BIGNUM_BC_SETMOD(      Q                       ),
    ASSH_BIGNUM_BC_MULMOD(      R1,     X,      R       ),

    /* sha(m) + (x * r) */
    ASSH_BIGNUM_BC_ADD(         R2,     M,      R1      ),

    /* k^-1 */
    ASSH_BIGNUM_BC_MODINV(      R1,     K,      Q       ),

    /* s = k^-1 * (sha(m) + (x * r)) mod q */
    ASSH_BIGNUM_BC_MULMOD(      S,      R1,     R2      ),

    ASSH_BIGNUM_BC_MOVE(        R_data, R               ),
    ASSH_BIGNUM_BC_MOVE(        S_data, S               ),

    ASSH_BIGNUM_BC_END(),
  };

  ASSH_ERR_GTO(assh_bignum_bytecode(c, bytecode, "DDDNNNNNTTTTTT",
                                    /* D */ rnd, r_str, s_str,
                                    /* N */ k->pn, k->qn, k->gn, k->xn, mn,
                                    /* T */ n, n, n, n, n + 1, l), err_scratch);

  err = ASSH_OK;

 err_scratch:
  ASSH_SCRATCH_FREE(c, scratch);
 err_mn:
  ASSH_BIGNUM_FREE(c, mn);
 err_:
  return err;
}

static ASSH_SIGN_VERIFY_FCN(assh_sign_dss_verify)
{
  struct assh_sign_dss_key_s *k = (void*)key;
  assh_error_t err;

  unsigned int l = assh_bignum_bits(k->pn);
  unsigned int n = assh_bignum_bits(k->qn);

#ifdef CONFIG_ASSH_DEBUG_SIGN
  ASSH_DEBUG("N=%u L=%u\n", n, l);
#endif

  ASSH_CHK_RET(sign_len != assh_dss_id_len + 4 + n * 2 / 8, ASSH_ERR_INPUT_OVERFLOW);

  ASSH_CHK_RET(memcmp(sign, assh_dss_id, assh_dss_id_len), ASSH_ERR_BAD_DATA);

  uint8_t *rs_str = (uint8_t*)sign + assh_dss_id_len;
  ASSH_CHK_RET(assh_load_u32(rs_str) != n * 2 / 8, ASSH_ERR_INPUT_OVERFLOW);

  ASSH_BIGNUM_ALLOC(c, mn, n, ASSH_ERRSV_CONTINUE, err_);  
  ASSH_ERR_GTO(assh_sign_dss_hash(c, data_count, data, data_len, n, mn), err_mn);

  enum bytecode_args_e
  {
    R_data, S_data,             /* data buffers */
    P, Q, G, Y, M,              /* big number inputs */
    R, S, W, U1, V1, U2, V2, V  /* big number temporaries */
  };

  assh_bignum_op_t bytecode[] = {
    ASSH_BIGNUM_BC_MOVE(        R,      R_data          ),
    ASSH_BIGNUM_BC_MOVE(        S,      S_data          ),

    ASSH_BIGNUM_BC_MODINV(      W,      S,      Q       ),

    /* (sha(m) * w) mod q */
    ASSH_BIGNUM_BC_SETMOD(      Q                       ),
    ASSH_BIGNUM_BC_MULMOD(      U1,     M,      W       ),

    /* g^u1 */
    ASSH_BIGNUM_BC_SETMOD(      P                       ),
    ASSH_BIGNUM_BC_EXPMOD(      V1,     G,      U1      ),

    /* r * w mod q */
    ASSH_BIGNUM_BC_SETMOD(      Q                       ),
    ASSH_BIGNUM_BC_MULMOD(      U2,     R,      W       ),

    /* y^u2 */
    ASSH_BIGNUM_BC_SETMOD(      P                       ),
    ASSH_BIGNUM_BC_EXPMOD(      V2,     Y,      U2      ),

    /* (g^u1 * y^u2) mod p */
    ASSH_BIGNUM_BC_MULMOD(      V,      V1,     V2      ),

    /* v = (g^u1 * y^u2) mod p mod q */
    ASSH_BIGNUM_BC_DIV(         V,      Q,      Q       ),

    ASSH_BIGNUM_BC_CMPEQ(       V,      R               ),
    ASSH_BIGNUM_BC_END(),
  };

  err = assh_bignum_bytecode(c, bytecode, "DDNNNNNTTTTTTTT",
                             /* D */ rs_str + 4, rs_str + 4 + n / 8,
                             /* N */ k->pn, k->qn, k->gn, k->yn, mn,
                             /* T */ n, n, n, n, l, n, l, l);

  if (err != ASSH_ERR_NUM_COMPARE_FAILED)
    ASSH_ERR_GTO(err, err_mn);

  *ok = (err == ASSH_OK);

  err = ASSH_OK;

 err_mn:
  ASSH_BIGNUM_FREE(c, mn);
 err_:
  return err;
}

struct assh_algo_sign_s assh_sign_dss =
{
  .algo = { .name = "ssh-dss", .class_ = ASSH_ALGO_SIGN,
            .need_host_key = 1, .safety = 50, .speed = 50 },
  .f_key_load = assh_sign_dss_key_load,
  .f_generate = assh_sign_dss_generate,
  .f_verify = assh_sign_dss_verify,
};

