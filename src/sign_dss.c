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
          ASSH_ERR_RET(assh_dss_id_len > *blob_len ? ASSH_ERR_OVERFLOW : 0);
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
              ASSH_ERR_RET(s > *blob_len ? ASSH_ERR_OVERFLOW : 0);
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
      ASSH_ERR_RET(k->xn == NULL ? ASSH_ERR_NOTSUP : 0);
      bn_[4] = k->xn;
      return ASSH_OK;
    }
#endif

    default:
      ASSH_ERR_RET(ASSH_ERR_NOTSUP);
    }
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

  *valid = 0;

  /*
   * FIPS 186-4 Appendix A2.2
   * SP 800-89 section 5.3.1
   */

  unsigned int l = assh_bignum_bits(k->pn);
  unsigned int n = assh_bignum_bits(k->qn);

  /* check key size */
  if (l < 1024 || n < 160 || l > 8192 || n > 512 || l % 8 || n % 8)
    goto err_;

  /* check generator range */
  if (assh_bignum_cmp_uint(k->gn, 2) > 0 ||  /* g >= 2 */
      assh_bignum_cmp(k->gn, k->pn) <= 0)    /* g < p */
    goto err_;

  /* check generator order in the group */
  ASSH_BIGNUM_ALLOC(c, rn, l, err_);
  ASSH_ERR_GTO(assh_bignum_expmod(rn, k->gn, k->qn, k->pn), err_rn);
  if (assh_bignum_cmp_uint(rn, 1))
    goto err_rn;

  /* check public key range */
  if (assh_bignum_cmp_uint(k->yn, 2) > 0)   /* y >= 2 */
    goto err_rn;

  ASSH_ERR_GTO(assh_bignum_uint(rn, 2), err_rn);
  ASSH_ERR_GTO(assh_bignum_sub(rn, k->pn, rn), err_rn);
  if (assh_bignum_cmp(k->yn, rn) < 0) /* y <= p-2 */
    goto err_rn;

  /* check public key order in the group */
  ASSH_ERR_GTO(assh_bignum_expmod(rn, k->yn, k->qn, k->pn), err_rn);
  if (assh_bignum_cmp_uint(rn, 1))
    goto err_rn;

  *valid = 1;

 err_rn:
  ASSH_BIGNUM_FREE(c, rn);
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

      if (blob_len < assh_dss_id_len || memcmp(assh_dss_id, blob, assh_dss_id_len))
        ASSH_ERR_RET(ASSH_ERR_BAD_DATA);

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

      if (blob[0] != 0x30)   /* sequence type */
        ASSH_ERR_RET(ASSH_ERR_BAD_DATA);

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
  ASSH_ERR_RET(l < 1024 || n < 160 || l % 8 || n % 8 ? ASSH_ERR_BAD_DATA : 0);
  ASSH_ERR_RET(l > 8192 || n > 512 ? ASSH_ERR_OVERFLOW : 0);

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
  ASSH_ERR_GTO(assh_bignum_init(c, k->pn, l), err_k);
  ASSH_ERR_GTO(assh_bignum_init(c, k->qn, n), err_pn);
  ASSH_ERR_GTO(assh_bignum_init(c, k->gn, l), err_qn);
  ASSH_ERR_GTO(assh_bignum_init(c, k->yn, l), err_gn);

  if (x_str != NULL)
    ASSH_ERR_GTO(assh_bignum_init(c, k->xn, n), err_yn);

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
 err_yn:
  assh_bignum_cleanup(c, k->yn);
 err_gn:
  assh_bignum_cleanup(c, k->gn);
 err_qn:
  assh_bignum_cleanup(c, k->qn);
 err_pn:
  assh_bignum_cleanup(c, k->pn);
 err_k:
  assh_free(c, k, ASSH_ALLOC_KEY);
  return err;
}

/************************************************************ dss sign algo */

/*

  p is a prime
  q is a prime divisor of p-1 (160 bits)
  g = h^((p-1)/q) mod p, where 1 < h < p-1 and h^((p-1)/q) mod p > 1
  p, q, g are known
  x is private key (random)
  y = g^x mod p
  y is the public key
  k is a secret single use random value

  sign:

  r = (g^k mod p) mod q
  s = (k^-1 * (sha(m) + x * r)) mod q

  k^-1 is multiplication inverse of k mod q

  verify:

  assert(r < q && s < q)
  w = s^-1 mod q
  u1 = (sha(m) * w) mod q
  u2 = r * w mod q
  v = (g^u1 * y^u2) mod p mod q
  return (v == r)

 */

static assh_error_t assh_sign_dss_hash(size_t data_count, const uint8_t * const data[], const size_t data_len[],
				       unsigned int n, struct assh_bignum_s *bn)
{
  assh_error_t err;
  uint8_t hash[n / 8];
  unsigned int i;

  switch (n)
    {
    case 160: {
      struct assh_hash_sha1_context_s sha1;
      assh_sha1_init(&sha1);
      for (i = 0; i < data_count; i++)
        assh_sha1_update(&sha1, data[i], data_len[i]);
      assh_sha1_final(&sha1, hash);
      break;
    }
    default:
      ASSH_ERR_RET(ASSH_ERR_NOTSUP);
    }

  ASSH_ERR_RET(assh_bignum_from_data(bn, hash, sizeof(hash)));
  return ASSH_OK;
}

static ASSH_SIGN_GENERATE_FCN(assh_sign_dss_generate)
{
  struct assh_sign_dss_key_s *k = (void*)key;
  assh_error_t err;

  /* check availability of the private key */
  ASSH_ERR_RET(k->xn == NULL ? ASSH_ERR_MISSING_KEY : 0);

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

  ASSH_ERR_RET(*sign_len < len ? ASSH_ERR_OVERFLOW : 0);
  *sign_len = len;

  /* message hash */
  ASSH_BIGNUM_ALLOC(c, mn, n, err_);
  ASSH_ERR_GTO(assh_sign_dss_hash(data_count, data, data_len, n, mn), err_mn);

  memcpy(sign, assh_dss_id, assh_dss_id_len);
  assh_store_u32(sign + assh_dss_id_len, n * 2 / 8);
  uint8_t *r_str = sign + assh_dss_id_len + 4;
  uint8_t *s_str = r_str + n / 8;

  ASSH_BIGNUM_ALLOC(c, kn, n, err_mn);
  /* Do not use the prng output directly as dsa nonce in order to
     avoid leaking key bits in case of a weak prng. Random data is
     hashed along with the private key and the message data. */
  {
    uint8_t rnd[n / 8 + 20];
    unsigned int i;
    struct assh_hash_sha1_context_s sha1;

    ASSH_ERR_GTO(c->prng->f_get(c, rnd, n / 8, ASSH_PRNG_QUALITY_NONCE), err_kn);
    assh_sha1_init(&sha1);
    for (i = 0; i < data_count; i++)
      assh_sha1_update(&sha1, data[i], data_len[i]);
    ASSH_ERR_RET(assh_hash_bignum(&sha1, &assh_sha1_update, k->xn));
    for (i = 0; ; )
      {
        assh_sha1_update(&sha1, rnd, n / 8);
        assh_sha1_final(&sha1, rnd + i);
        if ((i += 20) >= n / 8)
          break;
        assh_sha1_init(&sha1);
      }
    ASSH_ERR_GTO(assh_bignum_from_data(kn, rnd, n / 8), err_mn);
    ASSH_ERR_GTO(assh_bignum_div(kn, NULL, kn, k->qn), err_kn);
  }

  /* compute R */
  ASSH_BIGNUM_ALLOC(c, rn, l, err_kn);
  ASSH_ERR_GTO(assh_bignum_expmod(rn, k->gn, kn, k->pn), err_rn);
  ASSH_ERR_GTO(assh_bignum_div(rn, NULL, rn, k->qn), err_rn);
  ASSH_ERR_GTO(assh_bignum_shrink(rn, n), err_rn);

  /* compute S */
  ASSH_BIGNUM_ALLOC(c, sn, n, err_rn);

  ASSH_BIGNUM_ALLOC(c, r1, n, err_sn);
  ASSH_ERR_GTO(assh_bignum_mulmod(r1, k->xn, rn, k->qn), err_r1);

  ASSH_BIGNUM_ALLOC(c, r2, n + 1, err_r1);
  ASSH_ERR_GTO(assh_bignum_add(r2, mn, r1), err_r2);

  ASSH_ERR_GTO(assh_bignum_modinv(r1, kn, k->qn), err_r2);

  ASSH_ERR_GTO(assh_bignum_mulmod(sn, r1, r2, k->qn), err_r2);

  ASSH_ERR_GTO(assh_bignum_msb_to_data(rn, r_str, n / 8), err_r2);
  ASSH_ERR_GTO(assh_bignum_msb_to_data(sn, s_str, n / 8), err_r2);

  err = ASSH_OK;

 err_r2:
  ASSH_BIGNUM_FREE(c, r2);
 err_r1:
  ASSH_BIGNUM_FREE(c, r1);
 err_sn:
  ASSH_BIGNUM_FREE(c, sn);
 err_rn:
  ASSH_BIGNUM_FREE(c, rn);
 err_kn:
  ASSH_BIGNUM_FREE(c, kn);
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

  ASSH_ERR_RET(sign_len != assh_dss_id_len + 4 + n * 2 / 8 ? ASSH_ERR_OVERFLOW : 0);

  ASSH_ERR_RET(memcmp(sign, assh_dss_id, assh_dss_id_len) ? ASSH_ERR_BAD_DATA : 0);

  uint8_t *rs_str = (uint8_t*)sign + assh_dss_id_len;
  ASSH_ERR_RET(assh_load_u32(rs_str) != n * 2 / 8 ? ASSH_ERR_OVERFLOW : 0);

  ASSH_BIGNUM_ALLOC(c, rn, n, err_);
  ASSH_ERR_GTO(assh_bignum_from_data(rn, rs_str + 4, n / 8), err_rn);

  ASSH_BIGNUM_ALLOC(c, sn, n, err_rn);
  ASSH_ERR_GTO(assh_bignum_from_data(sn, rs_str + 4 + n / 8, n / 8), err_sn);

  ASSH_ERR_GTO(assh_bignum_cmp(k->qn, rn) > 0 ? ASSH_ERR_BAD_DATA : 0, err_sn);
  ASSH_ERR_GTO(assh_bignum_cmp(k->qn, sn) > 0 ? ASSH_ERR_BAD_DATA : 0, err_sn);
  ASSH_ERR_GTO(assh_bignum_cmpz(rn) ? ASSH_ERR_BAD_DATA : 0, err_sn);
  ASSH_ERR_GTO(assh_bignum_cmpz(sn) ? ASSH_ERR_BAD_DATA : 0, err_sn);

  ASSH_BIGNUM_ALLOC(c, mn, n, err_sn);
  
  ASSH_ERR_GTO(assh_sign_dss_hash(data_count, data, data_len, n, mn), err_mn);

  /* copute w */
  ASSH_BIGNUM_ALLOC(c, wn, n, err_mn);
  ASSH_ERR_GTO(assh_bignum_modinv(wn, sn, k->qn), err_wn);

  ASSH_BIGNUM_ALLOC(c, u1n, n, err_wn);
  ASSH_ERR_GTO(assh_bignum_mulmod(u1n, mn, wn, k->qn), err_u1n);

  ASSH_BIGNUM_ALLOC(c, v1n, l, err_u1n);
  ASSH_ERR_GTO(assh_bignum_expmod(v1n, k->gn, u1n, k->pn), err_v1n);

  ASSH_BIGNUM_ALLOC(c, u2n, n, err_v1n);
  ASSH_ERR_GTO(assh_bignum_mulmod(u2n, rn, wn, k->qn), err_u2n);

  ASSH_BIGNUM_ALLOC(c, v2n, l, err_u2n);
  ASSH_ERR_GTO(assh_bignum_expmod(v2n, k->yn, u2n, k->pn), err_v2n);

  ASSH_BIGNUM_ALLOC(c, vn, l, err_v2n);
  ASSH_ERR_GTO(assh_bignum_mulmod(vn, v1n, v2n, k->pn), err_vn);

  ASSH_ERR_GTO(assh_bignum_div(vn, NULL, vn, k->qn), err_vn);

  ASSH_ERR_GTO(assh_bignum_sub(vn, rn, vn), err_vn);

  *ok = assh_bignum_cmpz(vn);

  err = ASSH_OK;

 err_vn:
  ASSH_BIGNUM_FREE(c, vn);
 err_v2n:
  ASSH_BIGNUM_FREE(c, v2n);
 err_u2n:
  ASSH_BIGNUM_FREE(c, u2n);
 err_v1n:
  ASSH_BIGNUM_FREE(c, v1n);
 err_u1n:
  ASSH_BIGNUM_FREE(c, u1n);
 err_wn:
  ASSH_BIGNUM_FREE(c, wn);
 err_mn:
  ASSH_BIGNUM_FREE(c, mn);
 err_sn:
  ASSH_BIGNUM_FREE(c, sn);
 err_rn:
  ASSH_BIGNUM_FREE(c, rn);
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

