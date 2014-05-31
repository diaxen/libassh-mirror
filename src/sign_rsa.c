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

/************************************************************ rsa key */

enum assh_rsa_digest_e
{
  RSA_DIGEST_MD2,
  RSA_DIGEST_MD5,
  RSA_DIGEST_SHA1,
  RSA_DIGEST_SHA256,
  RSA_DIGEST_SHA384,
  RSA_DIGEST_SHA512,
  RSA_DIGEST_count,
};

struct assh_sign_rsa_key_s
{
  struct assh_key_s key;

  /* RSA modulus */
  struct assh_bignum_s *nn;
  /* RSA exponents */
  struct assh_bignum_s *en;
  struct assh_bignum_s *dn;
};

struct assh_rsa_digest_s
{
  /* asn1 DER digest algorithm identifier */
  uint_fast8_t oid_len;
  const char *oid;

  const struct assh_hash_s *algo;
};

static const struct assh_rsa_digest_s assh_rsa_digests[RSA_DIGEST_count] =
{
 /* len   DigestInfo header */
  { 18, "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x02\x05\x00\x04\x10",
    NULL /* md2 */ },
  { 18, "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10",
    &assh_hash_md5 },
  { 15, "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14",
    &assh_hash_sha1 },
  { 19, "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20",
    &assh_hash_sha256 },
  { 19, "\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30",
    &assh_hash_sha384 },
  { 19, "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40",
    &assh_hash_sha512 },
};

static const char *assh_rsa_id = "\x00\x00\x00\x07ssh-rsa";
static const size_t assh_rsa_id_len = 4 + 7;

static ASSH_KEY_CLEANUP_FCN(assh_sign_rsa_key_cleanup)
{
  struct assh_sign_rsa_key_s *k = (void*)key;

  assh_bignum_cleanup(c, k->nn);
  assh_bignum_cleanup(c, k->en);
  if (k->dn != NULL)
    assh_bignum_cleanup(c, k->dn);
  assh_free(c, k, ASSH_ALLOC_KEY);
}

static ASSH_KEY_OUTPUT_FCN(assh_sign_rsa_key_output)
{
  struct assh_sign_rsa_key_s *k = (void*)key;
  assh_error_t err;

  struct assh_bignum_s *bn_[4] = { k->en, k->nn, NULL, NULL };

  switch (format)
    {
    case ASSH_KEY_FMT_PUB_RFC4253_6_6: {
      /* add algo identifier */
      size_t l = assh_rsa_id_len;
      if (blob != NULL)
        {
          ASSH_CHK_RET(assh_rsa_id_len > *blob_len, ASSH_ERR_OUTPUT_OVERFLOW);
          memcpy(blob, assh_rsa_id, assh_rsa_id_len);
          *blob_len -= assh_rsa_id_len;
          blob += assh_rsa_id_len;
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

static ASSH_KEY_CMP_FCN(assh_sign_rsa_key_cmp)
{
  assert(!strcmp(key->type, "ssh-rsa"));

  if (strcmp(key->type, b->type))
    return 0;

  struct assh_sign_rsa_key_s *k = (void*)key;
  struct assh_sign_rsa_key_s *l = (void*)b;

  return (!assh_bignum_cmp(k->nn, l->nn) && 
          !assh_bignum_cmp(k->en, l->en) && 
          (pub || (k->dn == NULL && l->dn == NULL) ||
           (k->dn != NULL && l->dn != NULL && !assh_bignum_cmp(k->dn, l->dn))));
}

static ASSH_KEY_VALIDATE_FCN(assh_sign_rsa_key_validate)
{
  struct assh_sign_rsa_key_s *k = (void*)key;
  assh_error_t err = ASSH_OK;

  unsigned int n = assh_bignum_bits(k->nn);

#if 0
  /* check key size */
  if (n < 768 || n > 8192 || n % 8)
    return ASSH_OK;

  enum bytecode_args_e
  {
    E
  };

  assh_bignum_op_t bytecode[] = {
    ASSH_BIGNUM_BC_END(),
  };

  err = assh_bignum_bytecode(c, bytecode, "NNNNTT");

  if (err != ASSH_ERR_NUM_COMPARE_FAILED)
    ASSH_ERR_RET(err);
#endif
#warning rsa key validate

  return ASSH_OK;
}

static inline unsigned int
assh_sign_rsa_mpint_strip(uint8_t *num, unsigned int len)
{
  /* discard null MSB */
  if (len && num[0] == 0)
    len--;
  return len * 8;
}

static ASSH_KEY_LOAD_FCN(assh_sign_rsa_key_load)
{
  assh_error_t err;

  unsigned int n_len, e_len, d_len;
  uint8_t *n_str, *e_str, *d_str;

  /* parse the key blob */
  switch (format)
    {
    case ASSH_KEY_FMT_PUB_RFC4253_6_6: {

      ASSH_CHK_RET(blob_len < assh_rsa_id_len, ASSH_ERR_INPUT_OVERFLOW);
      ASSH_CHK_RET(memcmp(assh_rsa_id, blob, assh_rsa_id_len), ASSH_ERR_BAD_DATA);

      e_str = (uint8_t*)blob + assh_rsa_id_len;
      ASSH_ERR_RET(assh_check_string(blob, blob_len, e_str, &n_str));
      e_len = assh_sign_rsa_mpint_strip(e_str + 4, assh_load_u32(e_str));

      ASSH_ERR_RET(assh_check_string(blob, blob_len, n_str, NULL));
      n_len = assh_sign_rsa_mpint_strip(n_str + 4, assh_load_u32(n_str));

      d_len = 0;
      d_str = NULL;
      break;
    }

    case ASSH_KEY_FMT_PV_PEM_ASN1: {
      uint8_t *seq, *seq_end, *p_str, *version, *val;
      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, blob, &seq, &seq_end));
      /* sequence type */
      ASSH_CHK_RET(blob[0] != 0x30, ASSH_ERR_BAD_DATA);

      /* skip first value */
      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, seq, &version, &n_str));

      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, n_str, &val, &e_str));
      n_len = assh_sign_rsa_mpint_strip(val, e_str - val);

      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, e_str, &val, &d_str));
      e_len = assh_sign_rsa_mpint_strip(val, d_str - val);

      ASSH_ERR_RET(assh_check_asn1(blob, blob_len, d_str, &val, &p_str));
      d_len = assh_sign_rsa_mpint_strip(val, p_str - val);
      break;
    }

    default:
      ASSH_ERR_RET(ASSH_ERR_NOTSUP);
    }

  /* allocate key structure */
  ASSH_CHK_RET(n_len < 768 || n_len > 8192, ASSH_ERR_NOTSUP);
  ASSH_CHK_RET(e_len < 1 || e_len > 32, ASSH_ERR_NOTSUP);
  ASSH_CHK_RET(d_str != NULL && (d_len < 768 || d_len > 8192), ASSH_ERR_NOTSUP);

  size_t size = sizeof(struct assh_sign_rsa_key_s)
    + assh_bignum_sizeof(n_len)
    + assh_bignum_sizeof(e_len);

  if (d_str != NULL)
    size += assh_bignum_sizeof(d_len);

  ASSH_ERR_RET(assh_alloc(c, size, ASSH_ALLOC_KEY, (void**)key));
  struct assh_sign_rsa_key_s *k = (void*)*key;

  k->key.type = "ssh-rsa";
  k->key.f_output = assh_sign_rsa_key_output;
  k->key.f_validate = assh_sign_rsa_key_validate;
  k->key.f_cmp = assh_sign_rsa_key_cmp;
  k->key.f_cleanup = assh_sign_rsa_key_cleanup;

  /* init key structure */
  k->nn = (struct assh_bignum_s*)(k + 1);
  k->en = (struct assh_bignum_s*)((uint8_t*)k->nn + assh_bignum_sizeof(n_len));
  k->dn = (struct assh_bignum_s*)((d_str != NULL) ? (uint8_t*)k->en + assh_bignum_sizeof(e_len) : NULL);

  /* init numbers */
  assh_bignum_init(c, k->nn, n_len);
  assh_bignum_init(c, k->en, e_len);

  if (d_str != NULL)
    assh_bignum_init(c, k->dn, d_len);

  /* convert numbers from blob representation */
  switch (format)
    {
    case ASSH_KEY_FMT_PUB_RFC4253_6_6:
      ASSH_ERR_GTO(assh_bignum_from_mpint(k->nn, NULL, n_str), err_num);
      ASSH_ERR_GTO(assh_bignum_from_mpint(k->en, NULL, e_str), err_num);
      break;

    case ASSH_KEY_FMT_PV_PEM_ASN1:
      ASSH_ERR_GTO(assh_bignum_from_asn1(k->nn, NULL, n_str), err_num);
      ASSH_ERR_GTO(assh_bignum_from_asn1(k->en, NULL, e_str), err_num);
      ASSH_ERR_GTO(assh_bignum_from_asn1(k->dn, NULL, d_str), err_num);
    default:
      break;
    }

#ifdef CONFIG_ASSH_DEBUG_SIGN
  assh_bignum_print(stderr, "rsa key n", k->nn);
  assh_bignum_print(stderr, "rsa key e", k->en);
  if (k->dn != NULL)
    assh_bignum_print(stderr, "rsa key d", k->dn);
#endif

  return ASSH_OK;

 err_num:
  assh_bignum_cleanup(c, k->nn);
  assh_bignum_cleanup(c, k->en);
  if (k->dn != NULL)
    assh_bignum_cleanup(c, k->dn);
  assh_free(c, k, ASSH_ALLOC_KEY);
  return err;
}

/************************************************************ rsa sign algo */

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_sign_rsa_generate(struct assh_context_s *c, const struct assh_key_s *key, size_t data_count,
                       const uint8_t * const data[], size_t const data_len[],
                       uint8_t *sign, size_t *sign_len, enum assh_rsa_digest_e digest_id)
{
  struct assh_sign_rsa_key_s *k = (void*)key;
  assh_error_t err;

  assert(!strcmp(key->type, "ssh-rsa"));

  /* check availability of the private key */
  ASSH_CHK_RET(k->dn == NULL, ASSH_ERR_MISSING_KEY);

  unsigned int n = assh_bignum_bits(k->nn);

  /* check/return signature length */
  size_t len = assh_rsa_id_len + 4 + n / 8;

  if (sign == NULL)
    {
      *sign_len = len;
      return ASSH_OK;
    }

  ASSH_CHK_RET(*sign_len < len, ASSH_ERR_OUTPUT_OVERFLOW);
  *sign_len = len;

  const struct assh_rsa_digest_s *digest = assh_rsa_digests + digest_id;
  ASSH_CHK_RET(digest->algo == NULL, ASSH_ERR_NOTSUP);

  /* build encoded message buffer */
  unsigned int ps_len = n / 8 - 3 - digest->oid_len - digest->algo->hash_size;

  ASSH_CHK_RET(ps_len < 8, ASSH_ERR_BAD_DATA);

  ASSH_SCRATCH_ALLOC(c, uint8_t, scratch,
                     digest->algo->ctx_size + n / 8,
                     ASSH_ERRSV_CONTINUE, err_);

  uint8_t *em_buf = scratch + digest->algo->ctx_size;
  uint8_t *em = em_buf;

  *em++ = 0x00;
  *em++ = 0x01;
  memset(em, 0xff, ps_len);
  em += ps_len;
  *em++ = 0x00;
  memcpy(em, digest->oid, digest->oid_len);
  em += digest->oid_len;

  uint_fast16_t i;
  void *hash_ctx = scratch;
  digest->algo->f_init(hash_ctx);
  for (i = 0; i < data_count; i++)
    digest->algo->f_update(hash_ctx, data[i], data_len[i]);
  digest->algo->f_final(hash_ctx, em);

  /* build signature blob */
  memcpy(sign, assh_rsa_id, assh_rsa_id_len);
  assh_store_u32(sign + assh_rsa_id_len, n / 8);
  uint8_t *c_str = sign + assh_rsa_id_len + 4;

#ifdef CONFIG_ASSH_DEBUG_SIGN
  assh_hexdump("rsa generate em", em_buf, n / 8);
#endif

  enum bytecode_args_e
  {
    C_data, EM_data,            /* data buffers */
    N, D,                       /* big number inputs */
    C, EM                       /* big number temporaries */
  };

  assh_bignum_op_t bytecode[] = {
    ASSH_BIGNUM_BC_MOVE(        EM,      EM_data        ),

    ASSH_BIGNUM_BC_SETMOD(      N                       ),
    ASSH_BIGNUM_BC_EXPMOD(      C,     EM,      D       ),

    ASSH_BIGNUM_BC_MOVE(        C_data, C               ),
    ASSH_BIGNUM_BC_END(),
  };

  ASSH_ERR_GTO(assh_bignum_bytecode(c, bytecode, "DDNNTT",
                                    /* Data */ c_str, em_buf,
                                    /* Num  */ k->nn, k->dn,
                                    /* Temp */ n, n), err_scratch);

  err = ASSH_OK;

 err_scratch:
  ASSH_SCRATCH_FREE(c, scratch);
 err_:
  return err;
}

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_sign_rsa_verify(struct assh_context_s *c,
                     const struct assh_key_s *key, size_t data_count,
                     const uint8_t * const data[], size_t const data_len[],
                     const uint8_t *sign, size_t sign_len, uint8_t digest_mask)
{
  struct assh_sign_rsa_key_s *k = (void*)key;
  assh_error_t err;

  assert(!strcmp(key->type, "ssh-rsa"));

  unsigned int n = assh_bignum_bits(k->nn);

  ASSH_CHK_RET(sign_len != assh_rsa_id_len + 4 + n / 8, ASSH_ERR_INPUT_OVERFLOW);

  ASSH_CHK_RET(memcmp(sign, assh_rsa_id, assh_rsa_id_len), ASSH_ERR_BAD_DATA);

  uint8_t *c_str = (uint8_t*)sign + assh_rsa_id_len;
  ASSH_CHK_RET(assh_load_u32(c_str) != n / 8, ASSH_ERR_INPUT_OVERFLOW);

  ASSH_SCRATCH_ALLOC(c, uint8_t, em_buf, n / 8, ASSH_ERRSV_CONTINUE, err_);
  uint8_t *em = em_buf;

  enum bytecode_args_e
  {
    C_data, EM_data,            /* data buffers */
    N, E,                       /* big number inputs */
    C, EM                       /* big number temporaries */
  };

  assh_bignum_op_t bytecode[] = {
    ASSH_BIGNUM_BC_MOVE(        C,      C_data        ),

    ASSH_BIGNUM_BC_SETMOD(      N                     ),
    ASSH_BIGNUM_BC_EXPMOD(      EM,     C,      E     ),

    ASSH_BIGNUM_BC_MOVE(        EM_data, EM           ),
    ASSH_BIGNUM_BC_END(),
  };

  ASSH_ERR_GTO(assh_bignum_bytecode(c, bytecode, "DDNNTT",
                                    /* Data */ c_str + 4, em,
                                    /* Nun  */ k->nn, k->en,
                                    /* Temp */ n, n), err_em);

#ifdef CONFIG_ASSH_DEBUG_SIGN
  assh_hexdump("rsa verify em", em, n / 8);
#endif

  uint8_t *em_end = em + n / 8;
  uint_fast16_t i;

  /* check padding */
  ASSH_CHK_GTO(*em++ != 0x00, ASSH_ERR_BAD_DATA, err_em);
  ASSH_CHK_GTO(*em++ != 0x01, ASSH_ERR_BAD_DATA, err_em);
  for (i = 0; em + 1 < em_end && *em == 0xff; em++)
    i++;
  ASSH_CHK_GTO(i < 8, ASSH_ERR_BAD_DATA, err_em);
  ASSH_CHK_GTO(*em++ != 0x00, ASSH_ERR_BAD_DATA, err_em);

  /* lookup digest algorithm in use */
  const struct assh_rsa_digest_s *digest;
  for (i = 0; i < RSA_DIGEST_count; i++)
    {
      digest = assh_rsa_digests + i;
      if (digest->algo == NULL)
        continue;
      if (digest->oid_len + digest->algo->hash_size != em_end - em)
        continue;
      if (!memcmp(digest->oid, em, digest->oid_len))
        break;
    }

  ASSH_CHK_GTO(i == RSA_DIGEST_count, ASSH_ERR_NOTSUP, err_em);
  ASSH_CHK_GTO(!((digest_mask >> i) & 1), ASSH_ERR_WEAK_ALGORITHM, err_em);

  /* compute message hash */
  em += digest->oid_len;
  ASSH_SCRATCH_ALLOC(c, void, hash_ctx, digest->algo->ctx_size +
                     digest->algo->hash_size,
                     ASSH_ERRSV_CONTINUE, err_em);

  uint8_t *hash = hash_ctx + digest->algo->ctx_size;

  digest->algo->f_init(hash_ctx);
  for (i = 0; i < data_count; i++)
    digest->algo->f_update(hash_ctx, data[i], data_len[i]);
  digest->algo->f_final(hash_ctx, hash);

#ifdef CONFIG_ASSH_DEBUG_SIGN
  assh_hexdump("rsa verify hash", hash, digest->algo->hash_size);
#endif

  ASSH_CHK_GTO(assh_memcmp(hash, em, digest->algo->hash_size),
               ASSH_ERR_NUM_COMPARE_FAILED, err_hash);

  err = ASSH_OK;

 err_hash:
  ASSH_SCRATCH_FREE(c, hash_ctx);
 err_em:
  ASSH_SCRATCH_FREE(c, em_buf);
 err_:
  return err;
}

static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_rsa_suitable_key_768)
{
  if (strcmp(key->type, "ssh-rsa"))
    return 0;
  struct assh_sign_rsa_key_s *k = (void*)key;
  return assh_bignum_bits(k->nn) >= 768;
}

static ASSH_SIGN_VERIFY_FCN(assh_sign_rsa_verify_sha1_md5)
{
  return assh_sign_rsa_verify(c, key, data_count, data, data_len,
                              sign, sign_len, (1 << RSA_DIGEST_SHA1)
                              | (1 << RSA_DIGEST_MD5));
}

static ASSH_SIGN_GENERATE_FCN(assh_sign_rsa_generate_sha1)
{
  return assh_sign_rsa_generate(c, key, data_count, data, data_len,
                                sign, sign_len, RSA_DIGEST_SHA1);
}

struct assh_algo_sign_s assh_sign_rsa_sha1_md5 =
{
  .algo = {
    .name = "ssh-rsa", .variant = "sha1, md5, 768+ bits keys",
    .class_ = ASSH_ALGO_SIGN,
    .priority = 2, .safety = 15, .speed = 40,
    .f_suitable_key = assh_sign_rsa_suitable_key_768,
  },
  .key_type = "ssh-rsa",
  .f_key_load = assh_sign_rsa_key_load,
  .f_generate = assh_sign_rsa_generate_sha1,
  .f_verify = assh_sign_rsa_verify_sha1_md5,
};



static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_rsa_suitable_key_1024)
{
  if (strcmp(key->type, "ssh-rsa"))
    return 0;
  struct assh_sign_rsa_key_s *k = (void*)key;
  return assh_bignum_bits(k->nn) >= 1024;
}

static ASSH_SIGN_VERIFY_FCN(assh_sign_rsa_verify_sha1)
{
  return assh_sign_rsa_verify(c, key, data_count, data, data_len,
                              sign, sign_len, (1 << RSA_DIGEST_SHA1));
}

struct assh_algo_sign_s assh_sign_rsa_sha1 =
{
  .algo = {
    .name = "ssh-rsa",  .variant = "sha1, 1024+ bits keys",
    .class_ = ASSH_ALGO_SIGN,
    .priority = 1, .safety = 20, .speed = 40,
    .f_suitable_key = assh_sign_rsa_suitable_key_1024,
  },
  .key_type = "ssh-rsa",
  .f_key_load = assh_sign_rsa_key_load,
  .f_generate = assh_sign_rsa_generate_sha1,
  .f_verify = assh_sign_rsa_verify_sha1,
};



static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_rsa_suitable_key_2048)
{
  if (strcmp(key->type, "ssh-rsa"))
    return 0;
  struct assh_sign_rsa_key_s *k = (void*)key;
  return assh_bignum_bits(k->nn) >= 2048;
}

struct assh_algo_sign_s assh_sign_rsa_sha1_2048 =
{
  .algo = {
    .name = "ssh-rsa", .variant = "sha1, 2048+ bits keys",
    .class_ = ASSH_ALGO_SIGN,
    .priority = 0, .safety = 25, .speed = 30,
    .f_suitable_key = assh_sign_rsa_suitable_key_2048,
  },
  .key_type = "ssh-rsa",
  .f_key_load = assh_sign_rsa_key_load,
  .f_generate = assh_sign_rsa_generate_sha1,
  .f_verify = assh_sign_rsa_verify_sha1,
};



static ASSH_SIGN_VERIFY_FCN(assh_sign_rsa_verify_sha256)
{
  return assh_sign_rsa_verify(c, key, data_count, data, data_len,
                              sign, sign_len, (1 << RSA_DIGEST_SHA256));
}

static ASSH_SIGN_GENERATE_FCN(assh_sign_rsa_generate_sha256)
{
  return assh_sign_rsa_generate(c, key, data_count, data, data_len,
                                sign, sign_len, RSA_DIGEST_SHA256);
}

struct assh_algo_sign_s assh_sign_rsa_sha256 =
{
  .algo = {
    .name = "rsa2048-sha256@libassh.org",
    .class_ = ASSH_ALGO_SIGN,
    .safety = 40, .speed = 30,
    .f_suitable_key = assh_sign_rsa_suitable_key_2048,
  },
  .key_type = "ssh-rsa",
  .f_key_load = assh_sign_rsa_key_load,
  .f_generate = assh_sign_rsa_generate_sha256,
  .f_verify = assh_sign_rsa_verify_sha256,
};



static ASSH_SIGN_VERIFY_FCN(assh_sign_rsa_verify_sha512)
{
  return assh_sign_rsa_verify(c, key, data_count, data, data_len,
                              sign, sign_len, (1 << RSA_DIGEST_SHA512));
}

static ASSH_SIGN_GENERATE_FCN(assh_sign_rsa_generate_sha512)
{
  return assh_sign_rsa_generate(c, key, data_count, data, data_len,
                                sign, sign_len, RSA_DIGEST_SHA512);
}

struct assh_algo_sign_s assh_sign_rsa_sha512 =
{
  .algo = {
    .name = "rsa2048-sha512@libassh.org",
    .class_ = ASSH_ALGO_SIGN,
    .safety = 40, .speed = 30,
    .f_suitable_key = assh_sign_rsa_suitable_key_2048,
  },
  .key_type = "ssh-rsa",
  .f_key_load = assh_sign_rsa_key_load,
  .f_generate = assh_sign_rsa_generate_sha512,
  .f_verify = assh_sign_rsa_verify_sha512,
};

