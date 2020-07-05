/*

  libassh - asynchronous ssh2 client/server library.

  Copyright (C) 2013-2020 Alexandre Becoulet <alexandre.becoulet@free.fr>

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

#include "key_openssl_rsa.h"

#include <assh/mod_openssl.h>
#include <assh/assh_packet.h>
#include <assh/assh_buffer.h>
#include <assh/assh_alloc.h>
#include <assh/assh_prng.h>

#include <string.h>

#include <openssl/bn.h>
#include <openssl/rand.h>

static ASSH_KEY_CMP_FCN(assh_key_rsa_cmp)
{
  assert(key->algo == &assh_key_openssl_rsa);

  if (key->algo != b->algo)
    return 0;

  struct assh_key_rsa_s *k = (void*)key;
  struct assh_key_rsa_s *l = (void*)b;

  if (!pub)
    {
      if (k->key.private != l->key.private)
        return 0;
      if (!l->key.private)
        pub = 1;
    }

  const BIGNUM *kn, *ke, *kd, *ln, *le, *ld;
  RSA_get0_key(k->rsa, &kn, &ke, &kd);
  RSA_get0_key(l->rsa, &ln, &le, &ld);

  return (pub || !BN_cmp(kd, ld)) && !BN_cmp(ke, le) && !BN_cmp(kn, ln);
}

static ASSH_KEY_CLEANUP_FCN(assh_key_rsa_cleanup)
{
  struct assh_key_rsa_s *k = (void*)key;

  RSA_free(k->rsa);
  assh_free(c, k);
}

#ifdef CONFIG_ASSH_KEY_CREATE
static assh_status_t
assh_openssl_rng_seed(struct assh_context_s *c)
{
  assh_status_t err;
  if (RAND_status())
    return ASSH_OK;

#ifdef CONFIG_ASSH_USE_OPENSSL_PRNG
  ASSH_RET_IF_TRUE(c->prng == &assh_prng_openssl, ASSH_ERR_CRYPTO);
#endif

  static const size_t len = 128;
  ASSH_SCRATCH_ALLOC(c, uint8_t, data, len, ASSH_ERRSV_CONTINUE, err_);

  while (!RAND_status())
    {
      ASSH_JMP_ON_ERR(assh_prng_get(c, data, len,
			    ASSH_PRNG_QUALITY_LONGTERM_KEY), err_sc);
      RAND_seed(data, len);
    }

  err = ASSH_OK;

 err_sc:
  ASSH_SCRATCH_FREE(c, data);
 err_:
  return err;
}

static ASSH_KEY_CREATE_FCN(assh_key_rsa_create)
{
  assh_status_t err;

  ASSH_RET_IF_TRUE(bits < 1024, ASSH_ERR_NOTSUP);
  bits += bits & 1;

  ASSH_RET_ON_ERR(assh_openssl_rng_seed(c));

  struct assh_key_rsa_s *k;

  ASSH_RET_ON_ERR(assh_alloc(c, sizeof(struct assh_key_rsa_s),
                          ASSH_ALLOC_INTERNAL, (void**)&k));

  k->key.algo = &assh_key_openssl_rsa;
  k->key.type = "ssh-rsa";
  k->key.safety = ASSH_SAFETY_PRIMEFIELD(bits);
  k->key.bits = bits;
  k->key.private = 1;
  k->rsa = RSA_new();

  RSA *rsa = k->rsa;
  ASSH_JMP_IF_TRUE(!rsa, ASSH_ERR_MEM, err_key);

  BIGNUM *ke = BN_new();
  ASSH_JMP_IF_TRUE(!ke, ASSH_ERR_MEM, err_key);

  BN_set_word(ke, 65537);
  int r = RSA_generate_key_ex(rsa, bits, ke, NULL);
  BN_free(ke);
  ASSH_JMP_IF_TRUE(!r, ASSH_ERR_MEM, err_key);

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

  if (!key->private)
    *result = ASSH_KEY_NOT_CHECKED;
  else if (RSA_check_key(k->rsa) == 1)
    *result = ASSH_KEY_GOOD;

  return ASSH_OK;
}
#endif

static ASSH_BLOB_WRITE_FCN(assh_ossl_bn2mpi)
{
  *len = BN_bn2mpi(value, content);
  return ASSH_OK;
}

static ASSH_BLOB_WRITE_FCN(assh_ossl_bn2asn1)
{
  if (!content)
    {
      *len = /* ASN1 header */ 6 + /* sign */ 1 + BN_num_bytes(value);
      return ASSH_OK;
    }

  uint8_t *tail = content + 6 + 1;
  uint8_t *end = tail + BN_bn2bin(value, tail);

  if (end > tail && (tail[0] & 0x80))
    *--tail = 0; /* insert a sign padding byte */

  /* write ASN1 header */
  uint8_t *hend = content;
  assh_append_asn1(&hend, 2, end - tail);

  if (tail > hend)
    {
      /* remove gap */
      memmove(hend, tail, end - tail);
      end -= tail - hend;
    }

  *len = end - content;
  return ASSH_OK;
}

static ASSH_KEY_OUTPUT_FCN(assh_key_rsa_output)
{
  struct assh_key_rsa_s *k = (void*)key;
  assh_status_t err;

  assert(key->algo == &assh_key_openssl_rsa);

  const BIGNUM *kn, *ke, *kd, *kp, *kq, *kdp, *kdq, *ki;

  RSA_get0_key(k->rsa, &kn, &ke, &kd);

  if (k->key.private)
    {
      RSA_get0_factors(k->rsa, &kp, &kq);
      RSA_get0_crt_params(k->rsa, &kdp, &kdq, &ki);
    }

  switch (format)
    {
    case ASSH_KEY_FMT_PUB_RFC4253:
      ASSH_RETURN(assh_blob_write("E7;ssh-rsa s F F", blob, blob_len,
                                  &assh_ossl_bn2mpi, ke,
				  &assh_ossl_bn2mpi, kn));

    case ASSH_KEY_FMT_PUB_PEM_ASN1:
      ASSH_RETURN(assh_blob_write("(F F)a48", blob, blob_len,
                                  &assh_ossl_bn2asn1, kn,
				  &assh_ossl_bn2asn1, ke));

    case ASSH_KEY_FMT_PV_PEM_ASN1:
      ASSH_RET_IF_TRUE(!k->key.private, ASSH_ERR_MISSING_KEY);

      ASSH_RETURN(assh_blob_write("(E1;\x00_a2 F F F F F F F F)a48",
                                  blob, blob_len,
                                  &assh_ossl_bn2asn1, kn,
                                  &assh_ossl_bn2asn1, ke,
                                  &assh_ossl_bn2asn1, kd,
                                  &assh_ossl_bn2asn1, kp,
                                  &assh_ossl_bn2asn1, kq,
                                  &assh_ossl_bn2asn1, kdp,
                                  &assh_ossl_bn2asn1, kdq,
                                  &assh_ossl_bn2asn1, ki));

    case ASSH_KEY_FMT_PV_OPENSSH_V1_KEY:
      ASSH_RET_IF_TRUE(!k->key.private, ASSH_ERR_MISSING_KEY);

      ASSH_RETURN(assh_blob_write("E7;ssh-rsa s F F F F F F", blob, blob_len,
                                  &assh_ossl_bn2mpi, kn,
				  &assh_ossl_bn2mpi, ke,
				  &assh_ossl_bn2mpi, kd,
				  &assh_ossl_bn2mpi, ki,
				  &assh_ossl_bn2mpi, kp,
				  &assh_ossl_bn2mpi, kq));

    default:
      ASSH_RETURN(ASSH_ERR_NOTSUP);
    }

  ASSH_UNREACHABLE();
}

static ASSH_BLOB_SCAN_FCN(assh_ossl_bin2bn)
{
  assh_status_t err;
  BIGNUM *r = BN_bin2bn(content, len, NULL);
  ASSH_RET_IF_TRUE(!r, ASSH_ERR_MEM);
  *(BIGNUM**)pv = r;
  return ASSH_OK;
}

static ASSH_KEY_LOAD_FCN(assh_key_rsa_load)
{
  const uint8_t *blob = *blob_;
  assh_status_t err;

  struct assh_key_rsa_s *k = (void*)*key;

  if (k == NULL)
    {
      ASSH_RET_ON_ERR(assh_alloc(c, sizeof(struct assh_key_rsa_s),
                                 ASSH_ALLOC_INTERNAL, (void**)&k));

      k->key.algo = &assh_key_openssl_rsa;
      k->key.type = "ssh-rsa";
      k->rsa = RSA_new();
      k->key.private = 0;
      ASSH_JMP_IF_TRUE(!k->rsa, ASSH_ERR_MEM, err_);
    }

  BIGNUM *kn = NULL, *ke = NULL, *kd = NULL, *kp = NULL, *kq = NULL;
  BIGNUM *kdp = NULL, *kdq = NULL, *ki = NULL;

  /* parse the key blob */
  switch (format)
    {
    case ASSH_KEY_FMT_PUB_RFC4253:
      ASSH_JMP_ON_ERR(assh_blob_scan(c, "s_t7_e;7;ssh-rsa sF sF $",
                                     &blob, &blob_len,
				     &assh_ossl_bin2bn, &ke,
				     &assh_ossl_bin2bn, &kn), err_bn);

      ASSH_JMP_IF_TRUE(!RSA_set0_key(k->rsa, kn, ke, NULL),
		       ASSH_ERR_CRYPTO, err_bn);
      break;

    case ASSH_KEY_FMT_PUB_PEM_ASN1:
      ASSH_JMP_ON_ERR(assh_blob_scan(c, "a48(a2F a2F) $",
                                     &blob, &blob_len,
				     &assh_ossl_bin2bn, &kn,
				     &assh_ossl_bin2bn, &ke), err_bn);

      ASSH_JMP_IF_TRUE(!RSA_set0_key(k->rsa, kn, ke, NULL),
		       ASSH_ERR_CRYPTO, err_bn);
      break;

    case ASSH_KEY_FMT_PV_OPENSSH_V1_KEY: {
      k->key.private = 1;
      ASSH_JMP_ON_ERR(assh_blob_scan(c, "s_t7_e;7;ssh-rsa sF sF sF sF sF sF $",
                                     &blob, &blob_len,
                                     &assh_ossl_bin2bn, &kn,
				     &assh_ossl_bin2bn, &ke,
				     &assh_ossl_bin2bn, &kd,
				     &assh_ossl_bin2bn, &ki,
				     &assh_ossl_bin2bn, &kp,
				     &assh_ossl_bin2bn, &kq), err_bn);

      ASSH_JMP_IF_TRUE(!RSA_set0_key(k->rsa, kn, ke, kd),
		       ASSH_ERR_CRYPTO, err_bn);
      ASSH_JMP_IF_TRUE(!RSA_set0_factors(k->rsa, kp, kq),
		       ASSH_ERR_CRYPTO, err_bn_ned);

      /* compute missing dq, dp */
      int r = 0;
      BN_CTX *bnctx = BN_CTX_new();
      BIGNUM *tmp = BN_new();
      if (bnctx && tmp)
	{
	  BN_set_flags(kd, BN_FLG_CONSTTIME);
	  BN_set_flags(tmp, BN_FLG_CONSTTIME);
	  kdq = BN_new();
	  kdp = BN_new();
	  if (kdq && kdp)
	    r = (BN_sub(tmp, kq, BN_value_one()) &&
		 BN_mod(kdq, kd, tmp, bnctx) &&
		 BN_sub(tmp, kp, BN_value_one()) &&
		 BN_mod(kdp, kd, tmp, bnctx));
	}
      BN_CTX_free(bnctx);
      BN_free(tmp);

      ASSH_JMP_IF_TRUE(!r || !RSA_set0_crt_params(k->rsa, kdp, kdq, ki),
		       ASSH_ERR_CRYPTO, err_bn_pq);
      break;
    }

    case ASSH_KEY_FMT_PV_PEM_ASN1:
      k->key.private = 1;
      ASSH_JMP_ON_ERR(assh_blob_scan(c, "a48(a2 a2F a2F a2F a2F a2F a2F a2F a2F) $",
                                     &blob, &blob_len,
				     &assh_ossl_bin2bn, &kn,
				     &assh_ossl_bin2bn, &ke,
				     &assh_ossl_bin2bn, &kd,
				     &assh_ossl_bin2bn, &kp,
				     &assh_ossl_bin2bn, &kq,
				     &assh_ossl_bin2bn, &kdp,
				     &assh_ossl_bin2bn, &kdq,
				     &assh_ossl_bin2bn, &ki), err_bn);

      ASSH_JMP_IF_TRUE(!RSA_set0_key(k->rsa, kn, ke, kd),
		       ASSH_ERR_CRYPTO, err_bn);
      ASSH_JMP_IF_TRUE(!RSA_set0_factors(k->rsa, kp, kq),
		       ASSH_ERR_CRYPTO, err_bn_ned);
      ASSH_JMP_IF_TRUE(!RSA_set0_crt_params(k->rsa, kdp, kdq, ki),
		       ASSH_ERR_CRYPTO, err_bn_pq);
      break;

    default:
      ASSH_JMP_ON_ERR(ASSH_ERR_NOTSUP, err_);
    }

  k->key.bits = RSA_bits(k->rsa);
  k->key.safety = ASSH_SAFETY_PRIMEFIELD(k->key.bits);

  *key = &k->key;
  *blob_ = blob;
  return ASSH_OK;

 err_bn:
  BN_free(kn);
  BN_free(ke);
  BN_free(kd);
 err_bn_ned:
  BN_free(kp);
  BN_free(kq);
 err_bn_pq:
  BN_free(kdp);
  BN_free(kdq);
  BN_free(ki);
 err_:
  assh_key_rsa_cleanup(c, &k->key);
  return err;
}

const struct assh_key_algo_s assh_key_openssl_rsa =
{
  .name = "ssh-rsa",
  .implem = "assh-openssl",
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

