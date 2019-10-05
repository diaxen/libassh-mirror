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

/*
  This file implements rfc4432
*/

#include <assh/assh_kex.h>
#include <assh/assh_session.h>
#include <assh/assh_packet.h>
#include <assh/assh_transport.h>
#include <assh/assh_bignum.h>
#include <assh/assh_sign.h>
#include <assh/assh_prng.h>
#include <assh/assh_event.h>
#include <assh/assh_alloc.h>
#include <assh/assh_hash.h>
#include <assh/assh_cipher.h>
#include <assh/key_rsa.h>

#include <string.h>
#include <stdlib.h>

enum assh_kex_rsa_state_e
{
#ifdef CONFIG_ASSH_CLIENT
  ASSH_KEX_RSA_CLIENT_WAIT_PUBKEY,
  ASSH_KEX_RSA_CLIENT_LOOKUP_HOST_KEY_WAIT,
  ASSH_KEX_RSA_CLIENT_WAIT_SIGN,
#endif
#ifdef CONFIG_ASSH_SERVER
  ASSH_KEX_RSA_SERVER_SEND_PUBKEY,
  ASSH_KEX_RSA_SERVER_WAIT_SECRET,
#endif
};

struct assh_kex_rsa_private_s
{
  const struct assh_hash_algo_s *hash;

  const uint8_t *lhash;

  union {
#ifdef CONFIG_ASSH_SERVER
    struct {
      struct assh_key_s *host_key;
      struct assh_key_s *t_key;
      void *hash_ctx;
    };
#endif
#ifdef CONFIG_ASSH_CLIENT
    struct {
      struct assh_packet_s *pck;
      uint8_t *secret;
    };
#endif
  };

  enum assh_kex_rsa_state_e state:8;
  uint16_t minklen;
};

static assh_status_t assh_kex_rsa_mgf1(struct assh_context_s *c,
				      const struct assh_hash_algo_s *algo,
				      const uint8_t *in, size_t inlen,
				      uint8_t *out, size_t outlen)
{
  assh_status_t err;
  uint32_t i;
  size_t j, k;
  uint8_t cnt[4];

  assert(algo->hash_size != 0);

  ASSH_SCRATCH_ALLOC(c, uint8_t, scratch,
                     algo->ctx_size * 2 + algo->hash_size,
                     ASSH_ERRSV_CONTINUE, err_);

  void *hash_ctx1 = scratch;
  void *hash_ctx2 = scratch + algo->ctx_size;
  uint8_t *tmp = scratch + algo->ctx_size * 2;

  ASSH_JMP_ON_ERR(assh_hash_init(c, hash_ctx1, algo), err_scratch);
  assh_hash_update(hash_ctx1, in, inlen);

  for (i = j = 0; j + algo->hash_size < outlen; j += algo->hash_size)
    {
      ASSH_JMP_ON_ERR(assh_hash_copy(hash_ctx2, hash_ctx1), err_hash);
      assh_store_u32(cnt, i++);
      assh_hash_update(hash_ctx2, cnt, 4);
      assh_hash_final(hash_ctx2, tmp, algo->hash_size);
      assh_hash_cleanup(hash_ctx2);
      for (k = 0; k < algo->hash_size; k++)
	out[j + k] ^= tmp[k];
    }

  assh_store_u32(cnt, i++);
  assh_hash_update(hash_ctx1, cnt, 4);
  assh_hash_final(hash_ctx1, tmp, algo->hash_size);
  assh_hash_cleanup(hash_ctx1);
  for (k = 0; k < outlen - j; k++)
    out[j + k] ^= tmp[k];

  ASSH_SCRATCH_FREE(c, scratch);
  return ASSH_OK;

 err_hash:
  assh_hash_cleanup(hash_ctx1);
 err_scratch:
  ASSH_SCRATCH_FREE(c, scratch);
 err_:
  return err;
}

#ifdef CONFIG_ASSH_CLIENT

static ASSH_EVENT_DONE_FCN(assh_kex_rsa_host_key_lookup_done)
{
  struct assh_context_s *c = s->ctx;
  struct assh_kex_rsa_private_s *pv = s->kex_pv;
  assh_status_t err;

  assert(pv->state == ASSH_KEX_RSA_CLIENT_LOOKUP_HOST_KEY_WAIT);

  if (!e->kex.hostkey_lookup.accept || ASSH_STATUS(inerr))
    ASSH_RETURN(assh_kex_end(s, 0) | ASSH_ERRSV_DISCONNECT);

  /* SSH_MSG_KEXRSA_PUBKEY packet */
  struct assh_packet_s *p = pv->pck;
  const uint8_t *ks_str = p->head.end;
  const uint8_t *t_str;
  ASSH_ASSERT(assh_packet_check_string(p, ks_str, &t_str));

  /* load transient RSA key */
  struct assh_key_s *t_key_ = NULL;

  const uint8_t *key_blob = t_str + 4;
  ASSH_RET_ON_ERR(assh_key_load(c, &t_key_, &assh_key_rsa, ASSH_ALGO_ANY,
    ASSH_KEY_FMT_PUB_RFC4253, &key_blob, assh_load_u32(t_str))
               | ASSH_ERRSV_DISCONNECT);

  const struct assh_key_rsa_s *t_key = (const void*)t_key_;

  size_t kbits = assh_bignum_bits(&t_key->nn);

  ASSH_JMP_IF_TRUE(kbits < pv->minklen, ASSH_ERR_BAD_DATA
               | ASSH_ERRSV_DISCONNECT, err_tkey);

  /* create shared secret */
  size_t hlen = pv->hash->hash_size;
  size_t sbits = kbits - 2 * hlen * 8 - 49;
  size_t slen = 4 + ASSH_ALIGN8(sbits) / 8;

  size_t elen = ASSH_ALIGN8(kbits) / 8;

  ASSH_JMP_ON_ERR(assh_alloc(c, slen + 4 + elen, ASSH_ALLOC_SECUR,
			  (void**)&pv->secret)
               | ASSH_ERRSV_DISCONNECT, err_tkey);

  uint8_t *secret = pv->secret;
  uint8_t *em = secret + slen + 4;
  assh_store_u32(em - 4, elen);

  ASSH_JMP_ON_ERR(assh_prng_get(c, secret + 4, slen - 4,
		ASSH_PRNG_QUALITY_EPHEMERAL_KEY)
               | ASSH_ERRSV_DISCONNECT, err_tkey);
  assh_store_u32(secret, slen - 4);
  secret[4] &= 0x7f & (0xff >> ((8 - sbits) & 7));

#ifdef CONFIG_ASSH_DEBUG_KEX
  ASSH_DEBUG_HEXDUMP("secret", secret, slen);
#endif

  /* encode secret using OAEP */

  em[0] = 0;
  uint8_t *seed = em + 1;
  ASSH_JMP_ON_ERR(assh_prng_get(c, seed, hlen,
		ASSH_PRNG_QUALITY_NONCE)
               | ASSH_ERRSV_DISCONNECT, err_tkey);

  uint8_t *db = em + 1 + hlen;
  memcpy(db, pv->lhash, hlen); /* hash of empty label */
  memset(db + hlen, 0, elen - slen - 2 - 2 * hlen);

  uint8_t *m = em + elen - slen;
  m[-1] = 0x01;
  memcpy(m, secret, slen);

#ifdef CONFIG_ASSH_DEBUG_KEX
  ASSH_DEBUG_HEXDUMP("e", em, elen);
#endif

  ASSH_JMP_ON_ERR(assh_kex_rsa_mgf1(c, pv->hash,
	         em + 1, hlen, db, elen - hlen - 1)
               | ASSH_ERRSV_DISCONNECT, err_tkey);
  ASSH_JMP_ON_ERR(assh_kex_rsa_mgf1(c, pv->hash,
                 db, elen - hlen - 1, em + 1, hlen)
               | ASSH_ERRSV_DISCONNECT, err_tkey);

#ifdef CONFIG_ASSH_DEBUG_KEX
  ASSH_DEBUG_HEXDUMP("em", em, elen);
#endif

  /* encrypt encoded secret using the transient RSA key */

  enum bytecode_args_e
  {
    EM_data,                    /* data buffer */
    N, E,                       /* big number inputs */
    A, B, MT                    /* big number temporaries */
  };

  static const assh_bignum_op_t bytecode[] = {
    ASSH_BOP_SIZER(     A,      MT,     N		),

    ASSH_BOP_MOVES(     A,      EM_data                 ),

    ASSH_BOP_MTINIT(    MT,     N                       ),
    ASSH_BOP_MTTO(      A,      A,      A,      MT      ),
    ASSH_BOP_EXPM(      B,      A,      E,	MT	),
    ASSH_BOP_MTFROM(    B,      B,      B,      MT      ),

    ASSH_BOP_MOVE(      EM_data, B			),
    ASSH_BOP_END(),
  };

  ASSH_JMP_ON_ERR(assh_bignum_bytecode(c, 0, bytecode, "DNNTTm",
                em, &t_key->nn, &t_key->en)
               | ASSH_ERRSV_DISCONNECT, err_tkey);

#ifdef CONFIG_ASSH_DEBUG_KEX
  ASSH_DEBUG_HEXDUMP("emc", em, elen);
#endif

  /* send packet with encrypted secret */
  struct assh_packet_s *pout;
  ASSH_JMP_ON_ERR(assh_packet_alloc(c, SSH_MSG_KEXRSA_SECRET, 4 + elen, &pout)
	       | ASSH_ERRSV_DISCONNECT, err_tkey);

  uint8_t *e_str;
  ASSH_ASSERT(assh_packet_add_string(pout, elen, &e_str));
  memcpy(e_str, em, elen);

  assh_transport_push(s, pout);

  ASSH_SET_STATE(pv, state, ASSH_KEX_RSA_CLIENT_WAIT_SIGN);

  err = ASSH_OK;

 err_tkey:
  assh_key_drop(c, &t_key_);
  return err;
}

static assh_status_t assh_kex_rsa_client_wait_pubkey(struct assh_session_s *s,
						    struct assh_packet_s *p,
						    struct assh_event_s *e)
{
  struct assh_kex_rsa_private_s *pv = s->kex_pv;
  assh_status_t err;

  ASSH_RET_IF_TRUE(p->head.msg != SSH_MSG_KEXRSA_PUBKEY, ASSH_ERR_PROTOCOL);

  const uint8_t *ks_str = p->head.end;
  const uint8_t *t_str;

  ASSH_RET_ON_ERR(assh_packet_check_string(p, ks_str, &t_str));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, t_str, NULL));

  ASSH_RET_ON_ERR(assh_kex_client_get_key(s, ks_str, e,
                 &assh_kex_rsa_host_key_lookup_done, pv));

  ASSH_SET_STATE(pv, state, ASSH_KEX_RSA_CLIENT_LOOKUP_HOST_KEY_WAIT);
  pv->pck = assh_packet_refinc(p);

  return ASSH_OK;
}

static assh_status_t assh_kex_rsa_client_wait_sign(struct assh_session_s *s,
						  struct assh_packet_s *p)
{
  struct assh_kex_rsa_private_s *pv = s->kex_pv;
  assh_status_t err;

  /* SSH_MSG_KEXRSA_PUBKEY packet */
  const uint8_t *ks_str = pv->pck->head.end;
  const uint8_t *t_str;
  ASSH_ASSERT(assh_packet_check_string(pv->pck, ks_str, &t_str));

  /* SSH_MSG_KEXRSA_DONE packet */
  ASSH_RET_IF_TRUE(p->head.msg != SSH_MSG_KEXRSA_DONE, ASSH_ERR_PROTOCOL);

  uint8_t *h_str = p->head.end;
  ASSH_RET_ON_ERR(assh_packet_check_string(p, h_str, NULL));

  ASSH_SCRATCH_ALLOC(s->ctx, uint8_t, scratch,
                     pv->hash->ctx_size,
                     ASSH_ERRSV_CONTINUE, err_);
  void *hash_ctx = scratch;

  ASSH_JMP_ON_ERR(assh_hash_init(s->ctx, hash_ctx, pv->hash), err_scratch);

  ASSH_JMP_ON_ERR(assh_kex_client_hash1(s, hash_ctx, ks_str), err_hash);

  assh_hash_string(hash_ctx, t_str);
  assh_hash_string(hash_ctx, pv->secret + assh_load_u32(pv->secret) + 4);

  ASSH_JMP_ON_ERR(assh_kex_client_hash2(s, hash_ctx, pv->secret, h_str), err_hash);

  ASSH_JMP_ON_ERR(assh_kex_end(s, 1), err_hash);

  err = ASSH_OK;

 err_hash:
  assh_hash_cleanup(hash_ctx);
 err_scratch:
  ASSH_SCRATCH_FREE(s->ctx, scratch);
 err_:
  return err;
}
#endif

#ifdef CONFIG_ASSH_SERVER
static assh_status_t assh_kex_rsa_server_send_pubkey(struct assh_session_s *s)
{
  assh_status_t err;
  struct assh_context_s *c = s->ctx;
  struct assh_kex_rsa_private_s *pv = s->kex_pv;

  /* look for an host key pair which can be used with the selected algorithm. */

  struct assh_key_s *hk;
  ASSH_RET_IF_TRUE(assh_key_lookup(c, &hk, &s->host_sign_algo->algo) != ASSH_OK,
               ASSH_ERR_MISSING_KEY);
  pv->host_key = hk;

  /* alloc reply packet */
  size_t ks_len;
  ASSH_RET_ON_ERR(assh_key_output(c, hk, NULL, &ks_len,
	         ASSH_KEY_FMT_PUB_RFC4253));

  size_t t_len;
  ASSH_RET_ON_ERR(assh_key_output(c, pv->t_key, NULL, &t_len,
	         ASSH_KEY_FMT_PUB_RFC4253));

  struct assh_packet_s *pout;

  ASSH_RET_ON_ERR(assh_packet_alloc(c, SSH_MSG_KEXRSA_PUBKEY,
		(4 + ks_len) + (4 + t_len), &pout));

  uint8_t *ks_str;
  ASSH_ASSERT(assh_packet_add_string(pout, ks_len, &ks_str));
  ASSH_JMP_ON_ERR(assh_key_output(c, hk, ks_str, &ks_len,
		ASSH_KEY_FMT_PUB_RFC4253), err_p);

  assh_packet_shrink_string(pout, ks_str, ks_len);

  uint8_t *t_str;
  ASSH_ASSERT(assh_packet_add_string(pout, t_len, &t_str));
  ASSH_JMP_ON_ERR(assh_key_output(c, pv->t_key, t_str, &t_len,
		ASSH_KEY_FMT_PUB_RFC4253), err_p);

  assh_packet_shrink_string(pout, t_str, t_len);

  /* prepare H hash */
  ASSH_JMP_ON_ERR(assh_alloc(c, pv->hash->ctx_size, ASSH_ALLOC_SECUR,
			  (void**)&pv->hash_ctx), err_p);

  ASSH_JMP_ON_ERR(assh_hash_init(s->ctx, pv->hash_ctx, pv->hash), err_p);

  assh_hash_bytes_as_string(pv->hash_ctx, s->ident_str, s->ident_len);
  assh_hash_bytes_as_string(pv->hash_ctx, (const uint8_t*)ASSH_IDENT,
			    sizeof(ASSH_IDENT) /* \r\n\0 */ - 3);
  assh_hash_payload_as_string(pv->hash_ctx, s->kex_init_remote);
  assh_hash_payload_as_string(pv->hash_ctx, s->kex_init_local);
  assh_hash_string(pv->hash_ctx, ks_str - 4);
  assh_hash_string(pv->hash_ctx, t_str - 4);

  /* send packet */
  assh_transport_push(s, pout);
  ASSH_SET_STATE(pv, state, ASSH_KEX_RSA_SERVER_WAIT_SECRET);

  return ASSH_OK;
 err_p:
  assh_packet_release(pout);
  return err;
}

static assh_status_t assh_kex_rsa_server_wait_secret(struct assh_session_s *s,
						    struct assh_packet_s *p)
{
  struct assh_context_s *c = s->ctx;
  struct assh_kex_rsa_private_s *pv = s->kex_pv;
  assh_status_t err;

  ASSH_RET_IF_TRUE(p->head.msg != SSH_MSG_KEXRSA_SECRET, ASSH_ERR_PROTOCOL);

  uint8_t *e_str = p->head.end;

  ASSH_RET_ON_ERR(assh_packet_check_string(p, e_str, NULL));

  assh_hash_string(pv->hash_ctx, e_str);

  const struct assh_key_rsa_s *t_key = (const void*)pv->t_key;

  size_t kbits = assh_bignum_bits(&t_key->nn);

  size_t hlen = pv->hash->hash_size;
  size_t elen = ASSH_ALIGN8(kbits) / 8;

  ASSH_RET_IF_TRUE(assh_load_u32(e_str) != elen, ASSH_ERR_BAD_DATA);

  uint8_t *em = e_str + 4;

#ifdef CONFIG_ASSH_DEBUG_KEX
  ASSH_DEBUG_HEXDUMP("emc", em, elen);
#endif

  /* use Chinese Remainder */
  enum bytecode_args_e
  {
    EM_data,                    /* data buffers */
    Q, P, DP, DQ, I, N,         /* big number inputs */
    M2, EM, T3, T0, T1, T2,         /* big number temporaries */
    MT, PQ_size
  };

  static const assh_bignum_op_t bytecode[] = {
    ASSH_BOP_SIZER(     M2,     EM,     N		),
    ASSH_BOP_SIZER(     T0,     MT,     P		),
    ASSH_BOP_SIZEM(     T3,     PQ_size, 0, 1		),

    ASSH_BOP_MOVE(      EM,     EM_data			),

    /* m2 = em^dq % q */
    ASSH_BOP_MOVE(      T2,     Q			),
    ASSH_BOP_MOD(       T0,     EM,     T2               ),
    ASSH_BOP_MTINIT(    MT,     T2                       ),
    ASSH_BOP_MTTO(      T0,     T0,     T0,     MT      ),
    ASSH_BOP_EXPM(      T0,     T0,     DQ,	MT	),
    ASSH_BOP_MTFROM(    T0,     T0,     T0,     MT      ),
    ASSH_BOP_MOVE(      M2,     T0			),

    /* m1 = em^dp % p */
    ASSH_BOP_MOVE(      T2,     P			),
    ASSH_BOP_MOD(       T1,     EM,     T2              ),
    ASSH_BOP_MTINIT(    MT,     T2                      ),
    ASSH_BOP_MTTO(      T1,     T1,     T1,     MT      ),
    ASSH_BOP_EXPM(      T1,     T1,     DP,	MT	),

    /* h = i * (m1 - m2) */
    ASSH_BOP_MTTO(      T0,     T0,     T0,     MT      ),
    ASSH_BOP_SUBM(      T1,     T1,     T0,     MT      ),
    ASSH_BOP_MTTO(      T2,     T2,     I,      MT      ),
    ASSH_BOP_MULM(      T0,     T1,     T2,     MT      ),
    ASSH_BOP_MTFROM(    T1,     T1,     T0,     MT      ),

    /* m = m2 + h * q */
    ASSH_BOP_MUL(       T3,     T1,     Q               ),
    ASSH_BOP_ADD(       M2,     M2,     T3              ),

    ASSH_BOP_MOVE(      EM_data, M2			),
    ASSH_BOP_END(),
  };

  intptr_t pqsize = ASSH_MAX(assh_bignum_bits(&t_key->pn),
			     assh_bignum_bits(&t_key->qn));

  ASSH_RET_ON_ERR(assh_bignum_bytecode(c, 0, bytecode, "DNNNNNNTTTTTTms",
                   /* Data */ em,
                   /* Num  */ &t_key->qn, &t_key->pn, &t_key->dpn, &t_key->dqn,
			      &t_key->in, &t_key->nn, pqsize));

#ifdef CONFIG_ASSH_DEBUG_KEX
  ASSH_DEBUG_HEXDUMP("em", em, elen);
#endif

  /* em[0] should be 0 here. We do not check in order to prevent a
     padding oracle attack */

  uint8_t *db = em + 1 + hlen;

  ASSH_RET_ON_ERR(assh_kex_rsa_mgf1(c, pv->hash,
                 db, elen - hlen - 1, em + 1, hlen));
  ASSH_RET_ON_ERR(assh_kex_rsa_mgf1(c, pv->hash,
	         em + 1, hlen, db, elen - hlen - 1));

#ifdef CONFIG_ASSH_DEBUG_KEX
  ASSH_DEBUG_HEXDUMP("e", em, elen);
#endif

  ASSH_RET_IF_TRUE(assh_memcmp(db, pv->lhash, hlen), ASSH_ERR_BAD_DATA);

  /* check and skip padding */
  uint8_t *ps = db + hlen;

  while (*ps == 0x00)
    ASSH_RET_IF_TRUE(++ps == em + elen, ASSH_ERR_BAD_DATA);
  ASSH_RET_IF_TRUE(*ps++ != 0x01, ASSH_ERR_BAD_DATA);
  ASSH_RET_IF_TRUE(em + elen - ps < 4, ASSH_ERR_BAD_DATA);
  ASSH_RET_IF_TRUE(em + elen - ps != 4 + assh_load_u32(ps), ASSH_ERR_BAD_DATA);

  /* send signature packet */
  struct assh_key_s *hk = pv->host_key;

  size_t sign_len;
  const struct assh_algo_sign_s *sign_algo = s->host_sign_algo;
  ASSH_RET_ON_ERR(assh_sign_generate(c, sign_algo, hk, 0, NULL, NULL, &sign_len));

  struct assh_packet_s *pout;
  ASSH_RET_ON_ERR(assh_packet_alloc(c, SSH_MSG_KEXRSA_DONE, (4 + sign_len), &pout));

  ASSH_JMP_ON_ERR(assh_kex_server_hash2(s, pv->hash_ctx, pout, sign_len, hk, ps), err_p);

  assh_transport_push(s, pout);

  ASSH_RETURN(assh_kex_end(s, 1));

 err_p:
  assh_packet_release(pout);
  return err;
}
#endif

static ASSH_KEX_PROCESS_FCN(assh_kex_rsa_process)
{
  struct assh_kex_rsa_private_s *pv = s->kex_pv;
  assh_status_t err;

  switch (pv->state)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_KEX_RSA_CLIENT_WAIT_PUBKEY:
      if (p == NULL)
        return ASSH_OK;
      ASSH_RETURN(assh_kex_rsa_client_wait_pubkey(s, p, e)
                    | ASSH_ERRSV_DISCONNECT);

    case ASSH_KEX_RSA_CLIENT_LOOKUP_HOST_KEY_WAIT:
      ASSH_UNREACHABLE();

    case ASSH_KEX_RSA_CLIENT_WAIT_SIGN:
      if (p == NULL)
        return ASSH_OK;
      ASSH_RETURN(assh_kex_rsa_client_wait_sign(s, p)
                    | ASSH_ERRSV_DISCONNECT);

#endif

#ifdef CONFIG_ASSH_SERVER
    case ASSH_KEX_RSA_SERVER_SEND_PUBKEY:
      assert(p == NULL);
      ASSH_RETURN(assh_kex_rsa_server_send_pubkey(s)
                    | ASSH_ERRSV_DISCONNECT);

    case ASSH_KEX_RSA_SERVER_WAIT_SECRET:
      if (p == NULL)
        return ASSH_OK;
      ASSH_RETURN(assh_kex_rsa_server_wait_secret(s, p)
                    | ASSH_ERRSV_DISCONNECT);
#endif
    }

  ASSH_UNREACHABLE();
}

static assh_status_t assh_kex_rsa_init(struct assh_session_s *s,
				      size_t cipher_key_size, size_t minklen,
				      const struct assh_algo_s *algo,
				      const struct assh_hash_algo_s *hash,
				      const uint8_t *lhash)
{
  struct assh_context_s *c = s->ctx;
  assh_status_t err;
  struct assh_kex_rsa_private_s *pv;

  ASSH_RET_ON_ERR(assh_alloc(c, sizeof(*pv), ASSH_ALLOC_INTERNAL, (void**)&pv));

  switch (c->type)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_CLIENT: {
      ASSH_SET_STATE(pv, state, ASSH_KEX_RSA_CLIENT_WAIT_PUBKEY);
      break;
    }
#endif
#ifdef CONFIG_ASSH_SERVER
    case ASSH_SERVER:
      if (assh_key_lookup(c, &pv->t_key, algo))
	{
#ifdef CONFIG_ASSH_KEY_CREATE
	  ASSH_JMP_ON_ERR(assh_key_create(c, &c->keys, minklen, &assh_key_rsa,
		       ASSH_ALGO_KEX), err);
	  pv->t_key = c->keys;
#else
          ASSH_JMP_ON_ERR(ASSH_ERR_MISSING_KEY, err);
#endif
	}
      ASSH_SET_STATE(pv, state, ASSH_KEX_RSA_SERVER_SEND_PUBKEY);
      break;
#endif
    default:
      ASSH_UNREACHABLE();
    }

  s->kex_pv = pv;
  pv->hash = hash;
  pv->lhash = lhash;
  pv->minklen = minklen;

  switch (c->type)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_CLIENT:
      pv->pck = NULL;
      pv->secret = NULL;
      break;
#endif

#ifdef CONFIG_ASSH_SERVER
    case ASSH_SERVER:
      pv->hash_ctx = NULL;
      break;
#endif
    default:;
    }

  return ASSH_OK;

#ifdef CONFIG_ASSH_SERVER
 err:
  assh_free(c, pv);
  return err;
#endif
}

static ASSH_KEX_CLEANUP_FCN(assh_kex_rsa_cleanup)
{
  struct assh_kex_rsa_private_s *pv = s->kex_pv;

  switch (s->ctx->type)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_CLIENT:
      assh_packet_release(pv->pck);
      assh_free(s->ctx, pv->secret);
      break;
#endif

#ifdef CONFIG_ASSH_SERVER
    case ASSH_SERVER:
      if (pv->hash_ctx != NULL)
	{
	  assh_hash_cleanup(pv->hash_ctx);
	  assh_free(s->ctx, pv->hash_ctx);
	}
      break;
#endif

    default:
      ASSH_UNREACHABLE();
    }

  assh_free(s->ctx, s->kex_pv);
  s->kex_pv = NULL;
}

static ASSH_KEX_INIT_FCN(assh_kex_rsa1024_sha1_init)
{
  return assh_kex_rsa_init(s, cipher_key_size, 1024,
    &assh_kex_rsa1024_sha1.algo, &assh_hash_sha1,
    (const uint8_t*)"\xda\x39\xa3\xee\x5e\x6b\x4b\x0d\x32\x55"
		    "\xbf\xef\x95\x60\x18\x90\xaf\xd8\x07\x09");
}

static ASSH_ALGO_SUITABLE_KEY_FCN(assh_kex_rsa1024_suitable_key)
{
  if (key == NULL)
#ifdef CONFIG_ASSH_KEY_CREATE
    return 0;
#else
    return c->type == ASSH_SERVER;
#endif
  if (key->algo != &assh_key_rsa || key->role != ASSH_ALGO_KEX)
    return 0;
  const struct assh_key_rsa_s *k = (const void*)key;
  return assh_bignum_bits(&k->nn) >= 1024;
}

const struct assh_algo_kex_s assh_kex_rsa1024_sha1 =
{
  ASSH_ALGO_BASE(KEX, "assh-builtin", 10, 30,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF, "rsa1024-sha1" }),
    .f_suitable_key = assh_kex_rsa1024_suitable_key,
    .key = &assh_key_rsa
  ),
  .f_init = assh_kex_rsa1024_sha1_init,
  .f_cleanup = assh_kex_rsa_cleanup,
  .f_process = assh_kex_rsa_process,
};

static ASSH_KEX_INIT_FCN(assh_kex_rsa2048_sha256_init)
{
  return assh_kex_rsa_init(s, cipher_key_size, 2048,
    &assh_kex_rsa2048_sha256.algo, &assh_hash_sha256,
    (const uint8_t*)"\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8"
		    "\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c"
		    "\xa4\x95\x99\x1b\x78\x52\xb8\x55");
}

static ASSH_ALGO_SUITABLE_KEY_FCN(assh_kex_rsa2048_suitable_key)
{
  if (key == NULL)
#ifdef CONFIG_ASSH_KEY_CREATE
    return 0;
#else
    return c->type == ASSH_SERVER;
#endif
  if (key->algo != &assh_key_rsa || key->role != ASSH_ALGO_KEX)
    return 0;
  const struct assh_key_rsa_s *k = (const void*)key;
  return assh_bignum_bits(&k->nn) >= 2048;
}

const struct assh_algo_kex_s assh_kex_rsa2048_sha256 =
{
  ASSH_ALGO_BASE(KEX, "assh-builtin", 20, 20,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF, "rsa2048-sha256"}),
    .f_suitable_key = assh_kex_rsa2048_suitable_key,
    .key = &assh_key_rsa
  ),
  .f_init = assh_kex_rsa2048_sha256_init,
  .f_cleanup = assh_kex_rsa_cleanup,
  .f_process = assh_kex_rsa_process,
};

