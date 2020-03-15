/*

  libassh - asynchronous ssh2 client/server library.

  Copyright (C) 2014 Alexandre Becoulet <alexandre.becoulet@free.fr>

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
  Implement ECDH using montgomery elliptic curves from:
   - Curve25519: new Diffie-Hellman speed records.

  SSH key exchange protocol from:
    - curve25519-sha256_libssh.org.txt
*/

#include <assh/assh_kex.h>
#include <assh/assh_context.h>
#include <assh/assh_prng.h>
#include <assh/assh_session.h>
#include <assh/assh_packet.h>
#include <assh/assh_transport.h>
#include <assh/assh_sign.h>
#include <assh/assh_event.h>
#include <assh/assh_alloc.h>
#include <assh/assh_hash.h>
#include <assh/mod_builtin.h>

#include <string.h>
#include <stdlib.h>

#include <sodium/crypto_scalarmult_curve25519.h>

enum assh_kex_curve25519_state_e
{
#ifdef CONFIG_ASSH_CLIENT
  ASSH_KEX_CURVE25519_CLIENT_SEND_PUB,
  ASSH_KEX_CURVE25519_CLIENT_INIT,
  ASSH_KEX_CURVE25519_CLIENT_LOOKUP_HOST_KEY_WAIT,
#endif
#ifdef CONFIG_ASSH_SERVER
  ASSH_KEX_CURVE25519_SERVER_WAIT_E,
#endif
};

#define ASSH_CURVE25519_KSIZE 32

struct assh_kex_curve25519_private_s
{
#ifdef CONFIG_ASSH_CLIENT
  struct assh_packet_s *pck;
#endif

  enum assh_kex_curve25519_state_e state:8;
  uint8_t pubkey[ASSH_CURVE25519_KSIZE];
  uint8_t pvkey[ASSH_CURVE25519_KSIZE];
};

static assh_status_t ASSH_WARN_UNUSED_RESULT
assh_kex_curve25519_private_gen(struct assh_session_s *s,
				uint8_t *private)
{
  assh_status_t err;

  ASSH_RET_ON_ERR(assh_prng_get(s->ctx, private, ASSH_CURVE25519_KSIZE,
                      ASSH_PRNG_QUALITY_EPHEMERAL_KEY));

  private[0] &= ~0x07;
  private[31] &= ~0x80;
  private[31] |= 0x40;

  return ASSH_OK;
}

static uint8_t *
assh_kex_curve25519_to_mpint(uint8_t *secret, uint8_t *secret_end)
{
  /* makes the secret looks like a mpint */
  secret[4] = 0;
  while (secret_end - secret > 4 && secret[4] == 0 &&
         (secret_end - secret == 5 || !(secret[5] & 0x80)))
    secret++;
  assh_store_u32(secret, secret_end - secret - 4);
  return secret;
}

#ifdef CONFIG_ASSH_CLIENT
static assh_status_t assh_kex_curve25519_client_send_pubkey(struct assh_session_s *s)
{
  struct assh_kex_curve25519_private_s *pv = s->kex_pv;
  struct assh_context_s *c = s->ctx;
  assh_status_t err;

  /* generate ephemeral key pair */
  ASSH_RET_ON_ERR(assh_kex_curve25519_private_gen(s, pv->pvkey));

  ASSH_RET_IF_TRUE(crypto_scalarmult_curve25519_base(pv->pubkey, pv->pvkey),
		   ASSH_ERR_CRYPTO | ASSH_ERRSV_DISCONNECT);

  /* send a packet containing the public key */
  struct assh_packet_s *p;
  ASSH_RET_ON_ERR(assh_packet_alloc(c, SSH_MSG_KEX_ECDH_INIT,
               4 + ASSH_CURVE25519_KSIZE, &p));

  uint8_t *qc_str;
  ASSH_ASSERT(assh_packet_add_string(p, ASSH_CURVE25519_KSIZE, &qc_str));
  memcpy(qc_str, pv->pubkey, ASSH_CURVE25519_KSIZE);

  assh_transport_push(s, p);

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_kex_curve25519_host_key_lookup_done)
{
  struct assh_kex_curve25519_private_s *pv = s->kex_pv;
  assh_status_t err;

  assert(pv->state == ASSH_KEX_CURVE25519_CLIENT_LOOKUP_HOST_KEY_WAIT);

  if (!e->kex.hostkey_lookup.accept || ASSH_STATUS(inerr))
    ASSH_RETURN(assh_kex_end(s, 0) | ASSH_ERRSV_DISCONNECT);

  struct assh_packet_s *p = pv->pck;

  const uint8_t *ks_str = p->head.end;
  const uint8_t *qs_str, *h_str;

  ASSH_RET_ON_ERR(assh_packet_check_string(p, ks_str, &qs_str)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_RET_ON_ERR(assh_packet_check_string(p, qs_str, &h_str)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_RET_ON_ERR(assh_packet_check_string(p, h_str, NULL)
	       | ASSH_ERRSV_DISCONNECT);

  ASSH_RET_IF_TRUE(assh_load_u32(qs_str) != ASSH_CURVE25519_KSIZE,
               ASSH_ERR_BAD_DATA | ASSH_ERRSV_DISCONNECT);

  /* compute shared secret */
  ASSH_SCRATCH_ALLOC(s->ctx, uint8_t, scratch,
                     assh_hash_sha256.ctx_size + 5 + ASSH_CURVE25519_KSIZE,
		     ASSH_ERRSV_DISCONNECT, err_);

  void *hash_ctx = scratch;
  uint8_t *secret = scratch + assh_hash_sha256.ctx_size;
  uint8_t *secret_end = secret + 5 + ASSH_CURVE25519_KSIZE;

  ASSH_JMP_IF_TRUE(crypto_scalarmult_curve25519(secret + 5,
		     pv->pvkey, qs_str + 4),
		   ASSH_ERR_CRYPTO | ASSH_ERRSV_DISCONNECT, err_sc);

  secret = assh_kex_curve25519_to_mpint(secret, secret_end);

  /* compute exchange hash and send reply */
  ASSH_JMP_ON_ERR(assh_hash_init(s->ctx, hash_ctx, &assh_hash_sha256)
               | ASSH_ERRSV_DISCONNECT, err_sc);

  ASSH_JMP_ON_ERR(assh_kex_client_hash1(s, hash_ctx, ks_str)
               | ASSH_ERRSV_DISCONNECT, err_sc);

  assh_hash_bytes_as_string(hash_ctx, pv->pubkey, ASSH_CURVE25519_KSIZE);
  assh_hash_string(hash_ctx, qs_str);

  ASSH_JMP_ON_ERR(assh_kex_client_hash2(s, hash_ctx, secret, h_str)
               | ASSH_ERRSV_DISCONNECT, err_sc);

  ASSH_JMP_ON_ERR(assh_kex_end(s, 1) | ASSH_ERRSV_DISCONNECT, err_hash);

  err = ASSH_OK;

 err_hash:
  assh_hash_cleanup(hash_ctx);
 err_sc:
  ASSH_SCRATCH_FREE(s->ctx, scratch);
 err_:
  return err;
}

static assh_status_t assh_kex_curve25519_client_wait_reply(struct assh_session_s *s,
                                                      struct assh_packet_s *p,
                                                      struct assh_event_s *e)
{
  struct assh_kex_curve25519_private_s *pv = s->kex_pv;
  assh_status_t err;

  ASSH_RET_IF_TRUE(p->head.msg != SSH_MSG_KEX_ECDH_REPLY, ASSH_ERR_PROTOCOL);

  const uint8_t *ks_str = p->head.end;
  const uint8_t *qs_str, *h_str;

  ASSH_RET_ON_ERR(assh_packet_check_string(p, ks_str, &qs_str));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, qs_str, &h_str));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, h_str, NULL));

  ASSH_RET_IF_TRUE(assh_load_u32(qs_str) != ASSH_CURVE25519_KSIZE,
               ASSH_ERR_BAD_DATA);

  ASSH_RET_ON_ERR(assh_kex_client_get_key(s, ks_str, e,
                 &assh_kex_curve25519_host_key_lookup_done, pv));

  ASSH_SET_STATE(pv, state, ASSH_KEX_CURVE25519_CLIENT_LOOKUP_HOST_KEY_WAIT);
  pv->pck = assh_packet_refinc(p);

  return ASSH_OK;
}

#endif


#ifdef CONFIG_ASSH_SERVER

static assh_status_t assh_kex_curve25519_server_wait_pubkey(struct assh_session_s *s,
                                                       struct assh_packet_s *p)
{
  struct assh_kex_curve25519_private_s *pv = s->kex_pv;
  struct assh_context_s *c = s->ctx;
  assh_status_t err;

  ASSH_RET_IF_TRUE(p->head.msg != SSH_MSG_KEX_ECDH_INIT,
	       ASSH_ERR_PROTOCOL);

  uint8_t *qc_str = p->head.end;

  ASSH_RET_ON_ERR(assh_packet_check_string(p, qc_str, NULL));

  ASSH_RET_IF_TRUE(assh_load_u32(qc_str) != ASSH_CURVE25519_KSIZE,
               ASSH_ERR_BAD_DATA);

  /* generate ephemeral key pair */
  ASSH_RET_ON_ERR(assh_kex_curve25519_private_gen(s, pv->pvkey));

  /* compute shared secret */
  ASSH_SCRATCH_ALLOC(s->ctx, uint8_t, scratch,
                     assh_hash_sha256.ctx_size + 5 + ASSH_CURVE25519_KSIZE,
		     ASSH_ERRSV_CONTINUE, err_);

  void *hash_ctx = scratch;
  uint8_t *secret = scratch + assh_hash_sha256.ctx_size;
  uint8_t *secret_end = secret + 5 + ASSH_CURVE25519_KSIZE;

  ASSH_JMP_IF_TRUE(crypto_scalarmult_curve25519_base(pv->pubkey, pv->pvkey),
		   ASSH_ERR_CRYPTO | ASSH_ERRSV_DISCONNECT, err_sc);

  ASSH_JMP_IF_TRUE(crypto_scalarmult_curve25519(secret + 5,
		     pv->pvkey, qc_str + 4),
		   ASSH_ERR_CRYPTO | ASSH_ERRSV_DISCONNECT, err_sc);

  secret = assh_kex_curve25519_to_mpint(secret, secret_end);

  /* compute exchange hash and send reply */
  ASSH_JMP_ON_ERR(assh_hash_init(s->ctx, hash_ctx,
				 &assh_hash_sha256), err_sc);

  struct assh_packet_s *pout;
  struct assh_key_s *hk;
  size_t slen;

  ASSH_JMP_ON_ERR(assh_kex_server_hash1(s, 
                 /* room for qs_str */ 4 + ASSH_CURVE25519_KSIZE,
                 hash_ctx, &pout, &slen, &hk,
                 SSH_MSG_KEX_ECDH_REPLY), err_sc);

  uint8_t *qs_str;
  ASSH_ASSERT(assh_packet_add_string(pout, ASSH_CURVE25519_KSIZE, &qs_str));
  memcpy(qs_str, pv->pubkey, ASSH_CURVE25519_KSIZE);

  /* hash both ephemeral public keys */
  assh_hash_string(hash_ctx, qc_str);
  assh_hash_string(hash_ctx, qs_str - 4);

  ASSH_JMP_ON_ERR(assh_kex_server_hash2(s, hash_ctx, pout, slen, hk, secret), err_p);

  assh_transport_push(s, pout);

  ASSH_JMP_ON_ERR(assh_kex_end(s, 1), err_hash);

  err = ASSH_OK;
  goto err_hash;

 err_p:
  assh_packet_release(pout);
 err_hash:
  assh_hash_cleanup(hash_ctx);
 err_sc:
  ASSH_SCRATCH_FREE(c, scratch);
 err_:
  return err;
}
#endif

static ASSH_KEX_PROCESS_FCN(assh_kex_curve25519_process)
{
  struct assh_kex_curve25519_private_s *pv = s->kex_pv;
  assh_status_t err;

  switch (pv->state)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_KEX_CURVE25519_CLIENT_INIT:
      assert(p == NULL);
      ASSH_RET_ON_ERR(assh_kex_curve25519_client_send_pubkey(s)
		   | ASSH_ERRSV_DISCONNECT);
      ASSH_SET_STATE(pv, state, ASSH_KEX_CURVE25519_CLIENT_SEND_PUB);
      return ASSH_OK;

    case ASSH_KEX_CURVE25519_CLIENT_SEND_PUB:
      if (p == NULL)
        return ASSH_OK;
      ASSH_RETURN(assh_kex_curve25519_client_wait_reply(s, p, e)
                    | ASSH_ERRSV_DISCONNECT);

    case ASSH_KEX_CURVE25519_CLIENT_LOOKUP_HOST_KEY_WAIT:
      ASSH_UNREACHABLE();
#endif

#ifdef CONFIG_ASSH_SERVER
    case ASSH_KEX_CURVE25519_SERVER_WAIT_E:
      if (p == NULL)
        return ASSH_OK;
      ASSH_RETURN(assh_kex_curve25519_server_wait_pubkey(s, p)
                    | ASSH_ERRSV_DISCONNECT);
#endif
    }

  return ASSH_OK;
}

static ASSH_KEX_CLEANUP_FCN(assh_kex_curve25519_cleanup)
{
  struct assh_kex_curve25519_private_s *pv = s->kex_pv;

#ifdef CONFIG_ASSH_CLIENT
  if (s->ctx->type == ASSH_CLIENT)
    assh_packet_release(pv->pck);
#endif

  assh_free(s->ctx, s->kex_pv);
  s->kex_pv = NULL;
}

static ASSH_KEX_INIT_FCN(assh_kex_curve25519_init)
{
  assh_status_t err;

  struct assh_kex_curve25519_private_s *pv;
  ASSH_RET_ON_ERR(assh_alloc(s->ctx, sizeof(*pv),
                          ASSH_ALLOC_SECUR, (void**)&pv));

  s->kex_pv = pv;

  switch (s->ctx->type)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_CLIENT:
      ASSH_SET_STATE(pv, state, ASSH_KEX_CURVE25519_CLIENT_INIT);
      pv->pck = NULL;
      break;
#endif
#ifdef CONFIG_ASSH_SERVER
    case ASSH_SERVER:
      ASSH_SET_STATE(pv, state, ASSH_KEX_CURVE25519_SERVER_WAIT_E);
      break;
#endif
    default:
      ASSH_UNREACHABLE();
    }

  return ASSH_OK;
}

const struct assh_algo_kex_s assh_kex_sodium_curve25519_sha256 =
{
  .algo_wk = {
    ASSH_ALGO_BASE(KEX, "assh-sodium", 50, 90,
      ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_COMMON,
                        "curve25519-sha256@libssh.org" }),
      .nondeterministic = 1,
    ),
  },
  .f_init = assh_kex_curve25519_init,
  .f_cleanup = assh_kex_curve25519_cleanup,
  .f_process = assh_kex_curve25519_process,
};


