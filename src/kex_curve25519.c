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

#include <assh/assh_25519num.h>

#include <string.h>
#include <stdlib.h>


enum assh_kex_25519_state_e
{
#ifdef CONFIG_ASSH_CLIENT
  ASSH_KEX_25519_CLIENT_SEND_PUB,
  ASSH_KEX_25519_CLIENT_INIT,
  ASSH_KEX_25519_CLIENT_LOOKUP_HOST_KEY_WAIT,
#endif
#ifdef CONFIG_ASSH_SERVER
  ASSH_KEX_25519_SERVER_WAIT_E,
#endif
};

struct assh_kex_25519_private_s
{
  enum assh_kex_25519_state_e state;

#ifdef CONFIG_ASSH_CLIENT
  struct assh_key_s *host_key;
  struct assh_packet_s *pck;
#endif
  uint8_t *qs_str;
  uint8_t *qc_str;

  assh_25519key_t pvkey;
  assh_25519key_t pubkey;
};

static void assh_kex_25519_pv_adjust(assh_25519key_t private)
{
  private[0] &= ~0x07;
  private[31] &= ~0x80;
  private[31] |= 0x40;
}

#define ASSH_KEX_25519_SECRET_BUFSIZE (5 + sizeof(assh_25519key_t))

uint8_t *assh_kex_25519_secret_to_mpint(uint8_t *buf, const assh_25519num_t num)
{
  uint8_t *secret_str = buf;
  assh_25519num_to_data(buf + 5, num);

  /* the shared secret must be a positive mpint, we have to insert a
     null byte if the sign bit is set in the current msb. */
  if (secret_str[5] & 0x80)
    {
      secret_str[4] = 0;
      assh_store_u32(secret_str, sizeof(assh_25519key_t) + 1);
    }
  else
    {
      secret_str++;
      assh_store_u32(secret_str, sizeof(assh_25519key_t));
    }

  return secret_str;
}

static const assh_25519num_t curve25519_basepoint = { 9 };

#ifdef CONFIG_ASSH_CLIENT
static assh_error_t assh_kex_25519_client_send_pubkey(struct assh_session_s *s)
{
  struct assh_kex_25519_private_s *pv = s->kex_pv;
  struct assh_context_s *c = s->ctx;
  assh_error_t err;

  /* generate ephemeral key pair */
  ASSH_ERR_RET(c->prng->f_get(c, pv->pvkey, sizeof(assh_25519key_t),
                              ASSH_PRNG_QUALITY_EPHEMERAL_KEY));

  assh_kex_25519_pv_adjust(pv->pvkey);

  struct scratch_s
  {
    assh_25519num_t pub;
  };

  ASSH_SCRATCH_ALLOC(c, struct scratch_s, scratch, sizeof(struct scratch_s),
		     ASSH_ERRSV_CONTINUE, err_);

  ASSH_ASSERT(assh_25519num_point_mul(scratch->pub, curve25519_basepoint, pv->pvkey));
  assh_25519num_to_data(pv->pubkey, scratch->pub);

  ASSH_SCRATCH_FREE(c, scratch);

  /* send a packet containing the public key */
  struct assh_packet_s *p;
  ASSH_ERR_RET(assh_packet_alloc(c, SSH_MSG_KEX_ECDH_INIT,
               4 + sizeof(assh_25519key_t), &p) | ASSH_ERRSV_DISCONNECT);

  uint8_t *qc_str;
  ASSH_ASSERT(assh_packet_add_string(p, sizeof(assh_25519key_t), &qc_str));
  memcpy(qc_str, pv->pubkey, sizeof(assh_25519key_t));

  assh_transport_push(s, p);

  err = ASSH_OK;
 err_:
  return err;
}

static ASSH_KEX_CLIENT_HASH(assh_kex_25519_client_hash)
{
  struct assh_kex_25519_private_s *pv = s->kex_pv;

  assh_hash_bytes_as_string(hash_ctx, hash_algo->f_update, pv->pubkey, sizeof(pv->pubkey));
  assh_hash_string(hash_ctx, hash_algo->f_update, pv->qs_str);

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_kex_25519_host_key_lookup_done)
{
  struct assh_kex_25519_private_s *pv = s->kex_pv;
  assh_error_t err;

  ASSH_CHK_RET(pv->state != ASSH_KEX_25519_CLIENT_LOOKUP_HOST_KEY_WAIT,
               ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);

  if (!e->kex.hostkey_lookup.accept)
    {
      ASSH_ERR_RET(assh_kex_end(s, 0) | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;
    }

  struct assh_packet_s *p = pv->pck;

  uint8_t *ks_str = p->head.end;
  uint8_t *qs_str, *h_str;

  ASSH_ERR_RET(assh_packet_check_string(p, ks_str, &qs_str)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_string(p, qs_str, &h_str)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_string(p, h_str, NULL)
	       | ASSH_ERRSV_DISCONNECT);

  /* compute shared secret */
  struct scratch_s
  {
    assh_25519num_t pub, secret;
    uint8_t secret_buf[ASSH_KEX_25519_SECRET_BUFSIZE];
  };

  ASSH_SCRATCH_ALLOC(s->ctx, struct scratch_s, scratch, sizeof(struct scratch_s),
		     ASSH_ERRSV_CONTINUE, err_);

  assh_25519num_from_data(scratch->pub, qs_str + 4);
  ASSH_ERR_GTO(assh_25519num_point_mul(scratch->secret,
                           scratch->pub, pv->pvkey), err_sc);

  uint8_t *secret_str = assh_kex_25519_secret_to_mpint(scratch->secret_buf,
                                                       scratch->secret);

  /* compute exchange hash and send reply */
  pv->qs_str = qs_str;
  ASSH_ERR_GTO(assh_kex_client_hash(s, &assh_kex_25519_client_hash,
                                    &assh_hash_sha256, pv->host_key,
                                    secret_str, ks_str, h_str)
               | ASSH_ERRSV_DISCONNECT, err_sc);

  ASSH_SCRATCH_FREE(s->ctx, scratch);
  assh_packet_release(pv->pck);
  pv->pck = NULL;

  ASSH_ERR_RET(assh_kex_end(s, 1) | ASSH_ERRSV_DISCONNECT);
  return ASSH_OK;

 err_sc:
  ASSH_SCRATCH_FREE(s->ctx, scratch);
 err_:
  assh_packet_release(pv->pck);
  pv->pck = NULL;
  return err;
}

static assh_error_t assh_kex_25519_client_wait_reply(struct assh_session_s *s,
                                                     struct assh_packet_s *p,
                                                     struct assh_event_s *e)
{
  struct assh_kex_25519_private_s *pv = s->kex_pv;
  struct assh_context_s *c = s->ctx;
  assh_error_t err;

  ASSH_CHK_RET(p->head.msg != SSH_MSG_KEX_ECDH_REPLY, ASSH_ERR_PROTOCOL
	       | ASSH_ERRSV_DISCONNECT);

  uint8_t *ks_str = p->head.end;
  uint8_t *qs_str, *h_str;

  ASSH_ERR_RET(assh_packet_check_string(p, ks_str, &qs_str)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_string(p, qs_str, &h_str)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_string(p, h_str, NULL)
	       | ASSH_ERRSV_DISCONNECT);

  ASSH_CHK_RET(assh_load_u32(qs_str) != sizeof(assh_25519key_t),
               ASSH_ERR_BAD_DATA | ASSH_ERRSV_DISCONNECT);

  ASSH_ERR_RET(assh_kex_client_get_key(s, &pv->host_key, ks_str, e,
                              &assh_kex_25519_host_key_lookup_done, pv));

  pv->state = ASSH_KEX_25519_CLIENT_LOOKUP_HOST_KEY_WAIT;
  pv->pck = assh_packet_refinc(p);

  return ASSH_OK;
}

#endif


#ifdef CONFIG_ASSH_SERVER
static ASSH_KEX_SERVER_HASH(assh_kex_25519_server_hash)
{
  struct assh_kex_25519_private_s *pv = s->kex_pv;

  /* append server ephemeral public key to packet. */
  uint8_t *qs_str;
  ASSH_ASSERT(assh_packet_add_string(pout, sizeof(assh_25519key_t), &qs_str));
  memcpy(qs_str, pv->pubkey, sizeof(assh_25519key_t));

  /* hash both ephemeral public keys */
  assh_hash_string(hash_ctx, hash_algo->f_update, pv->qc_str);
  assh_hash_string(hash_ctx, hash_algo->f_update, qs_str - 4);

  return ASSH_OK;
}

static assh_error_t assh_kex_25519_server_wait_pubkey(struct assh_session_s *s,
                                                      struct assh_packet_s *p)
{
  struct assh_kex_25519_private_s *pv = s->kex_pv;
  struct assh_context_s *c = s->ctx;
  assh_error_t err;

  ASSH_CHK_RET(p->head.msg != SSH_MSG_KEX_ECDH_INIT,
	       ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);

  uint8_t *qc_str = p->head.end;

  ASSH_ERR_RET(assh_packet_check_string(p, qc_str, NULL)
	       | ASSH_ERRSV_DISCONNECT);

  ASSH_CHK_RET(assh_load_u32(qc_str) != sizeof(assh_25519key_t),
               ASSH_ERR_BAD_DATA | ASSH_ERRSV_DISCONNECT);

  /* generate ephemeral key pair */
  ASSH_ERR_RET(c->prng->f_get(c, pv->pvkey, sizeof(assh_25519key_t),
                              ASSH_PRNG_QUALITY_EPHEMERAL_KEY));

  assh_kex_25519_pv_adjust(pv->pvkey);

  struct scratch_s
  {
    assh_25519num_t pub, secret;
    uint8_t secret_buf[ASSH_KEX_25519_SECRET_BUFSIZE];
  };

  ASSH_SCRATCH_ALLOC(c, struct scratch_s, scratch, sizeof(struct scratch_s),
		     ASSH_ERRSV_CONTINUE, err_);

  ASSH_ASSERT(assh_25519num_point_mul(scratch->pub, curve25519_basepoint, pv->pvkey));
  assh_25519num_to_data(pv->pubkey, scratch->pub);

  /* compute shared secret */
  assh_25519num_from_data(scratch->pub, qc_str + 4);
  ASSH_ERR_GTO(assh_25519num_point_mul(scratch->secret, scratch->pub, pv->pvkey), err_sc);

  uint8_t *secret_str = assh_kex_25519_secret_to_mpint(scratch->secret_buf,
                                                       scratch->secret);

  /* compute exchange hash and send reply */
  pv->qc_str = qc_str;
  ASSH_ERR_GTO(assh_kex_server_hash(s, &assh_kex_25519_server_hash,
                        /* room for qs_str */ 4 + sizeof(assh_25519num_t),
                        &assh_hash_sha256, secret_str), err_sc);

  err = ASSH_OK;

 err_sc:
  ASSH_SCRATCH_FREE(c, scratch);
 err_:
  return err;
}
#endif

static ASSH_KEX_PROCESS_FCN(assh_kex_25519_process)
{
  struct assh_kex_25519_private_s *pv = s->kex_pv;
  assh_error_t err;

  switch (pv->state)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_KEX_25519_CLIENT_INIT:
      assert(p == NULL);
      ASSH_ERR_RET(assh_kex_25519_client_send_pubkey(s)
		   | ASSH_ERRSV_DISCONNECT);
      pv->state = ASSH_KEX_25519_CLIENT_SEND_PUB;
      return ASSH_OK;

    case ASSH_KEX_25519_CLIENT_SEND_PUB:
      if (p == NULL)
        return ASSH_OK;
      ASSH_ERR_RET(assh_kex_25519_client_wait_reply(s, p, e)
		   | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;

    case ASSH_KEX_25519_CLIENT_LOOKUP_HOST_KEY_WAIT:
      ASSH_ERR_RET(ASSH_ERR_STATE | ASSH_ERRSV_FATAL);
#endif

#ifdef CONFIG_ASSH_SERVER
    case ASSH_KEX_25519_SERVER_WAIT_E:
      if (p == NULL)
        return ASSH_OK;
      ASSH_ERR_RET(assh_kex_25519_server_wait_pubkey(s, p)
		   | ASSH_ERRSV_DISCONNECT);
      ASSH_ERR_RET(assh_kex_end(s, 1)
		   | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;
#endif
    }

  return ASSH_OK;
}

static ASSH_KEX_CLEANUP_FCN(assh_kex_25519_cleanup)
{
  struct assh_kex_25519_private_s *pv = s->kex_pv;

#ifdef CONFIG_ASSH_CLIENT
  if (s->ctx->type == ASSH_CLIENT)
    {
      assh_key_flush(s->ctx, &pv->host_key);
      assh_packet_release(pv->pck);
    }
#endif

  assh_free(s->ctx, s->kex_pv, ASSH_ALLOC_KEY);
  s->kex_pv = NULL;
}

static ASSH_KEX_INIT_FCN(assh_kex_25519_init)
{
  assh_error_t err;

  struct assh_kex_25519_private_s *pv;
  ASSH_ERR_RET(assh_alloc(s->ctx, sizeof(*pv), ASSH_ALLOC_KEY, (void**)&pv)
	       | ASSH_ERRSV_DISCONNECT);

  s->kex_pv = pv;

  switch (s->ctx->type)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_CLIENT:
      pv->state = ASSH_KEX_25519_CLIENT_INIT;
      pv->host_key = NULL;
      pv->pck = NULL;
      break;
#endif
#ifdef CONFIG_ASSH_SERVER
    case ASSH_SERVER:
      pv->state = ASSH_KEX_25519_SERVER_WAIT_E;
      break;
#endif
    default:
      abort();
    }

  return ASSH_OK;
}

struct assh_algo_kex_s assh_kex_curve25519_sha256 =
{
  .algo = { .name = "curve25519-sha256@libssh.org",
	    .class_ = ASSH_ALGO_KEX, .safety = 90, .speed = 90 },
  .f_init = assh_kex_25519_init,
  .f_cleanup = assh_kex_25519_cleanup,
  .f_process = assh_kex_25519_process,
};

