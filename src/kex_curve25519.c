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

#include <assh/assh_bignum.h>

#include <string.h>
#include <stdlib.h>

assh_error_t assh_montgomery_point_mul(const uint8_t *result,
                                       const uint8_t *basepoint,
                                       const uint8_t *scalar)
{
  assh_error_t err;

  ASSH_CHK_RET((scalar[0] & 0x07) != 0x00 ||
	       (scalar[31] & 0x80) != 0x00, ASSH_ERR_NUM_OVERFLOW);

  /* 2^255-19 */
  static const uint8_t *p_str = (const uint8_t*)"\x00\x00\x00\x20"
    "\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xed";

  /* 121666 */
  static const uint8_t *c_str = (const uint8_t*)"\x00\x00\x00\x03"
    "\x01\xdb\x42";

  struct assh_bignum_mlad_s mlad = {
    .data = scalar,
    .count = 255,
    .msbyte_1st = 0,
    .msbit_1st = 1,
  };

  enum {
    R_raw, BP_raw, P_mpint, C_mpint,
    X1, X2, Z2, X3, Z3, T0, T1, C, P,
    S, L
  };

  static const assh_bignum_op_t bytecode[] = {

    ASSH_BOP_SIZE(      P,      P_mpint                 ),
    ASSH_BOP_SIZE(      X1,     P                       ),
    ASSH_BOP_SIZE(      X2,     P                       ),
    ASSH_BOP_SIZE(      Z2,     P                       ),
    ASSH_BOP_SIZE(      X3,     P                       ),
    ASSH_BOP_SIZE(      Z3,     P                       ),
    ASSH_BOP_SIZE(      T0,     P                       ),
    ASSH_BOP_SIZE(      T1,     P                       ),
    ASSH_BOP_SIZE(      C,      P                       ),

    ASSH_BOP_MOVE(      P,      P_mpint                 ),
    ASSH_BOP_MOVE(      C,      C_mpint                 ),

    ASSH_BOP_MOVE(      X1,     BP_raw                  ),

    ASSH_BOP_UINT(      X2,     1                       ),
    ASSH_BOP_UINT(      Z2,     0                       ),
    ASSH_BOP_MOVE(      X3,     X1                      ),
    ASSH_BOP_UINT(      Z3,     1                       ),

    ASSH_BOP_SUBM(	T0,	X3,	Z3,	P	),
    ASSH_BOP_SUBM(	T1,	X2,	Z2,	P	),
    ASSH_BOP_ADDM(	X2,	X2,	Z2,	P	),
    ASSH_BOP_ADDM(	Z2,	X3,	Z3,	P	),
    ASSH_BOP_MULM(	Z3,	T0,	X2,	P	),
    ASSH_BOP_MULM(	Z2,	Z2,	T1,	P	),
    ASSH_BOP_MULM( 	T0,	T1,	T1,	P	),
    ASSH_BOP_MULM( 	T1,	X2,	X2,	P	),
    ASSH_BOP_ADDM(	X3,	Z3,	Z2,	P	),
    ASSH_BOP_SUBM(	Z2,	Z3,	Z2,	P	),
    ASSH_BOP_MULM(	X2,	T1,	T0,	P	),
    ASSH_BOP_SUBM(      T1,	T1,	T0,	P	),
    ASSH_BOP_MULM( 	Z2,	Z2,	Z2,	P	),
    ASSH_BOP_MULM(	Z3,	T1,	C,      P	),
    ASSH_BOP_MULM( 	X3,	X3,	X3,	P	),
    ASSH_BOP_ADDM(	T0,	T0,	Z3,	P	),
    ASSH_BOP_MULM(	Z3,	X1,	Z2,	P	),
    ASSH_BOP_MULM(	Z2,	T1,	T0,	P	),

    ASSH_BOP_MLADSWAP(  X2,     X3,     L               ),
    ASSH_BOP_MLADSWAP(  Z2,     Z3,     L               ),

    ASSH_BOP_MLADLOOP(  21,             L               ),

    ASSH_BOP_INV_C(     Z2,     Z2,             P       ),
    ASSH_BOP_MULM(      T0,     X2,     Z2,     P       ),

    ASSH_BOP_MOVE(      R_raw,  T0                      ),

    ASSH_BOP_END(),
  };

  struct assh_context_s context;
  assh_context_init(&context, ASSH_SERVER);

  ASSH_ERR_RET(assh_bignum_bytecode(&context, bytecode, "ddMMTTTTTTTTTsL",
                 result, basepoint, p_str, c_str, (size_t)256, &mlad));

  return ASSH_OK;
}


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

typedef uint8_t assh_25519key_t[32];

struct assh_kex_25519_private_s
{
  enum assh_kex_25519_state_e state;

#ifdef CONFIG_ASSH_CLIENT
  struct assh_key_s *host_key;
  struct assh_packet_s *pck;
#endif

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

uint8_t *assh_kex_25519_secret_to_mpint(uint8_t *buf)
{
  uint8_t *secret_str = buf;

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

static const assh_25519key_t curve25519_basepoint = { 9 };

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

  ASSH_ERR_RET(assh_montgomery_point_mul(pv->pubkey, curve25519_basepoint, pv->pvkey));

  /* send a packet containing the public key */
  struct assh_packet_s *p;
  ASSH_ERR_RET(assh_packet_alloc(c, SSH_MSG_KEX_ECDH_INIT,
               4 + sizeof(assh_25519key_t), &p) | ASSH_ERRSV_DISCONNECT);

  uint8_t *qc_str;
  ASSH_ASSERT(assh_packet_add_string(p, sizeof(assh_25519key_t), &qc_str));
  memcpy(qc_str, pv->pubkey, sizeof(assh_25519key_t));

  assh_transport_push(s, p);

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
  ASSH_SCRATCH_ALLOC(s->ctx, uint8_t, scratch,
                     assh_hash_sha256.ctx_size
                     + ASSH_KEX_25519_SECRET_BUFSIZE,
		     ASSH_ERRSV_CONTINUE, err_);

  void *hash_ctx = scratch;
  uint8_t *secret_buf = scratch + assh_hash_sha256.ctx_size;

  ASSH_ERR_GTO(assh_montgomery_point_mul(secret_buf + 5,
                           qs_str + 4, pv->pvkey), err_sc);

  uint8_t *secret = assh_kex_25519_secret_to_mpint(secret_buf);

  ASSH_ERR_GTO(assh_hash_init(s->ctx, hash_ctx, &assh_hash_sha256), err_sc);

  /* compute exchange hash and send reply */
  ASSH_ERR_GTO(assh_kex_client_hash1(s, hash_ctx, ks_str)
               | ASSH_ERRSV_DISCONNECT, err_sc);

  assh_hash_bytes_as_string(hash_ctx, pv->pubkey, sizeof(pv->pubkey));
  assh_hash_string(hash_ctx, qs_str);

  ASSH_ERR_GTO(assh_kex_client_hash2(s, hash_ctx, pv->host_key,
                                    secret, h_str)
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

  ASSH_SCRATCH_ALLOC(s->ctx, uint8_t, scratch,
                     assh_hash_sha256.ctx_size
                     + ASSH_KEX_25519_SECRET_BUFSIZE,
		     ASSH_ERRSV_CONTINUE, err_);

  void *hash_ctx = scratch;
  uint8_t *secret_buf = scratch + assh_hash_sha256.ctx_size;

  ASSH_ERR_GTO(assh_montgomery_point_mul(pv->pubkey,
                 curve25519_basepoint, pv->pvkey), err_sc);

  /* compute shared secret */
  ASSH_ERR_GTO(assh_montgomery_point_mul(secret_buf + 5,
                 qc_str + 4, pv->pvkey), err_sc);

  uint8_t *secret = assh_kex_25519_secret_to_mpint(secret_buf);

  ASSH_ERR_GTO(assh_hash_init(s->ctx, hash_ctx, &assh_hash_sha256), err_sc);

  /* compute exchange hash and send reply */
  struct assh_packet_s *pout;
  const struct assh_key_s *hk;
  size_t slen;

  ASSH_ERR_GTO(assh_kex_server_hash1(s, 
                 /* room for qs_str */ 4 + sizeof(assh_25519key_t),
                 hash_ctx, &pout, &slen, &hk), err_sc);

  uint8_t *qs_str;
  ASSH_ASSERT(assh_packet_add_string(pout, sizeof(assh_25519key_t), &qs_str));
  memcpy(qs_str, pv->pubkey, sizeof(assh_25519key_t));

  /* hash both ephemeral public keys */
  assh_hash_string(hash_ctx, qc_str);
  assh_hash_string(hash_ctx, qs_str - 4);

  ASSH_ERR_GTO(assh_kex_server_hash2(s, hash_ctx, pout, slen, hk, secret), err_p);

  assh_transport_push(s, pout);
  ASSH_SCRATCH_FREE(c, scratch);

  return ASSH_OK;

 err_p:
  assh_packet_release(pout);
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

