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
  Implement ECDH using weierstrass elliptic curves has defined in rfc5656
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

#include "ecc_weierstrass.h"

#include <string.h>
#include <stdlib.h>

enum assh_kex_ecdhws_state_e
{
#ifdef CONFIG_ASSH_CLIENT
  ASSH_KEX_ECDHWS_CLIENT_SEND_PUB,
  ASSH_KEX_ECDHWS_CLIENT_INIT,
  ASSH_KEX_ECDHWS_CLIENT_LOOKUP_HOST_KEY_WAIT,
#endif
#ifdef CONFIG_ASSH_SERVER
  ASSH_KEX_ECDHWS_SERVER_WAIT_E,
#endif
};

struct assh_kex_ecdhws_private_s
{
  const struct assh_weierstrass_curve_s *curve;
  const struct assh_hash_algo_s *hash;
  enum assh_kex_ecdhws_state_e state;

#ifdef CONFIG_ASSH_CLIENT
  struct assh_packet_s *pck;
#endif

  size_t size;
  uint8_t *pubkey;
  uint8_t *pvkey;
};

static assh_status_t ASSH_WARN_UNUSED_RESULT
assh_weierstrass_base_mul(struct assh_session_s *s)
{
  struct assh_kex_ecdhws_private_s *pv = s->kex_pv;
  const struct assh_weierstrass_curve_s *curve = pv->curve;
  assh_status_t err;

  assert(curve->cofactor == 1);

  enum {
    X_raw, Y_raw, P_raw, SC_raw,
    X1, Y1, Z1, X2, Y2, Z2, X3, Y3, Z3, T0, T1, T2, T3, SC,
    MT, S
  };

  static const assh_bignum_op_t bytecode[] = {

    ASSH_BOP_SIZER(     X1,     MT,    S                ),

    /* init */
    ASSH_BOP_MOVE(      T0,     P_raw                   ),
    ASSH_BOP_MTINIT(	MT,     T0                      ),

    ASSH_BOP_MOVES(     SC,     SC_raw                  ),
    ASSH_BOP_MOVE(      X1,     X_raw                   ),
    ASSH_BOP_MOVE(      Y1,     Y_raw                   ),
    ASSH_BOP_MTTO(      X1,     Y1,     X1,     MT      ),

    ASSH_BOP_WS_SCMUL(X3, Y3, Z3, X2, Y2, Z2, X1, Y1, Z1,
                      T0, T1, T2, T3, SC, MT),

    ASSH_BOP_MTFROM(	X2,     Y2,     X2,     MT      ),

#ifdef CONFIG_ASSH_DEBUG_KEX
    ASSH_BOP_PRINT(     X2,    'X'                      ),
    ASSH_BOP_PRINT(     Y2,    'Y'                      ),
#endif

    ASSH_BOP_MOVE(      X_raw,  X2                      ),
    ASSH_BOP_MOVE(      Y_raw,  Y2                      ),

    ASSH_BOP_END(),
  };

  /* public key with no point compression */
  pv->pubkey[0] = 0x04;
  uint8_t *rx = pv->pubkey + 1;
  uint8_t *ry = pv->pubkey + 1 + pv->size;

  memcpy(rx, curve->gx, pv->size);
  memcpy(ry, curve->gy, pv->size);

  ASSH_RETURN(assh_bignum_bytecode(s->ctx, 0, bytecode,
                "DDDDTTTTTTTTTTTTTTms", rx, ry, curve->p, pv->pvkey,
                (size_t)curve->bits));
}

static assh_status_t ASSH_WARN_UNUSED_RESULT
assh_weierstrass_point_mul(struct assh_session_s *s, uint8_t *px,
                           const uint8_t *r)
{
  struct assh_kex_ecdhws_private_s *pv = s->kex_pv;
  const struct assh_weierstrass_curve_s *curve = pv->curve;
  assh_status_t err;

  assert(curve->cofactor == 1);

  enum {
    X_raw, Y_raw, P_raw, B_raw, SC_raw, PX_mpint,
    X1, Y1, Z1, X2, Y2, Z2, X3, Y3, Z3, T0, T1, T2, T3, SC,
    MT, S
  };

  static const assh_bignum_op_t bytecode[] = {

    ASSH_BOP_SIZER(     X1,     MT,    S                ),

    /* init */
    ASSH_BOP_MOVE(      T0,     P_raw                   ),
    ASSH_BOP_MTINIT(	MT,     T0                      ),

    ASSH_BOP_MOVES(     SC,     SC_raw                  ),
    ASSH_BOP_MOVE(      X1,     X_raw                   ),
    ASSH_BOP_MOVE(      Y1,     Y_raw                   ),
    ASSH_BOP_MOVE(      T2,     B_raw                   ),
    ASSH_BOP_MTTO(      X1,     Y1,     X1,     MT      ),

    /* check that point is on curve */
    ASSH_BOP_WS_POINTONCURVE(X1, Y1, T0, T1, T2, MT),

#ifdef CONFIG_ASSH_DEBUG_KEX
    ASSH_BOP_PRINT(     X1,    'x'                      ),
    ASSH_BOP_PRINT(     Y1,    'y'                      ),
#endif

    ASSH_BOP_WS_SCMUL(X3, Y3, Z3, X2, Y2, Z2, X1, Y1, Z1,
                      T0, T1, T2, T3, SC, MT),

    ASSH_BOP_MTFROM(	X2,     Y2,     X2,     MT      ),

#ifdef CONFIG_ASSH_DEBUG_KEX
    ASSH_BOP_PRINT(     X2,    'X'                      ),
    ASSH_BOP_PRINT(     Y2,    'Y'                      ),
#endif

    ASSH_BOP_MOVE(      PX_mpint,  X2                   ),

    ASSH_BOP_END(),
  };

  const uint8_t *rx = r + 1;
  const uint8_t *ry = r + 1 + pv->size;

  ASSH_RET_ON_ERR(assh_bignum_bytecode(s->ctx, 0, bytecode, "DDDDDMTTTTTTTTTTTTTTms",
                 rx, ry, curve->p, curve->b, pv->pvkey, px, curve->bits));

  return ASSH_OK;
}

#ifdef CONFIG_ASSH_CLIENT
static assh_status_t assh_kex_ecdhws_client_send_pubkey(struct assh_session_s *s)
{
  struct assh_kex_ecdhws_private_s *pv = s->kex_pv;
  struct assh_context_s *c = s->ctx;
  assh_status_t err;

  /* generate ephemeral key pair */
  ASSH_RET_ON_ERR(assh_prng_get(s->ctx, pv->pvkey, pv->size,
                      ASSH_PRNG_QUALITY_EPHEMERAL_KEY));

  ASSH_RET_ON_ERR(assh_weierstrass_base_mul(s));

  /* send a packet containing the public key */
  struct assh_packet_s *p;
  size_t psize = pv->size * 2 + 1;

  ASSH_RET_ON_ERR(assh_packet_alloc(c, SSH_MSG_KEX_ECDH_INIT,
               4 + psize, &p));

  uint8_t *qc_str;
  ASSH_ASSERT(assh_packet_add_string(p, psize, &qc_str));
  memcpy(qc_str, pv->pubkey, psize);

  assh_transport_push(s, p);

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_kex_ecdhws_host_key_lookup_done)
{
  struct assh_kex_ecdhws_private_s *pv = s->kex_pv;
  assh_status_t err;

  assert(pv->state == ASSH_KEX_ECDHWS_CLIENT_LOOKUP_HOST_KEY_WAIT);

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

  ASSH_RET_IF_TRUE(assh_load_u32(qs_str) != pv->size * 2 + 1 ||
               qs_str[4] != 0x04,
               ASSH_ERR_BAD_DATA | ASSH_ERRSV_DISCONNECT);

  /* compute shared secret */
  ASSH_SCRATCH_ALLOC(s->ctx, uint8_t, scratch,
                     pv->hash->ctx_size + 5 + pv->size,
		     ASSH_ERRSV_DISCONNECT, err_);

  void *hash_ctx = scratch;
  uint8_t *secret = scratch + pv->hash->ctx_size;

  ASSH_JMP_ON_ERR(assh_weierstrass_point_mul(s, secret, qs_str + 4)
               | ASSH_ERRSV_DISCONNECT, err_sc);

  /* compute exchange hash and send reply */
  ASSH_JMP_ON_ERR(assh_hash_init(s->ctx, hash_ctx, pv->hash)
               | ASSH_ERRSV_DISCONNECT, err_sc);

  ASSH_JMP_ON_ERR(assh_kex_client_hash1(s, hash_ctx, ks_str)
               | ASSH_ERRSV_DISCONNECT, err_sc);

  assh_hash_bytes_as_string(hash_ctx, pv->pubkey, pv->size * 2 + 1);
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

static assh_status_t assh_kex_ecdhws_client_wait_reply(struct assh_session_s *s,
                                                      struct assh_packet_s *p,
                                                      struct assh_event_s *e)
{
  struct assh_kex_ecdhws_private_s *pv = s->kex_pv;
  assh_status_t err;

  ASSH_RET_IF_TRUE(p->head.msg != SSH_MSG_KEX_ECDH_REPLY, ASSH_ERR_PROTOCOL);

  const uint8_t *ks_str = p->head.end;
  const uint8_t *qs_str, *h_str;

  ASSH_RET_ON_ERR(assh_packet_check_string(p, ks_str, &qs_str));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, qs_str, &h_str));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, h_str, NULL));

  ASSH_RET_IF_TRUE(assh_load_u32(qs_str) != pv->size * 2 + 1,
               ASSH_ERR_BAD_DATA);

  ASSH_RET_ON_ERR(assh_kex_client_get_key(s, ks_str, e,
                 &assh_kex_ecdhws_host_key_lookup_done, pv));

  ASSH_SET_STATE(pv, state, ASSH_KEX_ECDHWS_CLIENT_LOOKUP_HOST_KEY_WAIT);
  pv->pck = assh_packet_refinc(p);

  return ASSH_OK;
}

#endif


#ifdef CONFIG_ASSH_SERVER

static assh_status_t assh_kex_ecdhws_server_wait_pubkey(struct assh_session_s *s,
                                                       struct assh_packet_s *p)
{
  struct assh_kex_ecdhws_private_s *pv = s->kex_pv;
  struct assh_context_s *c = s->ctx;
  assh_status_t err;

  ASSH_RET_IF_TRUE(p->head.msg != SSH_MSG_KEX_ECDH_INIT,
	       ASSH_ERR_PROTOCOL);

  uint8_t *qc_str = p->head.end;

  ASSH_RET_ON_ERR(assh_packet_check_string(p, qc_str, NULL));

  ASSH_RET_IF_TRUE(assh_load_u32(qc_str) != pv->size * 2 + 1 ||
               qc_str[4] != 0x04,
               ASSH_ERR_BAD_DATA);

  /* generate ephemeral key pair */
  ASSH_RET_ON_ERR(assh_prng_get(s->ctx, pv->pvkey, pv->size,
                      ASSH_PRNG_QUALITY_EPHEMERAL_KEY));

  ASSH_RET_ON_ERR(assh_weierstrass_base_mul(s));

  /* compute shared secret */
  ASSH_SCRATCH_ALLOC(s->ctx, uint8_t, scratch,
                     pv->hash->ctx_size + 5 + pv->size,
		     ASSH_ERRSV_CONTINUE, err_);

  void *hash_ctx = scratch;
  uint8_t *secret = scratch + pv->hash->ctx_size;

  ASSH_JMP_ON_ERR(assh_weierstrass_point_mul(s, secret, qc_str + 4), err_sc);

  /* compute exchange hash and send reply */
  ASSH_JMP_ON_ERR(assh_hash_init(s->ctx, hash_ctx, pv->hash), err_sc);

  struct assh_packet_s *pout;
  struct assh_key_s *hk;
  size_t slen;
  size_t psize = pv->size * 2 + 1;

  ASSH_JMP_ON_ERR(assh_kex_server_hash1(s, 
                 /* room for qs_str */ 4 + psize,
                 hash_ctx, &pout, &slen, &hk,
                 SSH_MSG_KEX_ECDH_REPLY), err_sc);

  uint8_t *qs_str;
  ASSH_ASSERT(assh_packet_add_string(pout, psize, &qs_str));
  memcpy(qs_str, pv->pubkey, psize);

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

static ASSH_KEX_PROCESS_FCN(assh_kex_ecdhws_process)
{
  struct assh_kex_ecdhws_private_s *pv = s->kex_pv;
  assh_status_t err;

  switch (pv->state)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_KEX_ECDHWS_CLIENT_INIT:
      assert(p == NULL);
      ASSH_RET_ON_ERR(assh_kex_ecdhws_client_send_pubkey(s)
		   | ASSH_ERRSV_DISCONNECT);
      ASSH_SET_STATE(pv, state, ASSH_KEX_ECDHWS_CLIENT_SEND_PUB);
      return ASSH_OK;

    case ASSH_KEX_ECDHWS_CLIENT_SEND_PUB:
      if (p == NULL)
        return ASSH_OK;
      ASSH_RETURN(assh_kex_ecdhws_client_wait_reply(s, p, e)
                    | ASSH_ERRSV_DISCONNECT);

    case ASSH_KEX_ECDHWS_CLIENT_LOOKUP_HOST_KEY_WAIT:
      ASSH_UNREACHABLE();
#endif

#ifdef CONFIG_ASSH_SERVER
    case ASSH_KEX_ECDHWS_SERVER_WAIT_E:
      if (p == NULL)
        return ASSH_OK;
      ASSH_RETURN(assh_kex_ecdhws_server_wait_pubkey(s, p)
		   | ASSH_ERRSV_DISCONNECT);
#endif
    }

  return ASSH_OK;
}

static ASSH_KEX_CLEANUP_FCN(assh_kex_ecdhws_cleanup)
{
  struct assh_kex_ecdhws_private_s *pv = s->kex_pv;

#ifdef CONFIG_ASSH_CLIENT
  if (s->ctx->type == ASSH_CLIENT)
    assh_packet_release(pv->pck);
#endif

  assh_free(s->ctx, s->kex_pv);
  s->kex_pv = NULL;
}

static assh_status_t
assh_kex_ecdhws_init(struct assh_session_s *s,
                     const struct assh_weierstrass_curve_s *curve,
                     const struct assh_hash_algo_s *hash)
{
  assh_status_t err;

  size_t l = ASSH_ALIGN8(curve->bits) / 8;

  struct assh_kex_ecdhws_private_s *pv;
  ASSH_RET_ON_ERR(assh_alloc(s->ctx, sizeof(*pv) + 1 + l * 3,
                          ASSH_ALLOC_SECUR, (void**)&pv));

  s->kex_pv = pv;

  pv->curve = curve;
  pv->hash = hash;
  pv->size = l;
  pv->pubkey = (void*)(pv + 1);
  pv->pvkey = 1 + pv->pubkey + l * 2;

  switch (s->ctx->type)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_CLIENT:
      ASSH_SET_STATE(pv, state, ASSH_KEX_ECDHWS_CLIENT_INIT);
      pv->pck = NULL;
      break;
#endif
#ifdef CONFIG_ASSH_SERVER
    case ASSH_SERVER:
      ASSH_SET_STATE(pv, state, ASSH_KEX_ECDHWS_SERVER_WAIT_E);
      break;
#endif
    default:
      ASSH_UNREACHABLE();
    }

  return ASSH_OK;
}

static ASSH_KEX_INIT_FCN(assh_kex_nistp256_init)
{
  return assh_kex_ecdhws_init(s, &assh_nistp256_curve, &assh_hash_sha256);
}

const struct assh_algo_kex_s assh_kex_sha2_nistp256 =
{
  ASSH_ALGO_BASE(KEX, "assh-builtin", ASSH_NISTP256_SAFETY, 80,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
                      "ecdh-sha2-nistp256" }),
    .nondeterministic = 1,
  ),
  .f_init = assh_kex_nistp256_init,
  .f_cleanup = assh_kex_ecdhws_cleanup,
  .f_process = assh_kex_ecdhws_process,
};

static ASSH_KEX_INIT_FCN(assh_kex_nistp384_init)
{
  return assh_kex_ecdhws_init(s, &assh_nistp384_curve, &assh_hash_sha384);
}

const struct assh_algo_kex_s assh_kex_sha2_nistp384 =
{
  ASSH_ALGO_BASE(KEX, "assh-builtin", ASSH_NISTP384_SAFETY, 70,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF, "ecdh-sha2-nistp384" }),
    .nondeterministic = 1,
  ),
  .f_init = assh_kex_nistp384_init,
  .f_cleanup = assh_kex_ecdhws_cleanup,
  .f_process = assh_kex_ecdhws_process,
};

static ASSH_KEX_INIT_FCN(assh_kex_nistp521_init)
{
  return assh_kex_ecdhws_init(s, &assh_nistp521_curve, &assh_hash_sha512);
}

const struct assh_algo_kex_s assh_kex_sha2_nistp521 =
{
  ASSH_ALGO_BASE(KEX, "assh-builtin", ASSH_NISTP521_SAFETY, 60,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF, "ecdh-sha2-nistp521" }),
    .nondeterministic = 1,
  ),
  .f_init = assh_kex_nistp521_init,
  .f_cleanup = assh_kex_ecdhws_cleanup,
  .f_process = assh_kex_ecdhws_process,
};

