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

#include "ecc_weierstrass.h"

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
  const struct assh_key_s *host_key;
  struct assh_packet_s *pck;
#endif

  size_t size;
  uint8_t *pubkey;
  uint8_t *pvkey;
};

assh_error_t ASSH_WARN_UNUSED_RESULT
assh_weierstrass_base_mul(struct assh_session_s *s)
{
  struct assh_kex_ecdhws_private_s *pv = s->kex_pv;
  const struct assh_weierstrass_curve_s *curve = pv->curve;
  assh_error_t err;

  assert(curve->cofactor == 1);

  enum {
    X_raw, Y_raw, P_raw, SC_raw,
    X1, Y1, Z1, X2, Y2, Z2, X3, Y3, Z3, T0, T1, T2, T3, SC,
    MT, S
  };

  static const assh_bignum_op_t bytecode[] = {

    ASSH_BOP_SIZER(     X1,     SC,    S                ),

    /* init */
    ASSH_BOP_MOVE(      T0,     P_raw                   ),
    ASSH_BOP_MTINIT(	MT,     T0                      ),

    ASSH_BOP_MOVE(      SC,     SC_raw                  ),
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

  ASSH_ERR_RET(assh_bignum_bytecode(s->ctx, 0, bytecode,
                "DDDDTTTTTTTTTTTTTXms", rx, ry, curve->p, pv->pvkey, curve->bits));

  return ASSH_OK;
}

assh_error_t ASSH_WARN_UNUSED_RESULT
assh_weierstrass_point_mul(struct assh_session_s *s, uint8_t *px,
                           const uint8_t *r)
{
  struct assh_kex_ecdhws_private_s *pv = s->kex_pv;
  const struct assh_weierstrass_curve_s *curve = pv->curve;
  assh_error_t err;

  assert(curve->cofactor == 1);

  enum {
    X_raw, Y_raw, P_raw, B_raw, SC_raw, PX_mpint,
    X1, Y1, Z1, X2, Y2, Z2, X3, Y3, Z3, T0, T1, T2, T3, SC,
    MT, S
  };

  static const assh_bignum_op_t bytecode[] = {

    ASSH_BOP_SIZER(     X1,     SC,    S                ),

    /* init */
    ASSH_BOP_MOVE(      T0,     P_raw                   ),
    ASSH_BOP_MTINIT(	MT,     T0                      ),

    ASSH_BOP_MOVE(      SC,     SC_raw                  ),
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

  ASSH_ERR_RET(assh_bignum_bytecode(s->ctx, 0, bytecode, "DDDDDMTTTTTTTTTTTTTXms",
                 rx, ry, curve->p, curve->b, pv->pvkey, px, curve->bits));

  return ASSH_OK;
}

#ifdef CONFIG_ASSH_CLIENT
static assh_error_t assh_kex_ecdhws_client_send_pubkey(struct assh_session_s *s)
{
  struct assh_kex_ecdhws_private_s *pv = s->kex_pv;
  struct assh_context_s *c = s->ctx;
  assh_error_t err;

  /* generate ephemeral key pair */
  ASSH_ERR_RET(s->ctx->prng->f_get(s->ctx, pv->pvkey, pv->size,
                      ASSH_PRNG_QUALITY_EPHEMERAL_KEY));

  ASSH_ERR_RET(assh_weierstrass_base_mul(s));

  /* send a packet containing the public key */
  struct assh_packet_s *p;
  size_t psize = pv->size * 2 + 1;

  ASSH_ERR_RET(assh_packet_alloc(c, SSH_MSG_KEX_ECDH_INIT,
               4 + psize, &p) | ASSH_ERRSV_DISCONNECT);

  uint8_t *qc_str;
  ASSH_ASSERT(assh_packet_add_string(p, psize, &qc_str));
  memcpy(qc_str, pv->pubkey, psize);

  assh_transport_push(s, p);

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_kex_ecdhws_host_key_lookup_done)
{
  struct assh_kex_ecdhws_private_s *pv = s->kex_pv;
  assh_error_t err;

  ASSH_CHK_RET(pv->state != ASSH_KEX_ECDHWS_CLIENT_LOOKUP_HOST_KEY_WAIT,
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

  ASSH_CHK_RET(assh_load_u32(qs_str) != pv->size * 2 + 1 ||
               qs_str[4] != 0x04,
               ASSH_ERR_BAD_DATA | ASSH_ERRSV_DISCONNECT);

  /* compute shared secret */
  ASSH_SCRATCH_ALLOC(s->ctx, uint8_t, scratch,
                     pv->hash->ctx_size + 5 + pv->size,
		     ASSH_ERRSV_CONTINUE, err_);

  void *hash_ctx = scratch;
  uint8_t *secret = scratch + pv->hash->ctx_size;

  ASSH_ERR_GTO(assh_weierstrass_point_mul(s, secret, qs_str + 4), err_sc);

  /* compute exchange hash and send reply */
  ASSH_ERR_GTO(assh_hash_init(s->ctx, hash_ctx, pv->hash), err_sc);

  ASSH_ERR_GTO(assh_kex_client_hash1(s, hash_ctx, ks_str)
               | ASSH_ERRSV_DISCONNECT, err_sc);

  assh_hash_bytes_as_string(hash_ctx, pv->pubkey, pv->size * 2 + 1);
  assh_hash_string(hash_ctx, qs_str);

  ASSH_ERR_GTO(assh_kex_client_hash2(s, hash_ctx, pv->host_key,
                                    secret, h_str)
               | ASSH_ERRSV_DISCONNECT, err_sc);

  ASSH_ERR_GTO(assh_kex_end(s, 1) | ASSH_ERRSV_DISCONNECT, err_hash);

  err = ASSH_OK;

 err_hash:
  assh_hash_cleanup(hash_ctx);
 err_sc:
  ASSH_SCRATCH_FREE(s->ctx, scratch);
 err_:
  return err;
}

static assh_error_t assh_kex_ecdhws_client_wait_reply(struct assh_session_s *s,
                                                      struct assh_packet_s *p,
                                                      struct assh_event_s *e)
{
  struct assh_kex_ecdhws_private_s *pv = s->kex_pv;
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

  ASSH_CHK_RET(assh_load_u32(qs_str) != pv->size * 2 + 1,
               ASSH_ERR_BAD_DATA | ASSH_ERRSV_DISCONNECT);

  ASSH_ERR_RET(assh_kex_client_get_key(s, &pv->host_key, ks_str, e,
                              &assh_kex_ecdhws_host_key_lookup_done, pv));

  pv->state = ASSH_KEX_ECDHWS_CLIENT_LOOKUP_HOST_KEY_WAIT;
  pv->pck = assh_packet_refinc(p);

  return ASSH_OK;
}

#endif


#ifdef CONFIG_ASSH_SERVER

static assh_error_t assh_kex_ecdhws_server_wait_pubkey(struct assh_session_s *s,
                                                       struct assh_packet_s *p)
{
  struct assh_kex_ecdhws_private_s *pv = s->kex_pv;
  struct assh_context_s *c = s->ctx;
  assh_error_t err;

  ASSH_CHK_RET(p->head.msg != SSH_MSG_KEX_ECDH_INIT,
	       ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);

  uint8_t *qc_str = p->head.end;

  ASSH_ERR_RET(assh_packet_check_string(p, qc_str, NULL)
	       | ASSH_ERRSV_DISCONNECT);

  ASSH_CHK_RET(assh_load_u32(qc_str) != pv->size * 2 + 1 ||
               qc_str[4] != 0x04,
               ASSH_ERR_BAD_DATA | ASSH_ERRSV_DISCONNECT);

  /* generate ephemeral key pair */
  ASSH_ERR_RET(s->ctx->prng->f_get(s->ctx, pv->pvkey, pv->size,
                      ASSH_PRNG_QUALITY_EPHEMERAL_KEY));

  ASSH_ERR_RET(assh_weierstrass_base_mul(s));

  /* compute shared secret */
  ASSH_SCRATCH_ALLOC(s->ctx, uint8_t, scratch,
                     pv->hash->ctx_size + 5 + pv->size,
		     ASSH_ERRSV_CONTINUE, err_);

  void *hash_ctx = scratch;
  uint8_t *secret = scratch + pv->hash->ctx_size;

  ASSH_ERR_GTO(assh_weierstrass_point_mul(s, secret, qc_str + 4), err_sc);

  /* compute exchange hash and send reply */
  ASSH_ERR_GTO(assh_hash_init(s->ctx, hash_ctx, pv->hash), err_sc);

  struct assh_packet_s *pout;
  const struct assh_key_s *hk;
  size_t slen;
  size_t psize = pv->size * 2 + 1;

  ASSH_ERR_GTO(assh_kex_server_hash1(s, 
                 /* room for qs_str */ 4 + psize,
                 hash_ctx, &pout, &slen, &hk,
                 SSH_MSG_KEX_ECDH_REPLY), err_sc);

  uint8_t *qs_str;
  ASSH_ASSERT(assh_packet_add_string(pout, psize, &qs_str));
  memcpy(qs_str, pv->pubkey, psize);

  /* hash both ephemeral public keys */
  assh_hash_string(hash_ctx, qc_str);
  assh_hash_string(hash_ctx, qs_str - 4);

  ASSH_ERR_GTO(assh_kex_server_hash2(s, hash_ctx, pout, slen, hk, secret), err_p);

  assh_transport_push(s, pout);

  ASSH_ERR_GTO(assh_kex_end(s, 1) | ASSH_ERRSV_DISCONNECT, err_hash);

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
  assh_error_t err;

  switch (pv->state)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_KEX_ECDHWS_CLIENT_INIT:
      assert(p == NULL);
      ASSH_ERR_RET(assh_kex_ecdhws_client_send_pubkey(s)
		   | ASSH_ERRSV_DISCONNECT);
      pv->state = ASSH_KEX_ECDHWS_CLIENT_SEND_PUB;
      return ASSH_OK;

    case ASSH_KEX_ECDHWS_CLIENT_SEND_PUB:
      if (p == NULL)
        return ASSH_OK;
      ASSH_ERR_RET(assh_kex_ecdhws_client_wait_reply(s, p, e)
		   | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;

    case ASSH_KEX_ECDHWS_CLIENT_LOOKUP_HOST_KEY_WAIT:
      ASSH_ERR_RET(ASSH_ERR_STATE | ASSH_ERRSV_FATAL);
#endif

#ifdef CONFIG_ASSH_SERVER
    case ASSH_KEX_ECDHWS_SERVER_WAIT_E:
      if (p == NULL)
        return ASSH_OK;
      ASSH_ERR_RET(assh_kex_ecdhws_server_wait_pubkey(s, p)
		   | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;
#endif
    }

  return ASSH_OK;
}

static ASSH_KEX_CLEANUP_FCN(assh_kex_ecdhws_cleanup)
{
  struct assh_kex_ecdhws_private_s *pv = s->kex_pv;

#ifdef CONFIG_ASSH_CLIENT
  if (s->ctx->type == ASSH_CLIENT)
    {
      assh_key_flush(s->ctx, &pv->host_key);
      assh_packet_release(pv->pck);
    }
#endif

  assh_free(s->ctx, s->kex_pv);
  s->kex_pv = NULL;
}

static assh_error_t
assh_kex_ecdhws_init(struct assh_session_s *s,
                     const struct assh_weierstrass_curve_s *curve,
                     const struct assh_hash_algo_s *hash)
{
  assh_error_t err;

  size_t l = ASSH_ALIGN8(curve->bits) / 8;

  struct assh_kex_ecdhws_private_s *pv;
  ASSH_ERR_RET(assh_alloc(s->ctx, sizeof(*pv) + 1 + l * 3,
                          ASSH_ALLOC_SECUR, (void**)&pv)
	       | ASSH_ERRSV_DISCONNECT);

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
      pv->state = ASSH_KEX_ECDHWS_CLIENT_INIT;
      pv->host_key = NULL;
      pv->pck = NULL;
      break;
#endif
#ifdef CONFIG_ASSH_SERVER
    case ASSH_SERVER:
      pv->state = ASSH_KEX_ECDHWS_SERVER_WAIT_E;
      break;
#endif
    default:
      abort();
    }

  return ASSH_OK;
}

#warning move

const struct assh_weierstrass_curve_s assh_nistp256_curve =
  {
    .p = (const uint8_t*)
    "\xff\xff\xff\xff\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
    .n = (const uint8_t*)
    "\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xbc\xe6\xfa\xad\xa7\x17\x9e\x84\xf3\xb9\xca\xc2\xfc\x63\x25\x51",
    .b = (const uint8_t*)
    "\x5a\xc6\x35\xd8\xaa\x3a\x93\xe7\xb3\xeb\xbd\x55\x76\x98\x86\xbc"
    "\x65\x1d\x06\xb0\xcc\x53\xb0\xf6\x3b\xce\x3c\x3e\x27\xd2\x60\x4b",
    .gx = (const uint8_t*)
    "\x6b\x17\xd1\xf2\xe1\x2c\x42\x47\xf8\xbc\xe6\xe5\x63\xa4\x40\xf2"
    "\x77\x03\x7d\x81\x2d\xeb\x33\xa0\xf4\xa1\x39\x45\xd8\x98\xc2\x96",
    .gy = (const uint8_t*)
    "\x4f\xe3\x42\xe2\xfe\x1a\x7f\x9b\x8e\xe7\xeb\x4a\x7c\x0f\x9e\x16"
    "\x2b\xce\x33\x57\x6b\x31\x5e\xce\xcb\xb6\x40\x68\x37\xbf\x51\xf5",
    .bits = 256,
    .cofactor = 1,
  };

const struct assh_weierstrass_curve_s assh_nistp384_curve =
  {
    .p = (const uint8_t*)
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe"
    "\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff",
    .n = (const uint8_t*)
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xc7\x63\x4d\x81\xf4\x37\x2d\xdf"
    "\x58\x1a\x0d\xb2\x48\xb0\xa7\x7a\xec\xec\x19\x6a\xcc\xc5\x29\x73",
    .b = (const uint8_t*)
    "\xb3\x31\x2f\xa7\xe2\x3e\xe7\xe4\x98\x8e\x05\x6b\xe3\xf8\x2d\x19"
    "\x18\x1d\x9c\x6e\xfe\x81\x41\x12\x03\x14\x08\x8f\x50\x13\x87\x5a"
    "\xc6\x56\x39\x8d\x8a\x2e\xd1\x9d\x2a\x85\xc8\xed\xd3\xec\x2a\xef",
    .gx = (const uint8_t*)
    "\xaa\x87\xca\x22\xbe\x8b\x05\x37\x8e\xb1\xc7\x1e\xf3\x20\xad\x74"
    "\x6e\x1d\x3b\x62\x8b\xa7\x9b\x98\x59\xf7\x41\xe0\x82\x54\x2a\x38"
    "\x55\x02\xf2\x5d\xbf\x55\x29\x6c\x3a\x54\x5e\x38\x72\x76\x0a\xb7",
    .gy = (const uint8_t*)
    "\x36\x17\xde\x4a\x96\x26\x2c\x6f\x5d\x9e\x98\xbf\x92\x92\xdc\x29"
    "\xf8\xf4\x1d\xbd\x28\x9a\x14\x7c\xe9\xda\x31\x13\xb5\xf0\xb8\xc0"
    "\x0a\x60\xb1\xce\x1d\x7e\x81\x9d\x7a\x43\x1d\x7c\x90\xea\x0e\x5f",
    .bits = 384,
    .cofactor = 1,
  };

const struct assh_weierstrass_curve_s assh_nistp521_curve =
  {
    .p = (const uint8_t*)
    "\x01\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
    .n = (const uint8_t*)
    "\x01\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfa"
    "\x51\x86\x87\x83\xbf\x2f\x96\x6b\x7f\xcc\x01\x48\xf7\x09\xa5\xd0"
    "\x3b\xb5\xc9\xb8\x89\x9c\x47\xae\xbb\x6f\xb7\x1e\x91\x38\x64\x09",
    .b = (const uint8_t*)
    "\x00\x51"
    "\x95\x3e\xb9\x61\x8e\x1c\x9a\x1f\x92\x9a\x21\xa0\xb6\x85\x40\xee"
    "\xa2\xda\x72\x5b\x99\xb3\x15\xf3\xb8\xb4\x89\x91\x8e\xf1\x09\xe1"
    "\x56\x19\x39\x51\xec\x7e\x93\x7b\x16\x52\xc0\xbd\x3b\xb1\xbf\x07"
    "\x35\x73\xdf\x88\x3d\x2c\x34\xf1\xef\x45\x1f\xd4\x6b\x50\x3f\x00",
    .gx = (const uint8_t*)
    "\x00\xc6"
    "\x85\x8e\x06\xb7\x04\x04\xe9\xcd\x9e\x3e\xcb\x66\x23\x95\xb4\x42"
    "\x9c\x64\x81\x39\x05\x3f\xb5\x21\xf8\x28\xaf\x60\x6b\x4d\x3d\xba"
    "\xa1\x4b\x5e\x77\xef\xe7\x59\x28\xfe\x1d\xc1\x27\xa2\xff\xa8\xde"
    "\x33\x48\xb3\xc1\x85\x6a\x42\x9b\xf9\x7e\x7e\x31\xc2\xe5\xbd\x66",
    .gy = (const uint8_t*)
    "\x01\x18"
    "\x39\x29\x6a\x78\x9a\x3b\xc0\x04\x5c\x8a\x5f\xb4\x2c\x7d\x1b\xd9"
    "\x98\xf5\x44\x49\x57\x9b\x44\x68\x17\xaf\xbd\x17\x27\x3e\x66\x2c"
    "\x97\xee\x72\x99\x5e\xf4\x26\x40\xc5\x50\xb9\x01\x3f\xad\x07\x61"
    "\x35\x3c\x70\x86\xa2\x72\xc2\x40\x88\xbe\x94\x76\x9f\xd1\x66\x50",
    .bits = 521,
    .cofactor = 1,
  };

static ASSH_KEX_INIT_FCN(assh_kex_nistp256_init)
{
  return assh_kex_ecdhws_init(s, &assh_nistp256_curve, &assh_hash_sha256);
}

const struct assh_algo_kex_s assh_kex_sha2_nistp256 =
{
  .algo = { .name = "ecdh-sha2-nistp256",
	    .class_ = ASSH_ALGO_KEX, .safety = 21, .speed = 80 },
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
  .algo = { .name = "ecdh-sha2-nistp384",
	    .class_ = ASSH_ALGO_KEX, .safety = 23, .speed = 70 },
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
  .algo = { .name = "ecdh-sha2-nistp521",
	    .class_ = ASSH_ALGO_KEX, .safety = 25, .speed = 60 },
  .f_init = assh_kex_nistp521_init,
  .f_cleanup = assh_kex_ecdhws_cleanup,
  .f_process = assh_kex_ecdhws_process,
};

