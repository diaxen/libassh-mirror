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
   - A note on high-security general-purpose elliptic curves
   - IETF draft-ladd-safecurves-04.txt

  SSH key exchange protocol from:
    - curve25519-sha256_libssh.org.txt
*/

#define ASSH_PV

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

#include <assh/assh_bignum.h>

#include <string.h>
#include <stdlib.h>

struct assh_montgomery_curve_s
{
  const uint8_t *prime;
  const uint8_t *a24;
  const uint8_t *basepoint;
  size_t bits;
  uint_fast8_t cofactor;
};

enum assh_kex_ecdhmt_state_e
{
#ifdef CONFIG_ASSH_CLIENT
  ASSH_KEX_ECDHMT_CLIENT_SEND_PUB,
  ASSH_KEX_ECDHMT_CLIENT_INIT,
  ASSH_KEX_ECDHMT_CLIENT_LOOKUP_HOST_KEY_WAIT,
#endif
#ifdef CONFIG_ASSH_SERVER
  ASSH_KEX_ECDHMT_SERVER_WAIT_E,
#endif
};

struct assh_kex_ecdhmt_private_s
{
  const struct assh_montgomery_curve_s *curve;
  const struct assh_hash_algo_s *hash;

#ifdef CONFIG_ASSH_CLIENT
  struct assh_packet_s *pck;
#endif

  uint8_t *pub_key;
  uint8_t *pv_key;
  enum assh_kex_ecdhmt_state_e state:8;
  size_t size;
};

/* addition on montgomery curve, single coordinate. 18ops */
#define ASSH_BOP_MONTGOMERY_SADD(X1, X2, X3, Z2, Z3,		\
				  T0, T1, A24, P)		\
    /* D = X3 - Z3        */					\
    ASSH_BOP_SUBM(	T0,	X3,	Z3,	P	),	\
    /* B = X2 - Z2        */					\
    ASSH_BOP_SUBM(	T1,	X2,	Z2,	P	),	\
    /* A = X2 + Z2        */					\
    ASSH_BOP_ADDM(	X2,	X2,	Z2,	P	),	\
    /* C = X3 + Z3        */					\
    ASSH_BOP_ADDM(	Z2,	X3,	Z3,	P	),	\
    /* DA = D*A           */					\
    ASSH_BOP_MULM(	Z3,	T0,	X2,	P	),	\
    /* CB = C*B           */					\
    ASSH_BOP_MULM(	Z2,	Z2,	T1,	P	),	\
    /* BB = B^2           */					\
    ASSH_BOP_MULM( 	T0,	T1,	T1,	P	),	\
    /* AA = A^2           */					\
    ASSH_BOP_MULM( 	T1,	X2,	X2,	P	),	\
    /* X5 = Z1*(DA+CB)^2  */					\
    ASSH_BOP_ADDM(	X3,	Z3,	Z2,	P	),	\
    ASSH_BOP_MULM( 	X3,	X3,	X3,	P	),	\
    /* Z5 = X1*(DA-CB)^2  */					\
    ASSH_BOP_SUBM(	Z2,	Z3,	Z2,	P	),	\
    ASSH_BOP_MULM( 	Z2,	Z2,	Z2,	P	),	\
    /* X4 = AA*BB         */					\
    ASSH_BOP_MULM(	X2,	T1,	T0,	P	),	\
    /* E = AA - BB        */					\
    ASSH_BOP_SUBM(      T1,	T1,	T0,	P	),	\
    /* Z4 = E*(BB+a24*E)  */					\
    ASSH_BOP_MULM(	Z3,	T1,	A24,    P	),	\
    ASSH_BOP_ADDM(	T0,	T0,	Z3,	P	),	\
    ASSH_BOP_MULM(	Z3,	X1,	Z2,	P	),	\
    ASSH_BOP_MULM(	Z2,	T1,	T0,	P	)

#define ASSH_BOP_MONTGOMERY_SADD_OPS 18

static assh_status_t ASSH_WARN_UNUSED_RESULT
assh_montgomery_point_mul(struct assh_session_s *s, uint8_t *result,
                          const uint8_t *basepoint, const uint8_t *scalar)
{
  struct assh_kex_ecdhmt_private_s *pv = s->kex_pv;
  const struct assh_montgomery_curve_s *curve = pv->curve;
  assh_status_t err;

  ASSH_RET_IF_TRUE(scalar[0] % curve->cofactor != 0, ASSH_ERR_BAD_DATA);

  enum {
    R_raw, BP_raw, SC_raw, P_mpint, A24_mpint,
    X2, Z2, Z3, X1, X3, T0, T1, A24, SC,
    MT, S
  };

  static const assh_bignum_op_t bytecode[] = {

    ASSH_BOP_SIZER(     X2,     MT,    S                ),

    /* init */
    ASSH_BOP_MOVE(      T0,     P_mpint                 ),
    ASSH_BOP_MTINIT(	MT,     T0                      ),

    ASSH_BOP_MOVES(     SC,     SC_raw                  ),
    ASSH_BOP_MOVE(      A24,    A24_mpint               ),
    ASSH_BOP_MOVE(      X1,     BP_raw                  ),

#ifdef CONFIG_ASSH_DEBUG_KEX
    ASSH_BOP_PRINT(     X1,    'B'                      ),
    ASSH_BOP_PRINT(     SC,    'S'                      ),
#endif

    ASSH_BOP_MTUINT(    X2,     1,      MT              ),
    ASSH_BOP_MTUINT(    Z2,     0,      MT              ),
    ASSH_BOP_MOVE(      X3,     X1                      ),
    ASSH_BOP_MTUINT(    Z3,     1,      MT              ),
    ASSH_BOP_LADINIT(   SC                              ),

    ASSH_BOP_MTTO(	X1,     A24,    X1,     MT      ),

    /* montgomery ladder */
    ASSH_BOP_LADTEST(   SC,     1                       ),
    ASSH_BOP_BOOL(      0,      0,      1,      ASSH_BOP_BOOL_XOR ),
    ASSH_BOP_CSWAP(     X2,     X3,     0,      0       ),
    ASSH_BOP_CSWAP(     Z2,     Z3,     0,      0       ),
    ASSH_BOP_BOOL(      0,      1,      1,      ASSH_BOP_BOOL_OR ),

    ASSH_BOP_MONTGOMERY_SADD(X1, X2, X3, Z2, Z3, T0, T1, A24, MT),

    ASSH_BOP_LADNEXT(   1                               ),
    ASSH_BOP_CJMP(      - ASSH_BOP_MONTGOMERY_SADD_OPS - 7,
                        0,      1   ),

    ASSH_BOP_CSWAP(     X2,     X3,     0,      0       ),
    ASSH_BOP_CSWAP(     Z2,     Z3,     0,      0       ),

    ASSH_BOP_INV(       T0,     Z2,             MT      ),
    ASSH_BOP_MULM(      T0,     X2,     T0,     MT      ),

    ASSH_BOP_MTFROM(	T0,     T1,     T0,     MT      ),

#ifdef CONFIG_ASSH_DEBUG_KEX
    ASSH_BOP_PRINT(     T0,     'R'                     ),
#endif
    /* check contributory behavior */
    ASSH_BOP_UINT(      T1,     0                       ),
    ASSH_BOP_CMPEQ(     T1,     T0,     0               ),
    ASSH_BOP_CFAIL(     0,      0                       ),

    ASSH_BOP_MOVE(      R_raw,  T0                      ),

    ASSH_BOP_END(),
  };

  ASSH_RETURN(assh_bignum_bytecode(s->ctx, 0, bytecode, "dddMMTTTTTTTTTms",
          result, basepoint, scalar, curve->prime, curve->a24, (size_t)curve->bits));
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

static assh_status_t ASSH_WARN_UNUSED_RESULT
assh_kex_ecdhmt_private_gen(struct assh_session_s *s,
                            uint8_t *private)
{
  struct assh_kex_ecdhmt_private_s *pv = s->kex_pv;
  const struct assh_montgomery_curve_s *curve = pv->curve;
  assh_status_t err;

  ASSH_RET_ON_ERR(assh_prng_get(s->ctx, private, pv->size,
                      ASSH_PRNG_QUALITY_EPHEMERAL_KEY));

  private[0] -= private[0] % curve->cofactor;

  uint_fast8_t i = (8 - curve->bits) & 7;
  uint_fast8_t j = (curve->bits - 1) / 8;

  private[j] &= 0xff >> i;

  /* Some montgomery ladder implementations need this to be resistant
     to timing attacks, some except this bit to be set. */
  private[j] |= 0x80 >> i;

  return ASSH_OK;
}

#ifdef CONFIG_ASSH_CLIENT
static assh_status_t assh_kex_ecdhmt_client_send_pubkey(struct assh_session_s *s)
{
  struct assh_kex_ecdhmt_private_s *pv = s->kex_pv;
  struct assh_context_s *c = s->ctx;
  assh_status_t err;

  /* generate ephemeral key pair */
  ASSH_RET_ON_ERR(assh_kex_ecdhmt_private_gen(s, pv->pv_key));

  ASSH_RET_ON_ERR(assh_montgomery_point_mul(s, pv->pub_key,
                          pv->curve->basepoint, pv->pv_key));

  /* send a packet containing the public key */
  struct assh_packet_s *p;
  ASSH_RET_ON_ERR(assh_packet_alloc(c, SSH_MSG_KEX_ECDH_INIT,
               4 + pv->size, &p));

  uint8_t *qc_str;
  ASSH_ASSERT(assh_packet_add_string(p, pv->size, &qc_str));
  memcpy(qc_str, pv->pub_key, pv->size);

  assh_transport_push(s, p);

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_kex_ecdhmt_host_key_lookup_done)
{
  struct assh_kex_ecdhmt_private_s *pv = s->kex_pv;
  assh_status_t err;

  assert(pv->state == ASSH_KEX_ECDHMT_CLIENT_LOOKUP_HOST_KEY_WAIT);

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

  ASSH_RET_IF_TRUE(assh_load_u32(qs_str) != pv->size,
               ASSH_ERR_BAD_DATA | ASSH_ERRSV_DISCONNECT);

  /* compute shared secret */
  ASSH_SCRATCH_ALLOC(s->ctx, uint8_t, scratch,
                     pv->hash->ctx_size + 5 + pv->size,
		     ASSH_ERRSV_DISCONNECT, err_);

  void *hash_ctx = scratch;
  uint8_t *secret = scratch + pv->hash->ctx_size;
  uint8_t *secret_end = secret + 5 + pv->size;

  ASSH_JMP_ON_ERR(assh_montgomery_point_mul(s, secret + 5,
                           qs_str + 4, pv->pv_key)
               | ASSH_ERRSV_DISCONNECT, err_sc);

  secret = assh_kex_curve25519_to_mpint(secret, secret_end);

  /* compute exchange hash and send reply */
  ASSH_JMP_ON_ERR(assh_hash_init(s->ctx, hash_ctx, pv->hash)
               | ASSH_ERRSV_DISCONNECT, err_sc);

  ASSH_JMP_ON_ERR(assh_kex_client_hash1(s, hash_ctx, ks_str)
               | ASSH_ERRSV_DISCONNECT, err_sc);

  assh_hash_bytes_as_string(hash_ctx, pv->pub_key, pv->size);
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

static assh_status_t assh_kex_ecdhmt_client_wait_reply(struct assh_session_s *s,
                                                      struct assh_packet_s *p,
                                                      struct assh_event_s *e)
{
  struct assh_kex_ecdhmt_private_s *pv = s->kex_pv;
  assh_status_t err;

  ASSH_RET_IF_TRUE(p->head.msg != SSH_MSG_KEX_ECDH_REPLY, ASSH_ERR_PROTOCOL);

  const uint8_t *ks_str = p->head.end;
  const uint8_t *qs_str, *h_str;

  ASSH_RET_ON_ERR(assh_packet_check_string(p, ks_str, &qs_str));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, qs_str, &h_str));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, h_str, NULL));

  ASSH_RET_IF_TRUE(assh_load_u32(qs_str) != pv->size,
               ASSH_ERR_BAD_DATA);

  ASSH_RET_ON_ERR(assh_kex_client_get_key(s, ks_str, e,
                 &assh_kex_ecdhmt_host_key_lookup_done, pv));

  ASSH_SET_STATE(pv, state, ASSH_KEX_ECDHMT_CLIENT_LOOKUP_HOST_KEY_WAIT);
  pv->pck = assh_packet_refinc(p);

  return ASSH_OK;
}

#endif


#ifdef CONFIG_ASSH_SERVER

static assh_status_t assh_kex_ecdhmt_server_wait_pubkey(struct assh_session_s *s,
                                                       struct assh_packet_s *p)
{
  struct assh_kex_ecdhmt_private_s *pv = s->kex_pv;
  struct assh_context_s *c = s->ctx;
  assh_status_t err;

  ASSH_RET_IF_TRUE(p->head.msg != SSH_MSG_KEX_ECDH_INIT,
	       ASSH_ERR_PROTOCOL);

  uint8_t *qc_str = p->head.end;

  ASSH_RET_ON_ERR(assh_packet_check_string(p, qc_str, NULL));

  ASSH_RET_IF_TRUE(assh_load_u32(qc_str) != pv->size,
               ASSH_ERR_BAD_DATA);

  /* generate ephemeral key pair */
  ASSH_RET_ON_ERR(assh_kex_ecdhmt_private_gen(s, pv->pv_key));

  /* compute shared secret */
  ASSH_SCRATCH_ALLOC(s->ctx, uint8_t, scratch,
                     pv->hash->ctx_size + 5 + pv->size,
		     ASSH_ERRSV_CONTINUE, err_);

  void *hash_ctx = scratch;
  uint8_t *secret = scratch + pv->hash->ctx_size;
  uint8_t *secret_end = secret + 5 + pv->size;

  ASSH_JMP_ON_ERR(assh_montgomery_point_mul(s, pv->pub_key,
                 pv->curve->basepoint, pv->pv_key), err_sc);

  ASSH_JMP_ON_ERR(assh_montgomery_point_mul(s, secret + 5,
                 qc_str + 4, pv->pv_key), err_sc);

  secret = assh_kex_curve25519_to_mpint(secret, secret_end);

  /* compute exchange hash and send reply */
  ASSH_JMP_ON_ERR(assh_hash_init(s->ctx, hash_ctx, pv->hash), err_sc);

  struct assh_packet_s *pout;
  struct assh_key_s *hk;
  size_t slen;

  ASSH_JMP_ON_ERR(assh_kex_server_hash1(s, 
                 /* room for qs_str */ 4 + pv->size,
                 hash_ctx, &pout, &slen, &hk,
                 SSH_MSG_KEX_ECDH_REPLY), err_sc);

  uint8_t *qs_str;
  ASSH_ASSERT(assh_packet_add_string(pout, pv->size, &qs_str));
  memcpy(qs_str, pv->pub_key, pv->size);

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

static ASSH_KEX_PROCESS_FCN(assh_kex_ecdhmt_process)
{
  struct assh_kex_ecdhmt_private_s *pv = s->kex_pv;
  assh_status_t err;

  switch (pv->state)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_KEX_ECDHMT_CLIENT_INIT:
      assert(p == NULL);
      ASSH_RET_ON_ERR(assh_kex_ecdhmt_client_send_pubkey(s)
		   | ASSH_ERRSV_DISCONNECT);
      ASSH_SET_STATE(pv, state, ASSH_KEX_ECDHMT_CLIENT_SEND_PUB);
      return ASSH_OK;

    case ASSH_KEX_ECDHMT_CLIENT_SEND_PUB:
      if (p == NULL)
        return ASSH_OK;
      ASSH_RETURN(assh_kex_ecdhmt_client_wait_reply(s, p, e)
                    | ASSH_ERRSV_DISCONNECT);

    case ASSH_KEX_ECDHMT_CLIENT_LOOKUP_HOST_KEY_WAIT:
      ASSH_UNREACHABLE();
#endif

#ifdef CONFIG_ASSH_SERVER
    case ASSH_KEX_ECDHMT_SERVER_WAIT_E:
      if (p == NULL)
        return ASSH_OK;
      ASSH_RETURN(assh_kex_ecdhmt_server_wait_pubkey(s, p)
                    | ASSH_ERRSV_DISCONNECT);
#endif
    }

  return ASSH_OK;
}

static ASSH_KEX_CLEANUP_FCN(assh_kex_ecdhmt_cleanup)
{
  struct assh_kex_ecdhmt_private_s *pv = s->kex_pv;

#ifdef CONFIG_ASSH_CLIENT
  if (s->ctx->type == ASSH_CLIENT)
    assh_packet_release(pv->pck);
#endif

  assh_free(s->ctx, s->kex_pv);
  s->kex_pv = NULL;
}

static assh_status_t
assh_kex_ecdhmt_init(struct assh_session_s *s,
                     const struct assh_montgomery_curve_s *curve,
                     const struct assh_hash_algo_s *hash)
{
  assh_status_t err;

  size_t l = ASSH_ALIGN8(curve->bits) / 8;

  struct assh_kex_ecdhmt_private_s *pv;
  ASSH_RET_ON_ERR(assh_alloc(s->ctx, sizeof(*pv) + l * 2,
                          ASSH_ALLOC_SECUR, (void**)&pv));

  s->kex_pv = pv;

  pv->curve = curve;
  pv->hash = hash;
  pv->size = l;
  pv->pub_key = (void*)(pv + 1);
  pv->pv_key = pv->pub_key + l;

  switch (s->ctx->type)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_CLIENT:
      ASSH_SET_STATE(pv, state, ASSH_KEX_ECDHMT_CLIENT_INIT);
      pv->pck = NULL;
      break;
#endif
#ifdef CONFIG_ASSH_SERVER
    case ASSH_SERVER:
      ASSH_SET_STATE(pv, state, ASSH_KEX_ECDHMT_SERVER_WAIT_E);
      break;
#endif
    default:
      ASSH_UNREACHABLE();
    }

  return ASSH_OK;
}

static ASSH_KEX_INIT_FCN(assh_kex_curve25519_init)
{
  /* y^2=x^3+486662x^2+x */
  static const struct assh_montgomery_curve_s curve25519 =
    {
      /* 2^255-19 mpint */
      .prime = (const uint8_t*)"\x00\x00\x00\x20"
        "\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xed",
      /* 121666 mpint */
      .a24 = (const uint8_t*)"\x00\x00\x00\x03" "\x01\xdb\x42",
      /* 9 raw */
      .basepoint = (const uint8_t*)
        "\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      .cofactor = 8,
      .bits = 255,
    };
  return assh_kex_ecdhmt_init(s, &curve25519, &assh_hash_sha256);
}

const struct assh_algo_kex_s assh_kex_builtin_curve25519_sha256 =
{
  .algo_wk = {
    ASSH_ALGO_BASE(KEX, "assh-builtin", 50, 93,
      ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_COMMON,
                        "curve25519-sha256@libssh.org" }),
      .nondeterministic = 1,
    ),
  },
  .f_init = assh_kex_curve25519_init,
  .f_cleanup = assh_kex_ecdhmt_cleanup,
  .f_process = assh_kex_ecdhmt_process,
};


static ASSH_KEX_INIT_FCN(assh_kex_m383_init)
{
  /* y^2=x^3+2065150x^2+x */
  static const struct assh_montgomery_curve_s m383 =
    {
      /* 2^383-187 mpint */
      .prime = (const uint8_t*)"\x00\x00\x00\x30"
        "\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x45",
      /* 516288 mpint */
      .a24 = (const uint8_t*)"\x00\x00\x00\x03" "\x07\xe0\xc0",
      /* 12 raw */
      .basepoint = (const uint8_t*)
        "\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      .cofactor = 8,
      .bits = 383,
    };
  return assh_kex_ecdhmt_init(s, &m383, &assh_hash_sha384);
}

const struct assh_algo_kex_s assh_kex_builtin_m383_sha384 =
{
  .algo_wk = {
    ASSH_ALGO_BASE(KEX, "assh-builtin", 70, 51,
      ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_ASSH,
                        "m383-sha384@libassh.org" }),
      .nondeterministic = 1,
    ),
  },
  .f_init = assh_kex_m383_init,
  .f_cleanup = assh_kex_ecdhmt_cleanup,
  .f_process = assh_kex_ecdhmt_process,
};

static ASSH_KEX_INIT_FCN(assh_kex_m511_init)
{
  /* y^2 = x^3+530438x^2+x */
  static const struct assh_montgomery_curve_s m511 =
    {
      /* 2^511-187 mpint */
      .prime = (const uint8_t*)"\x00\x00\x00\x40"
        "\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x45",
      /* 132610 mpint */
      .a24 = (const uint8_t*)"\x00\x00\x00\x03" "\x02\x06\x02",
      /* 5 raw */
      .basepoint = (const uint8_t*)
        "\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      .cofactor = 8,
      .bits = 511,
    };
  return assh_kex_ecdhmt_init(s, &m511, &assh_hash_sha512);
}

const struct assh_algo_kex_s assh_kex_builtin_m511_sha512 =
{
  .algo_wk = {
    ASSH_ALGO_BASE(KEX, "assh-builtin", 90, 28,
      ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_ASSH,
                        "m511-sha512@libassh.org" }),
      .nondeterministic = 1,
    ),
  },
  .f_init = assh_kex_m511_init,
  .f_cleanup = assh_kex_ecdhmt_cleanup,
  .f_process = assh_kex_ecdhmt_process,
};

