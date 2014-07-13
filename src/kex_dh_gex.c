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
#include <assh/assh_session.h>
#include <assh/assh_packet.h>
#include <assh/assh_transport.h>
#include <assh/assh_bignum.h>
#include <assh/assh_sign.h>
#include <assh/assh_event.h>
#include <assh/assh_alloc.h>
#include <assh/assh_hash.h>
#include <assh/assh_cipher.h>

#include <string.h>
#include <stdlib.h>

#define DH_MAX_GRSIZE 16384

enum assh_kex_dh_gex_state_e
{
#ifdef CONFIG_ASSH_CLIENT
  ASSH_KEX_DH_GEX_CLIENT_SEND_SIZE,
  ASSH_KEX_DH_GEX_CLIENT_WAIT_GROUP,
  ASSH_KEX_DH_GEX_CLIENT_WAIT_F,
  ASSH_KEX_DH_GEX_CLIENT_LOOKUP_HOST_KEY_WAIT,
#endif
#ifdef CONFIG_ASSH_SERVER
  ASSH_KEX_DH_GEX_SERVER_WAIT_SIZE,
  ASSH_KEX_DH_GEX_SERVER_WAIT_E,
#endif
};

/* t[i] = N where 2^(1024 + i) - N is the
   greatest safe prime under a power of 2 */
extern const uint32_t assh_kex_dh_gex_mod_offset[DH_MAX_GRSIZE-1024];

/* Contains associated group generators */
extern const uint8_t  assh_kex_dh_gex_gen[DH_MAX_GRSIZE-1024];

struct assh_kex_dh_gex_private_s
{
  /* minimum and favorite group sizes */
  size_t algo_min;
  size_t algo_n;

  /* server retained group size */
  uint32_t server_n;

  /* exponent size */
  uint32_t exp_n;

  enum assh_kex_dh_gex_state_e state;

  union {
#ifdef CONFIG_ASSH_SERVER
    struct {
      /* client requested group sizes */
      uint32_t client_min;
      uint32_t client_n;
      uint32_t client_max;

      struct assh_bignum_s *fn;
      uint8_t *e_str;
    };
#endif
#ifdef CONFIG_ASSH_CLIENT
    struct {
      struct assh_bignum_s *en;
      struct assh_bignum_s *pn;
      struct assh_bignum_s *gn;
      struct assh_bignum_s *xn;
      struct assh_key_s *host_key;
      uint8_t *f_str;
      struct assh_packet_s *pck;
    };
#endif
  };
};

#ifdef CONFIG_ASSH_CLIENT
static assh_error_t assh_kex_dh_gex_client_send_size(struct assh_session_s *s)
{
  struct assh_kex_dh_gex_private_s *pv = s->kex_pv;
  struct assh_context_s *c = s->ctx;
  assh_error_t err;

  struct assh_packet_s *p;
  ASSH_ERR_RET(assh_packet_alloc(c, SSH_MSG_KEX_DH_GEX_REQUEST, 3 * 4, &p)
	       | ASSH_ERRSV_DISCONNECT);

  ASSH_ASSERT(assh_packet_add_u32(p, pv->algo_min));
  ASSH_ASSERT(assh_packet_add_u32(p, pv->algo_n));
  ASSH_ASSERT(assh_packet_add_u32(p, DH_MAX_GRSIZE));

  assh_transport_push(s, p);
  pv->state = ASSH_KEX_DH_GEX_CLIENT_WAIT_GROUP;
  return ASSH_OK;
}

static assh_error_t assh_kex_dh_gex_client_wait_group(struct assh_session_s *s,
                                                      struct assh_packet_s *p)
{
  struct assh_kex_dh_gex_private_s *pv = s->kex_pv;
  assh_error_t err;

  ASSH_CHK_RET(p->head.msg != SSH_MSG_KEX_DH_GEX_GROUP, ASSH_ERR_PROTOCOL
	       | ASSH_ERRSV_DISCONNECT);

  uint8_t *p_str = p->head.end;
  uint8_t *g_str;

  ASSH_ERR_RET(assh_packet_check_string(p, p_str, &g_str)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_string(p, g_str, NULL)
	       | ASSH_ERRSV_DISCONNECT);

  unsigned int n;
  ASSH_ERR_RET(assh_bignum_from_mpint(NULL, &n, p_str)
               | ASSH_ERRSV_DISCONNECT);

  ASSH_CHK_RET(n < pv->algo_min, ASSH_ERR_WEAK_ALGORITHM | ASSH_ERRSV_DISCONNECT);
  ASSH_CHK_RET(n > DH_MAX_GRSIZE, ASSH_ERR_NOTSUP | ASSH_ERRSV_DISCONNECT);

  pv->server_n = n;

  assh_bignum_shrink(pv->en, n);
  assh_bignum_shrink(pv->pn, n);
  assh_bignum_shrink(pv->gn, n);

  enum bytecode_args_e
  {
    G_mpint, P_mpint,
    E, G, P, X,
    T1, T2
  };

  assh_bignum_op_t bytecode[] = {
    ASSH_BOP_MOVE(        G,      G_mpint         ),
    ASSH_BOP_MOVE(        P,      P_mpint         ),

    ASSH_BOP_BNDUMP(      G ),
    ASSH_BOP_BNDUMP(      P ),

#warning check group
#if 0
    /* check P is a safe prime */
    ASSH_BOP_PRIME(       P,                      ), 
    ASSH_BOP_UINT(        T1,     1               ),
    ASSH_BOP_SUB(         T2,     P,      T1      ),
    ASSH_BOP_RSHIFT(      T2,     T2,      1      ),
    ASSH_BOP_PRIME(       T2,                     ), 

    /* check generator range */
    ASSH_BOP_CMPLT(       T1,     G               ), /* g > 1 */
    ASSH_BOP_CMPLT(       G,      P               ), /* g < p */

    /* check generator order in the group */
    ASSH_BOP_SETMOD(      P                       ),
    ASSH_BOP_EXPMOD(      T2,     G,      Q       ),
    ASSH_BOP_CMPEQ(       T1,     T2              ),
#endif

    /* generate private exponent */
    ASSH_BOP_RAND(        X,      ASSH_PRNG_QUALITY_EPHEMERAL_KEY),
    ASSH_BOP_UINT(        T1,     DH_MAX_GRSIZE   ),
    ASSH_BOP_CMPLT(       T1,     X               ),
    ASSH_BOP_CMPLT(       X,      P               ),

    /* compute dh public key */
    ASSH_BOP_SETMOD(      P                       ),
    ASSH_BOP_EXPMOD(      E,      G,      X       ),

    ASSH_BOP_END(),
  };

  ASSH_ERR_RET(assh_bignum_bytecode(s->ctx, bytecode, "MMNNNNTT",
                                    /* M */ g_str, p_str,
                                    /* N */ pv->gn, pv->pn, pv->en, pv->xn,
                                    /* T */ n, n));

  /* send a packet containing e */
  struct assh_packet_s *pout;
  ASSH_ERR_RET(assh_packet_alloc(s->ctx, SSH_MSG_KEX_DH_GEX_INIT,
                 assh_bignum_mpint_size(pv->en), &pout)
	       | ASSH_ERRSV_DISCONNECT);

  ASSH_ERR_GTO(assh_packet_add_mpint(pout, pv->en)
	       | ASSH_ERRSV_DISCONNECT, err_p);

  assh_transport_push(s, pout);
  pv->state = ASSH_KEX_DH_GEX_CLIENT_WAIT_F;
  return ASSH_OK;

 err_p:
  assh_packet_release(pout);
  return err;

  return ASSH_OK;
}

static ASSH_KEX_CLIENT_HASH(assh_kex_dh_gex_client_hash)
{
  struct assh_kex_dh_gex_private_s *pv = s->kex_pv;
  assh_error_t err;
  uint8_t bit_sizes[3*4];

  assh_store_u32(bit_sizes + 0, pv->algo_min);
  assh_store_u32(bit_sizes + 4, pv->algo_n);
  assh_store_u32(bit_sizes + 8, DH_MAX_GRSIZE);

  hash_algo->f_update(hash_ctx, bit_sizes, sizeof(bit_sizes));

  ASSH_ERR_RET(assh_hash_bignum(s->ctx, hash_ctx, hash_algo->f_update, pv->pn)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_hash_bignum(s->ctx, hash_ctx, hash_algo->f_update, pv->gn)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_hash_bignum(s->ctx, hash_ctx, hash_algo->f_update, pv->en)
	       | ASSH_ERRSV_DISCONNECT);
  assh_hash_string(hash_ctx, hash_algo->f_update, pv->f_str);

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_kex_dh_gex_host_key_lookup_done)
{
  struct assh_kex_dh_gex_private_s *pv = s->kex_pv;
  assh_error_t err;

  ASSH_CHK_RET(pv->state != ASSH_KEX_DH_GEX_CLIENT_LOOKUP_HOST_KEY_WAIT,
               ASSH_ERR_STATE | ASSH_ERRSV_FATAL);

  if (!e->kex.hostkey_lookup.accept)
    {
      ASSH_ERR_RET(assh_kex_end(s, 0) | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;
    }

  struct assh_packet_s *p = pv->pck;

  uint8_t *ks_str = p->head.end;
  uint8_t *f_str, *h_str;

  ASSH_ERR_RET(assh_packet_check_string(p, ks_str, &f_str)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_string(p, f_str, &h_str)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_string(p, h_str, NULL)
	       | ASSH_ERRSV_DISCONNECT);

  ASSH_SCRATCH_ALLOC(s->ctx, uint8_t, secret, assh_packet_mpint_size(pv->server_n),
                     ASSH_ERRSV_CONTINUE, err_);

  enum bytecode_args_e
  {
    F_mpint, K_mpint,
    X, G, P,
    F, T, K
  };

  assh_bignum_op_t bytecode[] = {
    ASSH_BOP_MOVE(        F,      F_mpint         ),

    /* check server public exponent */
    ASSH_BOP_UINT(        T,      2               ),
    ASSH_BOP_CMPLTEQ(     T,      F               ), /* f >= 2 */
    ASSH_BOP_SUB(         T,      P,      T       ),
    ASSH_BOP_BNDUMP(F),
    ASSH_BOP_BNDUMP(T),
    ASSH_BOP_CMPLTEQ(     F,      T               ), /* f <= p-2 */

    /* compute shared secret */
    ASSH_BOP_SETMOD(      P                       ),
    ASSH_BOP_EXPMOD(      T,      F,      X       ),
    ASSH_BOP_MOVE(        K,      T               ),

    /* check shared secret range */
    ASSH_BOP_UINT(        T,      2               ),
    ASSH_BOP_CMPLTEQ(     T,      K               ), /* k >= 2 */
    ASSH_BOP_SUB(         T,      P,      T       ),
    ASSH_BOP_CMPLTEQ(     K,      T               ), /* k <= p-2 */

    ASSH_BOP_MOVE(        K_mpint,        K       ),

    ASSH_BOP_END(),
  };

  ASSH_ERR_GTO(assh_bignum_bytecode(s->ctx, bytecode, "MMNNNTTT",
                 /* M */ f_str, secret,
                 /* N */ pv->xn, pv->gn, pv->pn,
                 /* T */ pv->server_n, pv->server_n, pv->server_n),
               err_secret);

  pv->f_str = f_str;

  ASSH_ERR_GTO(assh_kex_client_hash(s, &assh_kex_dh_gex_client_hash,
                                    &assh_hash_sha1, pv->host_key,
                                    secret, ks_str, h_str)
               | ASSH_ERRSV_DISCONNECT, err_secret);

  ASSH_SCRATCH_FREE(s->ctx, secret);
  assh_packet_release(pv->pck);
  pv->pck = NULL;

  ASSH_ERR_RET(assh_kex_end(s, 1) | ASSH_ERRSV_DISCONNECT);
  return ASSH_OK;

 err_secret:
  ASSH_SCRATCH_FREE(s->ctx, secret);
 err_:
  assh_packet_release(pv->pck);
  pv->pck = NULL;
  return err;
}

static assh_error_t assh_kex_dh_gex_client_wait_f(struct assh_session_s *s,
                                                  struct assh_packet_s *p,
                                                  struct assh_event_s *e)
{
  struct assh_kex_dh_gex_private_s *pv = s->kex_pv;
  assh_error_t err;

  ASSH_CHK_RET(p->head.msg != SSH_MSG_KEX_DH_GEX_REPLY, ASSH_ERR_PROTOCOL
	       | ASSH_ERRSV_DISCONNECT);

  uint8_t *ks_str = p->head.end;
  uint8_t *f_str, *h_str;

  ASSH_ERR_RET(assh_packet_check_string(p, ks_str, &f_str)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_string(p, f_str, &h_str)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_string(p, h_str, NULL)
	       | ASSH_ERRSV_DISCONNECT);

  ASSH_ERR_RET(assh_kex_client_get_key(s, &pv->host_key, ks_str, e,
                                       &assh_kex_dh_gex_host_key_lookup_done, pv));

  pv->state = ASSH_KEX_DH_GEX_CLIENT_LOOKUP_HOST_KEY_WAIT;
  pv->pck = assh_packet_refinc(p);

  return ASSH_OK;

 err_hk:
  assh_key_flush(s->ctx, &pv->host_key);
  return err;
}
#endif

#ifdef CONFIG_ASSH_SERVER
static ASSH_KEX_SERVER_HASH(assh_kex_dh_gex_server_hash)
{
  struct assh_kex_dh_gex_private_s *pv = s->kex_pv;
  assh_error_t err;

  /* append server ephemeral public key to packet. */
  uint8_t *f_str = pout->data + pout->data_size;
  ASSH_ERR_RET(assh_packet_add_mpint(pout, pv->fn) | ASSH_ERRSV_DISCONNECT);

  /* hash both ephemeral public keys */
  assh_hash_string(hash_ctx, hash_algo->f_update, pv->e_str);
  assh_hash_string(hash_ctx, hash_algo->f_update, f_str);

  return ASSH_OK;
}

static assh_error_t assh_kex_dh_gex_server_wait_size(struct assh_session_s *s,
                                                     struct assh_packet_s *p)
{
  struct assh_kex_dh_gex_private_s *pv = s->kex_pv;
  struct assh_context_s *c = s->ctx;
  assh_error_t err;

#warning SSH_MSG_KEX_DH_GEX_REQUEST_OLD
  ASSH_CHK_RET(p->head.msg != SSH_MSG_KEX_DH_GEX_REQUEST,
	       ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);

  uint8_t *next = p->head.end;
  ASSH_ERR_RET(assh_packet_check_u32(p, &pv->client_min, next, &next)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_u32(p, &pv->client_n, next, &next)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_u32(p, &pv->client_max, next, &next)
	       | ASSH_ERRSV_DISCONNECT);

  /* check group size bounds */
  ASSH_CHK_RET(pv->client_n > pv->client_max ||
               pv->client_n < pv->client_min || pv->client_n < 1024,
               ASSH_ERR_BAD_DATA | ASSH_ERRSV_DISCONNECT);

  ASSH_CHK_RET(pv->client_max < pv->algo_min,
               ASSH_ERR_WEAK_ALGORITHM | ASSH_ERRSV_DISCONNECT);

  ASSH_CHK_RET(pv->client_min > DH_MAX_GRSIZE,
               ASSH_ERR_NOTSUP | ASSH_ERRSV_DISCONNECT);

  /* get group size intervals intersection */
  size_t n = ASSH_MAX(pv->algo_min, pv->client_n);
  size_t min = ASSH_MAX(pv->client_min, 1024);
  size_t max = ASSH_MIN(pv->client_max, DH_MAX_GRSIZE);

  /* randomize group size */
  uint8_t r;
  ASSH_ERR_RET(s->ctx->prng->f_get(s->ctx, &r, 1, ASSH_PRNG_QUALITY_NONCE));
  r %= ASSH_MIN(max - min + 1, 256);
  size_t n = n + r > max ? max - r : n + r;

  pv->server_n = n;

  intptr_t o = assh_kex_dh_gex_mod_offset[n - 1024];

  struct assh_packet_s *pout;
  ASSH_ERR_RET(assh_packet_alloc(s->ctx, SSH_MSG_KEX_DH_GEX_INIT,
                                 assh_packet_mpint_size(n) /* p */ +
                                 assh_packet_mpint_size(1) /* g */, &pout)
	       | ASSH_ERRSV_DISCONNECT);

  XXX bytecode

  assh_transport_push(s, pout);
  pv->state = ASSH_KEX_DH_GEX_CLIENT_WAIT_F;
  return ASSH_OK;

 err_p:
  assh_packet_release(pout);
  return err;
}

static assh_error_t assh_kex_dh_gex_server_wait_e(struct assh_session_s *s,
                                                  struct assh_packet_s *p)
{
  struct assh_kex_dh_gex_private_s *pv = s->kex_pv;
  struct assh_context_s *c = s->ctx;
  assh_error_t err;

  ASSH_CHK_RET(p->head.msg != SSH_MSG_KEX_DH_GEX_INIT,
	       ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);

  /* compute DH */
  uint8_t *e_str = p->head.end;

  ASSH_ERR_RET(assh_packet_check_string(p, e_str, NULL)
	       | ASSH_ERRSV_DISCONNECT);

  ASSH_SCRATCH_ALLOC(c, uint8_t, secret, pv->server_n,
                     ASSH_ERRSV_CONTINUE, err_);

  enum bytecode_args_e
  {
    E_mpint, K_mpint,
    F, G, P,
    E, X, K, T
  };

  assh_bignum_op_t bytecode[] = {
    ASSH_BOP_MOVE(        E,      E_mpint         ),

    /* check client public key */
    ASSH_BOP_UINT(        T,      2               ),
    ASSH_BOP_CMPLTEQ(     T,      E               ), /* f >= 2 */
    ASSH_BOP_SUB(         T,      P,      T       ),
    ASSH_BOP_CMPLTEQ(     E,      T               ), /* f <= p-2 */

    /* generate private exponent */
    ASSH_BOP_RAND(        X,      ASSH_PRNG_QUALITY_EPHEMERAL_KEY),
    ASSH_BOP_UINT(        T,      DH_MAX_GRSIZE   ),
    ASSH_BOP_CMPLT(       T,      X               ),
    ASSH_BOP_CMPLT(       X,      P               ),

    /* compute dh public key */
    ASSH_BOP_SETMOD(      P                       ),
    ASSH_BOP_EXPMOD(      F,      G,      X       ),

    /* compute shared secret */
    ASSH_BOP_EXPMOD(      K,      E,      X       ),

    /* check shared secret range */
    ASSH_BOP_UINT(        T,      2               ),
    ASSH_BOP_CMPLTEQ(     T,      K               ), /* k >= 2 */
    ASSH_BOP_SUB(         T,      P,      T       ),
    ASSH_BOP_CMPLTEQ(     K,      T               ), /* k <= p-2 */

    ASSH_BOP_MOVE(        K_mpint, K              ),

    ASSH_BOP_END(),
  };

  uint32_t n = pv->server_n;
  ASSH_ERR_GTO(assh_bignum_bytecode(c, bytecode, "MMNNNTTTT",
                   /* M */ e_str, secret,
                   /* N */ pv->fn, pv->gn, pv->pn,
                   /* T */ n, pv->exp_n, n, n), err_secret);

  pv->e_str = e_str;

  /* compute exchange hash and send reply */
  ASSH_ERR_GTO(assh_kex_server_hash(s, &assh_kex_dh_gex_server_hash,
                                    n, &assh_hash_sha1, secret), err_secret);

  err = ASSH_OK;

 err_secret:
  ASSH_SCRATCH_FREE(c, secret);
 err_:
  return err;
}
#endif


static ASSH_KEX_PROCESS_FCN(assh_kex_dh_gex_process)
{
  struct assh_kex_dh_gex_private_s *pv = s->kex_pv;
  assh_error_t err;

  switch (pv->state)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_KEX_DH_GEX_CLIENT_SEND_SIZE:
      assert(p == NULL);
      ASSH_ERR_RET(assh_kex_dh_gex_client_send_size(s)
		   | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;

    case ASSH_KEX_DH_GEX_CLIENT_WAIT_GROUP:
      if (p == NULL)
        return ASSH_OK;
      ASSH_ERR_RET(assh_kex_dh_gex_client_wait_group(s, p)
		   | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;

    case ASSH_KEX_DH_GEX_CLIENT_WAIT_F:
      if (p == NULL)
        return ASSH_OK;
      ASSH_ERR_RET(assh_kex_dh_gex_client_wait_f(s, p, e)
		   | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;

    case ASSH_KEX_DH_GEX_CLIENT_LOOKUP_HOST_KEY_WAIT:
      ASSH_ERR_RET(ASSH_ERR_STATE | ASSH_ERRSV_FATAL);
#endif

#ifdef CONFIG_ASSH_SERVER
    case ASSH_KEX_DH_GEX_SERVER_WAIT_SIZE:
      if (p == NULL)
        return ASSH_OK;
      ASSH_ERR_RET(assh_kex_dh_gex_server_wait_size(s, p)
		   | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;

    case ASSH_KEX_DH_GEX_SERVER_WAIT_E:
      if (p == NULL)
        return ASSH_OK;
      ASSH_ERR_RET(assh_kex_dh_gex_server_wait_e(s, p)
		   | ASSH_ERRSV_DISCONNECT);
      ASSH_ERR_RET(assh_kex_end(s, 1)
		   | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;
#endif
    }

  abort();
}

static assh_error_t assh_kex_dh_gex_init(struct assh_session_s *s,
                                         const struct assh_hash_s *hash,
                                         size_t cipher_key_size,
                                         uint_fast8_t ldiv, uint_fast8_t hdiv)
{
  assh_error_t err;
  struct assh_kex_dh_gex_private_s *pv;
  size_t pvsize = sizeof(*pv);
  enum assh_kex_dh_gex_state_e state;
  size_t bnl = assh_bignum_size_of_bits(DH_MAX_GRSIZE);

  size_t exp_n = cipher_key_size * 2;

  switch (s->ctx->type)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_CLIENT:
      state = ASSH_KEX_DH_GEX_CLIENT_SEND_SIZE;
      pvsize += /* en */ bnl
             + /* pn, gn */ bnl * 2
             + /* xn */ assh_bignum_size_of_bits(exp_n);
      break;
#endif
#ifdef CONFIG_ASSH_SERVER
    case ASSH_SERVER:
      state = ASSH_KEX_DH_GEX_SERVER_WAIT_SIZE;
      pvsize += /* fn */ + bnl;
      break;
#endif
    default:
      abort();
    }

  /* allocate DH private context */
  ASSH_ERR_RET(assh_alloc(s->ctx, pvsize, ASSH_ALLOC_KEY, (void**)&pv)
	       | ASSH_ERRSV_DISCONNECT);

  s->kex_pv = pv;
  pv->state = state;
  pv->algo_min = ASSH_MIN(ASSH_MAX(cipher_key_size * cipher_key_size / hdiv, 1024), DH_MAX_GRSIZE);
  pv->algo_n = ASSH_MIN(ASSH_MAX(cipher_key_size * cipher_key_size / ldiv, 1024), DH_MAX_GRSIZE);
  pv->exp_n = cipher_key_size * 2;

#ifdef CONFIG_ASSH_DEBUG_KEX
  ASSH_DEBUG("group exchange client request algo_n:%u bits, algo_min:%u bits, exp_n:%u bits\n",
             pv->algo_n, pv->algo_min, pv->exp_n);
#endif

  switch (s->ctx->type)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_CLIENT:
      pv->en = (struct assh_bignum_s )(pv + 1);
      pv->pn = (struct assh_bignum_s )((uint8_t*)pv->en + bnl);
      pv->gn = (struct assh_bignum_s )((uint8_t*)pv->en + bnl * 2);
      pv->xn = (struct assh_bignum_s )((uint8_t*)pv->en + bnl * 3);
      pv->host_key = NULL;
      pv->pck = NULL;

      assh_bignum_init(s->ctx, pv->en, DH_MAX_GRSIZE);
      assh_bignum_init(s->ctx, pv->pn, DH_MAX_GRSIZE);
      assh_bignum_init(s->ctx, pv->gn, DH_MAX_GRSIZE);
      assh_bignum_init(s->ctx, pv->xn, exp_n);
      break;
#endif

#ifdef CONFIG_ASSH_SERVER
    case ASSH_SERVER:
      pv->fn = (struct assh_bignum_s )(pv + 1);
      assh_bignum_init(s->ctx, pv->fn, DH_MAX_GRSIZE);
      break;
#endif
    default:
      abort();
    }

  return ASSH_OK;
}

static ASSH_KEX_CLEANUP_FCN(assh_kex_dh_gex_cleanup)
{
  struct assh_kex_dh_gex_private_s *pv = s->kex_pv;

  switch (s->ctx->type)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_CLIENT:
      assh_bignum_cleanup(s->ctx, pv->en);
      assh_bignum_cleanup(s->ctx, pv->pn);
      assh_bignum_cleanup(s->ctx, pv->gn);
      assh_bignum_cleanup(s->ctx, pv->xn);
      assh_key_flush(s->ctx, &pv->host_key);
      assh_packet_release(pv->pck);
      break;
#endif

#ifdef CONFIG_ASSH_SERVER
    case ASSH_SERVER:
      assh_bignum_cleanup(s->ctx, pv->fn);
      break;
#endif
    }

  assh_free(s->ctx, s->kex_pv, ASSH_ALLOC_KEY);
  s->kex_pv = NULL;
}

static ASSH_KEX_INIT_FCN(assh_kex_dh_gex_sha1_init)
{
  return assh_kex_dh_gex_init(s, &assh_hash_sha1, cipher_key_size, 12, 16);
}

struct assh_algo_kex_s assh_kex_dh_gex_sha1 =
{
  .algo = { .name = "diffie-hellman-group-exchange-sha1",
            .class_ = ASSH_ALGO_KEX,
            .safety = 20, .speed = 30 },
  .f_init = assh_kex_dh_gex_sha1_init,
  .f_cleanup = assh_kex_dh_gex_cleanup,
  .f_process = assh_kex_dh_gex_process,
};


static ASSH_KEX_INIT_FCN(assh_kex_dh_gex_sha256_12_init)
{
  return assh_kex_dh_gex_init(s, &assh_hash_sha256, cipher_key_size, 12, 16);
}

struct assh_algo_kex_s assh_kex_dh_gex_sha256_12 =
{
  .algo = { .name = "diffie-hellman-group-exchange-sha256",
            .variant = "n^2/12 bits modulus",
            .class_ = ASSH_ALGO_KEX,
            .priority = 10, .safety = 20, .speed = 30 },
  .f_init = assh_kex_dh_gex_sha256_12_init,
  .f_cleanup = assh_kex_dh_gex_cleanup,
  .f_process = assh_kex_dh_gex_process,
};


static ASSH_KEX_INIT_FCN(assh_kex_dh_gex_sha256_8_init)
{
  return assh_kex_dh_gex_init(s, &assh_hash_sha256, cipher_key_size, 8, 12);
}

struct assh_algo_kex_s assh_kex_dh_gex_sha256_8 =
{
  .algo = { .name = "diffie-hellman-group-exchange-sha256",
            .variant = "n^2/8 bits modulus",
            .class_ = ASSH_ALGO_KEX,
            .priority = 9, .safety = 25, .speed = 20 },
  .f_init = assh_kex_dh_gex_sha256_8_init,
  .f_cleanup = assh_kex_dh_gex_cleanup,
  .f_process = assh_kex_dh_gex_process,
};


static ASSH_KEX_INIT_FCN(assh_kex_dh_gex_sha256_4_init)
{
  return assh_kex_dh_gex_init(s, &assh_hash_sha256, cipher_key_size, 4, 8);
}

struct assh_algo_kex_s assh_kex_dh_gex_sha256_4 =
{
  .algo = { .name = "diffie-hellman-group-exchange-sha256",
            .variant = "n^2/4 bits modulus",
            .class_ = ASSH_ALGO_KEX,
            .priority = 8, .safety = 40, .speed = 10 },
  .f_init = assh_kex_dh_gex_sha256_4_init,
  .f_cleanup = assh_kex_dh_gex_cleanup,
  .f_process = assh_kex_dh_gex_process,
};

/*
1024 1093337
1536 1503317
2048 1942289
3072 1103717
4096 10895177
6144 40207829
8192 43644929 49930517 71186057
12288
16384 364486013
*/

const uint32_t assh_kex_dh_gex_mod_offset[DH_MAX_GRSIZE-1024] = 
{
};

const uint8_t  assh_kex_dh_gex_gen[DH_MAX_GRSIZE-1024] =
{
};

