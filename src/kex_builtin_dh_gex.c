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

/*
  This file implements rfc4419
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
#include <assh/mod_builtin.h>

#ifdef CONFIG_ASSH_SERVER
# include <assh/safe_primes.h>
#endif

#include <string.h>
#include <stdlib.h>

/* The kex safety is lowered depending on the retained group size. The
   safety factor declared in the algorithm descriptor corresponds to
   smallest allowed group size for the retained algorithm variant. */

#define DH_MAX_GRSIZE 16384

#define DH_MAX_RFC_SUGGESTED_GRSIZE 8192
#define DH_MIN_RFC_GRSIZE 1024

/* derive group size from symmetric key size, see doc/dh/ */
#define ASSH_DH_GEX_GRPSIZE(n, div) ((n) * (n) / (div))

enum assh_kex_dh_gex_state_e
{
#ifdef CONFIG_ASSH_CLIENT
  ASSH_KEX_DH_GEX_CLIENT_SEND_SIZE,
  ASSH_KEX_DH_GEX_CLIENT_WAIT_GROUP,
  ASSH_KEX_DH_GEX_CLIENT_WAIT_GROUP_OLD,
  ASSH_KEX_DH_GEX_CLIENT_WAIT_F,
  ASSH_KEX_DH_GEX_CLIENT_LOOKUP_HOST_KEY_WAIT,
#endif
#ifdef CONFIG_ASSH_SERVER
  ASSH_KEX_DH_GEX_SERVER_WAIT_SIZE,
  ASSH_KEX_DH_GEX_SERVER_WAIT_E,
#endif
};

struct assh_kex_dh_gex_private_s
{
  enum assh_kex_dh_gex_state_e state:8;
  uint8_t request_type;

  /* minimum and favorite group sizes */
  uint16_t algo_max;
  uint16_t algo_min;
  uint16_t algo_n;

  /* server retained group size */
  uint16_t server_n;

  /* exponent size */
  uint16_t exp_n;

  const struct assh_hash_algo_s *hash;

  struct assh_bignum_s pn;

  union {
#ifdef CONFIG_ASSH_SERVER
    struct {
      /* client requested group sizes */
      uint32_t client_min;
      uint32_t client_n;
      uint32_t client_max;
    };
#endif
#ifdef CONFIG_ASSH_CLIENT
    struct {
      struct assh_bignum_s gn;
      struct assh_bignum_s en;
      struct assh_bignum_s xn;
      struct assh_packet_s *pck;
    };
#endif
  };
};

#ifdef CONFIG_ASSH_CLIENT
static assh_status_t assh_kex_dh_gex_client_send_size(struct assh_session_s *s)
{
  struct assh_kex_dh_gex_private_s *pv = s->kex_pv;
  struct assh_context_s *c = s->ctx;
  assh_status_t err;

  struct assh_packet_s *p;

  pv->request_type = SSH_MSG_KEX_DH_GEX_REQUEST;
  ASSH_RET_ON_ERR(assh_packet_alloc(c, pv->request_type, 3 * 4, &p));

  ASSH_ASSERT(assh_packet_add_u32(p, pv->algo_min));
  ASSH_ASSERT(assh_packet_add_u32(p, pv->algo_n));
  ASSH_ASSERT(assh_packet_add_u32(p, pv->algo_max));

  assh_transport_push(s, p);
  ASSH_SET_STATE(pv, state, ASSH_KEX_DH_GEX_CLIENT_WAIT_GROUP);
  return ASSH_OK;
}

static assh_status_t assh_kex_dh_gex_client_send_size_old(struct assh_session_s *s)
{
  struct assh_kex_dh_gex_private_s *pv = s->kex_pv;
  struct assh_context_s *c = s->ctx;
  assh_status_t err;

  struct assh_packet_s *p;

  pv->request_type = SSH_MSG_KEX_DH_GEX_REQUEST_OLD;
  ASSH_RET_ON_ERR(assh_packet_alloc(c, pv->request_type, 4, &p));

  ASSH_ASSERT(assh_packet_add_u32(p, pv->algo_n));

  assh_transport_push(s, p);
  ASSH_SET_STATE(pv, state, ASSH_KEX_DH_GEX_CLIENT_WAIT_GROUP_OLD);
  return ASSH_OK;
}

static assh_status_t assh_kex_dh_gex_client_wait_group(struct assh_session_s *s,
                                                      struct assh_packet_s *p)
{
  struct assh_kex_dh_gex_private_s *pv = s->kex_pv;
  assh_status_t err;

  ASSH_RET_IF_TRUE(p->head.msg != SSH_MSG_KEX_DH_GEX_GROUP, ASSH_ERR_PROTOCOL);

  const uint8_t *p_str = p->head.end;
  const uint8_t *g_str;

  ASSH_RET_ON_ERR(assh_packet_check_string(p, p_str, &g_str));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, g_str, NULL));

  size_t n;
  ASSH_RET_ON_ERR(assh_bignum_size_of_data(ASSH_BIGNUM_MPINT, p_str, NULL, NULL, &n));

#ifdef CONFIG_ASSH_DEBUG_KEX
  ASSH_DEBUG("kex_dh_gex server group size: %u\n", n);
#endif

  uint_fast16_t algo_max = pv->algo_max;

  /* do not enforce a limit we couldn't advertise */
  if (pv->state == ASSH_KEX_DH_GEX_CLIENT_WAIT_GROUP_OLD)
    algo_max = assh_max_uint(DH_MAX_RFC_SUGGESTED_GRSIZE, algo_max);

  ASSH_RET_IF_TRUE(n < pv->algo_min, ASSH_ERR_WEAK_ALGORITHM);
  ASSH_RET_IF_TRUE(n > algo_max, ASSH_ERR_NOTSUP);

  pv->server_n = n;

  assh_kex_lower_safety(s, ASSH_SAFETY_PRIMEFIELD(n));

  size_t e_size = assh_bignum_size_of_bits(ASSH_BIGNUM_MPINT, n);

  /* send a packet containing e */
  struct assh_packet_s *pout;
  ASSH_RET_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_KEX_DH_GEX_INIT,
                 e_size, &pout));

  uint8_t *e_str;
  ASSH_ASSERT(assh_packet_add_array(pout, e_size, &e_str));

  enum bytecode_args_e
  {
    G_mpint, P_mpint, E_mpint,
    X, G, P, E,
    T1, T2, Q, MT, G_n
  };

  static const assh_bignum_op_t bytecode[] = {

    ASSH_BOP_SIZER(     G,      MT,     G_n            	),

    ASSH_BOP_MOVE(      G,      G_mpint                 ),
    ASSH_BOP_MOVE(      P,      P_mpint                 ),

#ifdef CONFIG_ASSH_DEBUG_KEX
    ASSH_BOP_PRINT(     G,      'G'                     ),
    ASSH_BOP_PRINT(     P,      'P'                     ),
#endif

    /* check prime */
    ASSH_BOP_UINT(      T1,     1                       ),
    ASSH_BOP_TEST(      P,      1,      G_n,    0       ),
    ASSH_BOP_CFAIL(     1,      0                       ),
#if 0
    ASSH_BOP_ISPRIME(   P,      5,      0               ),
    ASSH_BOP_CFAIL(	1,	0                       ),
    ASSH_BOP_SUB(       T2,     P,      T1              ),
    ASSH_BOP_SHR(       Q,      T2,     1, ASSH_BOP_NOREG	),
    ASSH_BOP_ISPRIME(   Q,      5,      0               ),
    ASSH_BOP_CFAIL(	1,	0                       ),
#endif

    /* check generator */
    ASSH_BOP_CMPGT(     G,     T1,      0               ), /* g > 1 */
    ASSH_BOP_CFAIL(     1,      0                       ),

    ASSH_BOP_SUB(       T2,     P,      T1              ),
    ASSH_BOP_CMPLT(     G,      T2,     0               ), /* g < p - 1 */
    ASSH_BOP_CFAIL(     1,      0                       ),

    /* generate private exponent */
    ASSH_BOP_UINT(      T1,     DH_MAX_GRSIZE           ),
    ASSH_BOP_RAND(      X,      T1,     P,
                        ASSH_PRNG_QUALITY_EPHEMERAL_KEY),

    /* compute dh public key */
    ASSH_BOP_MTINIT(    MT,     P                       ),
    ASSH_BOP_MTTO(      T1,     T1,     G,      MT      ),
    ASSH_BOP_EXPM(      E,      T1,     X,      MT      ),
    ASSH_BOP_MTFROM(    E,      E,      E,      MT      ),

    ASSH_BOP_MOVE(      E_mpint,        E               ),

    ASSH_BOP_END(),
  };

  ASSH_JMP_ON_ERR(assh_bignum_bytecode(s->ctx, 0, bytecode, "MMMNNNNTTTms",
                                    /* M */ g_str, p_str, e_str,
                                    /* N */ &pv->xn, &pv->gn, &pv->pn, &pv->en,
                                    /* S */ (size_t)n), err_p);

  assert(pv->xn.secret);

  assh_packet_string_resized(pout, e_str + 4);

  assh_transport_push(s, pout);
  ASSH_SET_STATE(pv, state, ASSH_KEX_DH_GEX_CLIENT_WAIT_F);
  return ASSH_OK;

 err_p:
  assh_packet_release(pout);
  return err;

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_kex_dh_gex_host_key_lookup_done)
{
  struct assh_kex_dh_gex_private_s *pv = s->kex_pv;
  assh_status_t err;

  assert(pv->state == ASSH_KEX_DH_GEX_CLIENT_LOOKUP_HOST_KEY_WAIT);

  if (!e->kex.hostkey_lookup.accept || ASSH_STATUS(inerr))
    ASSH_RETURN(assh_kex_end(s, 0) | ASSH_ERRSV_DISCONNECT);

  struct assh_packet_s *p = pv->pck;

  const uint8_t *ks_str = p->head.end;
  const uint8_t *f_str, *h_str;

  ASSH_RET_ON_ERR(assh_packet_check_string(p, ks_str, &f_str)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_RET_ON_ERR(assh_packet_check_string(p, f_str, &h_str)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_RET_ON_ERR(assh_packet_check_string(p, h_str, NULL)
	       | ASSH_ERRSV_DISCONNECT);

  ASSH_SCRATCH_ALLOC(s->ctx, uint8_t, scratch,
                     assh_bignum_size_of_bits(ASSH_BIGNUM_MPINT, pv->server_n) +
                     pv->hash->ctx_size,
                     ASSH_ERRSV_DISCONNECT, err_);

  void *hash_ctx = scratch;
  uint8_t *secret = scratch + pv->hash->ctx_size;

  enum bytecode_args_e
  {
    F_mpint, K_mpint,
    X, G, P,
    F, T, K, MT
  };

  static const assh_bignum_op_t bytecode[] = {

#ifdef CONFIG_ASSH_DEBUG_KEX
    ASSH_BOP_PRINT(     G,      'G'             	),
    ASSH_BOP_PRINT(     P,      'P'             	),
#endif

    ASSH_BOP_SIZER(     F,      MT,      P       	),

    ASSH_BOP_MOVE(      F,      F_mpint         	),

#ifdef CONFIG_ASSH_DEBUG_KEX
    ASSH_BOP_PRINT(     F,      'F'             	),
    ASSH_BOP_PRINT(     T,      'T'             	),
    ASSH_BOP_PRINT(     X,      'X'             	),
#endif

    /* check server public exponent */
    ASSH_BOP_UINT(      T,      2               	),
    ASSH_BOP_CMPGTEQ(   F,      T,      0  /* f >= 2 */	),
    ASSH_BOP_CFAIL(     1,      0                       ),

    ASSH_BOP_SUB(       T,      P,      T       	),
    ASSH_BOP_CMPLTEQ(   F,      T,      0 /* f <= p-2 */),
    ASSH_BOP_CFAIL(     1,      0                       ),

    /* compute shared secret */
    ASSH_BOP_MTINIT(    MT,     P                       ),
    ASSH_BOP_MTTO(      F,      F,      F,      MT      ),
    ASSH_BOP_EXPM(      T,      F,      X,      MT      ),
    ASSH_BOP_MTFROM(    K,	K,      T,	MT     	),

    /* check shared secret range */
    ASSH_BOP_UINT(      T,      2               	),
    ASSH_BOP_CMPGTEQ(   K,      T,      0 /* k >= 2 */	),
    ASSH_BOP_CFAIL(     1,      0                       ),

    ASSH_BOP_SUB(       T,      P,      T       	),
    ASSH_BOP_CMPLTEQ(   K,      T,      0 /* k <= p-2 */),
    ASSH_BOP_CFAIL(     1,      0                       ),

    ASSH_BOP_MOVE(      K_mpint,        K       	),

    ASSH_BOP_END(),
  };

  ASSH_JMP_ON_ERR(assh_bignum_bytecode(s->ctx, 0, bytecode, "MMNNNTTTm",
                 /* M */ f_str, secret,
                 /* N */ &pv->xn, &pv->gn, &pv->pn,
                 /* T */ pv->server_n, pv->server_n, pv->server_n)
               | ASSH_ERRSV_DISCONNECT,
               err_scratch);

  ASSH_JMP_ON_ERR(assh_hash_init(s->ctx, hash_ctx, pv->hash)
               | ASSH_ERRSV_DISCONNECT, err_scratch);

  ASSH_JMP_ON_ERR(assh_kex_client_hash1(s, hash_ctx, ks_str)
               | ASSH_ERRSV_DISCONNECT, err_hash);

  uint8_t bit_sizes[12];

  assh_store_u32(bit_sizes + 0, pv->algo_min);
  assh_store_u32(bit_sizes + 4, pv->algo_n);
  assh_store_u32(bit_sizes + 8, pv->algo_max);

  switch (pv->request_type)
    {
    case SSH_MSG_KEX_DH_GEX_REQUEST:
      assh_hash_update(hash_ctx, bit_sizes, 12);
      break;

    case SSH_MSG_KEX_DH_GEX_REQUEST_OLD:
      assh_hash_update(hash_ctx, bit_sizes + 4, 4);
      break;
    }

  ASSH_JMP_ON_ERR(assh_hash_bignum(s->ctx, hash_ctx, &pv->pn)
	       | ASSH_ERRSV_DISCONNECT, err_hash);
  ASSH_JMP_ON_ERR(assh_hash_bignum(s->ctx, hash_ctx, &pv->gn)
	       | ASSH_ERRSV_DISCONNECT, err_hash);
  ASSH_JMP_ON_ERR(assh_hash_bignum(s->ctx, hash_ctx, &pv->en)
	       | ASSH_ERRSV_DISCONNECT, err_hash);

  assh_hash_string(hash_ctx, f_str);

  ASSH_JMP_ON_ERR(assh_kex_client_hash2(s, hash_ctx, secret, h_str)
               | ASSH_ERRSV_DISCONNECT, err_hash);

  ASSH_JMP_ON_ERR(assh_kex_end(s, 1) | ASSH_ERRSV_DISCONNECT, err_hash);

  err = ASSH_OK;

 err_hash:
  assh_hash_cleanup(hash_ctx);
 err_scratch:
  ASSH_SCRATCH_FREE(s->ctx, scratch);
 err_:
  return err;
}

static assh_status_t assh_kex_dh_gex_client_wait_f(struct assh_session_s *s,
                                                  struct assh_packet_s *p,
                                                  struct assh_event_s *e)
{
  struct assh_kex_dh_gex_private_s *pv = s->kex_pv;
  assh_status_t err;

  ASSH_RET_IF_TRUE(p->head.msg != SSH_MSG_KEX_DH_GEX_REPLY, ASSH_ERR_PROTOCOL);

  const uint8_t *ks_str = p->head.end;
  const uint8_t *f_str, *h_str;

  ASSH_RET_ON_ERR(assh_packet_check_string(p, ks_str, &f_str));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, f_str, &h_str));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, h_str, NULL));

  ASSH_RET_ON_ERR(assh_kex_client_get_key(s, ks_str, e,
                 &assh_kex_dh_gex_host_key_lookup_done, pv));

  ASSH_SET_STATE(pv, state, ASSH_KEX_DH_GEX_CLIENT_LOOKUP_HOST_KEY_WAIT);
  pv->pck = assh_packet_refinc(p);

  return ASSH_OK;
}
#endif

#ifdef CONFIG_ASSH_SERVER
static assh_status_t assh_kex_dh_gex_server_wait_size(struct assh_session_s *s,
                                                     struct assh_packet_s *p)
{
  struct assh_kex_dh_gex_private_s *pv = s->kex_pv;
  struct assh_context_s *c = s->ctx;
  assh_status_t err;

  const uint8_t *next = p->head.end;
  size_t min, max, n;
  pv->request_type = p->head.msg;

  switch (pv->request_type)
    {
#if 1 /* disable this to test old gex requests  */
    case SSH_MSG_KEX_DH_GEX_REQUEST:
      ASSH_RET_ON_ERR(assh_packet_check_u32(p, &pv->client_min, next, &next));
      ASSH_RET_ON_ERR(assh_packet_check_u32(p, &pv->client_n, next, &next));
      ASSH_RET_ON_ERR(assh_packet_check_u32(p, &pv->client_max, next, &next));

      /* check group size bounds */
      n = pv->client_n;
      ASSH_RET_IF_TRUE(n > pv->client_max ||
                   n < pv->client_min || n < DH_MIN_RFC_GRSIZE,
                   ASSH_ERR_BAD_DATA);

      ASSH_RET_IF_TRUE(pv->client_min > pv->algo_max,
                   ASSH_ERR_NOTSUP);

      /* group size intervals intersection */
      min = assh_max_uint(pv->algo_min, pv->client_min);
      max = assh_min_uint(pv->algo_max, pv->client_max);

      /* random interval around requested size */
      min = assh_max_uint(min, n * 7 / 8);
      max = assh_min_uint(max, n * 3 / 2);
      break;
#endif

    case SSH_MSG_KEX_DH_GEX_REQUEST_OLD:
      ASSH_RET_ON_ERR(assh_packet_check_u32(p, &pv->client_n, next, &next));
      pv->client_min = pv->client_max = 0;

      /* restrict requested size to supported interval */
      min = pv->algo_min;
      max = pv->algo_max;
      n = assh_max_uint(min, assh_min_uint(max, pv->client_n));

      /* random interval around requested size */
      min = assh_max_uint(min, n);
      max = assh_min_uint(max, n * 3 / 2);
      break;

    default:
      ASSH_RETURN(assh_transport_unimp(s, p));
    }

  ASSH_RET_IF_TRUE(max < min, ASSH_ERR_NOTSUP);

  /* randomize group size */
  uint8_t r_[2];
  ASSH_RET_ON_ERR(assh_prng_get(s->ctx, r_, 2, ASSH_PRNG_QUALITY_NONCE));
  uint16_t r = r_[0] | (r_[1] << 8);

  size_t bits = min + r * (max - min + 1) / 65536;
  bits -= bits % 8;

  pv->server_n = bits;
  assh_kex_lower_safety(s, ASSH_SAFETY_PRIMEFIELD(bits));

#ifdef CONFIG_ASSH_DEBUG_KEX
  ASSH_DEBUG("kex_dh_gex client requested group size %u in [%u, %u]\n",
             pv->client_n, pv->client_min, pv->client_max);
  ASSH_DEBUG("kex_dh_gex server selected group size %zu in [%zu, %zu]\n",
             bits, min, max);
#endif

  size_t p_size = assh_bignum_size_of_bits(ASSH_BIGNUM_MPINT, bits);

  struct assh_packet_s *pout;
  ASSH_RET_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_KEX_DH_GEX_GROUP,
                 /* p */ p_size + /* g */ 5, &pout));

  /* Append P */
  uint8_t *p_str;
  ASSH_ASSERT(assh_packet_add_array(pout, p_size, &p_str));

  enum bytecode_args_e
  {
    P_mpint,
    P_n, O, B, P,
    T
  };

  static const assh_bignum_op_t bytecode[] = {

    ASSH_BOP_SIZE (     P,      P_n                     ),
    ASSH_BOP_SIZE (     T,      O                       ),

    /* P = B + O */
    ASSH_BOP_MOVE(      P,      B                       ),
    ASSH_BOP_MOVE(      T,      O                       ),
    ASSH_BOP_ADD(       P,      P,      T               ),

#ifdef CONFIG_ASSH_DEBUG_KEX
    ASSH_BOP_PRINT(     T,      'O'                     ),
    ASSH_BOP_PRINT(     P,      'P'                     ),
#endif

#if 0
    ASSH_BOP_ISPRIME(   P,      2,      0               ),
    ASSH_BOP_CFAIL(	1,	0                       ),
#endif

    ASSH_BOP_MOVE(      P_mpint,        P               ),

    ASSH_BOP_END(),
  };

  uint8_t base[bits / 8];
  intptr_t offset;
  assh_safeprime_get(&assh_safeprimes, bits, base, &offset);

  ASSH_JMP_ON_ERR(assh_bignum_bytecode(c, 0, bytecode, "MsidNT", p_str,
                                    (size_t)bits, offset, base, &pv->pn), err_p);

  assh_packet_string_resized(pout, p_str + 4);

  /* Append G = 2 */
  uint8_t *g_str;
  ASSH_ASSERT(assh_packet_add_array(pout, 5, &g_str));
  assh_store_u32(g_str, 1);
  g_str[4] = 2;

  assh_transport_push(s, pout);
  ASSH_SET_STATE(pv, state, ASSH_KEX_DH_GEX_SERVER_WAIT_E);
  return ASSH_OK;

 err_p:
  assh_packet_release(pout);
  return err;
}

static assh_status_t assh_kex_dh_gex_server_wait_e(struct assh_session_s *s,
                                                  struct assh_packet_s *p)
{
  struct assh_kex_dh_gex_private_s *pv = s->kex_pv;
  struct assh_context_s *c = s->ctx;
  assh_status_t err;

  ASSH_RET_IF_TRUE(p->head.msg != SSH_MSG_KEX_DH_GEX_INIT,
	       ASSH_ERR_PROTOCOL);

  /* compute DH */
  uint8_t *e_str = p->head.end;

  ASSH_RET_ON_ERR(assh_packet_check_string(p, e_str, NULL));

  size_t l = assh_bignum_size_of_num(ASSH_BIGNUM_MPINT, &pv->pn);

  ASSH_SCRATCH_ALLOC(c, uint8_t, scratch,
                     l + pv->hash->ctx_size,
                     ASSH_ERRSV_CONTINUE, err_);

  void *hash_ctx = scratch;
  uint8_t *secret = scratch + pv->hash->ctx_size;

  ASSH_JMP_ON_ERR(assh_hash_init(s->ctx, hash_ctx, pv->hash), err_scratch);

  struct assh_packet_s *pout;
  struct assh_key_s *hk;
  size_t slen;

  ASSH_JMP_ON_ERR(assh_kex_server_hash1(s, l, hash_ctx, &pout,
                 &slen, &hk, SSH_MSG_KEX_DH_GEX_REPLY), err_hash);

  uint8_t *f_str;
  ASSH_ASSERT(assh_packet_add_array(pout, l, &f_str));

  enum bytecode_args_e
  {
    E_mpint, F_mpint, K_mpint,
    P, X_n,
    X, F, E, K, T, MT
  };

  static const assh_bignum_op_t bytecode[] = {

    ASSH_BOP_SIZE(      X,      X_n                     ),
    ASSH_BOP_SIZER(     F,      MT,     P               ),

    ASSH_BOP_MOVE(      E,      E_mpint                 ),

#ifdef CONFIG_ASSH_DEBUG_KEX
    ASSH_BOP_PRINT(     P,      'P'                     ),
#endif

    /* check client public key */
    ASSH_BOP_UINT(      T,      2                       ),
    ASSH_BOP_CMPGTEQ(   E,      T,      0 /* f >= 2 */  ),
    ASSH_BOP_CFAIL(     1,      0                       ),
    ASSH_BOP_SUB(       T,      P,      T               ),
    ASSH_BOP_CMPLTEQ(   E,      T,      0 /* f <= p-2 */),
    ASSH_BOP_CFAIL(     1,      0                       ),

    /* generate private exponent */
    ASSH_BOP_UINT(      T,      DH_MAX_GRSIZE   	),
    ASSH_BOP_RAND(      X,      T,      P,
                        ASSH_PRNG_QUALITY_EPHEMERAL_KEY),

    /* compute dh public key using 2 as generator */
    ASSH_BOP_UINT(      T,      2               	),

    ASSH_BOP_MTINIT(    MT,     P                       ),
    ASSH_BOP_MTTO(      T,      T,      T,      MT      ),
    ASSH_BOP_EXPM(      F,      T,      X,      MT      ),
    ASSH_BOP_MTFROM(    F,      F,      F,      MT      ),

    /* compute shared secret */
    ASSH_BOP_MTTO(      E,      E,      E,      MT      ),
    ASSH_BOP_EXPM(      K,      E,      X,      MT      ),
    ASSH_BOP_MTFROM(    K,      K,      K,      MT      ),

    /* check shared secret range */
    ASSH_BOP_UINT(      T,      2               	),
    ASSH_BOP_CMPGTEQ(   K,      T,      0 /* k >= 2 */	),
    ASSH_BOP_CFAIL(     1,      0                       ),

    ASSH_BOP_SUB(       T,      P,      T       	),
    ASSH_BOP_CMPLTEQ(   K,      T,      0 /* k <= p-2 */),
    ASSH_BOP_CFAIL(     1,      0                       ),

    ASSH_BOP_MOVE(      K_mpint,        K               ),
    ASSH_BOP_MOVE(      F_mpint,        F               ),

    ASSH_BOP_END(),
  };

  ASSH_JMP_ON_ERR(assh_bignum_bytecode(c, 0, bytecode, "MMMNsTTTTTm",
                   e_str, f_str, secret, &pv->pn,
                   (size_t)pv->exp_n), err_p);

  assh_packet_string_resized(pout, f_str + 4);

  /* hash group sizes values */
  uint8_t buf[12];
  assh_store_u32(buf + 4, pv->client_n);

  switch (pv->request_type)
    {
    case SSH_MSG_KEX_DH_GEX_REQUEST:
      assh_store_u32(buf + 0, pv->client_min);
      assh_store_u32(buf + 8, pv->client_max);
      assh_hash_update(hash_ctx, buf, 12);
      break;

    case SSH_MSG_KEX_DH_GEX_REQUEST_OLD:
      assh_hash_update(hash_ctx, buf + 4, 4);
      break;
    }

  /* hash P */
  ASSH_JMP_ON_ERR(assh_hash_bignum(s->ctx, hash_ctx, &pv->pn), err_p);

  /* hash G */
  assh_store_u32(buf, 1);  
  buf[4] = 2;
  assh_hash_update(hash_ctx, buf, 5);

  /* hash both ephemeral public keys */
  assh_hash_string(hash_ctx, e_str);
  assh_hash_string(hash_ctx, f_str);

  ASSH_JMP_ON_ERR(assh_kex_server_hash2(s, hash_ctx, pout,
                 slen, hk, secret), err_p);

  assh_transport_push(s, pout);

  ASSH_JMP_ON_ERR(assh_kex_end(s, 1), err_hash);

  err = ASSH_OK;
  goto err_hash;

 err_p:
  assh_packet_release(pout);
 err_hash:
  assh_hash_cleanup(hash_ctx);
 err_scratch:
  ASSH_SCRATCH_FREE(c, scratch);
 err_:
  return err;
}
#endif


static ASSH_KEX_PROCESS_FCN(assh_kex_dh_gex_process)
{
  struct assh_kex_dh_gex_private_s *pv = s->kex_pv;
  assh_status_t err;

  switch (pv->state)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_KEX_DH_GEX_CLIENT_SEND_SIZE:
      assert(p == NULL);
      ASSH_RETURN(assh_kex_dh_gex_client_send_size(s)
		   | ASSH_ERRSV_DISCONNECT);

    case ASSH_KEX_DH_GEX_CLIENT_WAIT_GROUP:
      if (p == NULL)
        return ASSH_OK;
      if (p->head.msg == SSH_MSG_UNIMPLEMENTED)
        ASSH_RETURN(assh_kex_dh_gex_client_send_size_old(s)
                      | ASSH_ERRSV_DISCONNECT);

    case ASSH_KEX_DH_GEX_CLIENT_WAIT_GROUP_OLD:
      if (p == NULL)
        return ASSH_OK;
      ASSH_RETURN(assh_kex_dh_gex_client_wait_group(s, p)
                    | ASSH_ERRSV_DISCONNECT);

    case ASSH_KEX_DH_GEX_CLIENT_WAIT_F:
      if (p == NULL)
        return ASSH_OK;
      ASSH_RETURN(assh_kex_dh_gex_client_wait_f(s, p, e)
                    | ASSH_ERRSV_DISCONNECT);

    case ASSH_KEX_DH_GEX_CLIENT_LOOKUP_HOST_KEY_WAIT:
      ASSH_UNREACHABLE();
#endif

#ifdef CONFIG_ASSH_SERVER
    case ASSH_KEX_DH_GEX_SERVER_WAIT_SIZE:
      if (p == NULL)
        return ASSH_OK;
      ASSH_RETURN(assh_kex_dh_gex_server_wait_size(s, p)
                    | ASSH_ERRSV_DISCONNECT);

    case ASSH_KEX_DH_GEX_SERVER_WAIT_E:
      if (p == NULL)
        return ASSH_OK;
      ASSH_RETURN(assh_kex_dh_gex_server_wait_e(s, p)
                    | ASSH_ERRSV_DISCONNECT);
#endif
    }

  ASSH_UNREACHABLE();
}

static assh_status_t assh_kex_dh_gex_init(struct assh_session_s *s,
                                         const struct assh_hash_algo_s *hash,
                                         size_t cipher_key_size,
                                         uint_fast8_t ldiv,
					 uint_fast16_t algo_min,
					 uint_fast16_t algo_max)
{
  assh_status_t err;
  struct assh_kex_dh_gex_private_s *pv;

  assert(algo_max <= DH_MAX_GRSIZE);
  assert(algo_min <= algo_max);
  cipher_key_size = assh_min_uint(assh_max_uint(cipher_key_size, 64), 256);

  size_t exp_n = cipher_key_size * 2;

  /* allocate DH private context */
  ASSH_RET_ON_ERR(assh_alloc(s->ctx, sizeof(*pv), ASSH_ALLOC_INTERNAL, (void**)&pv));

  switch (s->ctx->type)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_CLIENT:
      ASSH_SET_STATE(pv, state, ASSH_KEX_DH_GEX_CLIENT_SEND_SIZE);
      break;
#endif
#ifdef CONFIG_ASSH_SERVER
    case ASSH_SERVER:
      ASSH_SET_STATE(pv, state, ASSH_KEX_DH_GEX_SERVER_WAIT_SIZE);
      algo_max = assh_max_uint(DH_MAX_RFC_SUGGESTED_GRSIZE, algo_max);
      break;
#endif
    default:
      ASSH_UNREACHABLE();
    }

  s->kex_pv = pv;
  pv->hash = hash;
  pv->algo_min = algo_min;
  pv->algo_max = algo_max;
  pv->algo_n = assh_min_uint(assh_max_uint(
		   ASSH_DH_GEX_GRPSIZE(cipher_key_size, ldiv),
		   algo_min), algo_max);
  pv->exp_n = cipher_key_size * 2;

#ifdef CONFIG_ASSH_DEBUG_KEX
  ASSH_DEBUG("kex_dh_gex init algo_n:%u bits, algo_min:%u bits, algo_max:%u bits, exp_n:%u bits\n",
             pv->algo_n, pv->algo_min, pv->algo_max, pv->exp_n);
#endif

  assh_bignum_init(s->ctx, &pv->pn, 0);

  switch (s->ctx->type)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_CLIENT:
      pv->pck = NULL;

      assh_bignum_init(s->ctx, &pv->gn, 0);
      assh_bignum_init(s->ctx, &pv->en, 0);
      assh_bignum_init(s->ctx, &pv->xn, exp_n);
      break;
#endif

#ifdef CONFIG_ASSH_SERVER
    case ASSH_SERVER:
      break;
#endif
    default:
      ASSH_UNREACHABLE();
    }

  return ASSH_OK;
}

static ASSH_KEX_CLEANUP_FCN(assh_kex_dh_gex_cleanup)
{
  struct assh_kex_dh_gex_private_s *pv = s->kex_pv;
  struct assh_context_s *c = s->ctx;

  assh_bignum_release(c, &pv->pn);

  switch (c->type)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_CLIENT:
      assh_bignum_release(c, &pv->en);
      assh_bignum_release(c, &pv->xn);
      assh_bignum_release(c, &pv->gn);
      assh_packet_release(pv->pck);
      break;
#endif

#ifdef CONFIG_ASSH_SERVER
    case ASSH_SERVER:
      break;
#endif

    default:
      ASSH_UNREACHABLE();
    }

  assh_free(c, s->kex_pv);
  s->kex_pv = NULL;
}

static ASSH_KEX_INIT_FCN(assh_kex_dh_gex_sha1_init)
{
  return assh_kex_dh_gex_init(s, &assh_hash_sha1, cipher_key_size, 12, 1024, 4096);
}

const struct assh_algo_kex_s assh_kex_builtin_dh_gex_sha1 =
{
  ASSH_ALGO_BASE(KEX, "assh-builtin", ASSH_SAFETY_PRIMEFIELD(1024), 10,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
	              "diffie-hellman-group-exchange-sha1" }),
    ASSH_ALGO_VARIANT(9, "1024 <= group <= 4096"),
    .nondeterministic = 1
  ),
  .f_init = assh_kex_dh_gex_sha1_init,
  .f_cleanup = assh_kex_dh_gex_cleanup,
  .f_process = assh_kex_dh_gex_process,
};

static ASSH_KEX_INIT_FCN(assh_kex_dh_gex_sha256_12_init)
{
  return assh_kex_dh_gex_init(s, &assh_hash_sha256, cipher_key_size, 12, 1024, 2048);
}

const struct assh_algo_kex_s assh_kex_builtin_dh_gex_sha256_12 =
{
  ASSH_ALGO_BASE(KEX, "assh-builtin", ASSH_SAFETY_PRIMEFIELD(1024), 30,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
                      "diffie-hellman-group-exchange-sha256" }),
    ASSH_ALGO_VARIANT(10, "1024 <= group <= 2048"),
    .nondeterministic = 1
  ),
  .f_init = assh_kex_dh_gex_sha256_12_init,
  .f_cleanup = assh_kex_dh_gex_cleanup,
  .f_process = assh_kex_dh_gex_process,
};


static ASSH_KEX_INIT_FCN(assh_kex_dh_gex_sha256_8_init)
{
  return assh_kex_dh_gex_init(s, &assh_hash_sha256, cipher_key_size, 8, 2048, 4096);
}

const struct assh_algo_kex_s assh_kex_builtin_dh_gex_sha256_8 =
{
  ASSH_ALGO_BASE(KEX, "assh-builtin", ASSH_SAFETY_PRIMEFIELD(2048), 10,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
                      "diffie-hellman-group-exchange-sha256" }),
    ASSH_ALGO_VARIANT(9, "2048 <= group <= 4096"),
    .nondeterministic = 1
  ),
  .f_init = assh_kex_dh_gex_sha256_8_init,
  .f_cleanup = assh_kex_dh_gex_cleanup,
  .f_process = assh_kex_dh_gex_process,
};


static ASSH_KEX_INIT_FCN(assh_kex_dh_gex_sha256_4_init)
{
  return assh_kex_dh_gex_init(s, &assh_hash_sha256, cipher_key_size, 4, 4096, DH_MAX_GRSIZE);
}

const struct assh_algo_kex_s assh_kex_builtin_dh_gex_sha256_4 =
{
  ASSH_ALGO_BASE(KEX, "assh-builtin", ASSH_SAFETY_PRIMEFIELD(4096), 1,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
                      "diffie-hellman-group-exchange-sha256" }),
    ASSH_ALGO_VARIANT(8, "group >= 4096"),
    .nondeterministic = 1
  ),
  .f_init = assh_kex_dh_gex_sha256_4_init,
  .f_cleanup = assh_kex_dh_gex_cleanup,
  .f_process = assh_kex_dh_gex_process,
};


