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
#include <assh/assh_prng.h>
#include <assh/assh_sign.h>
#include <assh/assh_event.h>
#include <assh/assh_alloc.h>
#include <assh/assh_hash.h>
#include <assh/assh_cipher.h>

#include <string.h>
#include <stdlib.h>

#define DH_MAX_GRSIZE 8192

struct assh_kex_dh_group_s
{
  const struct assh_hash_algo_s *hash;
  const uint8_t *generator;
  const uint8_t *prime;
  uint16_t size;
};

enum assh_kex_dh_state_e
{
#ifdef CONFIG_ASSH_CLIENT
  ASSH_KEX_DH_CLIENT_WAIT_F,
  ASSH_KEX_DH_CLIENT_INIT,
  ASSH_KEX_DH_CLIENT_LOOKUP_HOST_KEY_WAIT,
#endif
#ifdef CONFIG_ASSH_SERVER
  ASSH_KEX_DH_SERVER_WAIT_E,
#endif
};

struct assh_kex_dh_private_s
{
  const struct assh_kex_dh_group_s *group;

  union {
#ifdef CONFIG_ASSH_SERVER
    struct {
      uint16_t exp_n;
    };
#endif
#ifdef CONFIG_ASSH_CLIENT
    struct {
      struct assh_bignum_s en;
      struct assh_bignum_s xn;
      struct assh_packet_s *pck;
    };
#endif
  };

  enum assh_kex_dh_state_e state:8;
};

#ifdef CONFIG_ASSH_CLIENT
static assh_error_t assh_kex_dh_client_send_expmod(struct assh_session_s *s)
{
  struct assh_kex_dh_private_s *pv = s->kex_pv;
  const struct assh_kex_dh_group_s *gr = pv->group;
  struct assh_context_s *c = s->ctx;
  assh_error_t err;

  struct assh_packet_s *p;
  size_t e_size = assh_bignum_size_of_bits(ASSH_BIGNUM_MPINT, gr->size);

  ASSH_RET_ON_ERR(assh_packet_alloc(c, SSH_MSG_KEX_DH_REQUEST, e_size, &p)
	       | ASSH_ERRSV_DISCONNECT);

  uint8_t *e_str;
  ASSH_ASSERT(assh_packet_add_array(p, e_size, &e_str));

  enum bytecode_args_e
  {
    G_mpint, P_mpint, E_mpint,
    E, X, G_n,
    G, P, MT
  };

  static const assh_bignum_op_t bytecode[] = {
    ASSH_BOP_SIZE(      G,      G_n		        ),
    ASSH_BOP_SIZE(      P,      G_n		        ),

    ASSH_BOP_MOVE(      G,      G_mpint			),
    ASSH_BOP_MOVE(      P,      P_mpint			),

    /* generate private exponent in range [ group bits, p - 2 ] */
    ASSH_BOP_UINT(      E,      DH_MAX_GRSIZE		),
    ASSH_BOP_RAND(      X,      E,      P,
                        ASSH_PRNG_QUALITY_EPHEMERAL_KEY),

    /* compute dh public key */
    ASSH_BOP_MTINIT(    MT,     P                       ),
    ASSH_BOP_MTTO(      G,      G,      G,      MT      ),
    ASSH_BOP_EXPM(      E,      G,      X,	MT      ),
    ASSH_BOP_MTFROM(    E,      E,      E,      MT      ),

    ASSH_BOP_MOVE(      E_mpint,        E		),

    ASSH_BOP_END(),
  };

  ASSH_JMP_ON_ERR(assh_bignum_bytecode(c, 0, bytecode, "MMMNNsTTm",
                   /* M */ gr->generator, gr->prime, e_str,
                   /* N */ &pv->en, &pv->xn, gr->size), err_p);

  assert(pv->xn.secret);

  assh_packet_string_resized(p, e_str + 4);

  assh_transport_push(s, p);
  pv->state = ASSH_KEX_DH_CLIENT_WAIT_F;
  return ASSH_OK;

 err_p:
  assh_packet_release(p);
  return err;
}

static ASSH_EVENT_DONE_FCN(assh_kex_dh_host_key_lookup_done)
{
  struct assh_kex_dh_private_s *pv = s->kex_pv;
  const struct assh_kex_dh_group_s *gr = pv->group;
  assh_error_t err;

  assert(pv->state == ASSH_KEX_DH_CLIENT_LOOKUP_HOST_KEY_WAIT);

  if (!e->kex.hostkey_lookup.accept)
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
                     assh_bignum_size_of_bits(ASSH_BIGNUM_MPINT, gr->size) +
                     gr->hash->ctx_size,
                     ASSH_ERRSV_CONTINUE, err_);

  void *hash_ctx = scratch;
  uint8_t *secret = scratch + gr->hash->ctx_size;

  enum bytecode_args_e
  {
    G_mpint, P_mpint, F_mpint, K_mpint,
    X, G_n,
    G, P, F, T, K, MT
  };

  static const assh_bignum_op_t bytecode[] = {
    ASSH_BOP_SIZER(     G,      K,	G_n		),

    ASSH_BOP_MOVE(      F,      F_mpint			),
    ASSH_BOP_MOVE(      G,      G_mpint			),
    ASSH_BOP_MOVE(      P,      P_mpint			),

    /* check server public exponent */
    ASSH_BOP_UINT(      T,      2			),
    ASSH_BOP_CMPGTEQ(   F,      T,      0  /* f >= 2 */	),
    ASSH_BOP_CFAIL(     1,      0                       ),
    ASSH_BOP_SUB(       T,      P,      T       	),
    ASSH_BOP_CMPLTEQ(   F,      T,      0 /* f <= p-2 */),
    ASSH_BOP_CFAIL(     1,      0                       ),

    /* compute shared secret */
    ASSH_BOP_MTINIT(    MT,     P                       ),
    ASSH_BOP_MTTO(      F,      F,      F,      MT      ),
    ASSH_BOP_EXPM(      T,      F,      X,      MT	),
    ASSH_BOP_MTFROM(    K,      K,      T,      MT      ),

    /* check shared secret range */
    ASSH_BOP_UINT(      T,      2			),
    ASSH_BOP_CMPGTEQ(   K,      T,      0  /* k >= 2 */	),
    ASSH_BOP_CFAIL(     1,      0                       ),
    ASSH_BOP_SUB(       T,      P,      T       	),
    ASSH_BOP_CMPLTEQ(   K,      T,      0 /* k <= p-2 */),
    ASSH_BOP_CFAIL(     1,      0                       ),

    ASSH_BOP_MOVE(      K_mpint,        K		),

    ASSH_BOP_END(),
  };

  ASSH_JMP_ON_ERR(assh_bignum_bytecode(s->ctx, 0, bytecode, "MMMMNsTTTTTm",
                   /* M */ gr->generator, gr->prime, f_str, secret,
                   /* N */ &pv->xn, gr->size), err_scratch);

  ASSH_JMP_ON_ERR(assh_hash_init(s->ctx, hash_ctx, gr->hash), err_scratch);

  ASSH_JMP_ON_ERR(assh_kex_client_hash1(s, hash_ctx, ks_str)
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

static assh_error_t assh_kex_dh_client_wait_f(struct assh_session_s *s,
					      struct assh_packet_s *p,
                                              struct assh_event_s *e)
{
  struct assh_kex_dh_private_s *pv = s->kex_pv;
  assh_error_t err;

  ASSH_RET_IF_TRUE(p->head.msg != SSH_MSG_KEX_DH_REPLY, ASSH_ERR_PROTOCOL
	       | ASSH_ERRSV_DISCONNECT);

  const uint8_t *ks_str = p->head.end;
  const uint8_t *f_str, *h_str;

  ASSH_RET_ON_ERR(assh_packet_check_string(p, ks_str, &f_str)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_RET_ON_ERR(assh_packet_check_string(p, f_str, &h_str)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_RET_ON_ERR(assh_packet_check_string(p, h_str, NULL)
	       | ASSH_ERRSV_DISCONNECT);

  ASSH_RET_ON_ERR(assh_kex_client_get_key(s, ks_str, e,
                 &assh_kex_dh_host_key_lookup_done, pv));

  pv->state = ASSH_KEX_DH_CLIENT_LOOKUP_HOST_KEY_WAIT;
  pv->pck = assh_packet_refinc(p);

  return ASSH_OK;
}
#endif

#ifdef CONFIG_ASSH_SERVER

static assh_error_t assh_kex_dh_server_wait_e(struct assh_session_s *s,
                                              struct assh_packet_s *p)
{
  struct assh_kex_dh_private_s *pv = s->kex_pv;
  const struct assh_kex_dh_group_s *gr = pv->group;
  struct assh_context_s *c = s->ctx;
  assh_error_t err;

  ASSH_RET_IF_TRUE(p->head.msg != SSH_MSG_KEX_DH_REQUEST,
	       ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);

  /* compute DH */
  uint8_t *e_str = p->head.end;

  ASSH_RET_ON_ERR(assh_packet_check_string(p, e_str, NULL)
	       | ASSH_ERRSV_DISCONNECT);

  size_t l = assh_bignum_size_of_bits(ASSH_BIGNUM_MPINT, gr->size);

  size_t hash_ctx_size = gr->hash->ctx_size;
  ASSH_SCRATCH_ALLOC(s->ctx, uint8_t, scratch,
                     l + hash_ctx_size,
                     ASSH_ERRSV_CONTINUE, err_);

  void *hash_ctx = scratch;
  uint8_t *secret = scratch + hash_ctx_size;

  ASSH_JMP_ON_ERR(assh_hash_init(s->ctx, hash_ctx, gr->hash), err_scratch);

  struct assh_packet_s *pout;
  struct assh_key_s *hk;
  size_t slen;

  ASSH_JMP_ON_ERR(assh_kex_server_hash1(s, l, hash_ctx, &pout,
                 &slen, &hk, SSH_MSG_KEX_DH_REPLY), err_hash);

  uint8_t *f_str;
  ASSH_ASSERT(assh_packet_add_array(pout, l, &f_str));

  enum bytecode_args_e
  {
    G_mpint, P_mpint, E_mpint, F_mpint, K_mpint,
    X_n, G_n,
    F, G, P, E, X, K, T, MT
  };

  static const assh_bignum_op_t bytecode[] = {
    ASSH_BOP_SIZER(     F,      T,	G_n		),

    ASSH_BOP_MOVE(      G,      G_mpint         	),
    ASSH_BOP_MOVE(      P,      P_mpint         	),
    ASSH_BOP_MOVE(      E,      E_mpint         	),

    /* check client public key */
    ASSH_BOP_UINT(      T,      2               	),
    ASSH_BOP_CMPGTEQ(   E,      T,      0 /* f >= 2 */  ),
    ASSH_BOP_CFAIL(     1,      0                       ),

    ASSH_BOP_SUB(       T,      P,      T               ),
    ASSH_BOP_CMPLTEQ(   E,      T,      0 /* f <= p-2 */),
    ASSH_BOP_CFAIL(     1,      0                       ),

    /* generate private exponent */
    ASSH_BOP_UINT(      T,      DH_MAX_GRSIZE   	),
    ASSH_BOP_RAND(      X,      T,      P,
                        ASSH_PRNG_QUALITY_EPHEMERAL_KEY),

    /* compute dh public key and shared secret */
    ASSH_BOP_MTINIT(    MT,     P                       ),
    ASSH_BOP_MTTO(      G,      G,      G,      MT      ),
    ASSH_BOP_EXPM(      F,      G,      X,	MT      ),
    ASSH_BOP_MTFROM(    F,      F,      F,      MT      ),
    ASSH_BOP_MTTO(      E,      E,      E,      MT      ),
    ASSH_BOP_EXPM(      K,      E,      X,	MT      ),
    ASSH_BOP_MTFROM(    K,      K,      K,      MT      ),

    /* check shared secret range */
    ASSH_BOP_UINT(      T,      2               	),
    ASSH_BOP_CMPGTEQ(   K,      T,      0 /* k >= 2 */	),
    ASSH_BOP_CFAIL(     1,      0                       ),
    ASSH_BOP_SUB(       T,      P,      T       	),
    ASSH_BOP_CMPLTEQ(   K,      T,      0 /* k <= p-2 */),
    ASSH_BOP_CFAIL(     1,      0                       ),

    ASSH_BOP_MOVE(      K_mpint,        K		),
    ASSH_BOP_MOVE(      F_mpint,        F		),

    ASSH_BOP_END(),
  };

  ASSH_JMP_ON_ERR(assh_bignum_bytecode(c, 0, bytecode, "MMMMMssTTTTTTTm",
                   gr->generator, gr->prime, e_str, f_str, secret,
                   pv->exp_n, gr->size), err_p);

  assh_packet_string_resized(pout, f_str + 4);

  /* hash both ephemeral public keys */
  assh_hash_string(hash_ctx, e_str);
  assh_hash_string(hash_ctx, f_str);

  ASSH_JMP_ON_ERR(assh_kex_server_hash2(s, hash_ctx, pout,
                 slen, hk, secret), err_p);

  assh_transport_push(s, pout);

  ASSH_JMP_ON_ERR(assh_kex_end(s, 1) | ASSH_ERRSV_DISCONNECT, err_hash);

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


static ASSH_KEX_PROCESS_FCN(assh_kex_dh_process)
{
  struct assh_kex_dh_private_s *pv = s->kex_pv;
  assh_error_t err;

  switch (pv->state)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_KEX_DH_CLIENT_INIT:
      assert(p == NULL);
      ASSH_RETURN(assh_kex_dh_client_send_expmod(s)
		   | ASSH_ERRSV_DISCONNECT);

    case ASSH_KEX_DH_CLIENT_WAIT_F:
      if (p == NULL)
        return ASSH_OK;
      ASSH_RETURN(assh_kex_dh_client_wait_f(s, p, e)
                    | ASSH_ERRSV_DISCONNECT);

    case ASSH_KEX_DH_CLIENT_LOOKUP_HOST_KEY_WAIT:
      ASSH_UNREACHABLE();
#endif

#ifdef CONFIG_ASSH_SERVER
    case ASSH_KEX_DH_SERVER_WAIT_E:
      if (p == NULL)
        return ASSH_OK;
      ASSH_RETURN(assh_kex_dh_server_wait_e(s, p)
                    | ASSH_ERRSV_DISCONNECT);
#endif
    }

  ASSH_UNREACHABLE();
}

static assh_error_t assh_kex_dh_init(struct assh_session_s *s,
                                     size_t cipher_key_size,
                                     const struct assh_kex_dh_group_s *group)
{
  assh_error_t err;
  struct assh_kex_dh_private_s *pv;

  if (cipher_key_size < 64)
    cipher_key_size = 64;

  size_t exp_n = cipher_key_size * 2;

  /* allocate DH private context */
  ASSH_RET_ON_ERR(assh_alloc(s->ctx, sizeof(*pv), ASSH_ALLOC_INTERNAL, (void**)&pv)
	       | ASSH_ERRSV_DISCONNECT);

  switch (s->ctx->type)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_CLIENT: {
      pv->state = ASSH_KEX_DH_CLIENT_INIT;
      break;
    }
#endif
#ifdef CONFIG_ASSH_SERVER
    case ASSH_SERVER:
      pv->state = ASSH_KEX_DH_SERVER_WAIT_E;
      break;
#endif
    default:
      ASSH_UNREACHABLE();
    }

  s->kex_pv = pv;
  pv->group = group;

  switch (s->ctx->type)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_CLIENT:
      assh_bignum_init(s->ctx, &pv->en, group->size);
      assh_bignum_init(s->ctx, &pv->xn, exp_n);
      pv->pck = NULL;
      break;
#endif

#ifdef CONFIG_ASSH_SERVER
    case ASSH_SERVER:
      pv->exp_n = exp_n;
      break;
#endif
    default:;
    }

  return ASSH_OK;
}

static ASSH_KEX_CLEANUP_FCN(assh_kex_dh_cleanup)
{
  struct assh_kex_dh_private_s *pv = s->kex_pv;
  struct assh_context_s *c = s->ctx;
  
  switch (c->type)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_CLIENT:
      assh_bignum_release(c, &pv->en);
      assh_bignum_release(c, &pv->xn);
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

static ASSH_KEX_INIT_FCN(assh_kex_dh_group1_sha1_init)
{
  static const struct assh_kex_dh_group_s group =
    {
      .hash = &assh_hash_sha1,
      .size = 1024,
      .generator = (const uint8_t*)"\x00\x00\x00\x01\x02",
      .prime = (const uint8_t*)"\x00\x00\x00\x81"
      "\x00\xff\xff\xff\xff\xff\xff\xff\xff\xc9\x0f\xda\xa2\x21\x68\xc2\x34"
      "\xc4\xc6\x62\x8b\x80\xdc\x1c\xd1\x29\x02\x4e\x08\x8a\x67\xcc\x74"
      "\x02\x0b\xbe\xa6\x3b\x13\x9b\x22\x51\x4a\x08\x79\x8e\x34\x04\xdd"
      "\xef\x95\x19\xb3\xcd\x3a\x43\x1b\x30\x2b\x0a\x6d\xf2\x5f\x14\x37"
      "\x4f\xe1\x35\x6d\x6d\x51\xc2\x45\xe4\x85\xb5\x76\x62\x5e\x7e\xc6"
      "\xf4\x4c\x42\xe9\xa6\x37\xed\x6b\x0b\xff\x5c\xb6\xf4\x06\xb7\xed"
      "\xee\x38\x6b\xfb\x5a\x89\x9f\xa5\xae\x9f\x24\x11\x7c\x4b\x1f\xe6"
      "\x49\x28\x66\x51\xec\xe6\x53\x81\xff\xff\xff\xff\xff\xff\xff\xff"
    };

  return assh_kex_dh_init(s, cipher_key_size, &group);
}

const struct assh_algo_kex_s assh_kex_dh_group1_sha1 =
{
  ASSH_ALGO_BASE(KEX, ASSH_SAFETY_PRIMEFIELD(1024)
                 /* precomputations */ / 2 /* sha1 */ - 1, 40,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
                      "diffie-hellman-group1-sha1" })
  ),
  .f_init = assh_kex_dh_group1_sha1_init,
  .f_cleanup = assh_kex_dh_cleanup,
  .f_process = assh_kex_dh_process,
};

static ASSH_KEX_INIT_FCN(assh_kex_dh_group14_sha1_init)
{
  static const struct assh_kex_dh_group_s group =
    {
      .hash = &assh_hash_sha1,
      .size = 2048,
      .generator = (const uint8_t*)"\x00\x00\x00\x01\x02",
      .prime = (const uint8_t*)"\x00\x00\x01\x01"
      "\x00\xff\xff\xff\xff\xff\xff\xff\xff\xc9\x0f\xda\xa2\x21\x68\xc2\x34"
      "\xc4\xc6\x62\x8b\x80\xdc\x1c\xd1\x29\x02\x4e\x08\x8a\x67\xcc\x74"
      "\x02\x0b\xbe\xa6\x3b\x13\x9b\x22\x51\x4a\x08\x79\x8e\x34\x04\xdd"
      "\xef\x95\x19\xb3\xcd\x3a\x43\x1b\x30\x2b\x0a\x6d\xf2\x5f\x14\x37"
      "\x4f\xe1\x35\x6d\x6d\x51\xc2\x45\xe4\x85\xb5\x76\x62\x5e\x7e\xc6"
      "\xf4\x4c\x42\xe9\xa6\x37\xed\x6b\x0b\xff\x5c\xb6\xf4\x06\xb7\xed"
      "\xee\x38\x6b\xfb\x5a\x89\x9f\xa5\xae\x9f\x24\x11\x7c\x4b\x1f\xe6"
      "\x49\x28\x66\x51\xec\xe4\x5b\x3d\xc2\x00\x7c\xb8\xa1\x63\xbf\x05"
      "\x98\xda\x48\x36\x1c\x55\xd3\x9a\x69\x16\x3f\xa8\xfd\x24\xcf\x5f"
      "\x83\x65\x5d\x23\xdc\xa3\xad\x96\x1c\x62\xf3\x56\x20\x85\x52\xbb"
      "\x9e\xd5\x29\x07\x70\x96\x96\x6d\x67\x0c\x35\x4e\x4a\xbc\x98\x04"
      "\xf1\x74\x6c\x08\xca\x18\x21\x7c\x32\x90\x5e\x46\x2e\x36\xce\x3b"
      "\xe3\x9e\x77\x2c\x18\x0e\x86\x03\x9b\x27\x83\xa2\xec\x07\xa2\x8f"
      "\xb5\xc5\x5d\xf0\x6f\x4c\x52\xc9\xde\x2b\xcb\xf6\x95\x58\x17\x18"
      "\x39\x95\x49\x7c\xea\x95\x6a\xe5\x15\xd2\x26\x18\x98\xfa\x05\x10"
      "\x15\x72\x8e\x5a\x8a\xac\xaa\x68\xff\xff\xff\xff\xff\xff\xff\xff"
    };

  return assh_kex_dh_init(s, cipher_key_size, &group);
}

const struct assh_algo_kex_s assh_kex_dh_group14_sha1 =
{
  ASSH_ALGO_BASE(KEX, ASSH_SAFETY_PRIMEFIELD(2048)
                 /* precomputations */ / 2 /* sha1 */ - 1, 30,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
                      "diffie-hellman-group14-sha1" })
  ),
  .f_init = assh_kex_dh_group14_sha1_init,
  .f_cleanup = assh_kex_dh_cleanup,
  .f_process = assh_kex_dh_process,
};

static ASSH_KEX_INIT_FCN(assh_kex_dh_group14_sha256_init)
{
  static const struct assh_kex_dh_group_s group =
    {
      .hash = &assh_hash_sha256,
      .size = 2048,
      .generator = (const uint8_t*)"\x00\x00\x00\x01\x02",
      .prime = (const uint8_t*)"\x00\x00\x01\x01"
      "\x00\xff\xff\xff\xff\xff\xff\xff\xff\xc9\x0f\xda\xa2\x21\x68\xc2\x34"
      "\xc4\xc6\x62\x8b\x80\xdc\x1c\xd1\x29\x02\x4e\x08\x8a\x67\xcc\x74"
      "\x02\x0b\xbe\xa6\x3b\x13\x9b\x22\x51\x4a\x08\x79\x8e\x34\x04\xdd"
      "\xef\x95\x19\xb3\xcd\x3a\x43\x1b\x30\x2b\x0a\x6d\xf2\x5f\x14\x37"
      "\x4f\xe1\x35\x6d\x6d\x51\xc2\x45\xe4\x85\xb5\x76\x62\x5e\x7e\xc6"
      "\xf4\x4c\x42\xe9\xa6\x37\xed\x6b\x0b\xff\x5c\xb6\xf4\x06\xb7\xed"
      "\xee\x38\x6b\xfb\x5a\x89\x9f\xa5\xae\x9f\x24\x11\x7c\x4b\x1f\xe6"
      "\x49\x28\x66\x51\xec\xe4\x5b\x3d\xc2\x00\x7c\xb8\xa1\x63\xbf\x05"
      "\x98\xda\x48\x36\x1c\x55\xd3\x9a\x69\x16\x3f\xa8\xfd\x24\xcf\x5f"
      "\x83\x65\x5d\x23\xdc\xa3\xad\x96\x1c\x62\xf3\x56\x20\x85\x52\xbb"
      "\x9e\xd5\x29\x07\x70\x96\x96\x6d\x67\x0c\x35\x4e\x4a\xbc\x98\x04"
      "\xf1\x74\x6c\x08\xca\x18\x21\x7c\x32\x90\x5e\x46\x2e\x36\xce\x3b"
      "\xe3\x9e\x77\x2c\x18\x0e\x86\x03\x9b\x27\x83\xa2\xec\x07\xa2\x8f"
      "\xb5\xc5\x5d\xf0\x6f\x4c\x52\xc9\xde\x2b\xcb\xf6\x95\x58\x17\x18"
      "\x39\x95\x49\x7c\xea\x95\x6a\xe5\x15\xd2\x26\x18\x98\xfa\x05\x10"
      "\x15\x72\x8e\x5a\x8a\xac\xaa\x68\xff\xff\xff\xff\xff\xff\xff\xff"
    };

  return assh_kex_dh_init(s, cipher_key_size, &group);
}

const struct assh_algo_kex_s assh_kex_dh_group14_sha256 =
{
  ASSH_ALGO_BASE(KEX, ASSH_SAFETY_PRIMEFIELD(2048)
                 /* precomputations */ / 2, 30,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_DRAFT,
                      "diffie-hellman-group14-sha256" })
  ),
  .f_init = assh_kex_dh_group14_sha256_init,
  .f_cleanup = assh_kex_dh_cleanup,
  .f_process = assh_kex_dh_process,
};

static ASSH_KEX_INIT_FCN(assh_kex_dh_group15_sha512_init)
{
  static const struct assh_kex_dh_group_s group =
    {
      .hash = &assh_hash_sha512,
      .size = 3072,
      .generator = (const uint8_t*)"\x00\x00\x00\x01\x02",
      .prime = (const uint8_t*)"\x00\x00\x01\x81"
      "\x00\xff\xff\xff\xff\xff\xff\xff\xff\xc9\x0f\xda\xa2\x21\x68\xc2\x34\xc4\xc6"
      "\x62\x8b\x80\xdc\x1c\xd1\x29\x02\x4e\x08\x8a\x67\xcc\x74\x02\x0b\xbe\xa6"
      "\x3b\x13\x9b\x22\x51\x4a\x08\x79\x8e\x34\x04\xdd\xef\x95\x19\xb3\xcd\x3a"
      "\x43\x1b\x30\x2b\x0a\x6d\xf2\x5f\x14\x37\x4f\xe1\x35\x6d\x6d\x51\xc2\x45"
      "\xe4\x85\xb5\x76\x62\x5e\x7e\xc6\xf4\x4c\x42\xe9\xa6\x37\xed\x6b\x0b\xff"
      "\x5c\xb6\xf4\x06\xb7\xed\xee\x38\x6b\xfb\x5a\x89\x9f\xa5\xae\x9f\x24\x11"
      "\x7c\x4b\x1f\xe6\x49\x28\x66\x51\xec\xe4\x5b\x3d\xc2\x00\x7c\xb8\xa1\x63"
      "\xbf\x05\x98\xda\x48\x36\x1c\x55\xd3\x9a\x69\x16\x3f\xa8\xfd\x24\xcf\x5f"
      "\x83\x65\x5d\x23\xdc\xa3\xad\x96\x1c\x62\xf3\x56\x20\x85\x52\xbb\x9e\xd5"
      "\x29\x07\x70\x96\x96\x6d\x67\x0c\x35\x4e\x4a\xbc\x98\x04\xf1\x74\x6c\x08"
      "\xca\x18\x21\x7c\x32\x90\x5e\x46\x2e\x36\xce\x3b\xe3\x9e\x77\x2c\x18\x0e"
      "\x86\x03\x9b\x27\x83\xa2\xec\x07\xa2\x8f\xb5\xc5\x5d\xf0\x6f\x4c\x52\xc9"
      "\xde\x2b\xcb\xf6\x95\x58\x17\x18\x39\x95\x49\x7c\xea\x95\x6a\xe5\x15\xd2"
      "\x26\x18\x98\xfa\x05\x10\x15\x72\x8e\x5a\x8a\xaa\xc4\x2d\xad\x33\x17\x0d"
      "\x04\x50\x7a\x33\xa8\x55\x21\xab\xdf\x1c\xba\x64\xec\xfb\x85\x04\x58\xdb"
      "\xef\x0a\x8a\xea\x71\x57\x5d\x06\x0c\x7d\xb3\x97\x0f\x85\xa6\xe1\xe4\xc7"
      "\xab\xf5\xae\x8c\xdb\x09\x33\xd7\x1e\x8c\x94\xe0\x4a\x25\x61\x9d\xce\xe3"
      "\xd2\x26\x1a\xd2\xee\x6b\xf1\x2f\xfa\x06\xd9\x8a\x08\x64\xd8\x76\x02\x73"
      "\x3e\xc8\x6a\x64\x52\x1f\x2b\x18\x17\x7b\x20\x0c\xbb\xe1\x17\x57\x7a\x61"
      "\x5d\x6c\x77\x09\x88\xc0\xba\xd9\x46\xe2\x08\xe2\x4f\xa0\x74\xe5\xab\x31"
      "\x43\xdb\x5b\xfc\xe0\xfd\x10\x8e\x4b\x82\xd1\x20\xa9\x3a\xd2\xca\xff\xff"
      "\xff\xff\xff\xff\xff\xff"
    };

  return assh_kex_dh_init(s, cipher_key_size, &group);
}

const struct assh_algo_kex_s assh_kex_dh_group15_sha512 =
{
  ASSH_ALGO_BASE(KEX, ASSH_SAFETY_PRIMEFIELD(3072)
                 /* precomputations */ / 2, 20,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_DRAFT,
                      "diffie-hellman-group15-sha512" })
  ),
  .f_init = assh_kex_dh_group15_sha512_init,
  .f_cleanup = assh_kex_dh_cleanup,
  .f_process = assh_kex_dh_process,
};

static ASSH_KEX_INIT_FCN(assh_kex_dh_group16_sha512_init)
{
  static const struct assh_kex_dh_group_s group =
    {
      .hash = &assh_hash_sha512,
      .size = 4096,
      .generator = (const uint8_t*)"\x00\x00\x00\x01\x02",
      .prime = (const uint8_t*)"\x00\x00\x02\x01"
      "\x00\xff\xff\xff\xff\xff\xff\xff\xff\xc9\x0f\xda\xa2\x21\x68\xc2\x34\xc4\xc6"
      "\x62\x8b\x80\xdc\x1c\xd1\x29\x02\x4e\x08\x8a\x67\xcc\x74\x02\x0b\xbe\xa6"
      "\x3b\x13\x9b\x22\x51\x4a\x08\x79\x8e\x34\x04\xdd\xef\x95\x19\xb3\xcd\x3a"
      "\x43\x1b\x30\x2b\x0a\x6d\xf2\x5f\x14\x37\x4f\xe1\x35\x6d\x6d\x51\xc2\x45"
      "\xe4\x85\xb5\x76\x62\x5e\x7e\xc6\xf4\x4c\x42\xe9\xa6\x37\xed\x6b\x0b\xff"
      "\x5c\xb6\xf4\x06\xb7\xed\xee\x38\x6b\xfb\x5a\x89\x9f\xa5\xae\x9f\x24\x11"
      "\x7c\x4b\x1f\xe6\x49\x28\x66\x51\xec\xe4\x5b\x3d\xc2\x00\x7c\xb8\xa1\x63"
      "\xbf\x05\x98\xda\x48\x36\x1c\x55\xd3\x9a\x69\x16\x3f\xa8\xfd\x24\xcf\x5f"
      "\x83\x65\x5d\x23\xdc\xa3\xad\x96\x1c\x62\xf3\x56\x20\x85\x52\xbb\x9e\xd5"
      "\x29\x07\x70\x96\x96\x6d\x67\x0c\x35\x4e\x4a\xbc\x98\x04\xf1\x74\x6c\x08"
      "\xca\x18\x21\x7c\x32\x90\x5e\x46\x2e\x36\xce\x3b\xe3\x9e\x77\x2c\x18\x0e"
      "\x86\x03\x9b\x27\x83\xa2\xec\x07\xa2\x8f\xb5\xc5\x5d\xf0\x6f\x4c\x52\xc9"
      "\xde\x2b\xcb\xf6\x95\x58\x17\x18\x39\x95\x49\x7c\xea\x95\x6a\xe5\x15\xd2"
      "\x26\x18\x98\xfa\x05\x10\x15\x72\x8e\x5a\x8a\xaa\xc4\x2d\xad\x33\x17\x0d"
      "\x04\x50\x7a\x33\xa8\x55\x21\xab\xdf\x1c\xba\x64\xec\xfb\x85\x04\x58\xdb"
      "\xef\x0a\x8a\xea\x71\x57\x5d\x06\x0c\x7d\xb3\x97\x0f\x85\xa6\xe1\xe4\xc7"
      "\xab\xf5\xae\x8c\xdb\x09\x33\xd7\x1e\x8c\x94\xe0\x4a\x25\x61\x9d\xce\xe3"
      "\xd2\x26\x1a\xd2\xee\x6b\xf1\x2f\xfa\x06\xd9\x8a\x08\x64\xd8\x76\x02\x73"
      "\x3e\xc8\x6a\x64\x52\x1f\x2b\x18\x17\x7b\x20\x0c\xbb\xe1\x17\x57\x7a\x61"
      "\x5d\x6c\x77\x09\x88\xc0\xba\xd9\x46\xe2\x08\xe2\x4f\xa0\x74\xe5\xab\x31"
      "\x43\xdb\x5b\xfc\xe0\xfd\x10\x8e\x4b\x82\xd1\x20\xa9\x21\x08\x01\x1a\x72"
      "\x3c\x12\xa7\x87\xe6\xd7\x88\x71\x9a\x10\xbd\xba\x5b\x26\x99\xc3\x27\x18"
      "\x6a\xf4\xe2\x3c\x1a\x94\x68\x34\xb6\x15\x0b\xda\x25\x83\xe9\xca\x2a\xd4"
      "\x4c\xe8\xdb\xbb\xc2\xdb\x04\xde\x8e\xf9\x2e\x8e\xfc\x14\x1f\xbe\xca\xa6"
      "\x28\x7c\x59\x47\x4e\x6b\xc0\x5d\x99\xb2\x96\x4f\xa0\x90\xc3\xa2\x23\x3b"
      "\xa1\x86\x51\x5b\xe7\xed\x1f\x61\x29\x70\xce\xe2\xd7\xaf\xb8\x1b\xdd\x76"
      "\x21\x70\x48\x1c\xd0\x06\x91\x27\xd5\xb0\x5a\xa9\x93\xb4\xea\x98\x8d\x8f"
      "\xdd\xc1\x86\xff\xb7\xdc\x90\xa6\xc0\x8f\x4d\xf4\x35\xc9\x34\x06\x31\x99"
      "\xff\xff\xff\xff\xff\xff\xff\xff"
    };

  return assh_kex_dh_init(s, cipher_key_size, &group);
}

const struct assh_algo_kex_s assh_kex_dh_group16_sha512 =
{
  ASSH_ALGO_BASE(KEX, ASSH_SAFETY_PRIMEFIELD(4096)
                 /* precomputations */ / 2, 10,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_DRAFT,
                      "diffie-hellman-group16-sha512" })
  ),
  .f_init = assh_kex_dh_group16_sha512_init,
  .f_cleanup = assh_kex_dh_cleanup,
  .f_process = assh_kex_dh_process,
};

static ASSH_KEX_INIT_FCN(assh_kex_dh_group17_sha512_init)
{
  static const struct assh_kex_dh_group_s group =
    {
      .hash = &assh_hash_sha512,
      .size = 6144,
      .generator = (const uint8_t*)"\x00\x00\x00\x01\x02",
      .prime = (const uint8_t*)"\x00\x00\x03\x01"
      "\x00\xff\xff\xff\xff\xff\xff\xff\xff\xc9\x0f\xda\xa2\x21\x68\xc2\x34\xc4\xc6"
      "\x62\x8b\x80\xdc\x1c\xd1\x29\x02\x4e\x08\x8a\x67\xcc\x74\x02\x0b\xbe\xa6"
      "\x3b\x13\x9b\x22\x51\x4a\x08\x79\x8e\x34\x04\xdd\xef\x95\x19\xb3\xcd\x3a"
      "\x43\x1b\x30\x2b\x0a\x6d\xf2\x5f\x14\x37\x4f\xe1\x35\x6d\x6d\x51\xc2\x45"
      "\xe4\x85\xb5\x76\x62\x5e\x7e\xc6\xf4\x4c\x42\xe9\xa6\x37\xed\x6b\x0b\xff"
      "\x5c\xb6\xf4\x06\xb7\xed\xee\x38\x6b\xfb\x5a\x89\x9f\xa5\xae\x9f\x24\x11"
      "\x7c\x4b\x1f\xe6\x49\x28\x66\x51\xec\xe4\x5b\x3d\xc2\x00\x7c\xb8\xa1\x63"
      "\xbf\x05\x98\xda\x48\x36\x1c\x55\xd3\x9a\x69\x16\x3f\xa8\xfd\x24\xcf\x5f"
      "\x83\x65\x5d\x23\xdc\xa3\xad\x96\x1c\x62\xf3\x56\x20\x85\x52\xbb\x9e\xd5"
      "\x29\x07\x70\x96\x96\x6d\x67\x0c\x35\x4e\x4a\xbc\x98\x04\xf1\x74\x6c\x08"
      "\xca\x18\x21\x7c\x32\x90\x5e\x46\x2e\x36\xce\x3b\xe3\x9e\x77\x2c\x18\x0e"
      "\x86\x03\x9b\x27\x83\xa2\xec\x07\xa2\x8f\xb5\xc5\x5d\xf0\x6f\x4c\x52\xc9"
      "\xde\x2b\xcb\xf6\x95\x58\x17\x18\x39\x95\x49\x7c\xea\x95\x6a\xe5\x15\xd2"
      "\x26\x18\x98\xfa\x05\x10\x15\x72\x8e\x5a\x8a\xaa\xc4\x2d\xad\x33\x17\x0d"
      "\x04\x50\x7a\x33\xa8\x55\x21\xab\xdf\x1c\xba\x64\xec\xfb\x85\x04\x58\xdb"
      "\xef\x0a\x8a\xea\x71\x57\x5d\x06\x0c\x7d\xb3\x97\x0f\x85\xa6\xe1\xe4\xc7"
      "\xab\xf5\xae\x8c\xdb\x09\x33\xd7\x1e\x8c\x94\xe0\x4a\x25\x61\x9d\xce\xe3"
      "\xd2\x26\x1a\xd2\xee\x6b\xf1\x2f\xfa\x06\xd9\x8a\x08\x64\xd8\x76\x02\x73"
      "\x3e\xc8\x6a\x64\x52\x1f\x2b\x18\x17\x7b\x20\x0c\xbb\xe1\x17\x57\x7a\x61"
      "\x5d\x6c\x77\x09\x88\xc0\xba\xd9\x46\xe2\x08\xe2\x4f\xa0\x74\xe5\xab\x31"
      "\x43\xdb\x5b\xfc\xe0\xfd\x10\x8e\x4b\x82\xd1\x20\xa9\x21\x08\x01\x1a\x72"
      "\x3c\x12\xa7\x87\xe6\xd7\x88\x71\x9a\x10\xbd\xba\x5b\x26\x99\xc3\x27\x18"
      "\x6a\xf4\xe2\x3c\x1a\x94\x68\x34\xb6\x15\x0b\xda\x25\x83\xe9\xca\x2a\xd4"
      "\x4c\xe8\xdb\xbb\xc2\xdb\x04\xde\x8e\xf9\x2e\x8e\xfc\x14\x1f\xbe\xca\xa6"
      "\x28\x7c\x59\x47\x4e\x6b\xc0\x5d\x99\xb2\x96\x4f\xa0\x90\xc3\xa2\x23\x3b"
      "\xa1\x86\x51\x5b\xe7\xed\x1f\x61\x29\x70\xce\xe2\xd7\xaf\xb8\x1b\xdd\x76"
      "\x21\x70\x48\x1c\xd0\x06\x91\x27\xd5\xb0\x5a\xa9\x93\xb4\xea\x98\x8d\x8f"
      "\xdd\xc1\x86\xff\xb7\xdc\x90\xa6\xc0\x8f\x4d\xf4\x35\xc9\x34\x02\x84\x92"
      "\x36\xc3\xfa\xb4\xd2\x7c\x70\x26\xc1\xd4\xdc\xb2\x60\x26\x46\xde\xc9\x75"
      "\x1e\x76\x3d\xba\x37\xbd\xf8\xff\x94\x06\xad\x9e\x53\x0e\xe5\xdb\x38\x2f"
      "\x41\x30\x01\xae\xb0\x6a\x53\xed\x90\x27\xd8\x31\x17\x97\x27\xb0\x86\x5a"
      "\x89\x18\xda\x3e\xdb\xeb\xcf\x9b\x14\xed\x44\xce\x6c\xba\xce\xd4\xbb\x1b"
      "\xdb\x7f\x14\x47\xe6\xcc\x25\x4b\x33\x20\x51\x51\x2b\xd7\xaf\x42\x6f\xb8"
      "\xf4\x01\x37\x8c\xd2\xbf\x59\x83\xca\x01\xc6\x4b\x92\xec\xf0\x32\xea\x15"
      "\xd1\x72\x1d\x03\xf4\x82\xd7\xce\x6e\x74\xfe\xf6\xd5\x5e\x70\x2f\x46\x98"
      "\x0c\x82\xb5\xa8\x40\x31\x90\x0b\x1c\x9e\x59\xe7\xc9\x7f\xbe\xc7\xe8\xf3"
      "\x23\xa9\x7a\x7e\x36\xcc\x88\xbe\x0f\x1d\x45\xb7\xff\x58\x5a\xc5\x4b\xd4"
      "\x07\xb2\x2b\x41\x54\xaa\xcc\x8f\x6d\x7e\xbf\x48\xe1\xd8\x14\xcc\x5e\xd2"
      "\x0f\x80\x37\xe0\xa7\x97\x15\xee\xf2\x9b\xe3\x28\x06\xa1\xd5\x8b\xb7\xc5"
      "\xda\x76\xf5\x50\xaa\x3d\x8a\x1f\xbf\xf0\xeb\x19\xcc\xb1\xa3\x13\xd5\x5c"
      "\xda\x56\xc9\xec\x2e\xf2\x96\x32\x38\x7f\xe8\xd7\x6e\x3c\x04\x68\x04\x3e"
      "\x8f\x66\x3f\x48\x60\xee\x12\xbf\x2d\x5b\x0b\x74\x74\xd6\xe6\x94\xf9\x1e"
      "\x6d\xcc\x40\x24\xff\xff\xff\xff\xff\xff\xff\xff"
    };

  return assh_kex_dh_init(s, cipher_key_size, &group);
}

const struct assh_algo_kex_s assh_kex_dh_group17_sha512 =
{
  ASSH_ALGO_BASE(KEX, ASSH_SAFETY_PRIMEFIELD(6144)
                 /* precomputations */ / 2, 5,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_DRAFT,
                      "diffie-hellman-group17-sha512" })
  ),
  .f_init = assh_kex_dh_group17_sha512_init,
  .f_cleanup = assh_kex_dh_cleanup,
  .f_process = assh_kex_dh_process,
};


static ASSH_KEX_INIT_FCN(assh_kex_dh_group18_sha512_init)
{
  static const struct assh_kex_dh_group_s group =
    {
      .hash = &assh_hash_sha512,
      .size = 8192,
      .generator = (const uint8_t*)"\x00\x00\x00\x01\x02",
      .prime = (const uint8_t*)"\x00\x00\x04\x01"
      "\x00\xff\xff\xff\xff\xff\xff\xff\xff\xc9\x0f\xda\xa2\x21\x68\xc2\x34\xc4\xc6"
      "\x62\x8b\x80\xdc\x1c\xd1\x29\x02\x4e\x08\x8a\x67\xcc\x74\x02\x0b\xbe\xa6"
      "\x3b\x13\x9b\x22\x51\x4a\x08\x79\x8e\x34\x04\xdd\xef\x95\x19\xb3\xcd\x3a"
      "\x43\x1b\x30\x2b\x0a\x6d\xf2\x5f\x14\x37\x4f\xe1\x35\x6d\x6d\x51\xc2\x45"
      "\xe4\x85\xb5\x76\x62\x5e\x7e\xc6\xf4\x4c\x42\xe9\xa6\x37\xed\x6b\x0b\xff"
      "\x5c\xb6\xf4\x06\xb7\xed\xee\x38\x6b\xfb\x5a\x89\x9f\xa5\xae\x9f\x24\x11"
      "\x7c\x4b\x1f\xe6\x49\x28\x66\x51\xec\xe4\x5b\x3d\xc2\x00\x7c\xb8\xa1\x63"
      "\xbf\x05\x98\xda\x48\x36\x1c\x55\xd3\x9a\x69\x16\x3f\xa8\xfd\x24\xcf\x5f"
      "\x83\x65\x5d\x23\xdc\xa3\xad\x96\x1c\x62\xf3\x56\x20\x85\x52\xbb\x9e\xd5"
      "\x29\x07\x70\x96\x96\x6d\x67\x0c\x35\x4e\x4a\xbc\x98\x04\xf1\x74\x6c\x08"
      "\xca\x18\x21\x7c\x32\x90\x5e\x46\x2e\x36\xce\x3b\xe3\x9e\x77\x2c\x18\x0e"
      "\x86\x03\x9b\x27\x83\xa2\xec\x07\xa2\x8f\xb5\xc5\x5d\xf0\x6f\x4c\x52\xc9"
      "\xde\x2b\xcb\xf6\x95\x58\x17\x18\x39\x95\x49\x7c\xea\x95\x6a\xe5\x15\xd2"
      "\x26\x18\x98\xfa\x05\x10\x15\x72\x8e\x5a\x8a\xaa\xc4\x2d\xad\x33\x17\x0d"
      "\x04\x50\x7a\x33\xa8\x55\x21\xab\xdf\x1c\xba\x64\xec\xfb\x85\x04\x58\xdb"
      "\xef\x0a\x8a\xea\x71\x57\x5d\x06\x0c\x7d\xb3\x97\x0f\x85\xa6\xe1\xe4\xc7"
      "\xab\xf5\xae\x8c\xdb\x09\x33\xd7\x1e\x8c\x94\xe0\x4a\x25\x61\x9d\xce\xe3"
      "\xd2\x26\x1a\xd2\xee\x6b\xf1\x2f\xfa\x06\xd9\x8a\x08\x64\xd8\x76\x02\x73"
      "\x3e\xc8\x6a\x64\x52\x1f\x2b\x18\x17\x7b\x20\x0c\xbb\xe1\x17\x57\x7a\x61"
      "\x5d\x6c\x77\x09\x88\xc0\xba\xd9\x46\xe2\x08\xe2\x4f\xa0\x74\xe5\xab\x31"
      "\x43\xdb\x5b\xfc\xe0\xfd\x10\x8e\x4b\x82\xd1\x20\xa9\x21\x08\x01\x1a\x72"
      "\x3c\x12\xa7\x87\xe6\xd7\x88\x71\x9a\x10\xbd\xba\x5b\x26\x99\xc3\x27\x18"
      "\x6a\xf4\xe2\x3c\x1a\x94\x68\x34\xb6\x15\x0b\xda\x25\x83\xe9\xca\x2a\xd4"
      "\x4c\xe8\xdb\xbb\xc2\xdb\x04\xde\x8e\xf9\x2e\x8e\xfc\x14\x1f\xbe\xca\xa6"
      "\x28\x7c\x59\x47\x4e\x6b\xc0\x5d\x99\xb2\x96\x4f\xa0\x90\xc3\xa2\x23\x3b"
      "\xa1\x86\x51\x5b\xe7\xed\x1f\x61\x29\x70\xce\xe2\xd7\xaf\xb8\x1b\xdd\x76"
      "\x21\x70\x48\x1c\xd0\x06\x91\x27\xd5\xb0\x5a\xa9\x93\xb4\xea\x98\x8d\x8f"
      "\xdd\xc1\x86\xff\xb7\xdc\x90\xa6\xc0\x8f\x4d\xf4\x35\xc9\x34\x02\x84\x92"
      "\x36\xc3\xfa\xb4\xd2\x7c\x70\x26\xc1\xd4\xdc\xb2\x60\x26\x46\xde\xc9\x75"
      "\x1e\x76\x3d\xba\x37\xbd\xf8\xff\x94\x06\xad\x9e\x53\x0e\xe5\xdb\x38\x2f"
      "\x41\x30\x01\xae\xb0\x6a\x53\xed\x90\x27\xd8\x31\x17\x97\x27\xb0\x86\x5a"
      "\x89\x18\xda\x3e\xdb\xeb\xcf\x9b\x14\xed\x44\xce\x6c\xba\xce\xd4\xbb\x1b"
      "\xdb\x7f\x14\x47\xe6\xcc\x25\x4b\x33\x20\x51\x51\x2b\xd7\xaf\x42\x6f\xb8"
      "\xf4\x01\x37\x8c\xd2\xbf\x59\x83\xca\x01\xc6\x4b\x92\xec\xf0\x32\xea\x15"
      "\xd1\x72\x1d\x03\xf4\x82\xd7\xce\x6e\x74\xfe\xf6\xd5\x5e\x70\x2f\x46\x98"
      "\x0c\x82\xb5\xa8\x40\x31\x90\x0b\x1c\x9e\x59\xe7\xc9\x7f\xbe\xc7\xe8\xf3"
      "\x23\xa9\x7a\x7e\x36\xcc\x88\xbe\x0f\x1d\x45\xb7\xff\x58\x5a\xc5\x4b\xd4"
      "\x07\xb2\x2b\x41\x54\xaa\xcc\x8f\x6d\x7e\xbf\x48\xe1\xd8\x14\xcc\x5e\xd2"
      "\x0f\x80\x37\xe0\xa7\x97\x15\xee\xf2\x9b\xe3\x28\x06\xa1\xd5\x8b\xb7\xc5"
      "\xda\x76\xf5\x50\xaa\x3d\x8a\x1f\xbf\xf0\xeb\x19\xcc\xb1\xa3\x13\xd5\x5c"
      "\xda\x56\xc9\xec\x2e\xf2\x96\x32\x38\x7f\xe8\xd7\x6e\x3c\x04\x68\x04\x3e"
      "\x8f\x66\x3f\x48\x60\xee\x12\xbf\x2d\x5b\x0b\x74\x74\xd6\xe6\x94\xf9\x1e"
      "\x6d\xbe\x11\x59\x74\xa3\x92\x6f\x12\xfe\xe5\xe4\x38\x77\x7c\xb6\xa9\x32"
      "\xdf\x8c\xd8\xbe\xc4\xd0\x73\xb9\x31\xba\x3b\xc8\x32\xb6\x8d\x9d\xd3\x00"
      "\x74\x1f\xa7\xbf\x8a\xfc\x47\xed\x25\x76\xf6\x93\x6b\xa4\x24\x66\x3a\xab"
      "\x63\x9c\x5a\xe4\xf5\x68\x34\x23\xb4\x74\x2b\xf1\xc9\x78\x23\x8f\x16\xcb"
      "\xe3\x9d\x65\x2d\xe3\xfd\xb8\xbe\xfc\x84\x8a\xd9\x22\x22\x2e\x04\xa4\x03"
      "\x7c\x07\x13\xeb\x57\xa8\x1a\x23\xf0\xc7\x34\x73\xfc\x64\x6c\xea\x30\x6b"
      "\x4b\xcb\xc8\x86\x2f\x83\x85\xdd\xfa\x9d\x4b\x7f\xa2\xc0\x87\xe8\x79\x68"
      "\x33\x03\xed\x5b\xdd\x3a\x06\x2b\x3c\xf5\xb3\xa2\x78\xa6\x6d\x2a\x13\xf8"
      "\x3f\x44\xf8\x2d\xdf\x31\x0e\xe0\x74\xab\x6a\x36\x45\x97\xe8\x99\xa0\x25"
      "\x5d\xc1\x64\xf3\x1c\xc5\x08\x46\x85\x1d\xf9\xab\x48\x19\x5d\xed\x7e\xa1"
      "\xb1\xd5\x10\xbd\x7e\xe7\x4d\x73\xfa\xf3\x6b\xc3\x1e\xcf\xa2\x68\x35\x90"
      "\x46\xf4\xeb\x87\x9f\x92\x40\x09\x43\x8b\x48\x1c\x6c\xd7\x88\x9a\x00\x2e"
      "\xd5\xee\x38\x2b\xc9\x19\x0d\xa6\xfc\x02\x6e\x47\x95\x58\xe4\x47\x56\x77"
      "\xe9\xaa\x9e\x30\x50\xe2\x76\x56\x94\xdf\xc8\x1f\x56\xe8\x80\xb9\x6e\x71"
      "\x60\xc9\x80\xdd\x98\xed\xd3\xdf\xff\xff\xff\xff\xff\xff\xff\xff"
    };

  return assh_kex_dh_init(s, cipher_key_size, &group);
}

const struct assh_algo_kex_s assh_kex_dh_group18_sha512 =
{
  ASSH_ALGO_BASE(KEX, ASSH_SAFETY_PRIMEFIELD(8192)
                 /* precomputations */ / 2, 1,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_DRAFT,
                      "diffie-hellman-group18-sha512" })
  ),
  .f_init = assh_kex_dh_group18_sha512_init,
  .f_cleanup = assh_kex_dh_cleanup,
  .f_process = assh_kex_dh_process,
};
