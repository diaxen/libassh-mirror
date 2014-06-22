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

#define DH_MAX_GRSIZE 8192

struct assh_kex_dh_group_s
{
  unsigned int size;
  const uint8_t *generator;
  const uint8_t *prime;
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
  enum assh_kex_dh_state_e state;

  union {
#ifdef CONFIG_ASSH_SERVER
    struct {
      struct assh_bignum_s *fn;
      size_t exp_n;
      uint8_t *e_str;
    };
#endif
#ifdef CONFIG_ASSH_CLIENT
    struct {
      struct assh_bignum_s *en;
      struct assh_bignum_s *xn;
      struct assh_key_s *host_key;
      uint8_t *f_str;
      struct assh_packet_s *pck;
    };
#endif
  };
};

#ifdef CONFIG_ASSH_CLIENT
static assh_error_t assh_kex_dh_client_send_expmod(struct assh_session_s *s)
{
  struct assh_kex_dh_private_s *pv = s->kex_pv;
  const struct assh_kex_dh_group_s *gr = pv->group;
  struct assh_context_s *c = s->ctx;
  assh_error_t err;

  enum bytecode_args_e
  {
    G_mpint, P_mpint,
    E, X,
    G, P
  };

  assh_bignum_op_t bytecode[] = {
    ASSH_BIGNUM_BC_MOVE(        G,      G_mpint         ),
    ASSH_BIGNUM_BC_MOVE(        P,      P_mpint         ),

    /* generate private exponent in range [ group bits, p - 2 ] */
    ASSH_BIGNUM_BC_RAND(        X,      ASSH_PRNG_QUALITY_EPHEMERAL_KEY),
    ASSH_BIGNUM_BC_UINT(        E,      DH_MAX_GRSIZE   ),
    ASSH_BIGNUM_BC_CMPLT(       E,      X               ),
    ASSH_BIGNUM_BC_CMPLT(       X,      P               ),

    /* compute dh public key */
    ASSH_BIGNUM_BC_SETMOD(      P                       ),
    ASSH_BIGNUM_BC_EXPMOD(      E,      G,      X       ),

    ASSH_BIGNUM_BC_END(),
  };

  ASSH_ERR_RET(assh_bignum_bytecode(c, bytecode, "MMNNTT",
                                    /* M */ gr->generator, gr->prime,
                                    /* N */ pv->en, pv->xn,
                                    /* T */ gr->size, gr->size));

  /* send a packet containing e */
  struct assh_packet_s *p;
  ASSH_ERR_RET(assh_packet_alloc(c, SSH_MSG_KEX_DH_REQUEST,
                 assh_bignum_mpint_size(pv->en), &p)
	       | ASSH_ERRSV_DISCONNECT);

  ASSH_ERR_GTO(assh_packet_add_mpint(p, pv->en)
	       | ASSH_ERRSV_DISCONNECT, err_p);

  assh_transport_push(s, p);
  pv->state = ASSH_KEX_DH_CLIENT_WAIT_F;
  return ASSH_OK;

 err_p:
  assh_packet_release(p);
  return err;
}

static ASSH_KEX_CLIENT_HASH(assh_kex_dh_client_hash)
{
  struct assh_kex_dh_private_s *pv = s->kex_pv;
  assh_error_t err;

  ASSH_ERR_RET(assh_hash_bignum(s->ctx, hash_ctx, hash_algo->f_update, pv->en)
	       | ASSH_ERRSV_DISCONNECT);
  assh_hash_string(hash_ctx, hash_algo->f_update, pv->f_str);

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_kex_dh_host_key_lookup_done)
{
  struct assh_kex_dh_private_s *pv = s->kex_pv;
  const struct assh_kex_dh_group_s *gr = pv->group;
  assh_error_t err;

  ASSH_CHK_RET(pv->state != ASSH_KEX_DH_CLIENT_LOOKUP_HOST_KEY_WAIT,
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

  enum bytecode_args_e
  {
    G_mpint, P_mpint, F_mpint, K_mpint,
    X,
    G, P, F, T, K
  };

  assh_bignum_op_t bytecode[] = {
    ASSH_BIGNUM_BC_MOVE(        F,      F_mpint         ),
    ASSH_BIGNUM_BC_MOVE(        G,      G_mpint         ),
    ASSH_BIGNUM_BC_MOVE(        P,      P_mpint         ),

    /* check server public exponent */
    ASSH_BIGNUM_BC_UINT(        T,      2               ),
    ASSH_BIGNUM_BC_CMPLTEQ(     T,      F               ), /* f >= 2 */
    ASSH_BIGNUM_BC_SUB(         T,      P,      T       ),
    ASSH_BIGNUM_BC_CMPLTEQ(     F,      T               ), /* f <= p-2 */

    /* compute shared secret */
    ASSH_BIGNUM_BC_SETMOD(      P                       ),
    ASSH_BIGNUM_BC_EXPMOD(      T,      F,      X       ),
    ASSH_BIGNUM_BC_MOVE(        K,      T               ),

    /* check shared secret range */
    ASSH_BIGNUM_BC_UINT(        T,      2               ),
    ASSH_BIGNUM_BC_CMPLTEQ(     T,      K               ), /* k >= 2 */
    ASSH_BIGNUM_BC_SUB(         T,      P,      T       ),
    ASSH_BIGNUM_BC_CMPLTEQ(     K,      T               ), /* k <= p-2 */

    ASSH_BIGNUM_BC_MOVE(        K_mpint,        K       ),

    ASSH_BIGNUM_BC_END(),
  };

  size_t n = gr->size;

  ASSH_SCRATCH_ALLOC(s->ctx, uint8_t, secret, assh_packet_mpint_size(n),
                     ASSH_ERRSV_CONTINUE, err_);

  ASSH_ERR_GTO(assh_bignum_bytecode(s->ctx, bytecode, "MMMMNTTTTT",
                                    /* M */ gr->generator, gr->prime, f_str, secret,
                                    /* N */ pv->xn, /* T */ n, n, n, n, n), err_secret);

  pv->f_str = f_str;

  ASSH_ERR_GTO(assh_kex_client_hash(s, &assh_kex_dh_client_hash,
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

static assh_error_t assh_kex_dh_client_wait_f(struct assh_session_s *s,
					      struct assh_packet_s *p,
                                              struct assh_event_s *e)
{
  struct assh_kex_dh_private_s *pv = s->kex_pv;
  assh_error_t err;

  ASSH_CHK_RET(p->head.msg != SSH_MSG_KEX_DH_REPLY, ASSH_ERR_PROTOCOL
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
                                       &assh_kex_dh_host_key_lookup_done, pv));

  pv->state = ASSH_KEX_DH_CLIENT_LOOKUP_HOST_KEY_WAIT;
  pv->pck = assh_packet_refinc(p);

  return ASSH_OK;

 err_hk:
  assh_key_flush(s->ctx, &pv->host_key);
  return err;
}
#endif

#ifdef CONFIG_ASSH_SERVER
static ASSH_KEX_SERVER_HASH(assh_kex_dh_server_hash)
{
  struct assh_kex_dh_private_s *pv = s->kex_pv;
  assh_error_t err;

  /* append server ephemeral public key to packet. */
  uint8_t *f_str = pout->data + pout->data_size;
  ASSH_ERR_RET(assh_packet_add_mpint(pout, pv->fn) | ASSH_ERRSV_DISCONNECT);

  /* hash both ephemeral public keys */
  assh_hash_string(hash_ctx, hash_algo->f_update, pv->e_str);
  assh_hash_string(hash_ctx, hash_algo->f_update, f_str);

  return ASSH_OK;
}

static assh_error_t assh_kex_dh_server_wait_e(struct assh_session_s *s,
                                              struct assh_packet_s *p)
{
  struct assh_kex_dh_private_s *pv = s->kex_pv;
  const struct assh_kex_dh_group_s *gr = pv->group;
  struct assh_context_s *c = s->ctx;
  assh_error_t err;

  ASSH_CHK_RET(p->head.msg != SSH_MSG_KEX_DH_REQUEST,
	       ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);

  /* compute DH */
  uint8_t *e_str = p->head.end;

  ASSH_ERR_RET(assh_packet_check_string(p, e_str, NULL)
	       | ASSH_ERRSV_DISCONNECT);

  ASSH_SCRATCH_ALLOC(c, uint8_t, secret, gr->size,
                     ASSH_ERRSV_CONTINUE, err_);

  enum bytecode_args_e
  {
    G_mpint, P_mpint, E_mpint, K_mpint,
    F,
    G, P, E, X, K, T
  };

  assh_bignum_op_t bytecode[] = {
    ASSH_BIGNUM_BC_MOVE(        G,      G_mpint         ),
    ASSH_BIGNUM_BC_MOVE(        P,      P_mpint         ),
    ASSH_BIGNUM_BC_MOVE(        E,      E_mpint         ),

    /* check client public key */
    ASSH_BIGNUM_BC_UINT(        T,      2               ),
    ASSH_BIGNUM_BC_CMPLTEQ(     T,      E               ), /* f >= 2 */
    ASSH_BIGNUM_BC_SUB(         T,      P,      T       ),
    ASSH_BIGNUM_BC_CMPLTEQ(     E,      T               ), /* f <= p-2 */

    /* generate private exponent */
    ASSH_BIGNUM_BC_RAND(        X,      ASSH_PRNG_QUALITY_EPHEMERAL_KEY),
    ASSH_BIGNUM_BC_UINT(        T,      DH_MAX_GRSIZE   ),
    ASSH_BIGNUM_BC_CMPLT(       T,      X               ),
    ASSH_BIGNUM_BC_CMPLT(       X,      P               ),

    /* compute dh public key */
    ASSH_BIGNUM_BC_SETMOD(      P                       ),
    ASSH_BIGNUM_BC_EXPMOD(      F,      G,      X       ),

    /* compute shared secret */
    ASSH_BIGNUM_BC_EXPMOD(      K,      E,      X       ),

    /* check shared secret range */
    ASSH_BIGNUM_BC_UINT(        T,      2               ),
    ASSH_BIGNUM_BC_CMPLTEQ(     T,      K               ), /* k >= 2 */
    ASSH_BIGNUM_BC_SUB(         T,      P,      T       ),
    ASSH_BIGNUM_BC_CMPLTEQ(     K,      T               ), /* k <= p-2 */

    ASSH_BIGNUM_BC_MOVE(        K_mpint, K              ),

    ASSH_BIGNUM_BC_END(),
  };

  ASSH_ERR_GTO(assh_bignum_bytecode(c, bytecode, "MMMMNTTTTTT",
             /* M */ gr->generator, gr->prime, e_str, secret, /* N */ pv->fn,
             /* T */ gr->size, gr->size, gr->size,
                     pv->exp_n, gr->size, gr->size), err_secret);

  pv->e_str = e_str;

  /* compute exchange hash and send reply */
  ASSH_ERR_GTO(assh_kex_server_hash(s, &assh_kex_dh_server_hash,
       assh_packet_mpint_size(gr->size), &assh_hash_sha1, secret), err_secret);

  err = ASSH_OK;

 err_secret:
  ASSH_SCRATCH_FREE(c, secret);
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
      ASSH_ERR_RET(assh_kex_dh_client_send_expmod(s)
		   | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;

    case ASSH_KEX_DH_CLIENT_WAIT_F:
      if (p == NULL)
        return ASSH_OK;
      ASSH_ERR_RET(assh_kex_dh_client_wait_f(s, p, e)
		   | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;

    case ASSH_KEX_DH_CLIENT_LOOKUP_HOST_KEY_WAIT:
      ASSH_ERR_RET(ASSH_ERR_STATE | ASSH_ERRSV_FATAL);
#endif

#ifdef CONFIG_ASSH_SERVER
    case ASSH_KEX_DH_SERVER_WAIT_E:
      if (p == NULL)
        return ASSH_OK;
      ASSH_ERR_RET(assh_kex_dh_server_wait_e(s, p)
		   | ASSH_ERRSV_DISCONNECT);
      ASSH_ERR_RET(assh_kex_end(s, 1)
		   | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;
#endif
    }

  abort();
}

static assh_error_t assh_kex_dh_init(struct assh_session_s *s,
                                     size_t cipher_key_size,
                                     const struct assh_kex_dh_group_s *group)
{
  assh_error_t err;
  struct assh_kex_dh_private_s *pv;
  size_t bnl = assh_bignum_sizeof(group->size);
  size_t pvsize = sizeof(*pv);
  enum assh_kex_dh_state_e state;

  size_t exp_n = cipher_key_size * 2;

  switch (s->ctx->type)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_CLIENT: {
      state = ASSH_KEX_DH_CLIENT_INIT;
      pvsize += /* en */ + bnl /* xn */ + assh_bignum_sizeof(exp_n);
      break;
    }
#endif
#ifdef CONFIG_ASSH_SERVER
    case ASSH_SERVER:
      state = ASSH_KEX_DH_SERVER_WAIT_E;
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
  pv->group = group;
  pv->state = state;

  switch (s->ctx->type)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_CLIENT:
      pv->en = (struct assh_bignum_s*)(pv + 1);
      pv->xn = (struct assh_bignum_s*)((uint8_t*)pv->en + bnl);
      pv->host_key = NULL;
      pv->pck = NULL;

      assh_bignum_init(s->ctx, pv->en, group->size);
      assh_bignum_init(s->ctx, pv->xn, exp_n);
      break;
#endif

#ifdef CONFIG_ASSH_SERVER
    case ASSH_SERVER:
      pv->fn = (struct assh_bignum_s*)(pv + 1);
      pv->exp_n = exp_n;
      assh_bignum_init(s->ctx, pv->fn, group->size);
      break;
#endif
    }

  return ASSH_OK;
}

static ASSH_KEX_CLEANUP_FCN(assh_kex_dh_cleanup)
{
  struct assh_kex_dh_private_s *pv = s->kex_pv;

  switch (s->ctx->type)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_CLIENT:
      assh_bignum_cleanup(s->ctx, pv->en);
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

static ASSH_KEX_INIT_FCN(assh_kex_dh_group1_sha1_init)
{
  static const struct assh_kex_dh_group_s group =
    {
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

struct assh_algo_kex_s assh_kex_dh_group1_sha1 =
{
  .algo = { .name = "diffie-hellman-group1-sha1",
            .class_ = ASSH_ALGO_KEX, .safety = 10, .speed = 40 },
  .f_init = assh_kex_dh_group1_sha1_init,
  .f_cleanup = assh_kex_dh_cleanup,
  .f_process = assh_kex_dh_process,
};

static ASSH_KEX_INIT_FCN(assh_kex_dh_group14_sha1_init)
{
  static const struct assh_kex_dh_group_s group =
    {
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

struct assh_algo_kex_s assh_kex_dh_group14_sha1 =
{
  .algo = { .name = "diffie-hellman-group14-sha1",
            .class_ = ASSH_ALGO_KEX, .safety = 20, .speed = 30 },
  .f_init = assh_kex_dh_group14_sha1_init,
  .f_cleanup = assh_kex_dh_cleanup,
  .f_process = assh_kex_dh_process,
};

