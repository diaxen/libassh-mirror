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

#define ASSH_EV_CONST /* write access to event const fields */

#include <assh/assh_kex.h>
#include <assh/assh_session.h>
#include <assh/assh_packet.h>
#include <assh/assh_transport.h>
#include <assh/assh_bignum.h>
#include <assh/assh_sign.h>
#include <assh/assh_event.h>
#include <assh/assh_alloc.h>

#include <assh/hash_sha1.h>

#include <string.h>
#include <stdlib.h>

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
  struct assh_bignum_s *kn;

  union {
#ifdef CONFIG_ASSH_SERVER
    struct {
      struct assh_bignum_s *fn;
      uint8_t *e_str;
    };
#endif
#ifdef CONFIG_ASSH_CLIENT
    struct {
      struct assh_bignum_s *en;
      struct assh_key_s *host_key;
      uint8_t *f_str;
    };
#endif
  };
};

static assh_error_t assh_kex_dh_check_pub(struct assh_context_s *c,
                                          struct assh_bignum_s *pub,
                                          struct assh_bignum_s *p)
{
  assh_error_t err;

//  uint_fast16_t a = assh_bignum_popcount(p);
//  uint_fast16_t b = assh_bignum_popcount(pub);
//
//  ASSH_CHK_RET(a > b + 64 || XXX);

#warning check dh public key

  return ASSH_OK;
}

#ifdef CONFIG_ASSH_CLIENT
static assh_error_t assh_kex_dh_client_send_expmod(struct assh_session_s *s)
{
  struct assh_kex_dh_private_s *pv = s->kex_pv;
  const struct assh_kex_dh_group_s *gr = pv->group;
  struct assh_context_s *c = s->ctx;
  assh_error_t err;

  /* diffie hellman stuff */
  ASSH_ERR_RET(assh_bignum_rand(c, pv->kn, ASSH_PRNG_QUALITY_EPHEMERAL_KEY)
	       | ASSH_ERRSV_DISCONNECT);

  ASSH_BIGNUM_ALLOC(c, gn, gr->size, ASSH_ERRSV_DISCONNECT, err_);
  ASSH_BIGNUM_ALLOC(c, pn, gr->size, ASSH_ERRSV_DISCONNECT, err_gn);

  ASSH_ERR_GTO(assh_bignum_from_mpint(gn, NULL, gr->generator)
	       | ASSH_ERRSV_DISCONNECT, err_pn);
  ASSH_ERR_GTO(assh_bignum_from_mpint(pn, NULL, gr->prime)
	       | ASSH_ERRSV_DISCONNECT, err_pn);

  ASSH_ERR_GTO(assh_bignum_expmod(pv->en, gn, pv->kn, pn)
	       | ASSH_ERRSV_DISCONNECT, err_pn);

  /* send a packet containing e */
  struct assh_packet_s *p;
  ASSH_ERR_GTO(assh_packet_alloc(c, SSH_MSG_KEX_DH_REQUEST,
                 assh_bignum_mpint_size(pv->en), &p)
	       | ASSH_ERRSV_DISCONNECT, err_pn);

  ASSH_ERR_GTO(assh_packet_add_mpint(p, pv->en)
	       | ASSH_ERRSV_DISCONNECT, err_p);

  assh_transport_push(s, p);
  err = ASSH_OK;
  goto err_pn;

 err_p:
  assh_packet_release(p);
 err_pn:
  ASSH_BIGNUM_FREE(c, pn);
 err_gn:
  ASSH_BIGNUM_FREE(c, gn);
 err_:
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

static assh_error_t assh_kex_dh_client_wait_f(struct assh_session_s *s,
					      struct assh_packet_s *p)
{
  struct assh_kex_dh_private_s *pv = s->kex_pv;
  const struct assh_kex_dh_group_s *gr = pv->group;
  struct assh_context_s *c = s->ctx;
  assh_error_t err;

  ASSH_CHK_RET(p->head.msg != SSH_MSG_KEX_DH_REPLY, ASSH_ERR_PROTOCOL
	       | ASSH_ERRSV_DISCONNECT);

  uint8_t *ks_str = p->head.end;
  uint8_t *f_str, *h_str, *end;

  ASSH_ERR_RET(assh_packet_check_string(p, ks_str, &f_str)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_string(p, f_str, &h_str)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_string(p, h_str, &end)
	       | ASSH_ERRSV_DISCONNECT);

  /* diffie hellman stuff */
  ASSH_BIGNUM_ALLOC(c, fn, gr->size, ASSH_ERRSV_DISCONNECT, err_);

  ASSH_ERR_GTO(assh_bignum_from_mpint(fn, NULL, f_str)
	       | ASSH_ERRSV_DISCONNECT, err_fn);

  ASSH_BIGNUM_ALLOC(c, gn, gr->size, ASSH_ERRSV_DISCONNECT, err_fn);
  ASSH_BIGNUM_ALLOC(c, pn, gr->size, ASSH_ERRSV_DISCONNECT, err_gn);

  ASSH_ERR_GTO(assh_bignum_from_mpint(gn, NULL, gr->generator)
	       | ASSH_ERRSV_DISCONNECT, err_pn);
  ASSH_ERR_GTO(assh_bignum_from_mpint(pn, NULL, gr->prime)
	       | ASSH_ERRSV_DISCONNECT, err_pn);

  ASSH_ERR_GTO(assh_kex_dh_check_pub(c, fn, pn), err_pn);

  ASSH_BIGNUM_ALLOC(c, kn, gr->size, ASSH_ERRSV_DISCONNECT, err_pn);

  ASSH_ERR_GTO(assh_bignum_expmod(kn, fn, pv->kn, pn)
	       | ASSH_ERRSV_DISCONNECT, err_kn);

  ASSH_ERR_GTO(assh_bignum_copy(pv->kn, kn)
	       | ASSH_ERRSV_DISCONNECT, err_kn);

#ifdef CONFIG_ASSH_DEBUG_KEX
  assh_bignum_print(stderr, "K", pv->kn);
#endif

  pv->f_str = f_str;

  size_t l = assh_bignum_mpint_size(pv->kn);
  ASSH_SCRATCH_ALLOC(c, uint8_t, secret, l, ASSH_ERRSV_CONTINUE, err_kn);
  ASSH_ERR_GTO(assh_bignum_to_mpint(pv->kn, secret), err_secret);

  ASSH_ERR_GTO(assh_kex_client_hash(s, &assh_kex_dh_client_hash,
                                    &assh_hash_sha1, &pv->host_key,
                                    secret, ks_str, h_str)
               | ASSH_ERRSV_DISCONNECT, err_kn);

  err = ASSH_OK;

 err_secret:
  ASSH_SCRATCH_FREE(c, secret);
 err_kn:
  ASSH_BIGNUM_FREE(c, kn);
 err_pn:
  ASSH_BIGNUM_FREE(c, pn);
 err_gn:
  ASSH_BIGNUM_FREE(c, gn);
 err_fn:
  ASSH_BIGNUM_FREE(c, fn);
 err_:
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

  ASSH_ERR_GTO(assh_packet_check_string(p, e_str, NULL)
	       | ASSH_ERRSV_DISCONNECT, err_);

  ASSH_BIGNUM_ALLOC(c, en, gr->size, ASSH_ERRSV_DISCONNECT, err_);
  ASSH_ERR_GTO(assh_bignum_from_mpint(en, NULL, e_str)
	       | ASSH_ERRSV_DISCONNECT, err_en);

  /* generate ephemeral key pair */
  ASSH_BIGNUM_ALLOC(c, xn, gr->size, ASSH_ERRSV_DISCONNECT, err_en);
  ASSH_BIGNUM_ALLOC(c, fn, gr->size, ASSH_ERRSV_DISCONNECT, err_xn);
  ASSH_BIGNUM_ALLOC(c, gn, gr->size, ASSH_ERRSV_DISCONNECT, err_fn);
  ASSH_BIGNUM_ALLOC(c, pn, gr->size, ASSH_ERRSV_DISCONNECT, err_gn);

  ASSH_ERR_GTO(assh_bignum_rand(c, xn, ASSH_PRNG_QUALITY_EPHEMERAL_KEY)
	       | ASSH_ERRSV_DISCONNECT, err_pn);

  ASSH_ERR_GTO(assh_bignum_from_mpint(gn, NULL, gr->generator)
	       | ASSH_ERRSV_DISCONNECT, err_pn);
  ASSH_ERR_GTO(assh_bignum_from_mpint(pn, NULL, gr->prime)
	       | ASSH_ERRSV_DISCONNECT, err_pn);

  ASSH_ERR_GTO(assh_kex_dh_check_pub(c, en, pn), err_pn);

  ASSH_ERR_GTO(assh_bignum_expmod(fn, gn, xn, pn)
	       | ASSH_ERRSV_DISCONNECT, err_pn);

  /* compute shared secret */
  ASSH_ERR_GTO(assh_bignum_expmod(pv->kn, en, xn, pn)
	       | ASSH_ERRSV_DISCONNECT, err_pn);

  pv->e_str = e_str;
  pv->fn = fn;

  ASSH_SCRATCH_ALLOC(c, uint8_t, secret, assh_bignum_mpint_size(pv->kn),
                     ASSH_ERRSV_CONTINUE, err_pn);
  ASSH_ERR_GTO(assh_bignum_to_mpint(pv->kn, secret), err_secret);

  /* compute exchange hash and send reply */
  ASSH_ERR_GTO(assh_kex_server_hash(s, &assh_kex_dh_server_hash,
      assh_bignum_mpint_size(fn), &assh_hash_sha1, secret), err_secret);

  err = ASSH_OK;

 err_secret:
  ASSH_SCRATCH_FREE(c, secret);
 err_pn:
  ASSH_BIGNUM_FREE(c, pn);
 err_gn:
  ASSH_BIGNUM_FREE(c, gn);
 err_fn:
  ASSH_BIGNUM_FREE(c, fn);
 err_xn:
  ASSH_BIGNUM_FREE(c, xn);
 err_en:
  ASSH_BIGNUM_FREE(c, en);
 err_:
  return err;
}
#endif

#ifdef CONFIG_ASSH_CLIENT
static ASSH_EVENT_DONE_FCN(assh_kex_dh_host_key_lookup_done)
{
  struct assh_kex_dh_private_s *pv = s->kex_pv;
  assh_error_t err;

  ASSH_CHK_RET(pv->state != ASSH_KEX_DH_CLIENT_LOOKUP_HOST_KEY_WAIT,
               ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);

  ASSH_ERR_RET(assh_kex_end(s, e->kex.hostkey_lookup.accept)
	       | ASSH_ERRSV_DISCONNECT);
  return ASSH_OK;
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
      pv->state = ASSH_KEX_DH_CLIENT_WAIT_F;
      return ASSH_OK;

    case ASSH_KEX_DH_CLIENT_WAIT_F:
      if (p == NULL)
        return ASSH_OK;
      ASSH_ERR_RET(assh_kex_dh_client_wait_f(s, p)
		   | ASSH_ERRSV_DISCONNECT);
      pv->state = ASSH_KEX_DH_CLIENT_LOOKUP_HOST_KEY_WAIT;

      /* return an host key lookup event */
      e->id = ASSH_EVENT_KEX_HOSTKEY_LOOKUP;
      e->f_done = assh_kex_dh_host_key_lookup_done;
      e->done_pv = pv;
      e->kex.hostkey_lookup.key = pv->host_key;
      e->kex.hostkey_lookup.accept = 0;
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
                                     const struct assh_kex_dh_group_s *group)
{
  assh_error_t err;
  struct assh_kex_dh_private_s *pv;
  size_t bnl = assh_bignum_sizeof(group->size);
  size_t pvsize = sizeof(*pv) /* kn */ + bnl;
  enum assh_kex_dh_state_e state;

  switch (s->ctx->type)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_CLIENT:
      state = ASSH_KEX_DH_CLIENT_INIT;
      pvsize += /* en */ + bnl;
      break;
#endif
#ifdef CONFIG_ASSH_SERVER
    case ASSH_SERVER:
      state = ASSH_KEX_DH_SERVER_WAIT_E;
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
  pv->kn = (struct assh_bignum_s*)(pv + 1);

  ASSH_ERR_GTO(assh_bignum_init(s->ctx, pv->kn, group->size)
	       | ASSH_ERRSV_DISCONNECT, err_pv);

#ifdef CONFIG_ASSH_CLIENT
  if (s->ctx->type == ASSH_CLIENT)
    {
      pv->en = (struct assh_bignum_s*)((uint8_t*)pv->kn + bnl);
      pv->host_key = NULL;

      ASSH_ERR_GTO(assh_bignum_init(s->ctx, pv->en, group->size)
                   | ASSH_ERRSV_DISCONNECT, err_kn);
    }
#endif

  return ASSH_OK;
#ifdef CONFIG_ASSH_CLIENT
 err_kn:
  assh_bignum_cleanup(s->ctx, pv->kn);
#endif
 err_pv:
  assh_free(s->ctx, pv, ASSH_ALLOC_KEY);
  s->kex_pv = NULL;
  return err;
}

static ASSH_KEX_CLEANUP_FCN(assh_kex_dh_cleanup)
{
  struct assh_kex_dh_private_s *pv = s->kex_pv;

#ifdef CONFIG_ASSH_CLIENT
  if (s->ctx->type == ASSH_CLIENT)
    {
      assh_bignum_cleanup(s->ctx, pv->en);
      assh_key_flush(s->ctx, &pv->host_key);
    }
#endif

  assh_bignum_cleanup(s->ctx, pv->kn);

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
      "\x1e\x77\x8b\x1a\xf7\x6d\x50\x08\x0d\x39\xed\x82\xcb\xc8\x68\x6e",
    };

  return assh_kex_dh_init(s, &group);
}

struct assh_algo_kex_s assh_kex_dh_group1_sha1 =
{
  .algo = { .name = "diffie-hellman-group1-sha1", .class_ = ASSH_ALGO_KEX, .safety = 30, .speed = 50 },
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

  return assh_kex_dh_init(s, &group);
}

struct assh_algo_kex_s assh_kex_dh_group14_sha1 =
{
  .algo = { .name = "diffie-hellman-group14-sha1", .class_ = ASSH_ALGO_KEX, .safety = 60, .speed = 20 },
  .f_init = assh_kex_dh_group14_sha1_init,
  .f_cleanup = assh_kex_dh_cleanup,
  .f_process = assh_kex_dh_process,
};

