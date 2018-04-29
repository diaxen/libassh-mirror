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

#include "assh_userauth_client_pv.h"

#include <assh/assh_session.h>
#include <assh/assh_packet.h>
#include <assh/assh_transport.h>
#include <assh/assh_event.h>
#include <assh/assh_sign.h>
#include <assh/assh_alloc.h>

static assh_error_t
assh_userauth_client_pck_pubkey(struct assh_session_s *s,
                                struct assh_packet_s **pout,
                                assh_bool_t second,
                                size_t extra_len)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  struct assh_key_s *pub_key = pv->pubkey.keys;
  assh_error_t err;

  size_t algo_name_len = strlen(assh_algo_name(&pv->pubkey.algo->algo));

  /* allocate a packet and append common fileds for a publickey
     request */
  size_t blob_len;
  ASSH_RET_ON_ERR(assh_key_output(s->ctx, pub_key,
           NULL, &blob_len, ASSH_KEY_FMT_PUB_RFC4253));

  ASSH_RET_ON_ERR(assh_userauth_client_pck_head(s, pout, "publickey",
                 1 + 4 + algo_name_len + 4 + blob_len + extra_len));

  /* add boolean */
  uint8_t *str;
  ASSH_ASSERT(assh_packet_add_array(*pout, 1, &str));
  *str = second;

  /* add signature algorithm name */
  uint8_t *algo_name;
  ASSH_ASSERT(assh_packet_add_string(*pout, algo_name_len, &algo_name));
  memcpy(algo_name, assh_algo_name(&pv->pubkey.algo->algo), algo_name_len);

  /* add public key blob */
  uint8_t *blob;
  ASSH_ASSERT(assh_packet_add_string(*pout, blob_len, &blob));
  ASSH_JMP_ON_ERR(assh_key_output(s->ctx, pub_key, blob, &blob_len,
                 ASSH_KEY_FMT_PUB_RFC4253), err_packet);
  assh_packet_shrink_string(*pout, blob, blob_len);

  return ASSH_OK;

 err_packet:
  assh_packet_release(*pout);
  return err;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_client_pubkey_sign_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  assert(pv->state == ASSH_USERAUTH_ST_SENT_PUBKEY_RQ_DONE);

  /* promote event processing error */
  ASSH_RET_IF_TRUE(ASSH_ERR_ERROR(inerr), inerr | ASSH_ERRSV_DISCONNECT);

  struct assh_packet_s *pout = pv->pck;
  const struct assh_event_userauth_client_sign_s *ev = &e->userauth_client.sign;

  assh_packet_shrink_string(pout, ev->sign.data, ev->sign.len);

  assh_transport_push(s, pout);
  pv->pck = NULL;

  assh_free(s->ctx, pv->pubkey.auth_data);
  pv->pubkey.auth_data = NULL;

  ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_SENT_PUBKEY_RQ);

  return ASSH_OK;
}

/* send a public key authentication probing request */
static assh_error_t
assh_userauth_client_send_pubkey(struct assh_session_s *s,
                                 struct assh_event_s *e)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  struct assh_packet_s *pout;

#ifdef CONFIG_ASSH_CLIENT_AUTH_USE_PKOK /* send a public key lookup first */
  if (pv->state != ASSH_USERAUTH_ST_SENT_PUBKEY)
    {
      ASSH_RET_ON_ERR(assh_userauth_client_pck_pubkey(s, &pout,
                     0, 0));
      assh_transport_push(s, pout);
      ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_SENT_PUBKEY);
    }
  else
#endif  /* compute and send the signature directly */
    {
      const struct assh_algo_sign_s *algo = (const void *)pv->pubkey.algo;

      size_t sign_len;
      ASSH_RET_ON_ERR(assh_sign_generate(s->ctx, algo, pv->pubkey.keys, 0,
		     NULL, NULL, &sign_len));

      ASSH_RET_ON_ERR(assh_userauth_client_pck_pubkey(s, &pout,
                     1, 4 + sign_len));

      struct assh_userauth_keys_s *k = &pv->pubkey;

      if (k->keys->private)
        {
          ASSH_JMP_ON_ERR(assh_userauth_client_send_sign(s, k, pout, sign_len),
                       err_packet);
          ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_SENT_PUBKEY_RQ);
        }
      else
        {
          e->f_done = &assh_userauth_client_pubkey_sign_done;
          e->id = ASSH_EVENT_USERAUTH_CLIENT_SIGN;

          ASSH_JMP_ON_ERR(assh_userauth_client_get_sign(s, &e->userauth_client.sign,
                                                     k, pout, sign_len), err_packet);
          ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_SENT_PUBKEY_RQ_DONE);
        }
    }

  return ASSH_OK;

 err_packet:
  assh_packet_release(pout);
  return err;
}

static ASSH_USERAUTH_CLIENT_RETRY(assh_userauth_client_pubkey_retry)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  struct assh_userauth_keys_s *k = &pv->pubkey;
  assh_error_t err;

  assh_userauth_client_key_next(s, k);

  if (k->keys == NULL)
    return ASSH_NO_DATA;

  /* some user keys are already available */
  ASSH_RETURN(assh_userauth_client_send_pubkey(s, e));
}

static ASSH_USERAUTH_CLIENT_REQ(assh_userauth_client_pubkey_req)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  struct assh_userauth_keys_s *k = &pv->pubkey;
  assh_error_t err;

  assh_userauth_client_key_get(s, k, ev->keys);

  ASSH_RET_IF_TRUE(k->keys == NULL,
               ASSH_ERR_NO_AUTH | ASSH_ERRSV_DISCONNECT);

  ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_SEND_PUBKEY);

  return ASSH_OK;
}

static ASSH_USERAUTH_CLIENT_PROCESS(assh_userauth_client_pubkey_process)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  switch (pv->state)
    {
    case ASSH_USERAUTH_ST_SEND_PUBKEY:
      ASSH_RET_IF_TRUE(p != NULL, ASSH_ERR_PROTOCOL);
      ASSH_RETURN(assh_userauth_client_send_pubkey(s, e));

    case ASSH_USERAUTH_ST_SENT_PUBKEY:
      if (p == NULL)
        return ASSH_OK;
      switch(p->head.msg)
        {
        case SSH_MSG_USERAUTH_SUCCESS:
          ASSH_RETURN(ASSH_ERR_PROTOCOL);

        case SSH_MSG_USERAUTH_PK_OK:
          ASSH_RETURN(assh_userauth_client_send_pubkey(s, e));
        }

    case ASSH_USERAUTH_ST_SENT_PUBKEY_RQ:
      if (p == NULL)
        return ASSH_OK;
      ASSH_RETURN(assh_userauth_client_default_process(s, p, e));

    default:
      ASSH_UNREACHABLE();
    }

  return ASSH_OK;
}

const struct assh_userauth_client_method_s assh_userauth_client_publickey =
{
  .name = "publickey",
  .mask = ASSH_USERAUTH_METHOD_PUBKEY,
  .f_req = &assh_userauth_client_pubkey_req,
  .f_process = &assh_userauth_client_pubkey_process,
  .f_retry = &assh_userauth_client_pubkey_retry
};

