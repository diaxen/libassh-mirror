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

#define ASSH_EV_CONST /* write access to event const fields */

#include "assh_userauth_client_pv.h"

#include <assh/assh_session.h>
#include <assh/assh_packet.h>
#include <assh/assh_transport.h>
#include <assh/assh_event.h>
#include <assh/assh_sign.h>
#include <assh/assh_alloc.h>

/* allocate a packet and append common fileds for a publickey request */
static assh_status_t
assh_userauth_client_pck_hostbased(struct assh_session_s *s,
                                   struct assh_packet_s **pout,
                                   size_t *sign_len)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  struct assh_key_s *pub_key = pv->hostkey.keys;
  assh_status_t err;

  const struct assh_algo_sign_s *algo = (const void *)pv->hostkey.algo;

  size_t algo_name_len = strlen(assh_algo_name(&algo->algo));

  size_t blob_len;
  ASSH_RET_ON_ERR(assh_key_output(s->ctx, pub_key,
           NULL, &blob_len, ASSH_KEY_FMT_PUB_RFC4253));

  ASSH_RET_ON_ERR(assh_sign_generate(s->ctx, algo, pv->hostkey.keys, 0,
    	     NULL, NULL, sign_len));

  ASSH_RET_ON_ERR(assh_userauth_client_pck_head(s, pout, "hostbased",
                 4 + algo_name_len + 4 + blob_len +
                 4 + pv->hostname_len + 4 + pv->host_username_len +
                 4 + *sign_len));

  /* add signature algorithm name */
  uint8_t *str;
  ASSH_ASSERT(assh_packet_add_string(*pout, algo_name_len, &str));
  memcpy(str, assh_algo_name(&pv->hostkey.algo->algo), algo_name_len);

  /* add public key blob */
  uint8_t *blob;
  ASSH_ASSERT(assh_packet_add_string(*pout, blob_len, &blob));
  ASSH_JMP_ON_ERR(assh_key_output(s->ctx, pub_key, blob, &blob_len,
                 ASSH_KEY_FMT_PUB_RFC4253), err_packet);
  assh_packet_shrink_string(*pout, blob, blob_len);

  /* add hostname */
  ASSH_ASSERT(assh_packet_add_string(*pout, pv->hostname_len, &str));
  memcpy(str, pv->hostname, pv->hostname_len);

  /* add host username */
  ASSH_ASSERT(assh_packet_add_string(*pout, pv->host_username_len, &str));
  memcpy(str, pv->host_username, pv->host_username_len);

  return ASSH_OK;

 err_packet:
  assh_packet_release(*pout);
  return err;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_client_hostbased_sign_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_status_t err;

  /* promote event processing error */
  ASSH_RET_IF_TRUE(ASSH_STATUS(inerr), inerr | ASSH_ERRSV_DISCONNECT);

  struct assh_packet_s *pout = pv->pck;
  const struct assh_event_userauth_client_sign_s *ev = &e->userauth_client.sign;
  assh_packet_shrink_string(pout, ev->sign.data, ev->sign.len);

  assh_transport_push(s, pout);
  pv->pck = NULL;

  assh_free(s->ctx, pv->hostkey.auth_data);
  pv->hostkey.auth_data = NULL;

  return ASSH_OK;
}

/* send a public key authentication probing request */
static assh_status_t
assh_userauth_client_send_hostbased(struct assh_session_s *s,
                                    struct assh_event_s *e)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_status_t err;

  struct assh_packet_s *pout;
  size_t sign_len;

  ASSH_RET_ON_ERR(assh_userauth_client_pck_hostbased(s, &pout, &sign_len));

  struct assh_userauth_keys_s *k = &pv->hostkey;

  if (k->keys->private)
    {
      ASSH_JMP_ON_ERR(assh_userauth_client_send_sign(s, k, pout, sign_len),
                   err_packet);
    }
  else
    {
      e->f_done = &assh_userauth_client_hostbased_sign_done;
      e->id = ASSH_EVENT_USERAUTH_CLIENT_SIGN;

      ASSH_JMP_ON_ERR(assh_userauth_client_get_sign(s, &e->userauth_client.sign,
                                                 k, pout, sign_len),
                   err_packet);
    }

  ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_SENT_HOSTBASED_RQ);
  return ASSH_OK;

 err_packet:
  assh_packet_release(pout);
  return err;
}

static ASSH_USERAUTH_CLIENT_RETRY(assh_userauth_client_hostbased_retry)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  struct assh_userauth_keys_s *k = &pv->hostkey;
  assh_status_t err;

  assh_userauth_client_key_next(s, k);

  if (k->keys == NULL)
    return ASSH_NO_DATA;

  /* more keys are available */
  ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_SEND_HOSTBASED);

  ASSH_RETURN(assh_userauth_client_send_hostbased(s, e));
}

/* send a public key authentication probing request */
static ASSH_USERAUTH_CLIENT_REQ(assh_userauth_client_hostbased_req)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  struct assh_userauth_keys_s *k = &pv->hostkey;
  assh_status_t err;

  assh_userauth_client_key_get(s, k, ev->keys);

  ASSH_RET_IF_TRUE(k->keys == NULL, ASSH_ERR_NO_AUTH);

  size_t len = ev->host_name.len;
  pv->hostname_len = len;
  if (len)
    {
      ASSH_RET_IF_TRUE(len > sizeof(pv->hostname),
                   ASSH_ERR_OUTPUT_OVERFLOW);
      memcpy(pv->hostname, ev->host_name.str, len);
    }

  len = ev->host_username.len;
  pv->host_username_len = len;
  if (len)
    {
      ASSH_RET_IF_TRUE(len > sizeof(pv->host_username),
                   ASSH_ERR_OUTPUT_OVERFLOW);
      memcpy(pv->host_username, ev->host_username.str, len);
    }

  ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_SEND_HOSTBASED);

  return ASSH_OK;
}

static ASSH_USERAUTH_CLIENT_PROCESS(assh_userauth_client_hostbased_process)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_status_t err;

  switch (pv->state)
    {
    case ASSH_USERAUTH_ST_SEND_HOSTBASED:
      ASSH_RET_IF_TRUE(p != NULL, ASSH_ERR_PROTOCOL);
      ASSH_RETURN(assh_userauth_client_send_hostbased(s, e));

    case ASSH_USERAUTH_ST_SENT_HOSTBASED_RQ:
      ASSH_RETURN(assh_userauth_client_default_process(s, p, e));

    default:
      ASSH_UNREACHABLE();
    }
}

const struct assh_userauth_client_method_s assh_userauth_client_hostbased =
{
  .name = "hostbased",
  .mask = ASSH_USERAUTH_METHOD_HOSTBASED,
  .f_req = assh_userauth_client_hostbased_req,
  .f_process = assh_userauth_client_hostbased_process,
  .f_retry = &assh_userauth_client_hostbased_retry
};

