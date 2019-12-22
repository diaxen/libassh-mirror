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

#include "assh_userauth_server_pv.h"

#include <assh/assh_session.h>
#include <assh/assh_packet.h>
#include <assh/assh_transport.h>
#include <assh/assh_event.h>
#include <assh/assh_algo.h>
#include <assh/assh_key.h>

static ASSH_EVENT_DONE_FCN(assh_userauth_server_userkey_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_status_t err;

  const struct assh_event_userauth_server_userkey_s *ev =
    &e->userauth_server.userkey;

  switch (pv->state)
    {
    case ASSH_USERAUTH_ST_PUBKEY_PKOK: {      /* may need to send PK_OK */
      ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_WAIT_RQ);

      if (ASSH_STATUS(inerr) || !ev->found)
        break;

      /* alloc packet */
      size_t algo_name_len = strlen(pv->algo_name->name);

      size_t blob_len;
      ASSH_RET_ON_ERR(assh_key_output(s->ctx, pv->pub_key,
                     NULL, &blob_len, ASSH_KEY_FMT_PUB_RFC4253) | ASSH_ERRSV_DISCONNECT);

      struct assh_packet_s *pout;
      ASSH_RET_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_USERAUTH_PK_OK,
                     4 + algo_name_len + 4 + blob_len, &pout) | ASSH_ERRSV_DISCONNECT);

      /* add sign algorithm name */
      uint8_t *algo_name;
      ASSH_ASSERT(assh_packet_add_string(pout, algo_name_len, &algo_name));
      memcpy(algo_name, pv->algo_name->name, algo_name_len);

      /* add public key blob */
      uint8_t *blob;
      ASSH_ASSERT(assh_packet_add_string(pout, blob_len, &blob));
      ASSH_JMP_ON_ERR(assh_key_output(s->ctx, pv->pub_key,
                     blob, &blob_len, ASSH_KEY_FMT_PUB_RFC4253)
		   | ASSH_ERRSV_DISCONNECT, err_packet);
      assh_packet_shrink_string(pout, blob, blob_len);

      assh_transport_push(s, pout);
      ASSH_SET_STATE(pv, pubkey_state, ASSH_USERAUTH_PUBKEY_FOUND);

      return ASSH_OK;
     err_packet:
      assh_packet_release(pout);
      return err;
    }

    case ASSH_USERAUTH_ST_PUBKEY_VERIFY: {

      if (ASSH_STATUS(inerr) || !ev->found)
        {
          assh_packet_release(pv->pck);
          pv->pck = NULL;
          break;
        }

      ASSH_RET_ON_ERR(assh_userauth_server_sign_check(s, pv->pck, pv->sign)
                   | ASSH_ERRSV_DISCONNECT);

      ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_SUCCESS);

      assh_packet_release(pv->pck);
      pv->pck = NULL;

      return ASSH_OK;
    }

    default:
      ASSH_UNREACHABLE();
    }

  ASSH_RETURN(assh_userauth_server_failure(s, NULL)
                 | ASSH_ERRSV_DISCONNECT);
}

/* handle public key request packet */
static ASSH_USERAUTH_SERVER_REQ(assh_userauth_server_req_pubkey)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_status_t err;

  const uint8_t *second = auth_data;
  const uint8_t *algo_name, *pub_blob, *sign;

  ASSH_RET_ON_ERR(assh_packet_check_array(p, second, 1, &algo_name));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, algo_name, &pub_blob));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, pub_blob, &sign));

  const struct assh_algo_s *algo;
  struct assh_key_s *pub_key = NULL;

  ASSH_RET_ON_ERR(assh_userauth_server_get_key(s, algo_name, pub_blob,
                 &algo, &pub_key, &pv->algo_name));

  if (ASSH_STATUS(err) == ASSH_NO_DATA)
    ASSH_RETURN(assh_userauth_server_failure(s, e));

  /* test if the key has been previously found in the list of authorized user keys. */
  assh_bool_t new_key = (pv->pubkey_state == ASSH_USERAUTH_PUBKEY_NONE ||
                         !assh_key_cmp(s->ctx, pub_key, pv->pub_key, 1));

  if (new_key)
    {
      assh_key_flush(s->ctx, &pv->pub_key);
      pv->pub_key = pub_key;
      pv->algo = (void*)algo;
      ASSH_SET_STATE(pv, pubkey_state, ASSH_USERAUTH_PUBKEY_NEW);
    }
  else
    {
      assh_key_drop(s->ctx, &pub_key);
    }

  /* the packet contains a signature to check */
  if (*second)
    {
      ASSH_RET_ON_ERR(assh_packet_check_string(p, sign, NULL));

      if (pv->pubkey_state == ASSH_USERAUTH_PUBKEY_FOUND)
        {
          ASSH_RET_ON_ERR(assh_userauth_server_sign_check(s, p, sign));
          ASSH_RETURN(assh_userauth_server_success(s, e));
        }

      assert(pv->pck == NULL);
      pv->pck = assh_packet_refinc(p);
      pv->sign = sign;

      ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_PUBKEY_VERIFY);
    }
  else
    {
      if (pv->pubkey_state == ASSH_USERAUTH_PUBKEY_FOUND)
        return ASSH_OK;

      ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_PUBKEY_PKOK);
    }

  struct assh_event_userauth_server_userkey_s *ev =
    &e->userauth_server.userkey;

  ev->username.str = pv->username;
  ev->username.len = strlen(pv->username);
  ev->service = pv->srv;
  ev->pub_key = pv->pub_key;
  ev->found = 0;

  /* return an event to lookup the key in the list of authorized user keys */
  e->id = ASSH_EVENT_USERAUTH_SERVER_USERKEY;
  e->f_done = assh_userauth_server_userkey_done;

  return ASSH_OK;
}

const struct assh_userauth_server_method_s assh_userauth_server_publickey =
{
  .name = ",publickey",
  .mask = ASSH_USERAUTH_METHOD_PUBKEY,
  .f_req = &assh_userauth_server_req_pubkey
};
