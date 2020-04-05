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

static ASSH_EVENT_DONE_FCN(assh_userauth_server_hostbased_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_status_t err;

  assert(pv->state == ASSH_USERAUTH_ST_HOSTBASED_VERIFY);

  const struct assh_event_userauth_server_hostbased_s *ev =
    &e->userauth_server.hostbased;

  if (ASSH_STATUS(inerr) || !ev->found)
    {
      assh_packet_release(pv->pck);
      pv->pck = NULL;

      ASSH_RET_ON_ERR(assh_userauth_server_failure(s, NULL)
                   | ASSH_ERRSV_DISCONNECT);
    }
  else
    {
      ASSH_RET_ON_ERR(assh_userauth_server_sign_check(s, pv->pck, pv->sign)
                   | ASSH_ERRSV_DISCONNECT);

      ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_SUCCESS);

      assh_packet_release(pv->pck);
      pv->pck = NULL;
    }

  return ASSH_OK;
}

static ASSH_USERAUTH_SERVER_REQ(assh_userauth_server_req_hostbased)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_status_t err;

  const uint8_t *algo_name = auth_data;
  const uint8_t *pub_blob, *hostname, *husername, *sign;

  ASSH_RET_ON_ERR(assh_packet_check_string(p, algo_name, &pub_blob));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, pub_blob, &hostname));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, hostname, &husername));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, husername, &sign));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, sign, NULL));

  const struct assh_algo_sign_s *sa;
  struct assh_key_s *pub_key = NULL;

  ASSH_RET_ON_ERR(assh_userauth_server_get_key(s, algo_name, pub_blob,
                 &sa, &pub_key, NULL));

  if (ASSH_STATUS(err) == ASSH_NO_DATA)
    ASSH_RETURN(assh_userauth_server_failure(s, e));

  pv->sign_algo = sa;
  pv->pub_key = pub_key;
  pv->pck = assh_packet_refinc(p);
  pv->sign = sign;

  struct assh_event_userauth_server_hostbased_s *ev =
    &e->userauth_server.hostbased;

  ev->username.str = pv->username;
  ev->username.len = strlen(pv->username);
  ev->service = pv->srv;
  ev->host_key = pub_key;
  ev->hostname.data = hostname + 4;
  ev->hostname.len = assh_load_u32(hostname);
  ev->host_username.data = husername + 4;
  ev->host_username.len = assh_load_u32(husername);
  ev->found = 0;

  e->id = ASSH_EVENT_USERAUTH_SERVER_HOSTBASED;
  e->f_done = assh_userauth_server_hostbased_done;

  ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_HOSTBASED_VERIFY);

  return err;
}

const struct assh_userauth_server_method_s assh_userauth_server_hostbased =
{
  .name = ",hostbased",
  .mask = ASSH_USERAUTH_METHOD_HOSTBASED,
  .f_req = &assh_userauth_server_req_hostbased
};

