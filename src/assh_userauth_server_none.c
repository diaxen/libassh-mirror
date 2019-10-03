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

#include "assh_userauth_server_pv.h"

#include <assh/assh_session.h>
#include <assh/assh_packet.h>
#include <assh/assh_transport.h>
#include <assh/assh_event.h>

static ASSH_EVENT_DONE_FCN(assh_userauth_server_none_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_status_t err;

  const struct assh_event_userauth_server_none_s *ev =
    &e->userauth_server.none;

  if (ASSH_STATUS(inerr) || !ev->accept)
    ASSH_RET_ON_ERR(assh_userauth_server_failure(s, NULL) | ASSH_ERRSV_DISCONNECT);
  else
    ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_SUCCESS);

  return ASSH_OK;
}

static ASSH_USERAUTH_SERVER_REQ(assh_userauth_server_req_none)
{
  struct assh_userauth_context_s *pv = s->srv_pv;

  struct assh_event_userauth_server_none_s *ev =
    &e->userauth_server.none;

  ev->username.str = pv->username;
  ev->username.len = strlen(pv->username);
  ev->service = pv->srv;
  ev->accept = 0;

  e->id = ASSH_EVENT_USERAUTH_SERVER_NONE;
  e->f_done = assh_userauth_server_none_done;

  return ASSH_OK;
}

const struct assh_userauth_server_method_s assh_userauth_server_none =
{
  .name = ",none",
  .mask = ASSH_USERAUTH_METHOD_NONE,
  .f_req = &assh_userauth_server_req_none
};

