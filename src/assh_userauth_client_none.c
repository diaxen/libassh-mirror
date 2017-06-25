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

static ASSH_USERAUTH_CLIENT_REQ(assh_userauth_client_none_req)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  struct assh_packet_s *pout;

  ASSH_RET_ON_ERR(assh_userauth_client_pck_head(s, &pout, "none", 0));

  assh_transport_push(s, pout);

  pv->state = ASSH_USERAUTH_ST_SENT_NONE_RQ;

  return ASSH_OK;
}

const struct assh_userauth_client_method_s assh_userauth_client_none =
{
  .name = "none",
  .mask = ASSH_USERAUTH_METHOD_NONE,
  .f_req = &assh_userauth_client_none_req,
  .f_process = &assh_userauth_client_default_process,
  .f_retry = &assh_userauth_client_no_retry
};

