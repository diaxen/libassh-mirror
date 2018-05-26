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

static assh_error_t
assh_userauth_server_pwchange(struct assh_session_s *s,
                              const struct assh_event_s *e)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  const struct assh_event_userauth_server_password_s *ev =
    &e->userauth_server.password;

  size_t prompt_len = ev->change_prompt.len;
  size_t lang_len = ev->change_lang.len;
  struct assh_packet_s *pout;

  ASSH_RET_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_USERAUTH_PASSWD_CHANGEREQ,
                 4 + prompt_len + 4 + lang_len, &pout));

  uint8_t *str;
  ASSH_ASSERT(assh_packet_add_string(pout, prompt_len, &str));
  if (prompt_len)
    memcpy(str, ev->change_prompt.str, prompt_len);

  ASSH_ASSERT(assh_packet_add_string(pout, lang_len, &str));
  if (lang_len)
    memcpy(str, ev->change_lang.str, lang_len);

  assh_transport_push(s, pout);

  ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_PASSWORD_WAIT_CHANGE);

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_server_password_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  assert(pv->state == ASSH_USERAUTH_ST_PASSWORD);

  assh_packet_release(pv->pck);
  pv->pck = NULL;

  const struct assh_event_userauth_server_password_s *ev =
    &e->userauth_server.password;

  if (ASSH_ERR_ERROR(inerr))
    goto failure;

  switch (ev->result)
    {
    case ASSH_SERVER_PWSTATUS_FAILURE:
    failure:
      ASSH_RET_ON_ERR(assh_userauth_server_failure(s, NULL) | ASSH_ERRSV_DISCONNECT);
      break;
    case ASSH_SERVER_PWSTATUS_SUCCESS:
      ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_SUCCESS);
      break;
    case ASSH_SERVER_PWSTATUS_CHANGE:
      ASSH_RET_ON_ERR(assh_userauth_server_pwchange(s, e) | ASSH_ERRSV_DISCONNECT);
      break;
    }

  return ASSH_OK;
}

/* handle password request packet */
static ASSH_USERAUTH_SERVER_REQ(assh_userauth_server_req_password)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  const uint8_t *pwchange = auth_data;
  const uint8_t *password, *new_password;

  ASSH_RET_ON_ERR(assh_packet_check_array(p, pwchange, 1, &password));

  ASSH_RET_ON_ERR(assh_packet_check_string(p, password, &new_password));

  struct assh_event_userauth_server_password_s *ev =
    &e->userauth_server.password;

  ev->username.str = pv->username;
  ev->username.len = strlen(pv->username);
  ev->service = pv->srv;
  ev->password.data = password + 4;
  ev->password.len = assh_load_u32(password);

  if (*pwchange)
    {
      ASSH_RET_ON_ERR(assh_packet_check_string(p, new_password, NULL));
      ev->new_password.data = new_password + 4;
      ev->new_password.len = assh_load_u32(new_password);
    }
  else if (pv->state == ASSH_USERAUTH_ST_PASSWORD_WAIT_CHANGE)
    {
      ASSH_RETURN(assh_userauth_server_failure(s, e));
    }
  else
    {
      ev->new_password.len = 0;
    }

  /* report a password checking event */
  ev->result = ASSH_SERVER_PWSTATUS_FAILURE;
  ev->change_prompt.len = 0;
  ev->change_lang.len = 0;

  e->id = ASSH_EVENT_USERAUTH_SERVER_PASSWORD;
  e->f_done = assh_userauth_server_password_done;

  ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_PASSWORD);

  assert(pv->pck == NULL);
  pv->pck = assh_packet_refinc(p);

  return ASSH_OK;
}

const struct assh_userauth_server_method_s assh_userauth_server_password =
{
  .name = ",password",
  .mask = ASSH_USERAUTH_METHOD_PASSWORD,
  .f_req = &assh_userauth_server_req_password
};
