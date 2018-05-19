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

/* send a password authentication request */
static assh_error_t
assh_userauth_client_send_password(struct assh_session_s *s,
                                   const struct assh_cbuffer_s *password,
                                   const struct assh_cbuffer_s *new_password)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  uint8_t *bool_, *str;

  struct assh_packet_s *pout;

  size_t pw_len = 4 + password->len
    + (new_password != NULL ? 4 + new_password->len : 0);

  /* Any password with a length less than 128 bytes will result in a
     packet of the same size. */
  size_t pw_hidden_len = ASSH_MAX((size_t)pw_len, 128);

  ASSH_RET_ON_ERR(assh_userauth_client_pck_head(s, &pout, "password",
	           1 + pw_hidden_len));
  pout->padding = ASSH_PADDING_MAX;

  ASSH_ASSERT(assh_packet_add_array(pout, 1, &bool_));
  *bool_ = (new_password != NULL);

  ASSH_ASSERT(assh_packet_add_string(pout, password->len, &str));
  memcpy(str, password->str, password->len);

  if (new_password)
    {
      ASSH_ASSERT(assh_packet_add_string(pout, new_password->len, &str));
      memcpy(str, new_password->str, new_password->len);
    }

  assh_transport_push(s, pout);

  ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_SENT_PASSWORD_RQ);

  return ASSH_OK;
}

static ASSH_USERAUTH_CLIENT_REQ(assh_userauth_client_password_req)
{
  assh_error_t err;

  ASSH_RETURN(assh_userauth_client_send_password(s,
                &ev->password, NULL));
}

static ASSH_EVENT_DONE_FCN(assh_userauth_client_req_pwchange_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  const struct assh_event_userauth_client_pwchange_s *ev = &e->userauth_client.pwchange;
  assh_error_t err;

  assh_packet_release(pv->pck);
  pv->pck = NULL;

  if (!ASSH_ERR_ERROR(inerr) &&
      ev->old_password.len && ev->new_password.len)
    {
      ASSH_RET_ON_ERR(assh_userauth_client_send_password(s,
        &ev->old_password, &ev->new_password) | ASSH_ERRSV_DISCONNECT);
    }
  else
    {
      ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_PWCHANGE_SKIP);
    }

  return ASSH_OK;
}

static assh_error_t
assh_userauth_client_req_pwchange(struct assh_session_s *s,
                                  struct assh_packet_s *p,
                                  struct assh_event_s *e)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
   assh_error_t err;

  const uint8_t *end, *lang, *prompt = p->head.end;

  ASSH_RET_ON_ERR(assh_packet_check_string(p, prompt, &lang));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, lang, &end));

  struct assh_event_userauth_client_pwchange_s *ev = &e->userauth_client.pwchange;
  ev->prompt.data = prompt + 4;
  ev->prompt.len = assh_load_u32(prompt);
  ev->lang.data = lang + 4;
  ev->lang.len = assh_load_u32(lang);
  ev->old_password.len = 0;
  ev->new_password.len = 0;

  e->id = ASSH_EVENT_USERAUTH_CLIENT_PWCHANGE;
  e->f_done = assh_userauth_client_req_pwchange_done;

  assert(pv->pck == NULL);
  pv->pck = assh_packet_refinc(p);

  return ASSH_OK;
}

static ASSH_USERAUTH_CLIENT_PROCESS(assh_userauth_client_password_process)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  switch (pv->state)
    {
    case ASSH_USERAUTH_ST_SENT_PASSWORD_RQ:
      if (p == NULL)
        return ASSH_OK;

      switch(p->head.msg)
        {
        case SSH_MSG_USERAUTH_PASSWD_CHANGEREQ:
          ASSH_RETURN(assh_userauth_client_req_pwchange(s, p, e));

        default:
          ASSH_RETURN(assh_userauth_client_default_process(s, p, e));
        }

    case ASSH_USERAUTH_ST_PWCHANGE_SKIP:
      ASSH_RET_ON_ERR(assh_userauth_client_get_methods(s, e, 0));
      return ASSH_NO_DATA;

    default:
      ASSH_UNREACHABLE();
    }
}

const struct assh_userauth_client_method_s assh_userauth_client_password =
{
  .name = "password",
  .mask = ASSH_USERAUTH_METHOD_PASSWORD,
  .f_req = &assh_userauth_client_password_req,
  .f_process = &assh_userauth_client_password_process,
  .f_retry = &assh_userauth_client_no_retry
};

