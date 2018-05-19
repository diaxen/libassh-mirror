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
#include <assh/assh_alloc.h>

static ASSH_USERAUTH_CLIENT_REQ(assh_userauth_client_keyboard_req)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  uint8_t *str;

  struct assh_packet_s *pout;

  size_t sub_len = ev->keyboard_sub.len;

  ASSH_RET_ON_ERR(assh_userauth_client_pck_head(s, &pout, "keyboard-interactive",
                                             4 + 4 + sub_len));

  ASSH_ASSERT(assh_packet_add_string(pout, 0, &str)); /* lang */
  ASSH_ASSERT(assh_packet_add_string(pout, sub_len, &str)); /* sub methods */
  memcpy(str, ev->keyboard_sub.str, sub_len);

  assh_transport_push(s, pout);

  ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_KEYBOARD_SENT_RQ);

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_client_keyboard_info_done)
{
  struct assh_context_s *c = s->ctx;
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  assh_packet_release(pv->pck);
  pv->pck = NULL;

  struct assh_packet_s *pout;
  const struct assh_event_userauth_client_keyboard_s *ev = &e->userauth_client.keyboard;

  size_t i, count = ASSH_ERR_ERROR(inerr) ? 0 : ev->count;

  size_t psize = 4;
  for (i = 0; i < count; i++)
    psize += 4 + ev->responses[i].len;

  ASSH_RET_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_USERAUTH_INFO_RESPONSE,
                                 ASSH_MAX(psize, 256), &pout)
               | ASSH_ERRSV_DISCONNECT);
  pout->padding = ASSH_PADDING_MAX;

  uint8_t *str;
  ASSH_ASSERT(assh_packet_add_array(pout, 4, &str));
  assh_store_u32(str, count);

  for (i = 0; i < count; i++)
    {
      size_t len = ASSH_ERR_ERROR(inerr) ? 0 : ev->responses[i].len;
      ASSH_ASSERT(assh_packet_add_string(pout, len, &str));
      if (len)
        memcpy(str, ev->responses[i].str, len);
    }

  assh_transport_push(s, pout);
  ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_KEYBOARD_SENT_INFO);

  assh_free(c, pv->keyboard_array);
  pv->keyboard_array = NULL;

  return ASSH_OK;
}

static assh_error_t
assh_userauth_client_req_keyboard_info(struct assh_session_s *s,
                                       struct assh_packet_s *p,
                                       struct assh_event_s *e)
{
  struct assh_context_s *c = s->ctx;
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  const uint8_t *name = p->head.end;
  const uint8_t *ins, *lang, *count_, *prompt, *echo;

  ASSH_RET_ON_ERR(assh_packet_check_string(p, name, &ins));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, ins, &lang));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, lang, &count_));

  ASSH_RET_ON_ERR(assh_packet_check_array(p, count_, 4, &prompt));

  size_t i, count = assh_load_u32(count_);
  ASSH_RET_IF_TRUE(count > 32, ASSH_ERR_INPUT_OVERFLOW);

  struct assh_cbuffer_s *prompts = NULL;
  uint32_t echos = 0;

  if (count > 0)
    {
      ASSH_RET_ON_ERR(assh_alloc(c, sizeof(*prompts) * count,
                              ASSH_ALLOC_INTERNAL, (void**)&prompts));

      assert(pv->keyboard_array == NULL);
      pv->keyboard_array = prompts;

      for (i = 0; i < count; i++)
        {
          ASSH_RET_ON_ERR(assh_packet_check_string(p, prompt, &echo));
          size_t len = assh_load_u32(prompt);
          ASSH_RET_IF_TRUE(len == 0, ASSH_ERR_PROTOCOL);
          prompts[i].data = prompt + 4;
          prompts[i].len = len;

          ASSH_RET_ON_ERR(assh_packet_check_array(p, echo, 1, &prompt));

          echos |= !!*echo << i;
        }
    }

  struct assh_event_userauth_client_keyboard_s *ev = &e->userauth_client.keyboard;
  ev->name.data = name + 4;
  ev->name.len = assh_load_u32(name);
  ev->instruction.data = ins + 4;
  ev->instruction.len = assh_load_u32(ins);
  ev->count = count;
  ev->echos = echos;
  ev->prompts = prompts;
  e->id = ASSH_EVENT_USERAUTH_CLIENT_KEYBOARD;
  e->f_done = &assh_userauth_client_keyboard_info_done;

  assert(pv->pck == NULL);
  pv->pck = assh_packet_refinc(p);

  return ASSH_OK;
}

static ASSH_USERAUTH_CLIENT_PROCESS(assh_userauth_client_keyboard_process)
{
  struct assh_context_s *c = s->ctx;
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  switch (pv->state)
    {
    case ASSH_USERAUTH_ST_KEYBOARD_SENT_RQ:
    case ASSH_USERAUTH_ST_KEYBOARD_SENT_INFO:
      if (p == NULL)
        return ASSH_OK;

      switch(p->head.msg)
        {
        case SSH_MSG_USERAUTH_INFO_REQUEST:
          ASSH_RETURN(assh_userauth_client_req_keyboard_info(s, p, e));

        default:
          ASSH_RETURN(assh_userauth_client_default_process(s, p, e));
        }
      break;

    default:
      ASSH_UNREACHABLE();
    }
}

const struct assh_userauth_client_method_s assh_userauth_client_keyboard =
{
  .name = "keyboard-interactive",
  .mask = ASSH_USERAUTH_METHOD_KEYBOARD,
  .f_req = &assh_userauth_client_keyboard_req,
  .f_process = &assh_userauth_client_keyboard_process,
  .f_retry = &assh_userauth_client_no_retry
};

