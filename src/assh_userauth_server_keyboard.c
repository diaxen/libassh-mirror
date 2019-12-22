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
#include <assh/assh_alloc.h>

static ASSH_EVENT_DONE_FCN(assh_userauth_server_kbresponse_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_status_t err;

  assh_free(s->ctx, pv->keyboard_array);
  pv->keyboard_array = NULL;

  assh_packet_release(pv->pck);
  pv->pck = NULL;

  const struct assh_event_userauth_server_kbresponse_s *ev =
    &e->userauth_server.kbresponse;

  if (ASSH_STATUS(inerr))
    goto failure;

  switch (ev->result)
    {
    case ASSH_SERVER_KBSTATUS_FAILURE:
    failure:
      ASSH_RET_ON_ERR(assh_userauth_server_failure(s, NULL) | ASSH_ERRSV_DISCONNECT);
      break;
    case ASSH_SERVER_KBSTATUS_SUCCESS:
      ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_SUCCESS);
      break;
    case ASSH_SERVER_KBSTATUS_CONTINUE:
      ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_KEYBOARD_CONTINUE);
      break;
    }

  return ASSH_OK;
}

static assh_status_t
assh_userauth_server_kbresponse(struct assh_session_s *s,
                                struct assh_packet_s *p,
                                struct assh_event_s *e)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_status_t err;

  ASSH_RET_IF_TRUE(p->head.msg != SSH_MSG_USERAUTH_INFO_RESPONSE,
               ASSH_ERR_PROTOCOL);

  const uint8_t *count_ = p->head.end;
  const uint8_t *resp, *next;

  ASSH_RET_ON_ERR(assh_packet_check_array(p, count_, 4, &resp));

  size_t i, count = assh_load_u32(count_);

  if (count != pv->keyboard_count)
    ASSH_RETURN(assh_userauth_server_failure(s, e));

  struct assh_cbuffer_s *responses = NULL;

  if (count > 0)
    {

      ASSH_RET_ON_ERR(assh_alloc(s->ctx, sizeof(*responses) * count,
                              ASSH_ALLOC_INTERNAL, (void**)&responses));

      assert(pv->keyboard_array == NULL);
      pv->keyboard_array = responses;

      for (i = 0; i < count; i++)
        {
          ASSH_RET_ON_ERR(assh_packet_check_string(p, resp, &next));
          responses[i].data = resp + 4;
          responses[i].len = assh_load_u32(resp);
          resp = next;
        }

    }

  struct assh_event_userauth_server_kbresponse_s *ev =
    &e->userauth_server.kbresponse;

  ev->count = count;
  ev->responses = responses;
  ev->result = ASSH_SERVER_KBSTATUS_FAILURE;

  e->id = ASSH_EVENT_USERAUTH_SERVER_KBRESPONSE;
  e->f_done = assh_userauth_server_kbresponse_done;

  assert(pv->pck == NULL);
  pv->pck = assh_packet_refinc(p);

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_server_kbinfo_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_status_t err;

  assert(pv->state == ASSH_USERAUTH_ST_KEYBOARD_INFO);

  assh_packet_release(pv->pck);
  pv->pck = NULL;

  if (ASSH_STATUS(inerr))
    ASSH_RETURN(assh_userauth_server_failure(s, NULL)
                   | ASSH_ERRSV_DISCONNECT);

  const struct assh_event_userauth_server_kbinfo_s *ev =
    &e->userauth_server.kbinfo;

  size_t i, count = ev->count;

  assert(count <= 32);

  pv->keyboard_count = count;

  size_t name_len = ev->name.len;
  size_t ins_len = ev->instruction.len;
  size_t psize = 4 + name_len + 4 + ins_len + 4 + 4;

  for (i = 0; i < count; i++)
    psize += 4 + ev->prompts[i].len + 1;

  struct assh_packet_s *pout;
  ASSH_RET_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_USERAUTH_INFO_REQUEST,
                 psize, &pout) | ASSH_ERRSV_DISCONNECT);

  uint8_t *str;

  ASSH_ASSERT(assh_packet_add_string(pout, name_len, &str));
  memcpy(str, ev->name.str, name_len);

  ASSH_ASSERT(assh_packet_add_string(pout, ins_len, &str));
  memcpy(str, ev->instruction.str, ins_len);

  ASSH_ASSERT(assh_packet_add_string(pout, 0, NULL)); /* empty lang */

  ASSH_ASSERT(assh_packet_add_array(pout, 4, &str));
  assh_store_u32(str, count);

  for (i = 0; i < count; i++)
    {
      size_t len = ev->prompts[i].len;
      ASSH_ASSERT(assh_packet_add_string(pout, len, &str));
      memcpy(str, ev->prompts[i].str, len);

      ASSH_ASSERT(assh_packet_add_array(pout, 1, &str));
      *str = (ev->echos >> i) & 1;
    }

  assh_transport_push(s, pout);

  return ASSH_OK;
}

static assh_status_t
assh_userauth_server_kbinfo(struct assh_session_s *s,
                            struct assh_event_s *e,
                            const uint8_t *sub)
{
  struct assh_userauth_context_s *pv = s->srv_pv;

  struct assh_event_userauth_server_kbinfo_s *ev =
    &e->userauth_server.kbinfo;

  ev->username.str = pv->username;
  ev->username.len = strlen(pv->username);
  ev->service = pv->srv;
  ev->sub.data = sub + 4;
  ev->sub.len = assh_load_u32(sub);

  ev->name.len = 0;
  ev->instruction.len = 0;
  ev->echos = 0;
  ev->count = 0;
  ev->prompts = NULL;

  e->id = ASSH_EVENT_USERAUTH_SERVER_KBINFO;
  e->f_done = assh_userauth_server_kbinfo_done;

  ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_KEYBOARD_INFO);

  return ASSH_OK;
}

static ASSH_USERAUTH_SERVER_REQ(assh_userauth_server_req_kbinfo)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_status_t err;

  const uint8_t *lang = auth_data;
  const uint8_t *sub;

  ASSH_RET_ON_ERR(assh_packet_check_string(p, lang, &sub));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, sub, NULL));

  assert(pv->pck == NULL);
  pv->pck = assh_packet_refinc(p);

  ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_KEYBOARD_CONTINUE);

  ASSH_RETURN(assh_userauth_server_kbinfo(s, e, sub));
}

static ASSH_USERAUTH_SERVER_PROCESS(assh_userauth_server_kbprocess)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_status_t err;

  switch (pv->state)
    {
    case ASSH_USERAUTH_ST_KEYBOARD_INFO:
      if (p == NULL)
        return ASSH_OK;
      ASSH_RETURN(assh_userauth_server_kbresponse(s, p, e)
                     | ASSH_ERRSV_DISCONNECT);

    case ASSH_USERAUTH_ST_KEYBOARD_CONTINUE:
      ASSH_RET_ON_ERR(assh_userauth_server_kbinfo(s, e,
                     (const uint8_t *)"\x00\x00\x00\x00")
                   | ASSH_ERRSV_DISCONNECT);
      return ASSH_NO_DATA;

    default:
      ASSH_UNREACHABLE();
    }
}

const struct assh_userauth_server_method_s assh_userauth_server_keyboard =
{
  .name = ",keyboard-interactive",
  .mask = ASSH_USERAUTH_METHOD_KEYBOARD,
  .f_req = &assh_userauth_server_req_kbinfo,
  .f_process = &assh_userauth_server_kbprocess
};
