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

#include <assh/assh_context.h>
#include <assh/assh_transport.h>
#include <assh/assh_packet.h>
#include <assh/assh_session.h>
#include <assh/assh_kex.h>
#include <assh/assh_service.h>
#include <assh/assh_event.h>

#include <assert.h>

static ASSH_EVENT_DONE_FCN(assh_event_error_done)
{
  assert(s->last_err != 0);
  s->last_err = 0;
  return ASSH_OK;
}

assh_bool_t assh_event_get(struct assh_session_s *s,
                           struct assh_event_s *event,
                           assh_time_t time)
{
  assh_error_t err;

  s->time = time;

  if (s->last_err)
    goto err_ev;

  if (s->tr_st == ASSH_TR_CLOSED)
    return 0;

  event->id = ASSH_EVENT_INVALID;

  /* process the next incoming deciphered packet */
  ASSH_JMP_ON_ERR(assh_transport_dispatch(s, event), err);

  if (event->id != ASSH_EVENT_INVALID)
    goto done;

  /* protocol timeout */
  ASSH_JMP_IF_TRUE(s->tr_st < ASSH_TR_FIN &&
               s->deadline != 0 && s->deadline <= s->time,
               ASSH_ERR_TIMEOUT | ASSH_ERRSV_DISCONNECT, err);

  /* key re-exchange should have occured at this point */
  ASSH_JMP_IF_TRUE(s->tr_st < ASSH_TR_DISCONNECT &&
               s->kex_bytes > ASSH_REKEX_THRESHOLD + CONFIG_ASSH_MAX_PAYLOAD * 16,
               ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT, err);

  /* initiate key re-exchange */
  if (s->tr_st == ASSH_TR_SERVICE && s->kex_bytes > s->kex_max_bytes)
    {
      ASSH_JMP_ON_ERR(assh_kex_send_init(s) | ASSH_ERRSV_DISCONNECT, err);
      ASSH_SET_STATE(s, tr_st, ASSH_TR_SERVICE_KEX);
    }

  /* run the state machine which converts output packets to enciphered
     ssh stream */
  if (s->tr_st < ASSH_TR_FIN)
    {
      ASSH_JMP_ON_ERR(assh_transport_write(s, event), err);

      if (event->id != ASSH_EVENT_INVALID)
        goto done;
    }

  if (s->tr_st == ASSH_TR_DISCONNECT)
    {
      return assh_event_get(s, event, time);
      ASSH_SET_STATE(s, tr_st, ASSH_TR_FIN);
    }
  else if (s->tr_st > ASSH_TR_DISCONNECT)
    {
      /* all events have been reported, end of session. */
      ASSH_SET_STATE(s, tr_st, ASSH_TR_CLOSED);
      return 0;
    }

  /* run the state machine which extracts deciphered packets from the
     input ssh stream. */
  ASSH_JMP_ON_ERR(assh_transport_read(s, event), err);

 done:
#ifdef CONFIG_ASSH_DEBUG_EVENT
  if (event->id > 2)
    ASSH_DEBUG("ctx=%p session=%p event id=%u\n", s->ctx, s, event->id);
#endif
  return 1;

 err:
  assh_session_error(s, err);

 err_ev:
  event->id = ASSH_EVENT_ERROR;
  event->f_done = assh_event_error_done;
  event->error.code = s->last_err;
  return 1;
}

void
assh_event_done(struct assh_session_s *s,
                struct assh_event_s *e,
                assh_error_t inerr)
{
  assh_error_t err = ASSH_OK;

#ifdef CONFIG_ASSH_DEBUG_EVENT
  if (e->id > 2)
    ASSH_DEBUG("ctx=%p session=%p event done id=%u\n", s->ctx, s, e->id);
#endif

  if (s->tr_st == ASSH_TR_CLOSED)
    return;

  if (e->f_done != NULL)
    err = e->f_done(s, e, inerr);
  e->f_done = NULL;

  if (ASSH_ERR_SEVERITY(inerr) >= ASSH_ERR_SEVERITY(err))
    err = inerr | ASSH_ERR_EXTERNAL;

  if (err & 0x100)
    assh_session_error(s, err);
}

