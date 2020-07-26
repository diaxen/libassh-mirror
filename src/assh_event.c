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

#define ASSH_PV
#define ASSH_EV_CONST /* write access to event const fields */

#include <assh/assh_context.h>
#include <assh/assh_transport.h>
#include <assh/assh_packet.h>
#include <assh/assh_session.h>
#include <assh/assh_kex.h>
#include <assh/assh_service.h>
#include <assh/assh_event.h>

static ASSH_EVENT_DONE_FCN(assh_event_error_done)
{
  assert(ASSH_STATUS(s->last_err) != ASSH_OK);
  s->last_err = ASSH_OK;
  return ASSH_OK;
}

assh_bool_t assh_event_get(struct assh_session_s *s,
                           struct assh_event_s *e,
                           assh_time_t time)
{
  assh_status_t err;

  s->time = time;

  while (s->tr_st != ASSH_TR_CLOSED)
    {
      assert(s->event_done);

      if (ASSH_STATUS(s->last_err) != ASSH_OK)
        goto err_event;        /* report an event for the pending error */

      e->id = ASSH_EVENT_INVALID;

      /* process the next input packet if any and run kex or service. */
      ASSH_JMP_ON_ERR(assh_transport_dispatch(s, e), err);
      if (e->id != ASSH_EVENT_INVALID)
        goto got_event;

      /* or, write output packets as ssh stream. */
      ASSH_JMP_ON_ERR(assh_transport_write(s, e), err);
      if (e->id != ASSH_EVENT_INVALID)
        goto got_event;

      /* or, request and process some input ssh stream. */
      ASSH_JMP_ON_ERR(assh_transport_read(s, e), err);
      if (e->id != ASSH_EVENT_INVALID)
        goto got_event;

      if (s->tr_st == ASSH_TR_DISCONNECT)
        {
          ASSH_SET_STATE(s, tr_st, ASSH_TR_CLOSED);
          break;
        }

      /* one more iteration so that service can report disconnection
         related events. */
      ASSH_SET_STATE(s, tr_st, ASSH_TR_DISCONNECT);
    }

  return 0;

 err:
  assh_session_error(s, err);

 err_event:
  e->id = ASSH_EVENT_SESSION_ERROR;
  e->f_done = assh_event_error_done;
  e->session.error.code = s->last_err;

 got_event:
#ifndef NDEBUG
  s->event_done = 0;
#endif
#ifdef CONFIG_ASSH_DEBUG_EVENT
  if (e->id > 2)
    ASSH_DEBUG("ctx=%p session=%p event id=%u\n", s->ctx, s, e->id);
#endif

  return 1;
}

void
assh_event_done(struct assh_session_s *s,
                struct assh_event_s *e,
                enum assh_status_e inerr)
{
#ifdef CONFIG_ASSH_DEBUG_EVENT
  if (e->id > 2)
    ASSH_DEBUG("ctx=%p session=%p event done id=%u\n", s->ctx, s, e->id);
#endif

  if (s->tr_st == ASSH_TR_CLOSED)
    return;

  if (e->f_done != NULL)
    assh_session_error(s, e->f_done(s, e, ASSH_STATUS(inerr)));
  e->f_done = NULL;

#ifndef NDEBUG
  s->event_done = 1;
#endif
}

