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

static ASSH_EVENT_DONE_FCN(assh_event_error_done)
{
  assert(ASSH_ERR_ERROR(s->last_err) != ASSH_OK);
  s->last_err = ASSH_OK;
  return ASSH_OK;
}

assh_bool_t assh_event_get(struct assh_session_s *s,
                           struct assh_event_s *e,
                           assh_time_t time)
{
  assh_error_t err;

  s->time = time;

  assert(s->event_done);

  if (ASSH_ERR_ERROR(s->last_err) != ASSH_OK)
    goto err_event;        /* report an event for the pending error */

  switch (s->tr_st)
    {
    case ASSH_TR_IDENT:
    case ASSH_TR_KEX_INIT:
    case ASSH_TR_KEX_WAIT:
    case ASSH_TR_KEX_SKIP:
    case ASSH_TR_KEX_RUNNING:
    case ASSH_TR_NEWKEY:
    case ASSH_TR_SERVICE:
    case ASSH_TR_SERVICE_KEX:

      /* check protocol timeout */
      ASSH_JMP_IF_TRUE(s->deadline != 0 && s->deadline <= s->time,
                   ASSH_ERR_TIMEOUT | ASSH_ERRSV_DISCONNECT, err);

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
      goto got_event;

    case ASSH_TR_DISCONNECT:

      e->id = ASSH_EVENT_INVALID;

      /* run service, get last events */
      ASSH_JMP_ON_ERR(assh_service_loop(s, NULL, e), err);
      if (e->id != ASSH_EVENT_INVALID)
        goto got_event;

      /* or, write disconnect packets as ssh stream */
      ASSH_JMP_ON_ERR(assh_transport_write(s, e), err);
      if (e->id != ASSH_EVENT_INVALID)
        goto got_event;

      /* or, close session */
      ASSH_SET_STATE(s, tr_st, ASSH_TR_CLOSED);
      return 0;

    case ASSH_TR_FIN:

      e->id = ASSH_EVENT_INVALID;

      /* run service, get last events */
      ASSH_JMP_ON_ERR(assh_service_loop(s, NULL, e), err);
      if (e->id != ASSH_EVENT_INVALID)
        goto got_event;

      /* or, close session */
      ASSH_SET_STATE(s, tr_st, ASSH_TR_CLOSED);

    case ASSH_TR_CLOSED:
      return 0;
    }

  ASSH_UNREACHABLE();

 err:
  assh_session_error(s, err);

 err_event:
  e->id = ASSH_EVENT_ERROR;
  e->f_done = assh_event_error_done;
  e->error.code = s->last_err;

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

#ifndef NDEBUG
  s->event_done = 1;
#endif

  if (ASSH_ERR_SEVERITY(inerr) >= ASSH_ERR_SEVERITY(err))
    err = inerr | ASSH_ERR_EXTERNAL;

  if (err & 0x100)
    assh_session_error(s, err);
}

