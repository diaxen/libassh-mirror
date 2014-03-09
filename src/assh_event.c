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
#include <assh/assh_prng.h>
#include <assh/assh_service.h>
#include <assh/assh_event.h>

#include <assert.h>

static ASSH_EVENT_DONE_FCN(assh_event_random_done)
{
  return s->ctx->prng->f_feed(s->ctx, e->prng.feed.buf,
			      e->prng.feed.size);
  return ASSH_OK;
}

assh_error_t assh_event_get(struct assh_session_s *s,
			    struct assh_event_s *event)
{
  assh_error_t err;

  /* need to get some entropy for the prng */
  if (s->ctx->prng_entropy < 0)
    {
      event->id = ASSH_EVENT_PRNG_FEED;
      event->f_done = &assh_event_random_done;
      event->prng.feed.size = ASSH_MIN(-s->ctx->prng_entropy,
				       sizeof (event->prng.feed.buf));
      goto done;
    }

  event->id = ASSH_EVENT_INVALID;

  /* process the next incoming deciphered packet */
  ASSH_ERR_GTO(assh_transport_dispatch(s, event), err);

  if (event->id != ASSH_EVENT_INVALID)
    goto done;

  /* all service events have been processed, flusing done */
  if (s->tr_st >= ASSH_TR_FLUSHING)
    {
      assh_transport_state(s, ASSH_TR_DISCONNECTED);
      ASSH_ERR_RET(ASSH_ERR_DISCONNECTED);
    }

  /* run the state machine which converts output packets to enciphered
     ssh stream */
  ASSH_ERR_GTO(assh_transport_write(s, event), err);

  if (event->id != ASSH_EVENT_INVALID)
    goto done;

  /* all data has been sent, ending done */
  if (s->tr_st == ASSH_TR_ENDING)
    {
      assh_transport_state(s, ASSH_TR_DISCONNECTED);
      ASSH_ERR_RET(ASSH_ERR_DISCONNECTED);
    }

  /* run the state machine which extracts a deciphered packet from the
     input ssh stream. */
  ASSH_ERR_GTO(assh_transport_read(s, event), err);

 done:
#ifdef CONFIG_ASSH_DEBUG_EVENT
  if (event->id > 2)
    ASSH_DEBUG("ctx=%p session=%p event id=%u\n", s->ctx, s, event->id);
#endif
  return ASSH_OK;

 err:
  if (ASSH_ERR_DISCONNECT(err))
    {
#warning this FIXME reverts err to ASSH_OK
      ASSH_ERR_RET(assh_transport_disconnect(s, ASSH_ERR_DISCONNECT(err)));
      assh_transport_state(s, ASSH_TR_ENDING);
    }
  else
    {
      assh_transport_state(s, ASSH_TR_DISCONNECTED);
    }

  return err;
}

assh_error_t
assh_event_done(struct assh_session_s *s,
                struct assh_event_s *e)
{
  assh_error_t err;
  ASSH_ERR_RET(s->tr_st == ASSH_TR_DISCONNECTED ? ASSH_ERR_DISCONNECTED : 0);

#ifdef CONFIG_ASSH_DEBUG_EVENT
  if (e->id > 2)
    ASSH_DEBUG("ctx=%p session=%p event done id=%u\n", s->ctx, s, e->id);
#endif

  if (e->f_done == NULL)
    return ASSH_OK;

  if ((err = e->f_done(s, e)))
    {
      if (ASSH_ERR_DISCONNECT(err))
        {
          ASSH_ERR_RET(assh_transport_disconnect(s, ASSH_ERR_DISCONNECT(err)));
          assh_transport_state(s, ASSH_TR_ENDING);
        }
      else
        {
          assh_transport_state(s, ASSH_TR_DISCONNECTED);
        }
    }
  return err;
}

void assh_event_table_init(struct assh_event_hndl_table_s *t)
{
  unsigned int i;
  for (i = 0; i < ASSH_EVENT_COUNT; i++)
    t->table[i] = NULL;
}

void assh_event_table_register(struct assh_event_hndl_table_s *t,
			       enum assh_event_id_e id,
			       struct assh_event_hndl_s *h,
			       assh_event_hndl_func_t *f, void *ctx)
{
  struct assh_event_hndl_s **t_ = t->table + id;

  *t_ = h;
  h->f_handler = f;
  h->ctx = ctx;
}

assh_error_t
assh_event_table_run(struct assh_session_s *s,
		     struct assh_event_hndl_table_s *t, 
		     struct assh_event_s *e)
{
  assh_error_t err;

  while (1)
    {
      ASSH_ERR_RET(assh_event_get(s, e));

      struct assh_event_hndl_s *h = t->table[e->id];

      if (h == NULL)
        return ASSH_OK;
      ASSH_ERR_RET(h->f_handler(s, e, h->ctx));
      ASSH_ERR_RET(assh_event_done(s, e));
    }
}

