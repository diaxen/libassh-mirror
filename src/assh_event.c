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

#include <assh/assh_context.h>
#include <assh/assh_event.h>
#include <assh/assh_transport.h>
#include <assh/assh_packet.h>
#include <assh/assh_session.h>
#include <assh/assh_kex.h>
#include <assh/assh_prng.h>
#include <assh/assh_service.h>

#include <assert.h>

ASSH_EVENT_DONE_FCN(assh_event_random_done)
{
  return s->ctx->prng->f_feed(s->ctx, e->random.data, e->random.size);
}

assh_error_t assh_event_get(struct assh_session_s *s,
			    struct assh_event_s *event)
{
  assh_error_t err;

  /* need to get some entropy for the prng */
  if (s->ctx->prng_entropy < 0)
    {
      event->id = ASSH_EVENT_RANDOM;
      event->f_done = &assh_event_random_done;
      event->random.data = NULL;
      event->random.size = -s->ctx->prng_entropy;
      goto done;
    }

#ifdef CONFIG_ASSH_SERVER
  /* server initiates key exchange */
  if (s->tr_st == ASSH_TR_KEX_INIT)
    {
      s->tr_st = ASSH_TR_KEX_WAIT;
      ASSH_ERR_GTO(assh_algo_kex_send_init(s), err);
    }
#endif

  event->id = ASSH_EVENT_INVALID;

  /* process the next incoming deciphered packet */
  if (s->tr_st < ASSH_TR_ENDING && s->in_pck != NULL)
    {
      err = assh_transport_dispatch(s, s->in_pck, event);
      assh_packet_release(s->in_pck);
      s->in_pck = NULL;
      ASSH_ERR_GTO(err, err);
    }

  /* get event from running service */
  if (event->id == ASSH_EVENT_INVALID && s->srv != NULL)
    {
      ASSH_ERR_GTO(s->srv->f_process(s, NULL, event), err);
    }

#ifdef CONFIG_ASSH_CLIENT
  if (s->tr_st == ASSH_TR_SERVICE)
    {
      /* client requests next service */
      if (s->ctx->type == ASSH_CLIENT &&
          s->srv == NULL && s->srv_rq == NULL)
        ASSH_ERR_GTO(assh_service_send_request(s), err);
    }
#endif

  if (event->id != ASSH_EVENT_INVALID)
    goto done;

  /* all service events have been processed, flusing done */
  if (s->tr_st >= ASSH_TR_FLUSHING)
    {
      s->tr_st = ASSH_TR_DISCONNECTED;
      ASSH_ERR_RET(ASSH_ERR_DISCONNECTED);
    }

  /* run the state machine which converts output packets to enciphered
     ssh stream */
  switch (s->stream_out_st)
    {
    case ASSH_TR_OUT_PACKETS:
      if (s->out_queue.count == 0)
	break;
    case ASSH_TR_OUT_HELLO:
      event->id = ASSH_EVENT_WRITE;
      event->f_done = &assh_event_write_done;
      ASSH_ERR_GTO(assh_event_write(s, (const void **)&event->write.data,
                                    (size_t*)&event->write.size), err);
      goto done;

    default:
      ASSH_ERR_RET(ASSH_ERR_STATE);
    }

  /* all data has been sent, ending done */
  if (s->tr_st == ASSH_TR_ENDING)
    {
      s->tr_st = ASSH_TR_DISCONNECTED;
      ASSH_ERR_RET(ASSH_ERR_DISCONNECTED);
    }

  /* run the state machine which extracts a deciphered packet from the
     input ssh stream. */
  switch (s->stream_in_st)
    {
    case ASSH_TR_IN_HEAD:
      assert(s->in_pck == NULL);
      event->id = ASSH_EVENT_IDLE;
      event->f_done = &assh_event_read_done;
      ASSH_ERR_GTO(assh_event_read(s, (void**)&event->read.data,
                                   (size_t*)&event->read.size), err);
      goto done;

    case ASSH_TR_IN_HELLO:
    case ASSH_TR_IN_PAYLOAD:
      event->id = ASSH_EVENT_READ;
      event->f_done = &assh_event_read_done;
      ASSH_ERR_GTO(assh_event_read(s, (void**)&event->read.data,
                                   (size_t*)&event->read.size), err);
      goto done;

    default:
      ASSH_ERR_GTO(ASSH_ERR_STATE, err);
    }

 done:
#ifdef CONFIG_ASSH_DEBUG_EVENT
  ASSH_DEBUG("event id=%u\n", event->id);
#endif
  return ASSH_OK;

 err:
  if (ASSH_ERR_DISCONNECT(err))
    {
      ASSH_ERR_RET(assh_transport_disconnect(s, ASSH_ERR_DISCONNECT(err)));
      s->tr_st = ASSH_TR_ENDING;
    }
  else
    {
      s->tr_st = ASSH_TR_DISCONNECTED;
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
  ASSH_DEBUG("event done id=%u\n", e->id);
#endif

  if (e->f_done == NULL)
    return ASSH_OK;

  if ((err = e->f_done(s, e)))
    {
      if (ASSH_ERR_DISCONNECT(err))
        {
          ASSH_ERR_RET(assh_transport_disconnect(s, ASSH_ERR_DISCONNECT(err)));
          s->tr_st = ASSH_TR_ENDING;
        }
      else
        {
          s->tr_st = ASSH_TR_DISCONNECTED;
        }
    }
  return err;
}

