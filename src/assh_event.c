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
      return ASSH_OK;
    }

#ifdef CONFIG_ASSH_SERVER
  /* server initiates key exchange */
  if (s->kex_st == ASSH_KEX_INIT)
    {
      s->kex_st = ASSH_KEX_WAIT;
      ASSH_ERR_RET(assh_algo_kex_send_init(s));
    }
#endif

  event->id = ASSH_EVENT_INVALID;

  /* process the next incoming deciphered packet */
  if (s->in_packet != NULL)
    {
      err = assh_process_packet(s, s->in_packet, event);
      assh_packet_release(s->in_packet);
      s->in_packet = NULL;
      ASSH_ERR_RET(err);
    }

  /* get event from running service */
  else if (s->srv != NULL && s->kex_st == ASSH_KEX_DONE)
    {
      ASSH_ERR_RET(s->srv->f_process(s, NULL, event));
    }

#ifdef CONFIG_ASSH_CLIENT
  printf("%i %i %p %p\n", s->kex_st, s->ctx->type, s->srv, s->srv_rq);
  if (s->kex_st == ASSH_KEX_DONE)
    {
      /* client requests next service */
      if (s->ctx->type == ASSH_CLIENT &&
          s->srv == NULL && s->srv_rq == NULL)
        ASSH_ERR_RET(assh_service_send_request(s));
    }
#endif

  if (event->id != ASSH_EVENT_INVALID)
    return ASSH_OK;

  ASSH_ERR_RET(s->kex_st == ASSH_KEX_DISCONNECTED ? ASSH_ERR_DISCONNECTED : 0);

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
      ASSH_ERR_RET(assh_event_write(s, &event->write.data, &event->write.size));
      return ASSH_OK;

    default:
      ASSH_ERR_RET(ASSH_ERR_STATE);
    }

  /* run the state machine which extracts a deciphered packet from the
     input ssh stream. */
  switch (s->stream_in_st)
    {
    case ASSH_TR_IN_HEAD:
      assert(s->in_packet == NULL);
      event->id = ASSH_EVENT_IDLE;
      event->f_done = &assh_event_read_done;
      ASSH_ERR_RET(assh_event_read(s, &event->read.data, &event->read.size));
      return ASSH_OK;

    case ASSH_TR_IN_HELLO:
    case ASSH_TR_IN_PAYLOAD:
      event->id = ASSH_EVENT_READ;
      event->f_done = &assh_event_read_done;
      ASSH_ERR_RET(assh_event_read(s, &event->read.data, &event->read.size));
      return ASSH_OK;

    default:
      ASSH_ERR_RET(ASSH_ERR_STATE);
    }

  return ASSH_OK;
}

