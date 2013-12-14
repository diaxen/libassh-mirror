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


#include <assh/assh_session.h>
#include <assh/assh_context.h>
#include <assh/assh_packet.h>
#include <assh/assh_kex.h>
#include <assh/assh_queue.h>
#include <assh/assh_service.h>

assh_error_t assh_session_init(struct assh_context_s *c,
			       struct assh_session_s *s)
{
  assh_error_t err;

  ASSH_ERR_RET(c->prng == NULL ? ASSH_ERR_MISSING_ALGO : 0);

  s->ctx = c;

  switch (c->type)
    {
#ifdef CONFIG_ASSH_SERVER
    case ASSH_SERVER:
      ASSH_ERR_RET(c->host_keys == NULL ? ASSH_ERR_MISSING_KEY : 0);
      s->tr_st = ASSH_TR_KEX_INIT;      
      break;
#endif
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_CLIENT:
      s->tr_st = ASSH_TR_KEX_WAIT_REPLY;
      break;
#endif
    default:
      ASSH_ERR_RET(ASSH_ERR_NOTSUP);
    }

  s->hello_len = 0;
  s->session_id_len = 0;

  s->kex_init_local = NULL;
  s->kex_init_remote = NULL;
  s->kex_pv = NULL;

#ifdef CONFIG_ASSH_CLIENT
  s->srv_rq = NULL;
  s->srv_index = 0;
#endif
  s->srv = NULL;

  s->stream_out_st = ASSH_TR_OUT_HELLO;
  assh_queue_init(&s->out_queue);
  assh_queue_init(&s->alt_queue);
  s->stream_out_size = 0;
  s->cur_keys_out = NULL;
  s->new_keys_out = NULL;
  s->out_seq = 0;

  s->stream_in_st = ASSH_TR_IN_HELLO;
  s->stream_in_pck = NULL;
  s->stream_in_size = 0;
  s->in_pck = NULL;
  s->cur_keys_in = NULL;
  s->new_keys_in = NULL;
  s->in_seq = 0;

  c->session_count++;

  return ASSH_OK;
}

static void assh_pck_queue_cleanup(struct assh_queue_s *q)
{
  while (q->count > 0)
    {
      struct assh_queue_entry_s *e = assh_queue_front(q);
      assh_queue_remove(q, e);

      struct assh_packet_s *p = (struct assh_packet_s*)e;
      assh_packet_release(p);
    }
}

void assh_session_cleanup(struct assh_session_s *s)
{
  if (s->kex_pv != NULL)
    s->kex->f_cleanup(s);
  assert(s->kex_pv == NULL);

  if (s->srv != NULL)
    s->srv->f_cleanup(s);

  assh_packet_release(s->kex_init_local);
  assh_packet_release(s->kex_init_remote);

  assh_pck_queue_cleanup(&s->out_queue);
  assh_pck_queue_cleanup(&s->alt_queue);

  assh_kex_keys_cleanup(s, s->cur_keys_in);
  assh_kex_keys_cleanup(s, s->cur_keys_out);
  assh_kex_keys_cleanup(s, s->new_keys_in);
  assh_kex_keys_cleanup(s, s->new_keys_out);

  assh_packet_release(s->in_pck);
  assh_packet_release(s->stream_in_pck);

  s->ctx->session_count--;
}

