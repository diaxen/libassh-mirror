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

#include <assh/srv_connection.h>

#include <assh/assh_service.h>
#include <assh/assh_session.h>
#include <assh/assh_packet.h>
#include <assh/assh_transport.h>
#include <assh/assh_event.h>
#include <assh/assh_queue.h>
#include <assh/assh_map.h>

ASSH_EVENT_SIZE_SASSERT(connection);

struct assh_connection_context_s
{
  enum assh_event_id_e state;

  struct assh_queue_s request_rqueue; //< global requests we have to acknowledge
  struct assh_queue_s request_lqueue; //< global requests waiting for a reply from the remote host

  struct assh_map_entry_s *channel_map; //< allocated channels

  struct assh_packet_s *pck;         //< packet kept during event processing

  uint32_t ch_id_counter;
};

/************************************************* incoming request */

assh_error_t
assh_request_reply(struct assh_request_s *rq,
                   enum assh_connection_reply_e reply,
                   const uint8_t *rsp_data,
                   size_t rsp_data_size)
{
  assh_error_t err;
  struct assh_session_s *s = rq->session;
  struct assh_connection_context_s *pv = s->srv_pv;

  ASSH_ERR_RET(s->srv != &assh_service_connection ? ASSH_ERR_SERVICE_NA : 0);
  ASSH_ERR_RET(rq->status != ASSH_REQUEST_ST_REPLY_POSTPONED ? ASSH_ERR_STATE : 0);

  struct assh_channel_s *ch = rq->ch;
  size_t size = ch == NULL ? 0 : 4;

  switch (reply)
    {
    case ASSH_CONNECTION_REPLY_FAILED:
      /* prepare failed reply packet */
      ASSH_ERR_RET(assh_packet_alloc(s->ctx, ch == NULL ? SSH_MSG_REQUEST_FAILURE
				                        : SSH_MSG_CHANNEL_FAILURE,
                                     size, &rq->reply_pck));
      if (ch != NULL)
        ASSH_ASSERT(assh_packet_add_u32(rq->reply_pck, ch->remote_id));
      rq->status = ASSH_REQUEST_ST_REPLY_READY;
      break;

    case ASSH_CONNECTION_REPLY_SUCCESS:
      /* prepare success reply packet */
      ASSH_ERR_RET(assh_packet_alloc(s->ctx, ch == NULL ? SSH_MSG_REQUEST_SUCCESS
                                                        : SSH_MSG_CHANNEL_SUCCESS,
                                     size + rsp_data_size, &rq->reply_pck));
      if (ch != NULL)
        ASSH_ASSERT(assh_packet_add_u32(rq->reply_pck, ch->remote_id));
      if (rsp_data_size > 0)
        {
          /* add request specific data to reply */
          uint8_t *data;
          ASSH_ASSERT(assh_packet_add_bytes(rq->reply_pck, rsp_data_size, &data));
          memcpy(data, rsp_data, rsp_data_size);
        }
      rq->status = ASSH_REQUEST_ST_REPLY_READY;
      break;

    case ASSH_CONNECTION_REPLY_POSTPONED:
      break;
    }

  struct assh_queue_s *q = ch == NULL ? &pv->request_rqueue : &ch->request_rqueue;

  /* send and release ready replies present on queue in the right order */
  while (q->count > 0)
    {
      struct assh_queue_entry_s *e = assh_queue_back(q);
      rq = (void*)e;
      if (rq->status != ASSH_REQUEST_ST_REPLY_READY)
        break;
      assh_transport_push(s, rq->reply_pck);
      assh_queue_remove(q, e);
      assh_free(s->ctx, rq, ASSH_ALLOC_INTERNAL);
    }

  return ASSH_OK;
}

/* event done, may send reply */
static ASSH_EVENT_DONE_FCN(assh_event_request_done)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;

  assert(s->srv == &assh_service_connection);
  ASSH_ERR_RET(pv->state != ASSH_EVENT_REQUEST ? ASSH_ERR_STATE : 0);

  /* release request packet */
  assh_packet_release(pv->pck);
  pv->pck = NULL;
  pv->state = ASSH_EVENT_INVALID;

  struct assh_request_s *rq = e->connection.request.rq;
  enum assh_connection_reply_e reply = e->connection.request.reply;

  /* acknowledge request */
  if (reply != ASSH_CONNECTION_REPLY_POSTPONED)
    {
      if (rq != NULL)
        ASSH_ERR_RET(assh_request_reply(rq, reply,
                                        e->connection.request.rsp_data.data,
                                        e->connection.request.rsp_data.size));
    }
  else
    {
      ASSH_ERR_RET(rq == NULL ? ASSH_ERR_STATE : 0);
    }

  return ASSH_OK;
}

/* setup an event from incoming request */
static assh_error_t
assh_connection_got_request(struct assh_session_s *s,
                            struct assh_packet_s *p,
                            struct assh_event_s *e,
                            assh_bool_t global)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;

  /* parse packet */
  uint8_t *type, *want_reply, *data;
  struct assh_channel_s *ch;

  /* parse packet */
  if (global)
    {
      ch = NULL;
      type = p->head.end;
    }
  else
    {
      /* lookup channel */
      uint8_t *ch_id = p->head.end;
      ASSH_ERR_RET(assh_packet_check_array(p, &ch_id, 4, &type));
      ch = (void*)assh_map_lookup(pv->channel_map, assh_load_u32(ch_id), NULL);
      ASSH_ERR_RET(ch == NULL ? ASSH_ERR_PROTOCOL : 0);

      switch (ch->status)
	{
	case ASSH_CHANNEL_ST_OPEN_SENT:
	case ASSH_CHANNEL_ST_OPEN_RECEIVED:
	case ASSH_CHANNEL_ST_CLOSED:
	  ASSH_ERR_RET(ASSH_ERR_PROTOCOL);
	case ASSH_CHANNEL_ST_OPEN:
	case ASSH_CHANNEL_ST_EOF_SENT:
	case ASSH_CHANNEL_ST_EOF_RECEIVED:
	  break;
	case ASSH_CHANNEL_ST_CLOSE_SENT:
	  /* ignore request, channel close should
	     clear all pending channel requests */
	  return ASSH_OK;
	}
    }

  ASSH_ERR_RET(assh_packet_check_string(p, type, &want_reply));
  ASSH_ERR_RET(assh_packet_check_array(p, want_reply, 1, &data));

  struct assh_request_s *rq = NULL;
  if (*want_reply)
    {
      /* allocate a new request and push on appropriate queue */
      ASSH_ERR_RET(assh_alloc(s->ctx, sizeof(*rq), ASSH_ALLOC_INTERNAL, (void**)&rq));
      assh_queue_push_front(global ? &pv->request_rqueue
			           : &ch->request_rqueue, &rq->qentry);
      rq->status = ASSH_REQUEST_ST_REPLY_POSTPONED;
      rq->session = s;
      rq->ch = ch;
    }

  /* setup event */
  e->id = ASSH_EVENT_REQUEST;
  e->f_done = assh_event_request_done;

  *(struct assh_channel_s**)&e->connection.request.ch = ch;
  *(struct assh_request_s**)&e->connection.request.rq = rq;

  struct assh_string_s *type_ = (void*)&e->connection.request.type;
  type_->str = (char*)type + 4;
  type_->len = want_reply - type - 4;

  struct assh_buffer_s *rq_data = (void*)&e->connection.request.rq_data;
  rq_data->size = p->data + p->data_size - data;
  rq_data->data = rq_data->size > 0 ? data : NULL;

  struct assh_buffer_s *rsp_data = &e->connection.request.rsp_data;
  rsp_data->data = NULL;
  rsp_data->size = 0;

  e->connection.request.reply = ASSH_CONNECTION_REPLY_FAILED;

  /* keep packet for type and rq_data buffers */
  pv->pck = assh_packet_refinc(p);

  pv->state = ASSH_EVENT_REQUEST;

  return ASSH_OK;
}

/************************************************* outgoing request */

/* send a new request */
assh_error_t assh_request(struct assh_session_s *s,
                          struct assh_channel_s *ch,
                          const char *type, size_t type_len,
                          const uint8_t *data, size_t data_len,
                          assh_bool_t want_reply,
                          struct assh_request_s **rq_)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;

  ASSH_ERR_RET(s->srv != &assh_service_connection ? ASSH_ERR_SERVICE_NA : 0);

  /* send request packet */
  struct assh_packet_s *pout;
  size_t size = 4 + type_len + 1 + 4 + data_len;

  if (ch == NULL)
    {
      ASSH_ERR_RET(assh_packet_alloc(s->ctx, SSH_MSG_GLOBAL_REQUEST, size, &pout));
    }
  else
    switch (ch->status)
      {
      case ASSH_CHANNEL_ST_OPEN_SENT:
      case ASSH_CHANNEL_ST_OPEN_RECEIVED:
	ASSH_ERR_RET(ASSH_ERR_STATE);
      case ASSH_CHANNEL_ST_CLOSED:
      case ASSH_CHANNEL_ST_CLOSE_SENT:
	ASSH_ERR_RET(ASSH_ERR_BUSY);
      case ASSH_CHANNEL_ST_OPEN:
      case ASSH_CHANNEL_ST_EOF_SENT:
      case ASSH_CHANNEL_ST_EOF_RECEIVED:
	ASSH_ERR_RET(assh_packet_alloc(s->ctx, SSH_MSG_CHANNEL_REQUEST, 4 + size, &pout));
	ASSH_ASSERT(assh_packet_add_u32(pout, ch->remote_id));  
      }

  uint8_t *str;
  ASSH_ASSERT(assh_packet_add_string(pout, type_len, &str));
  memcpy(str, type, type_len);
  ASSH_ASSERT(assh_packet_add_bytes(pout, 1, &str));
  *str = want_reply;
  ASSH_ASSERT(assh_packet_add_string(pout, data_len, &str));
  memcpy(str, data, data_len);

  assh_transport_push(s, pout);

  /* push a new entry in the request queue */
  if (want_reply)
    {
      struct assh_request_s *rq;
      ASSH_ERR_RET(assh_alloc(s->ctx, sizeof(*rq), ASSH_ALLOC_INTERNAL, (void**)&rq));
      assh_queue_push_front(ch == NULL ? &pv->request_lqueue
                                       : &ch->request_lqueue, &rq->qentry);
      rq->status = ASSH_REQUEST_ST_WAIT_REPLY;
      rq->session = s;
      rq->ch = ch;

      if (rq != NULL)
	*rq_ = rq;
    }

  return ASSH_OK;
}

/* cleanup request reply event */
static ASSH_EVENT_DONE_FCN(assh_request_reply_done)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;

  assert(s->srv == &assh_service_connection);
  ASSH_ERR_RET(pv->state != ASSH_EVENT_REQUEST_REPLY ? ASSH_ERR_STATE : 0);

  /* release packet */
  assh_packet_release(pv->pck);
  pv->pck = NULL;
  pv->state = ASSH_EVENT_INVALID;

  /* pop and release request */
  struct assh_queue_entry_s *q = assh_queue_back(&pv->request_lqueue);
  struct assh_request_s *rq = (void*)q;

  assert(e->connection.request_reply.rq == rq);

  assh_queue_remove(&pv->request_lqueue, q);
  assh_free(s->ctx, rq, ASSH_ALLOC_INTERNAL);

  return ASSH_OK;
}

/* setup an event from incoming request reply */
static assh_error_t
assh_connection_got_request_reply(struct assh_session_s *s,
                                  struct assh_packet_s *p,
                                  struct assh_event_s *e,
                                  assh_bool_t global,
                                  assh_bool_t success)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;

  /* lookup channel */
  struct assh_channel_s *ch = NULL;
  uint8_t *data = p->head.end;
  struct assh_queue_s *q = &pv->request_lqueue;
  if (!global)
    {
      uint8_t *ch_id = p->head.end;
      ASSH_ERR_RET(assh_packet_check_array(p, ch_id, 4, &data));
      ch = (void*)assh_map_lookup(pv->channel_map, assh_load_u32(ch_id), NULL);
      ASSH_ERR_RET(ch == NULL ? ASSH_ERR_PROTOCOL : 0);
      q = &ch->request_lqueue;

      // FIXME check channel status
    }

  /* get next request in queue */
  ASSH_ERR_RET(q->count == 0 ? ASSH_ERR_PROTOCOL : 0);
  struct assh_request_s *rq = (void*)assh_queue_back(q);
  ASSH_ERR_RET(rq->status != ASSH_REQUEST_ST_WAIT_REPLY ? ASSH_ERR_PROTOCOL : 0);

  /* setup event */
  pv->state = e->id = ASSH_EVENT_REQUEST_REPLY;
  e->f_done = assh_request_reply_done;

  *(struct assh_channel_s**)&e->connection.request_reply.ch = ch;
  *(struct assh_request_s**)&e->connection.request_reply.rq = rq;
  *(enum assh_connection_reply_e*)&e->connection.request_reply.reply = success
    ? ASSH_CONNECTION_REPLY_SUCCESS : ASSH_CONNECTION_REPLY_FAILED;

  struct assh_buffer_s *rsp_data = (void*)&e->connection.request_reply.rsp_data;
  rsp_data->size = success ? p->data + p->data_size - data : 0;
  rsp_data->data = rsp_data->size > 0 ? data : NULL;

  /* keep packet for response data */
  if (rsp_data->size > 0)
    pv->pck = assh_packet_refinc(p);

  return ASSH_OK;
}

/************************************************* incoming channel open */

assh_error_t
assh_channel_open_reply(struct assh_channel_s *ch,
                        enum assh_connection_reply_e reply,
                        enum assh_channel_open_reason_e reason,
			uint32_t win_size,
			uint32_t pkt_size,
                        const uint8_t *rsp_data,
                        size_t rsp_data_len)
{
  assh_error_t err;
  struct assh_session_s *s = ch->session;
  struct assh_connection_context_s *pv = s->srv_pv;

  ASSH_ERR_RET(s->srv != &assh_service_connection ? ASSH_ERR_SERVICE_NA : 0);
  ASSH_ERR_RET(ch->status != ASSH_CHANNEL_ST_OPEN_RECEIVED ? ASSH_ERR_STATE : 0);
  ASSH_ERR_RET(pkt_size < 1 ? ASSH_ERR_BAD_DATA : 0);

  struct assh_packet_s *pout;

  switch (reply)
    {
    case ASSH_CONNECTION_REPLY_FAILED:
      /* release channel object */
      ASSH_ASSERT(assh_map_remove_id(&pv->channel_map, ch->mentry.id));
      assh_free(s->ctx, ch, ASSH_ALLOC_INTERNAL);

      /* send failed reply packet */
      ASSH_ERR_RET(assh_packet_alloc(s->ctx, SSH_MSG_CHANNEL_OPEN_FAILURE, 4*4, &pout));
      ASSH_ASSERT(assh_packet_add_u32(pout, ch->remote_id));
      ASSH_ASSERT(assh_packet_add_u32(pout, reason));
      ASSH_ASSERT(assh_packet_add_string(pout, 0, NULL));
      ASSH_ASSERT(assh_packet_add_string(pout, 0, NULL));
      assh_transport_push(s, pout);
      return ASSH_OK;

    case ASSH_CONNECTION_REPLY_SUCCESS: {
      /* send confirmation reply packet */
      uint8_t *data;
      ASSH_ERR_RET(assh_packet_alloc(s->ctx, SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
                                     4*4 + rsp_data_len, &pout));

      ch->lpkt_size = ASSH_MIN(pkt_size, ASSH_MAX_PCK_PAYLOAD_SIZE - /* extended data msg fields */ 3 * 4);
      ch->lwin_size = win_size;
      ch->status = ASSH_CHANNEL_ST_OPEN;

      ASSH_ASSERT(assh_packet_add_u32(pout, ch->remote_id));
      ASSH_ASSERT(assh_packet_add_u32(pout, ch->mentry.id));
      ASSH_ASSERT(assh_packet_add_u32(pout, ch->lwin_size));
      ASSH_ASSERT(assh_packet_add_u32(pout, ch->lpkt_size));
      ASSH_ASSERT(assh_packet_add_bytes(pout, rsp_data_len, &data));
      memcpy(data, rsp_data, rsp_data_len);
      assh_transport_push(s, pout);

      return ASSH_OK;
    }

    case ASSH_CONNECTION_REPLY_POSTPONED:
      return ASSH_OK;
    }

  return ASSH_OK;
}

/* event done, reply to open */
static ASSH_EVENT_DONE_FCN(assh_connection_channel_open_done)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;

  assert(s->srv == &assh_service_connection);
  ASSH_ERR_RET(pv->state != ASSH_EVENT_CHANNEL_OPEN ? ASSH_ERR_STATE : 0);

  /* release channel open packet */
  assh_packet_release(pv->pck);
  pv->pck = NULL;
  pv->state = ASSH_EVENT_INVALID;

  struct assh_event_channel_open_s *eo = &e->connection.channel_open;
  ASSH_ERR_RET(assh_channel_open_reply(eo->ch, eo->reply, eo->reason, eo->win_size,
				eo->pkt_size, eo->rsp_data.data, eo->rsp_data.size));

  return ASSH_OK;
}

static assh_error_t
assh_connection_got_channel_open(struct assh_session_s *s,
                                 struct assh_packet_s *p,
                                 struct assh_event_s *e)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;

  /* parse packet */
  uint8_t *type = p->head.end, *data;
  uint32_t rid, wsize, msize;
  ASSH_ERR_RET(assh_packet_check_string(p, type, &data));
  ASSH_ERR_RET(assh_packet_check_array(p, data, data, &data));
  rid = assh_load_u32(data);
  ASSH_ERR_RET(assh_packet_check_array(p, data, 4, &data));
  wsize = assh_load_u32(data);
  ASSH_ERR_RET(assh_packet_check_array(p, data, 4, &data));
  msize = assh_load_u32(data);

  ASSH_ERR_RET(msize < 1 ? ASSH_ERR_PROTOCOL : 0);

  /* create channel object */
  struct assh_channel_s *ch;
  ASSH_ERR_RET(assh_alloc(s->ctx, sizeof(*ch), ASSH_ALLOC_INTERNAL, (void**)&ch));

  ch->mentry.id = pv->ch_id_counter++;
  ch->remote_id = rid;
  ch->rwin_size = wsize;
  ch->rpkt_size = msize;
  ch->status = ASSH_CHANNEL_ST_OPEN_RECEIVED;
  ch->session = s;
  assh_queue_init(&ch->request_rqueue);
  assh_queue_init(&ch->request_lqueue);

  assh_map_insert(&pv->channel_map, &ch->mentry);

  /* setup event */
  pv->state = e->id = ASSH_EVENT_CHANNEL_OPEN;
  e->f_done = assh_connection_channel_open_done;

  *(struct assh_channel_s**)&e->connection.channel_open.ch = ch;

  struct assh_string_s *type_ = (void*)&e->connection.channel_open.type;
  type_->str = (char*)type + 4;
  type_->len = assh_load_u32(type);

  e->connection.channel_open.win_size = wsize;
  e->connection.channel_open.pkt_size = msize;

  struct assh_buffer_s *rq_data = (void*)&e->connection.channel_open.rq_data;
  rq_data->size = p->data + p->data_size - data;
  rq_data->data = rq_data->size > 0 ? data : NULL;

  e->connection.channel_open.reply = ASSH_CONNECTION_REPLY_FAILED;
  e->connection.channel_open.reason = SSH_OPEN_UNKNOWN_CHANNEL_TYPE;

  struct assh_buffer_s *rsp_data = &e->connection.channel_open.rsp_data;
  rsp_data->data = NULL;
  rsp_data->size = 0;

  /* keep packet which contains request data */
  if (rq_data->size > 0)
    pv->pck = assh_packet_refinc(p);

  return ASSH_OK;
}

/************************************************* outgoing channel open */

assh_error_t
assh_channel_open(struct assh_session_s *s, const char *type, size_t type_len,
                  size_t max_pkt_size, struct assh_channel_s **channel)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;

  ASSH_ERR_RET(s->srv != &assh_service_connection ? ASSH_ERR_SERVICE_NA : 0);

  return ASSH_OK;
}

static assh_error_t
assh_connection_got_channel_open_reply(struct assh_session_s *s,
                                       struct assh_packet_s *p,
                                       struct assh_event_s *e,
                                       assh_bool_t success)
{
  return ASSH_OK;
}

/************************************************* incoming channel data */

static assh_error_t
assh_connection_got_channel_data(struct assh_session_s *s,
                                 struct assh_packet_s *p,
                                 assh_bool_t extended)
{
  return ASSH_OK;
}

static assh_error_t
assh_connection_got_channel_window_adjust(struct assh_session_s *s,
                                          struct assh_packet_s *p)
{
  return ASSH_OK;
}

/************************************************* outgoing channel data */

assh_error_t
assh_channel_data(struct assh_channel_s *channel,
                  assh_bool_t extended, uint32_t extended_type,
                  const uint8_t *data, size_t size)
{
  assh_error_t err;
  struct assh_session_s *s = channel->session;
  struct assh_connection_context_s *pv = s->srv_pv;
  ASSH_ERR_RET(s->srv != &assh_service_connection ? ASSH_ERR_SERVICE_NA : 0);

  return ASSH_OK;
}

/************************************************* incoming channel close/eof */

static assh_error_t
assh_connection_got_channel_close(struct assh_session_s *s,
                                  struct assh_packet_s *p,
                                  struct assh_event_s *e)
{
  return ASSH_OK;
}

static assh_error_t
assh_connection_got_channel_eof(struct assh_session_s *s,
                                struct assh_packet_s *p,
                                struct assh_event_s *e)
{
  return ASSH_OK;
}

/************************************************* outgoing channel close/eof */

assh_error_t
assh_channel_eof(struct assh_channel_s *channel)
{
  assh_error_t err;
  struct assh_session_s *s = channel->session;
  struct assh_connection_context_s *pv = s->srv_pv;
  ASSH_ERR_RET(s->srv != &assh_service_connection ? ASSH_ERR_SERVICE_NA : 0);

  return ASSH_OK;
}

assh_error_t
assh_channel_close(struct assh_channel_s *channel)
{
  assh_error_t err;
  struct assh_session_s *s = channel->session;
  struct assh_connection_context_s *pv = s->srv_pv;
  ASSH_ERR_RET(s->srv != &assh_service_connection ? ASSH_ERR_SERVICE_NA : 0);

  return ASSH_OK;
}

/************************************************* connection service */

/* service initialization */
static ASSH_SERVICE_INIT_FCN(assh_connection_init)
{
  struct assh_connection_context_s *pv;
  assh_error_t err;

  ASSH_ERR_RET(assh_alloc(s->ctx, sizeof(*pv),
                    ASSH_ALLOC_INTERNAL, (void**)&pv));

  pv->state = ASSH_EVENT_CONNECTION_START;

  assh_queue_init(&pv->request_rqueue);
  assh_queue_init(&pv->request_lqueue);

  pv->channel_map = NULL;
  pv->pck = NULL;
  pv->ch_id_counter = 0;

  s->srv = &assh_service_connection;
  s->srv_pv = pv;

  return ASSH_OK;
}

static void assh_connection_queue_cleanup(struct assh_session_s *s,
                                          struct assh_queue_s *q)
{
  while (q->count > 0)
    {
      struct assh_queue_entry_s *e = assh_queue_back(q);
      assh_queue_remove(q, e);
      assh_free(s->ctx, e, ASSH_ALLOC_INTERNAL);
    }
}

/* service cleanup */
static ASSH_SERVICE_CLEANUP_FCN(assh_connection_cleanup)
{
  struct assh_connection_context_s *pv = s->srv_pv;

  assh_free(s->ctx, pv, ASSH_ALLOC_INTERNAL);
  assh_packet_release(pv->pck);

  assh_connection_queue_cleanup(s, &pv->request_rqueue);
  assh_connection_queue_cleanup(s, &pv->request_lqueue);

#warning cleanup channel_map

  s->srv_pv = NULL;
  s->srv = NULL;
}

static ASSH_SERVICE_PROCESS_FCN(assh_connection_process)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;

  switch (pv->state)
    {
    case ASSH_EVENT_CONNECTION_START:
      e->id = ASSH_EVENT_CONNECTION_START;
      e->f_done = NULL;
      pv->state = ASSH_EVENT_INVALID;
      return ASSH_OK;

    case ASSH_EVENT_INVALID:
      break;

    default:
      ASSH_ERR_RET(ASSH_ERR_STATE);
    }

  if (p != NULL)
    {
      switch (p->head.msg)
        {
        case SSH_MSG_GLOBAL_REQUEST:
          err = assh_connection_got_request(s, p, e, 1);
          break;
        case SSH_MSG_REQUEST_SUCCESS:
          err = assh_connection_got_request_reply(s, p, e, 1, 1);
          break;
        case SSH_MSG_REQUEST_FAILURE:
          err = assh_connection_got_request_reply(s, p, e, 1, 0);
          break;
        case SSH_MSG_CHANNEL_OPEN:
          err = assh_connection_got_channel_open(s, p, e);
          break;
        case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
          err = assh_connection_got_channel_open_reply(s, p, e, 1);
          break;
        case SSH_MSG_CHANNEL_OPEN_FAILURE:
          err = assh_connection_got_channel_open_reply(s, p, e, 0);
          break;
        case SSH_MSG_CHANNEL_WINDOW_ADJUST:
          err = assh_connection_got_channel_window_adjust(s, p);
          break;
        case SSH_MSG_CHANNEL_DATA:
          err = assh_connection_got_channel_data(s, p, 0);
          break;
        case SSH_MSG_CHANNEL_EXTENDED_DATA:
          err = assh_connection_got_channel_data(s, p, 1);
          break;
        case SSH_MSG_CHANNEL_EOF:
          err = assh_connection_got_channel_eof(s, p, e);
          break;
        case SSH_MSG_CHANNEL_CLOSE:
          err = assh_connection_got_channel_close(s, p, e);
          break;
        case SSH_MSG_CHANNEL_REQUEST:
          err = assh_connection_got_request(s, p, e, 0);
          break;
        case SSH_MSG_CHANNEL_SUCCESS:
          err = assh_connection_got_request_reply(s, p, e, 0, 1);
          break;
        case SSH_MSG_CHANNEL_FAILURE:
          err = assh_connection_got_request_reply(s, p, e, 0, 0);
          break;
	default:
	  err = ASSH_ERR_PROTOCOL;
        }
      ASSH_ERR_RET(err);
      return ASSH_OK;
    }

//  if (s->tr_st == ASSH_TR_DISCONNECTED)
//    {
//      if (pv->request_queue.count > 0)
//        ASSH_ERR_RET(assh_request_reply(s, NULL, e, 0));
//      else if (pv->channel_queue.count > 0)
//        /* ASSH_ERR_RET(assh_connection_channel_reply(s, NULL, e, 0)) */;
//      //      else if (map.head)    return close event;
//      return ASSH_OK;
//    }

  return ASSH_OK;
}

const struct assh_service_s assh_service_connection =
{
  .name = "ssh-connection",
  .side = ASSH_CLIENT_SERVER,
  .f_init = assh_connection_init,
  .f_cleanup = assh_connection_cleanup,
  .f_process = assh_connection_process,  
};

