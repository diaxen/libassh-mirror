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

#include <assh/assh_connection.h>

#include <assh/assh_service.h>
#include <assh/assh_session.h>
#include <assh/assh_packet.h>
#include <assh/assh_transport.h>
#include <assh/assh_event.h>
#include <assh/assh_queue.h>
#include <assh/assh_map.h>
#include <assh/assh_alloc.h>

ASSH_EVENT_SIZE_SASSERT(connection);

enum assh_connection_state_e
{
  ASSH_CONNECTION_ST_IDLE,
  ASSH_CONNECTION_ST_EVENT_REQUEST,
  ASSH_CONNECTION_ST_EVENT_REQUEST_ABORT,
  ASSH_CONNECTION_ST_EVENT_REQUEST_REPLY,
  ASSH_CONNECTION_ST_EVENT_CHANNEL_OPEN,
  ASSH_CONNECTION_ST_EVENT_CHANNEL_OPEN_REPLY,
  ASSH_CONNECTION_ST_EVENT_CHANNEL_DATA,
  ASSH_CONNECTION_ST_EVENT_CHANNEL_CLOSE,
  ASSH_CONNECTION_ST_EVENT_CHANNEL_EOF,
  ASSH_CONNECTION_ST_FIN,
};

struct assh_connection_context_s
{
  struct assh_queue_s request_rqueue; //< global requests we have to acknowledge
  struct assh_queue_s request_lqueue; //< global requests waiting for a reply from the remote host

  struct assh_map_entry_s *channel_map; //< allocated channels

  struct assh_packet_s *pck;          //< packet kept during event processing
  struct assh_queue_s closing_queue;  //< closing channels with some pending requests left

  uint32_t ch_id_counter;
  enum assh_connection_state_e state:8;

  /** bytes left to transfer from the partialy handled
      ASSH_CONNECTION_ST_EVENT_CHANNEL_DATA event. The associated
      incoming data packet is in the pck field. */
  uint32_t in_data_left:24;
};

struct assh_request_s
{
  struct assh_queue_entry_s qentry;

  struct assh_session_s *session;
  struct assh_channel_s *ch;
  struct assh_packet_s *reply_pck;
  union {
    void *pv;
    uintptr_t pvi;
  };
  enum assh_request_status_e status:8;
};

ASSH_FIRST_FIELD_ASSERT(assh_request_s, qentry);

struct assh_channel_s
{
  union {
    /** channel queue entry, valid when the channel is waiting for close. */
    struct assh_queue_entry_s qentry;
    /** channel map entry, valid when the channel is open. */
    struct assh_map_entry_s mentry;
  };

  struct assh_session_s *session;
  struct assh_packet_s *data_pck;
  union {
    void *pv;
    uintptr_t pvi;
  };

  struct assh_queue_s request_rqueue; //< requests we have to acknowledge
  struct assh_queue_s request_lqueue; //< requests waiting for a reply from the remote host

  uint32_t remote_id;
  uint32_t rpkt_size;		//< remote packet size
  uint32_t lpkt_size;		//< local packet size
  uint32_t lwin_size;		//< local window size

  uint32_t rwin_left;           //< remote window bytes left
  uint32_t lwin_left;           //< local window bytes left

  enum assh_channel_status_e status:8;
};

ASSH_FIRST_FIELD_ASSERT(assh_channel_s, qentry);
ASSH_FIRST_FIELD_ASSERT(assh_channel_s, mentry);

void assh_request_set_pv(struct assh_request_s *rq, void *pv)
{
  rq->pv = pv;
}

void * assh_request_pv(const struct assh_request_s *rq)
{
  return rq->pv;
}

void assh_request_set_pvi(struct assh_request_s *rq, uintptr_t pv)
{
  rq->pvi = pv;
}

uintptr_t assh_request_pvi(const struct assh_request_s *rq)
{
  return rq->pvi;
}

enum assh_request_status_e
assh_request_status(struct assh_request_s *rq)
{
  return rq->status;
}

struct assh_channel_s *
assh_request_channel(const struct assh_request_s *rq)
{
  return rq->ch;
}

struct assh_session_s *
assh_request_session(const struct assh_request_s *rq)
{
  return rq->session;
}

void assh_channel_set_pv(struct assh_channel_s *ch, void *pv)
{
  ch->pv = pv;
}

void * assh_channel_pv(const struct assh_channel_s *ch)
{
  return ch->pv;
}

void assh_channel_set_pvi(struct assh_channel_s *ch, uintptr_t pv)
{
  ch->pvi = pv;
}

uintptr_t assh_channel_pvi(const struct assh_channel_s *ch)
{
  return ch->pvi;
}

struct assh_session_s *
assh_channel_session(const struct assh_channel_s *ch)
{
  return ch->session;
}

enum assh_channel_status_e
assh_channel_status(const struct assh_channel_s *ch)
{
  return ch->status;
}

void assh_channel_set_win_size(struct assh_channel_s *ch,
                               uint32_t win_size)
{
  ch->lwin_size = ASSH_MAX(win_size, ch->lpkt_size * 2);
}

void assh_channel_get_win_size(const struct assh_channel_s *ch,
                               uint32_t *local, uint32_t *remote)
{
  if (local != NULL)
    *local = ch->lwin_left;
  if (remote != NULL)
    *remote = ch->rwin_left;
}

void assh_channel_get_pkt_size(const struct assh_channel_s *ch,
                               uint32_t *local, uint32_t *remote)
{
  if (local != NULL)
    *local = ch->lpkt_size;
  if (remote != NULL)
    *remote = ch->rpkt_size;
}

static uint32_t
assh_channel_next_id(struct assh_connection_context_s *pv)
{
  uint32_t id;

  do {
    id = pv->ch_id_counter++;
  } while (assh_map_lookup(&pv->channel_map, id, NULL) != NULL);

  return id;
}

static void assh_request_queue_cleanup(struct assh_session_s *s,
				       struct assh_queue_s *q)
{
  while (!assh_queue_isempty(q))
    {
      struct assh_queue_entry_s *rqe = assh_queue_back(q);
      struct assh_request_s *rq = (void*)rqe;

      assh_packet_release(rq->reply_pck);

      assh_queue_remove(rqe);
      assh_free(s->ctx, rqe);
    }
}

static void assh_channel_cleanup(struct assh_channel_s *ch)
{
  struct assh_session_s *s = ch->session;

  assh_request_queue_cleanup(s, &ch->request_rqueue);
  assh_request_queue_cleanup(s, &ch->request_lqueue);
  assh_packet_release(ch->data_pck);

  assh_free(s->ctx, ch);  
}

static void assh_channel_queue_cleanup(struct assh_session_s *s,
				       struct assh_queue_s *q)
{
  while (!assh_queue_isempty(q))
    {
      struct assh_queue_entry_s *che = assh_queue_back(q);
      struct assh_channel_s *ch = (void*)che;

      assh_queue_remove(che);
      assh_channel_cleanup(ch);
    }
}

/************************************************* incoming request */

static void assh_request_dequeue(struct assh_session_s *s,
                                 struct assh_channel_s *ch)
{
  struct assh_connection_context_s *pv = s->srv_pv;
  struct assh_queue_s *q = ch == NULL ? &pv->request_rqueue : &ch->request_rqueue;

  /* send and release ready replies present on queue in the right order */
  while (!assh_queue_isempty(q))
    {
      struct assh_queue_entry_s *rqe = assh_queue_back(q);
      struct assh_request_s *rq = (void*)rqe;
      if (rq->status != ASSH_REQUEST_ST_REPLY_READY)
        return;
      assh_transport_push(s, rq->reply_pck);
      rq->reply_pck = NULL;
      assh_queue_remove(rqe);
      assh_free(s->ctx, rq);
    }
}

assh_error_t
assh_request_failed_reply(struct assh_request_s *rq)
{
  assh_error_t err;
  struct assh_session_s *s = rq->session;
  struct assh_connection_context_s *pv = s->srv_pv;

  assert(s->srv == &assh_service_connection);
  assert(pv->state == ASSH_CONNECTION_ST_IDLE);
  assert(rq->status == ASSH_REQUEST_ST_REPLY_POSTPONED);

  /* prepare failed reply packet */
  struct assh_channel_s *ch = rq->ch;

  if (ch != NULL)
    {
      switch (ch->status)
	{
	case ASSH_CHANNEL_ST_OPEN_SENT:
	case ASSH_CHANNEL_ST_OPEN_RECEIVED:
	case ASSH_CHANNEL_ST_CLOSE_CALLED:
	case ASSH_CHANNEL_ST_CLOSE_CALLED_CLOSING:
        case ASSH_CHANNEL_ST_OPEN_SENT_FORCE_CLOSE:
	case ASSH_CHANNEL_ST_OPEN_RECEIVED_FORCE_CLOSE:
          ASSH_UNREACHABLE("call not allowed in current state");

	case ASSH_CHANNEL_ST_OPEN:
	case ASSH_CHANNEL_ST_EOF_SENT:
	case ASSH_CHANNEL_ST_EOF_RECEIVED:
	  break;

        case ASSH_CHANNEL_ST_EOF_CLOSE:
        case ASSH_CHANNEL_ST_FORCE_CLOSE:
	case ASSH_CHANNEL_ST_CLOSING:
          /* unable to send a reply for this event after exchanging
             close packets with the remote host. */
	  return ASSH_NO_DATA;
	}

      ASSH_JMP_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_CHANNEL_FAILURE,
		     4, &rq->reply_pck) | ASSH_ERRSV_CONTINUE, err);
      ASSH_ASSERT(assh_packet_add_u32(rq->reply_pck, ch->remote_id));
    }
  else
    {
      ASSH_JMP_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_REQUEST_FAILURE,
                     0, &rq->reply_pck) | ASSH_ERRSV_CONTINUE, err);
    }

  rq->status = ASSH_REQUEST_ST_REPLY_READY;
  assh_request_dequeue(s, ch);

  return ASSH_OK;
 err:
  return assh_session_error(s, err);
}

assh_error_t
assh_request_success_reply(struct assh_request_s *rq,
                           const uint8_t *rsp_data,
                           size_t rsp_data_size)
{
  assh_error_t err;
  struct assh_session_s *s = rq->session;
  struct assh_connection_context_s *pv = s->srv_pv;

  assert(s->srv == &assh_service_connection);
  assert(pv->state == ASSH_CONNECTION_ST_IDLE);
  assert(rq->status == ASSH_REQUEST_ST_REPLY_POSTPONED);

  /* prepare success reply packet */
  struct assh_channel_s *ch = rq->ch;

  if (ch != NULL)
    {
      switch (ch->status)
	{
	case ASSH_CHANNEL_ST_OPEN_SENT:
	case ASSH_CHANNEL_ST_OPEN_RECEIVED:
	case ASSH_CHANNEL_ST_CLOSE_CALLED:
	case ASSH_CHANNEL_ST_CLOSE_CALLED_CLOSING:
        case ASSH_CHANNEL_ST_OPEN_SENT_FORCE_CLOSE:
	case ASSH_CHANNEL_ST_OPEN_RECEIVED_FORCE_CLOSE:
          ASSH_UNREACHABLE("call not allowed in current state");

	case ASSH_CHANNEL_ST_OPEN:
	case ASSH_CHANNEL_ST_EOF_SENT:
	case ASSH_CHANNEL_ST_EOF_RECEIVED:
	  break;

        case ASSH_CHANNEL_ST_EOF_CLOSE:
        case ASSH_CHANNEL_ST_FORCE_CLOSE:
	case ASSH_CHANNEL_ST_CLOSING:
          /* unable to send a reply for this event after exchanging
             close packets with the remote host. */
	  return ASSH_NO_DATA;
	}

      ASSH_RET_IF_TRUE(rsp_data_size > 0,
		   ASSH_ERR_OUTPUT_OVERFLOW | ASSH_ERRSV_CONTINUE);

      ASSH_JMP_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_CHANNEL_SUCCESS,
                     4, &rq->reply_pck) | ASSH_ERRSV_CONTINUE, err);

      ASSH_ASSERT(assh_packet_add_u32(rq->reply_pck, ch->remote_id));
    }
  else
    {
      ASSH_JMP_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_REQUEST_SUCCESS,
                     rsp_data_size, &rq->reply_pck) | ASSH_ERRSV_CONTINUE, err);
      /* add request specific data to the reply */
      uint8_t *data;
      ASSH_ASSERT(assh_packet_add_array(rq->reply_pck, rsp_data_size, &data));
      memcpy(data, rsp_data, rsp_data_size);
    }

  rq->status = ASSH_REQUEST_ST_REPLY_READY;
  assh_request_dequeue(s, ch);

  return ASSH_OK;
 err:
  return assh_session_error(s, err);
}

/* event done, may send a reply */
static ASSH_EVENT_DONE_FCN(assh_event_request_done)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;

  assert(s->srv == &assh_service_connection);
  assert(pv->state == ASSH_CONNECTION_ST_EVENT_REQUEST);

  /* release request packet */
  assh_packet_release(pv->pck);
  pv->pck = NULL;
  pv->state = ASSH_CONNECTION_ST_IDLE;

  const struct assh_event_request_s *ev =
    &e->connection.request;

  struct assh_request_s *rq = ev->rq;

  if (ASSH_ERR_ERROR(inerr))
    goto failure;

  /* acknowledge request */
  switch (ev->reply)
    {
    case ASSH_CONNECTION_REPLY_SUCCESS:
      if (rq == NULL)
        return ASSH_OK;
      ASSH_RETURN(assh_request_success_reply(rq,
                      ev->rsp_data.data,
                      ev->rsp_data.size)
		     | ASSH_ERRSV_DISCONNECT);
      break;
    case ASSH_CONNECTION_REPLY_FAILED:
    failure:
      if (rq == NULL)
        return ASSH_OK;
      ASSH_RETURN(assh_request_failed_reply(rq)
                    | ASSH_ERRSV_DISCONNECT);
      break;
    case ASSH_CONNECTION_REPLY_POSTPONED:
      assert(rq != NULL);
      return ASSH_OK;

    default:
      ASSH_UNREACHABLE("unexpected event value");
    }
}

/* setup an event from incoming request */
static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_connection_got_request(struct assh_session_s *s,
                            struct assh_packet_s *p,
                            struct assh_event_s *e,
                            assh_bool_t global)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;

  /* parse packet */
  const uint8_t *type, *want_reply, *data;
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
      uint32_t ch_id = -1;
      ASSH_RET_ON_ERR(assh_packet_check_u32(p, &ch_id, p->head.end, &type));
      ch = (void*)assh_map_lookup(&pv->channel_map, ch_id, NULL);
      ASSH_RET_IF_TRUE(ch == NULL, ASSH_ERR_PROTOCOL);

      switch (ch->status)
	{
	case ASSH_CHANNEL_ST_OPEN_SENT:
	case ASSH_CHANNEL_ST_OPEN_RECEIVED:
	  ASSH_RETURN(ASSH_ERR_PROTOCOL);

	case ASSH_CHANNEL_ST_OPEN:
	case ASSH_CHANNEL_ST_EOF_SENT:
	case ASSH_CHANNEL_ST_EOF_RECEIVED:
	  break;

        case ASSH_CHANNEL_ST_EOF_CLOSE:
	case ASSH_CHANNEL_ST_CLOSE_CALLED:
	  /* ignore request; our channel close packet will clear all
             pending requests on the remote side. */
	  return ASSH_OK;

	case ASSH_CHANNEL_ST_CLOSING:
	case ASSH_CHANNEL_ST_CLOSE_CALLED_CLOSING:
        case ASSH_CHANNEL_ST_FORCE_CLOSE:
        case ASSH_CHANNEL_ST_OPEN_SENT_FORCE_CLOSE:
	case ASSH_CHANNEL_ST_OPEN_RECEIVED_FORCE_CLOSE:
          /* This channel id has been removed from the channel map
             when the close packet was received. */
          ASSH_UNREACHABLE("internal error");
	}
    }

  ASSH_RET_ON_ERR(assh_packet_check_string(p, type, &want_reply));
  ASSH_RET_ON_ERR(assh_packet_check_array(p, want_reply, 1, &data));

  struct assh_request_s *rq = NULL;
  if (*want_reply)
    {
      /* allocate a new request and push on appropriate queue */
      ASSH_RET_ON_ERR(assh_alloc(s->ctx, sizeof(*rq), ASSH_ALLOC_INTERNAL, (void**)&rq));
      assh_queue_push_front(global ? &pv->request_rqueue
			           : &ch->request_rqueue, &rq->qentry);
      rq->status = ASSH_REQUEST_ST_REPLY_POSTPONED;
      rq->session = s;
      rq->ch = ch;
      rq->reply_pck = NULL;
    }

  struct assh_event_request_s *ev =
    &e->connection.request;

  /* setup event */
  e->id = ASSH_EVENT_REQUEST;
  e->f_done = assh_event_request_done;

  ev->ch = ch;
  ev->rq = rq;

  struct assh_cbuffer_s *type_ = &ev->type;
  type_->str = (char*)type + 4;
  type_->len = want_reply - type - 4;

  struct assh_cbuffer_s *rq_data = &ev->rq_data;
  rq_data->size = p->data + p->data_size - data;
  rq_data->data = rq_data->size > 0 ? (uint8_t*)data : NULL;

  struct assh_cbuffer_s *rsp_data = &ev->rsp_data;
  rsp_data->data = NULL;
  rsp_data->size = 0;

  ev->reply = ASSH_CONNECTION_REPLY_FAILED;

  /* keep packet for type and rq_data buffers */
  pv->pck = assh_packet_refinc(p);

  pv->state = ASSH_CONNECTION_ST_EVENT_REQUEST;

  return ASSH_OK;
}

/************************************************* outgoing request */

/* send a new request */
assh_error_t assh_request(struct assh_session_s *s,
                          struct assh_channel_s *ch,
                          const char *type, size_t type_len,
                          const uint8_t *data, size_t data_len,
                          struct assh_request_s **rq_)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;

  assert(s->srv == &assh_service_connection);
  assert(pv->state == ASSH_CONNECTION_ST_IDLE);

  /* prepare request packet */
  struct assh_packet_s *pout;
  size_t size = 4 + type_len + 1 + 4 + data_len;

  if (s->tr_st >= ASSH_TR_DISCONNECT)
    return ASSH_NO_DATA;

  if (ch == NULL)
    {
      ASSH_JMP_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_GLOBAL_REQUEST, size, &pout)
		   | ASSH_ERRSV_CONTINUE, err);
    }
  else
    switch (ch->status)
      {
      case ASSH_CHANNEL_ST_OPEN_SENT:
      case ASSH_CHANNEL_ST_OPEN_RECEIVED:
      case ASSH_CHANNEL_ST_OPEN_SENT_FORCE_CLOSE:
      case ASSH_CHANNEL_ST_OPEN_RECEIVED_FORCE_CLOSE:
      case ASSH_CHANNEL_ST_FORCE_CLOSE:
      case ASSH_CHANNEL_ST_CLOSE_CALLED:
      case ASSH_CHANNEL_ST_CLOSE_CALLED_CLOSING:
        ASSH_UNREACHABLE("call not allowed in current state");

      case ASSH_CHANNEL_ST_EOF_CLOSE:
      case ASSH_CHANNEL_ST_CLOSING:
	return ASSH_NO_DATA;

      case ASSH_CHANNEL_ST_OPEN:
      case ASSH_CHANNEL_ST_EOF_SENT:
      case ASSH_CHANNEL_ST_EOF_RECEIVED:
	ASSH_JMP_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_CHANNEL_REQUEST, 4 + size, &pout)
		     | ASSH_ERRSV_CONTINUE, err);
	ASSH_ASSERT(assh_packet_add_u32(pout, ch->remote_id));  
      }

  uint8_t *str;
  ASSH_ASSERT(assh_packet_add_string(pout, type_len, &str));
  memcpy(str, type, type_len);
  ASSH_ASSERT(assh_packet_add_array(pout, 1, &str));
  *str = (rq_ != NULL);
  ASSH_ASSERT(assh_packet_add_array(pout, data_len, &str));
  memcpy(str, data, data_len);

  struct assh_request_s *rq = NULL;

  /* push a new entry in the request queue */
  if (rq_ != NULL)
    {
      ASSH_JMP_ON_ERR(assh_alloc(s->ctx, sizeof(*rq), ASSH_ALLOC_INTERNAL, (void**)&rq)
		   | ASSH_ERRSV_CONTINUE, err_pkt);
      assh_queue_push_front(ch == NULL ? &pv->request_lqueue
                                       : &ch->request_lqueue, &rq->qentry);
      rq->status = ASSH_REQUEST_ST_WAIT_REPLY;
      rq->session = s;
      rq->ch = ch;
      rq->reply_pck = NULL;
      *rq_ = rq;
    }

  assh_transport_push(s, pout);

  return ASSH_OK;

 err_pkt:
  assh_packet_release(pout);
 err:
  return assh_session_error(s, err);
}

/* cleanup request reply event */
static ASSH_EVENT_DONE_FCN(assh_event_request_reply_done)
{
  struct assh_connection_context_s *pv = s->srv_pv;

  assert(s->srv == &assh_service_connection);
  assert(pv->state == ASSH_CONNECTION_ST_EVENT_REQUEST_REPLY);

  /* release packet */
  assh_packet_release(pv->pck);
  pv->pck = NULL;
  pv->state = ASSH_CONNECTION_ST_IDLE;

  const struct assh_event_request_reply_s *ev =
    &e->connection.request_reply;

  /* pop and release request */
  struct assh_channel_s *ch = ev->ch;
  struct assh_queue_s *q = ch == NULL
    ? &pv->request_lqueue : &ch->request_lqueue;

  struct assh_queue_entry_s *rqe = assh_queue_back(q);
  struct assh_request_s *rq = (void*)rqe;
  assert(ev->rq == rq);

  assh_queue_remove(rqe);
  assh_free(s->ctx, rq);

  return ASSH_OK;
}

/* pop the next unreplied requests and report a reply failed event */
static assh_bool_t assh_request_reply_flush(struct assh_session_s *s,
					    struct assh_channel_s *ch,
					    struct assh_event_s *e)
{
  struct assh_connection_context_s *pv = s->srv_pv;
  struct assh_queue_s *q = ch == NULL
    ? &pv->request_lqueue : &ch->request_lqueue;

  if (assh_queue_isempty(q))
    return 0;

  struct assh_request_s *rq = (void*)assh_queue_back(q);

  struct assh_event_request_reply_s *ev =
    &e->connection.request_reply;

  e->id = ASSH_EVENT_REQUEST_REPLY;
  e->f_done = assh_event_request_reply_done;

  ev->ch = ch;
  ev->rq = rq;
  ev->reply = ASSH_CONNECTION_REPLY_CLOSED;

  struct assh_cbuffer_s *rsp_data = &ev->rsp_data;
  rsp_data->size = 0;
  rsp_data->data = NULL;

  pv->state = ASSH_CONNECTION_ST_EVENT_REQUEST_REPLY;

  return 1;
}

/* cleanup request abort event */
static ASSH_EVENT_DONE_FCN(assh_event_request_abort_done)
{
  struct assh_connection_context_s *pv = s->srv_pv;

  assert(s->srv == &assh_service_connection);
  assert(pv->state == ASSH_CONNECTION_ST_EVENT_REQUEST_ABORT);

  pv->state = ASSH_CONNECTION_ST_IDLE;

  const struct assh_event_request_abort_s *ev =
    &e->connection.request_abort;

  /* pop and release request */
  struct assh_channel_s *ch = ev->ch;
  struct assh_queue_s *q = ch == NULL
    ? &pv->request_rqueue : &ch->request_rqueue;

  struct assh_queue_entry_s *rqe = assh_queue_back(q);
  struct assh_request_s *rq = (void*)rqe;
  assert(ev->rq == rq);

  assh_queue_remove(rqe);
  assh_free(s->ctx, rq);

  return ASSH_OK;
}

/* pop the next unreplied requests and report a reply failed event */
static assh_bool_t
assh_request_abort_flush(struct assh_session_s *s,
                         struct assh_channel_s *ch,
                         struct assh_event_s *e)
{
  struct assh_connection_context_s *pv = s->srv_pv;
  struct assh_queue_s *q = ch == NULL
    ? &pv->request_rqueue : &ch->request_rqueue;

  while (!assh_queue_isempty(q))
    {
      struct assh_queue_entry_s *rqe = assh_queue_back(q);
      struct assh_request_s *rq = (void*)rqe;

      if (rq->status != ASSH_REQUEST_ST_REPLY_POSTPONED)
        {
          assh_packet_release(rq->reply_pck);

          assh_queue_remove(rqe);
          assh_free(s->ctx, rqe);
        }
      else
        {
          struct assh_event_request_abort_s *ev =
            &e->connection.request_abort;

          e->id = ASSH_EVENT_REQUEST_ABORT;
          e->f_done = assh_event_request_abort_done;

          ev->ch = ch;
          ev->rq = rq;
          pv->state = ASSH_CONNECTION_ST_EVENT_REQUEST_ABORT;

          return 1;
        }
    }

  return 0;
}

/* setup an event from incoming request reply */
static ASSH_WARN_UNUSED_RESULT assh_error_t
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
  const uint8_t *data = p->head.end;
  struct assh_queue_s *q = &pv->request_lqueue;

  if (!global)
    {
      uint32_t ch_id = -1;
      ASSH_RET_ON_ERR(assh_packet_check_u32(p, &ch_id, p->head.end, &data));
      ch = (void*)assh_map_lookup(&pv->channel_map, ch_id, NULL);
      ASSH_RET_IF_TRUE(ch == NULL, ASSH_ERR_PROTOCOL);
      q = &ch->request_lqueue;

      switch (ch->status)
        {
        case ASSH_CHANNEL_ST_OPEN_SENT:
        case ASSH_CHANNEL_ST_OPEN_RECEIVED:
	  ASSH_RETURN(ASSH_ERR_PROTOCOL);

        case ASSH_CHANNEL_ST_OPEN:
        case ASSH_CHANNEL_ST_EOF_SENT:
        case ASSH_CHANNEL_ST_EOF_RECEIVED:
          break;

        case ASSH_CHANNEL_ST_EOF_CLOSE:
        case ASSH_CHANNEL_ST_CLOSE_CALLED:
          /* ignore the actual reply; request fail events will be
             reported when flushing the queue of sent requests. */
          return ASSH_OK;

        case ASSH_CHANNEL_ST_OPEN_SENT_FORCE_CLOSE:
	case ASSH_CHANNEL_ST_OPEN_RECEIVED_FORCE_CLOSE:
        case ASSH_CHANNEL_ST_FORCE_CLOSE:
        case ASSH_CHANNEL_ST_CLOSE_CALLED_CLOSING:
        case ASSH_CHANNEL_ST_CLOSING:
          /* This channel id has been removed from the channel map
             when the close packet was received. */
          ASSH_UNREACHABLE("internal error");
        }
    }

  /* get next request in queue */
  ASSH_RET_IF_TRUE(assh_queue_isempty(q), ASSH_ERR_PROTOCOL);

  struct assh_request_s *rq = (void*)assh_queue_back(q);
  ASSH_RET_IF_TRUE(rq->status != ASSH_REQUEST_ST_WAIT_REPLY,
	       ASSH_ERR_PROTOCOL);

  struct assh_event_request_reply_s *ev =
    &e->connection.request_reply;

  /* setup event */
  e->id = ASSH_EVENT_REQUEST_REPLY;
  e->f_done = assh_event_request_reply_done;

  ev->ch = ch;
  ev->rq = rq;
  ev->reply = success ? ASSH_CONNECTION_REPLY_SUCCESS
                      : ASSH_CONNECTION_REPLY_FAILED;

  struct assh_cbuffer_s *rsp_data = &ev->rsp_data;
  rsp_data->size = global && success ? p->data + p->data_size - data : 0;
  rsp_data->data = rsp_data->size > 0 ? (uint8_t*) data : NULL;

  /* keep packet for response data */
  if (rsp_data->size > 0)
    pv->pck = assh_packet_refinc(p);

  pv->state = ASSH_CONNECTION_ST_EVENT_REQUEST_REPLY;

  return ASSH_OK;
}

/************************************************* incoming channel open */

static assh_error_t
assh_channel_open_failed_send(struct assh_session_s *s, uint32_t remote_id,
                              enum assh_channel_open_reason_e reason)
{
  assh_error_t err;

  struct assh_packet_s *pout;

  /* send failed reply packet */
  ASSH_RET_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_CHANNEL_OPEN_FAILURE, 4 * 4, &pout));
  ASSH_ASSERT(assh_packet_add_u32(pout, remote_id));
  ASSH_ASSERT(assh_packet_add_u32(pout, reason));
  ASSH_ASSERT(assh_packet_add_string(pout, 0, NULL));
  ASSH_ASSERT(assh_packet_add_string(pout, 0, NULL));
  assh_transport_push(s, pout);

  return ASSH_OK;
}

assh_error_t
assh_channel_open_failed_reply(struct assh_channel_s *ch,
                               enum assh_channel_open_reason_e reason)
{
  assh_error_t err;
  struct assh_session_s *s = ch->session;
  struct assh_connection_context_s *pv = s->srv_pv;

  assert(s->srv == &assh_service_connection);
  assert(pv->state == ASSH_CONNECTION_ST_IDLE);

  switch (ch->status)
    {
    case ASSH_CHANNEL_ST_OPEN_RECEIVED:
      break;
    case ASSH_CHANNEL_ST_OPEN_RECEIVED_FORCE_CLOSE:
      return ASSH_NO_DATA;
    default:
      ASSH_UNREACHABLE("call not allowed in current state");
    }

  ASSH_JMP_ON_ERR(assh_channel_open_failed_send(s, ch->remote_id, reason), err);

  /* release channel object */
  ASSH_ASSERT(assh_map_remove_id(&pv->channel_map, ch->mentry.id));
  assh_channel_cleanup(ch);

  return ASSH_OK;
 err:
  return assh_session_error(s, err);
}

assh_error_t
assh_channel_open_success_reply2(struct assh_channel_s *ch,
                                 uint32_t pkt_size, uint32_t win_size,
                                 const uint8_t *rsp_data,
                                 size_t rsp_data_len)
{
  assh_error_t err;
  struct assh_session_s *s = ch->session;
  struct assh_connection_context_s *pv = s->srv_pv;

  assert(s->srv == &assh_service_connection);
  assert(pv->state == ASSH_CONNECTION_ST_IDLE);

  switch (ch->status)
    {
    case ASSH_CHANNEL_ST_OPEN_RECEIVED:
      break;
    case ASSH_CHANNEL_ST_OPEN_RECEIVED_FORCE_CLOSE:
      return ASSH_NO_DATA;
    default:
      ASSH_UNREACHABLE("call not allowed in current state");
    }

  assert(pkt_size >= 1);

  ch->lpkt_size = ASSH_MIN(pkt_size, CONFIG_ASSH_MAX_PAYLOAD
                           - /* extended data message header */ 3 * 4);
  ch->lwin_size = ch->lwin_left = ASSH_MAX(win_size, ch->lpkt_size * 4);

  struct assh_packet_s *pout;

  /* send confirmation reply packet */
  uint8_t *data;
  ASSH_JMP_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
                 4 * 4 + rsp_data_len, &pout) | ASSH_ERRSV_CONTINUE, err);

  ch->status = ASSH_CHANNEL_ST_OPEN;

  ASSH_ASSERT(assh_packet_add_u32(pout, ch->remote_id));
  ASSH_ASSERT(assh_packet_add_u32(pout, ch->mentry.id));
  ASSH_ASSERT(assh_packet_add_u32(pout, ch->lwin_left));
  ASSH_ASSERT(assh_packet_add_u32(pout, ch->lpkt_size));
  ASSH_ASSERT(assh_packet_add_array(pout, rsp_data_len, &data));
  memcpy(data, rsp_data, rsp_data_len);
  assh_transport_push(s, pout);

  return ASSH_OK;
 err:
  return assh_session_error(s, err);
}

assh_error_t
assh_channel_open_success_reply(struct assh_channel_s *ch,
                                const uint8_t *rsp_data,
                                size_t rsp_data_len)
{
  return assh_channel_open_success_reply2(ch, ch->lpkt_size, ch->lwin_size,
                                          rsp_data, rsp_data_len);
}

/* event done, reply to open */
static ASSH_EVENT_DONE_FCN(assh_event_channel_open_done)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;

  assert(s->srv == &assh_service_connection);
  assert(pv->state == ASSH_CONNECTION_ST_EVENT_CHANNEL_OPEN);

  /* release channel open packet */
  assh_packet_release(pv->pck);
  pv->pck = NULL;
  pv->state = ASSH_CONNECTION_ST_IDLE;

  const struct assh_event_channel_open_s *eo =
    &e->connection.channel_open;

  struct assh_channel_s *ch = eo->ch;

  if (ASSH_ERR_ERROR(inerr))
    goto failure;

  switch (eo->reply)
    {
    case ASSH_CONNECTION_REPLY_SUCCESS:
      err = assh_channel_open_success_reply2(ch, eo->pkt_size,
                     eo->win_size, eo->rsp_data.data, eo->rsp_data.size);
      /* The channel is considered open for now even if we were not
         able to allocate the reply packet. This is because we can not
         report the error immediately to the application. */
      ch->status = ASSH_CHANNEL_ST_OPEN;
      ASSH_RETURN(err | ASSH_ERRSV_DISCONNECT);

    case ASSH_CONNECTION_REPLY_FAILED:
    failure: {
        uint32_t remote_id = ch->remote_id;
        ASSH_ASSERT(assh_map_remove_id(&pv->channel_map, ch->mentry.id));
        assh_channel_cleanup(ch);
        ASSH_RETURN(assh_channel_open_failed_send(s, remote_id, eo->reason)
                       | ASSH_ERRSV_DISCONNECT);
      }

    case ASSH_CONNECTION_REPLY_POSTPONED:
      /* keep values for assh_channel_open_success_reply */
      ch->lpkt_size = eo->pkt_size;
      ch->lwin_size = eo->win_size;
      return ASSH_OK;

    default:
      ASSH_UNREACHABLE("unexpected event value");
    }
}

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_connection_got_channel_open(struct assh_session_s *s,
                                 struct assh_packet_s *p,
                                 struct assh_event_s *e)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;

  /* parse packet */
  const uint8_t *type = p->head.end, *data;
  uint32_t rid = 0, win_size = 0, pkt_size = 0;
  ASSH_RET_ON_ERR(assh_packet_check_string(p, type, &data));
  ASSH_RET_ON_ERR(assh_packet_check_u32(p, &rid, data, &data));
  ASSH_RET_ON_ERR(assh_packet_check_u32(p, &win_size, data, &data));
  ASSH_RET_ON_ERR(assh_packet_check_u32(p, &pkt_size, data, &data));

  ASSH_RET_IF_TRUE(pkt_size < 1, ASSH_ERR_PROTOCOL);

  /* create channel object */
  struct assh_channel_s *ch;
  ASSH_RET_ON_ERR(assh_alloc(s->ctx, sizeof(*ch), ASSH_ALLOC_INTERNAL, (void**)&ch));

  ch->mentry.id = assh_channel_next_id(pv);
  ch->remote_id = rid;
  ch->rpkt_size = pkt_size;
  ch->rwin_left = win_size;
  ch->status = ASSH_CHANNEL_ST_OPEN_RECEIVED;
  ch->session = s;
  ch->data_pck = NULL;
  assh_queue_init(&ch->request_rqueue);
  assh_queue_init(&ch->request_lqueue);

  assh_map_insert(&pv->channel_map, &ch->mentry);

  struct assh_event_channel_open_s *ev =
    &e->connection.channel_open;

  /* setup event */
  e->id = ASSH_EVENT_CHANNEL_OPEN;
  e->f_done = assh_event_channel_open_done;

  ev->ch = ch;

  struct assh_cbuffer_s *type_ = &ev->type;
  type_->str = (char*)type + 4;
  type_->len = assh_load_u32(type);

  ev->win_size = win_size;
  ev->pkt_size = pkt_size;

  struct assh_cbuffer_s *rq_data = &ev->rq_data;
  rq_data->size = p->data + p->data_size - data;
  rq_data->data = rq_data->size > 0 ? (uint8_t*)data : NULL;

  ev->reply = ASSH_CONNECTION_REPLY_FAILED;
  ev->reason = SSH_OPEN_UNKNOWN_CHANNEL_TYPE;

  struct assh_cbuffer_s *rsp_data = &ev->rsp_data;
  rsp_data->data = NULL;
  rsp_data->size = 0;

  /* keep packet for type and rq_data */
  pv->pck = assh_packet_refinc(p);

  pv->state = ASSH_CONNECTION_ST_EVENT_CHANNEL_OPEN;

  return ASSH_OK;
}

/************************************************* outgoing channel open */

assh_error_t
assh_channel_open2(struct assh_session_s *s,
                   const char *type, size_t type_len,
                   const uint8_t *data, size_t data_len,
                   uint32_t pkt_size, uint32_t win_size,
		   struct assh_channel_s **ch_)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;

  assert(s->srv == &assh_service_connection);
  assert(pv->state == ASSH_CONNECTION_ST_IDLE);

  if (s->tr_st >= ASSH_TR_DISCONNECT)
    return ASSH_NO_DATA;

  assert(pkt_size >= 1);

  /* alloc open msg packet */
  struct assh_packet_s *pout;
  size_t size = 4 + type_len + 3 * 4 + 4 + data_len;

  ASSH_JMP_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_CHANNEL_OPEN, size, &pout)
	       | ASSH_ERRSV_CONTINUE, err);

  /* create new channel object */
  struct assh_channel_s *ch;
  ASSH_JMP_ON_ERR(assh_alloc(s->ctx, sizeof(*ch), ASSH_ALLOC_INTERNAL, (void**)&ch)
	       | ASSH_ERRSV_CONTINUE, err_pkt);

  ch->lpkt_size = ASSH_MIN(pkt_size, CONFIG_ASSH_MAX_PAYLOAD
                           - /* extended data message header */ 3 * 4);
  ch->lwin_size = ch->lwin_left = ASSH_MAX(win_size, ch->lpkt_size * 4);
  ch->mentry.id = assh_channel_next_id(pv);
  ch->status = ASSH_CHANNEL_ST_OPEN_SENT;
  ch->session = s;
  ch->data_pck = NULL;
  assh_queue_init(&ch->request_rqueue);
  assh_queue_init(&ch->request_lqueue);

  *ch_ = ch;
  assh_map_insert(&pv->channel_map, &ch->mentry);

  /* send open msg */
  uint8_t *str;
  ASSH_ASSERT(assh_packet_add_string(pout, type_len, &str));
  memcpy(str, type, type_len);
  ASSH_ASSERT(assh_packet_add_u32(pout, ch->mentry.id));
  ASSH_ASSERT(assh_packet_add_u32(pout, ch->lwin_left));
  ASSH_ASSERT(assh_packet_add_u32(pout, ch->lpkt_size));
  ASSH_ASSERT(assh_packet_add_array(pout, data_len, &str));
  memcpy(str, data, data_len);

  assh_transport_push(s, pout);

  return ASSH_OK;

 err_pkt:
  assh_packet_release(pout);
 err:
  return assh_session_error(s, err);
}

static ASSH_EVENT_DONE_FCN(assh_event_channel_open_reply_done)
{
  struct assh_connection_context_s *pv = s->srv_pv;

  assert(s->srv == &assh_service_connection);
  assert(pv->state == ASSH_CONNECTION_ST_EVENT_CHANNEL_OPEN_REPLY);

  /* release packet */
  assh_packet_release(pv->pck);
  pv->pck = NULL;
  pv->state = ASSH_CONNECTION_ST_IDLE;

  struct assh_channel_s *ch = e->connection.channel_open_reply.ch;

  switch (ch->status)
    {
    case ASSH_CHANNEL_ST_OPEN:
      break;

    case ASSH_CHANNEL_ST_OPEN_SENT:
      /* we are left in this state if the open has not been accepted,
         release channel object */
      ASSH_ASSERT(assh_map_remove_id(&pv->channel_map, ch->mentry.id));
      assh_channel_cleanup(ch);
      break;

    default:
      ASSH_UNREACHABLE("internal error");
    }

  return ASSH_OK;
}

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_connection_got_channel_open_reply(struct assh_session_s *s,
                                       struct assh_packet_s *p,
                                       struct assh_event_s *e,
                                       assh_bool_t success)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;

  uint32_t ch_id = -1;
  const uint8_t *data;
  ASSH_RET_ON_ERR(assh_packet_check_u32(p, &ch_id, p->head.end, &data));

  struct assh_channel_s *ch = (void*)assh_map_lookup(&pv->channel_map, ch_id, NULL);

  ASSH_RET_IF_TRUE(ch == NULL, ASSH_ERR_PROTOCOL);

  switch (ch->status)
    {
    case ASSH_CHANNEL_ST_OPEN_SENT:
      break;
    case ASSH_CHANNEL_ST_OPEN_SENT_FORCE_CLOSE:
      return ASSH_OK;
    default:
      ASSH_RETURN(ASSH_ERR_PROTOCOL);
    }

  struct assh_event_channel_open_reply_s *ev =
    &e->connection.channel_open_reply;

  e->id = ASSH_EVENT_CHANNEL_OPEN_REPLY;
  e->f_done = assh_event_channel_open_reply_done;

  ev->ch = ch;
  struct assh_cbuffer_s *rsp_data = &ev->rsp_data;

  if (success)
    {
      ASSH_RET_ON_ERR(assh_packet_check_u32(p, &ch->remote_id, data, &data));
      ASSH_RET_ON_ERR(assh_packet_check_u32(p, &ch->rwin_left, data, &data));
      ASSH_RET_ON_ERR(assh_packet_check_u32(p, &ch->rpkt_size, data, &data));

      ASSH_RET_IF_TRUE(ch->rpkt_size < 1, ASSH_ERR_PROTOCOL);

      ev->reply = ASSH_CONNECTION_REPLY_SUCCESS;

      rsp_data->size = p->data + p->data_size - data;
      rsp_data->data = rsp_data->size > 0 ? (uint8_t*)data : NULL;

      ch->status = ASSH_CHANNEL_ST_OPEN;
    }
  else
    {
      uint32_t reason = 0;
      ASSH_RET_ON_ERR(assh_packet_check_u32(p, &reason, data, &data));

      ev->reply = ASSH_CONNECTION_REPLY_FAILED;
      ev->reason = (enum assh_channel_open_reason_e)reason;

      rsp_data->data = NULL;
      rsp_data->size = 0;
    }

  /* keep packet for response data */
  if (rsp_data->size > 0)
    pv->pck = assh_packet_refinc(p);

  pv->state = ASSH_CONNECTION_ST_EVENT_CHANNEL_OPEN_REPLY;

  return ASSH_OK;
}

/************************************************* incoming channel data */

static ASSH_EVENT_DONE_FCN(assh_event_channel_data_done)
{
  struct assh_connection_context_s *pv = s->srv_pv;

  assert(s->srv == &assh_service_connection);
  assert(pv->state == ASSH_CONNECTION_ST_EVENT_CHANNEL_DATA);

  const struct assh_event_channel_data_s *ev =
    &e->connection.channel_data;

  size_t transferred = ASSH_ERR_ERROR(inerr) ? 0 : ev->transferred;

  assert(pv->in_data_left >= transferred);
  pv->in_data_left -= transferred;

  if (!pv->in_data_left)
    {
      assh_packet_release(pv->pck);
      pv->pck = NULL;
    }

  pv->state = ASSH_CONNECTION_ST_IDLE;

  return ASSH_OK;
}

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_connection_more_channel_data(struct assh_session_s *s,
                                  struct assh_event_s *e)
{
  struct assh_connection_context_s *pv = s->srv_pv;

  assert(s->srv == &assh_service_connection);
  assert(pv->in_data_left && pv->pck);

  struct assh_packet_s *p = pv->pck;
  assh_bool_t ext = p->head.msg == SSH_MSG_CHANNEL_EXTENDED_DATA;

  uint32_t ch_id = -1;
  const uint8_t *data;
  ASSH_ASSERT(assh_packet_check_u32(p, &ch_id, p->head.end, &data));

  struct assh_channel_s *ch = (void*)assh_map_lookup(&pv->channel_map, ch_id, NULL);

  uint32_t ext_type = 0;
  if (ext)
    ASSH_ASSERT(assh_packet_check_u32(p, &ext_type, data, &data));

  uint32_t size = 0;
  ASSH_ASSERT(assh_packet_check_u32(p, &size, data, &data));
  ASSH_ASSERT(assh_packet_check_array(p, data, size, NULL));

  struct assh_event_channel_data_s *ev =
    &e->connection.channel_data;

  /* setup event */
  e->id = ASSH_EVENT_CHANNEL_DATA;
  e->f_done = assh_event_channel_data_done;

  ev->ch = ch;
  ev->ext = ext;
  ev->ext_type = ext_type;

  ev->data.size = pv->in_data_left;
  ev->data.data = (uint8_t*)data + size - pv->in_data_left;
  ev->transferred = 0;

  pv->state = ASSH_CONNECTION_ST_EVENT_CHANNEL_DATA;

  return ASSH_OK;
}

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_connection_got_channel_data(struct assh_session_s *s,
                                 struct assh_packet_s *p,
				 struct assh_event_s *e)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;
  assh_bool_t ext = p->head.msg == SSH_MSG_CHANNEL_EXTENDED_DATA;

  uint32_t ch_id = -1;
  const uint8_t *data;
  ASSH_RET_ON_ERR(assh_packet_check_u32(p, &ch_id, p->head.end, &data));

  struct assh_channel_s *ch = (void*)assh_map_lookup(&pv->channel_map, ch_id, NULL);
  ASSH_RET_IF_TRUE(ch == NULL, ASSH_ERR_PROTOCOL);

  switch (ch->status)
    {
    case ASSH_CHANNEL_ST_OPEN_SENT:
    case ASSH_CHANNEL_ST_OPEN_RECEIVED:
    case ASSH_CHANNEL_ST_EOF_RECEIVED:
    case ASSH_CHANNEL_ST_EOF_CLOSE:
      ASSH_RETURN(ASSH_ERR_PROTOCOL);

    case ASSH_CHANNEL_ST_CLOSE_CALLED:
    case ASSH_CHANNEL_ST_OPEN:
    case ASSH_CHANNEL_ST_EOF_SENT:
      break;

    case ASSH_CHANNEL_ST_CLOSING:
    case ASSH_CHANNEL_ST_CLOSE_CALLED_CLOSING:
    case ASSH_CHANNEL_ST_FORCE_CLOSE:
    case ASSH_CHANNEL_ST_OPEN_SENT_FORCE_CLOSE:
    case ASSH_CHANNEL_ST_OPEN_RECEIVED_FORCE_CLOSE:
      ASSH_UNREACHABLE("internal error");
    }

  uint32_t ext_type = 0;
  if (ext)
    ASSH_RET_ON_ERR(assh_packet_check_u32(p, &ext_type, data, &data));

  uint32_t size = 0;
  ASSH_RET_ON_ERR(assh_packet_check_u32(p, &size, data, &data));
  ASSH_RET_ON_ERR(assh_packet_check_array(p, data, size, NULL));

  ASSH_RET_IF_TRUE(size > ch->lpkt_size, ASSH_ERR_PROTOCOL);

#if 1
  ASSH_RET_IF_TRUE(size > ch->lwin_left, ASSH_ERR_PROTOCOL);
#else
  if (size > ch->lwin_left)
    size = ch->lwin_left;     /* ignore extra data, rfc4254 section 5.2 */
#endif

  /* update window and send adjustment */
  ch->lwin_left -= size;

#if 0
  ASSH_DEBUG("lwin_left=%u lwin_size=%u lpkt_size=%u\n",
	     ch->lwin_left, ch->lwin_size, ch->lpkt_size);
#endif

  if ((ch->lwin_left < ch->lwin_size / 2) &&
      ch->status != ASSH_CHANNEL_ST_CLOSE_CALLED)
    {
      uint32_t inc = ch->lwin_size - ch->lwin_left;

      struct assh_packet_s *pout;
      ASSH_RET_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_CHANNEL_WINDOW_ADJUST,
                                     2 * 4, &pout));
      ASSH_ASSERT(assh_packet_add_u32(pout, ch->remote_id));
      ASSH_ASSERT(assh_packet_add_u32(pout, inc));
      assh_transport_push(s, pout);

      ch->lwin_left += inc;
    }

  struct assh_event_channel_data_s *ev =
    &e->connection.channel_data;

  /* setup event */
  e->id = ASSH_EVENT_CHANNEL_DATA;
  e->f_done = assh_event_channel_data_done;

  ev->ch = ch;
  ev->ext = ext;
  ev->ext_type = ext_type;

  ev->data.size = size;
  ev->data.data = (uint8_t*)data;
  ev->transferred = 0;

  /* keep packet for data buffer */
  pv->in_data_left = size;
  pv->pck = assh_packet_refinc(p);

  pv->state = ASSH_CONNECTION_ST_EVENT_CHANNEL_DATA;

  return ASSH_OK;
}

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_connection_got_channel_window_adjust(struct assh_session_s *s,
                                          struct assh_packet_s *p,
					  struct assh_event_s *e)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;

  uint32_t ch_id = -1, inc = 0;
  const uint8_t *data;
  ASSH_RET_ON_ERR(assh_packet_check_u32(p, &ch_id, p->head.end, &data));
  ASSH_RET_ON_ERR(assh_packet_check_u32(p, &inc, data, NULL));

  struct assh_channel_s *ch = (void*)assh_map_lookup(&pv->channel_map, ch_id, NULL);
  ASSH_RET_IF_TRUE(ch == NULL, ASSH_ERR_PROTOCOL);

  switch (ch->status)
    {
    case ASSH_CHANNEL_ST_OPEN_SENT:
    case ASSH_CHANNEL_ST_OPEN_RECEIVED:
      ASSH_RETURN(ASSH_ERR_PROTOCOL);

    case ASSH_CHANNEL_ST_EOF_SENT:
    case ASSH_CHANNEL_ST_EOF_CLOSE:
      return ASSH_OK;

    case ASSH_CHANNEL_ST_CLOSE_CALLED:
    case ASSH_CHANNEL_ST_EOF_RECEIVED:
    case ASSH_CHANNEL_ST_OPEN:
      break;

    case ASSH_CHANNEL_ST_CLOSING:
    case ASSH_CHANNEL_ST_CLOSE_CALLED_CLOSING:
    case ASSH_CHANNEL_ST_FORCE_CLOSE:
    case ASSH_CHANNEL_ST_OPEN_SENT_FORCE_CLOSE:
    case ASSH_CHANNEL_ST_OPEN_RECEIVED_FORCE_CLOSE:
      ASSH_UNREACHABLE("internal error");
    }

  if (inc == 0)
    return ASSH_OK;

  uint32_t left = ch->rwin_left + inc;

  ASSH_RET_IF_TRUE(left < ch->rwin_left, ASSH_ERR_PROTOCOL);

  struct assh_event_channel_window_s *ev =
    &e->connection.channel_window;

  /* setup event */
  e->id = ASSH_EVENT_CHANNEL_WINDOW;
  e->f_done = NULL;

  ev->ch = ch;
  ev->old_size = ch->rwin_left;
  ev->new_size = left;

  ch->rwin_left = left;

  return ASSH_OK;
}

struct assh_channel_s *
assh_channel_more_data(struct assh_session_s *s)
{
  struct assh_connection_context_s *pv = s->srv_pv;

  if (s->srv == &assh_service_connection &&
      pv->in_data_left > 0)
    {
      struct assh_packet_s *p = pv->pck;
      uint32_t ch_id = -1;
      ASSH_ASSERT(assh_packet_check_u32(p, &ch_id, p->head.end, NULL));
      return (void*)assh_map_lookup(&pv->channel_map, ch_id, NULL);
    }

  return NULL;
}

/************************************************* outgoing channel data */

size_t assh_channel_data_size(struct assh_channel_s *ch)
{
  switch (ch->status)
    {
    default:
      return 0;

    case ASSH_CHANNEL_ST_OPEN:
    case ASSH_CHANNEL_ST_EOF_RECEIVED:
      return ASSH_MIN(ch->rpkt_size, ch->rwin_left);
    }
}

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_channel_data_alloc_chk(struct assh_channel_s *ch,
                            size_t *size, size_t min_size)
{
  struct assh_session_s *s = ch->session;

  assert(s->srv == &assh_service_connection);

  switch (ch->status)
    {
    case ASSH_CHANNEL_ST_OPEN_SENT:
    case ASSH_CHANNEL_ST_OPEN_SENT_FORCE_CLOSE:
    case ASSH_CHANNEL_ST_OPEN_RECEIVED:
    case ASSH_CHANNEL_ST_OPEN_RECEIVED_FORCE_CLOSE:
    case ASSH_CHANNEL_ST_EOF_SENT:
    case ASSH_CHANNEL_ST_EOF_CLOSE:
    case ASSH_CHANNEL_ST_CLOSE_CALLED:
    case ASSH_CHANNEL_ST_CLOSE_CALLED_CLOSING:
      ASSH_UNREACHABLE("call not allowed in current state");

    case ASSH_CHANNEL_ST_OPEN:
    case ASSH_CHANNEL_ST_EOF_RECEIVED:
      break;

    case ASSH_CHANNEL_ST_FORCE_CLOSE:
    case ASSH_CHANNEL_ST_CLOSING:
      *size = 0;
      return ASSH_NO_DATA;
    }

  /* adjust size */
  size_t sz = *size;
  if (sz > ch->rpkt_size)
    sz = ch->rpkt_size;
  if (sz > ch->rwin_left)
    sz = ch->rwin_left;
  *size = sz;

  if (sz < min_size || min_size == 0)
    return ASSH_NO_DATA;

  /* release old unused packet */
  assh_packet_release(ch->data_pck);
  ch->data_pck = NULL;

  return ASSH_OK;
}

assh_error_t
assh_channel_data_alloc(struct assh_channel_s *ch,
                        uint8_t **data, size_t *size,
                        size_t min_size)
{
  assh_error_t err;
  struct assh_session_s *s = ch->session;

  ASSH_JMP_ON_ERR(assh_channel_data_alloc_chk(ch, size, min_size), err);

  struct assh_packet_s *pout;

  ASSH_JMP_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_CHANNEL_DATA,
		 2 * 4 + *size, &pout) | ASSH_ERRSV_CONTINUE, err);
  ASSH_ASSERT(assh_packet_add_u32(pout, ch->remote_id));

  *data = pout->data + pout->data_size
    + /* room for data size */ 4;

  assh_packet_release(ch->data_pck);
  ch->data_pck = pout;

  return ASSH_OK;
 err:
  return assh_session_error(s, err);
}

assh_error_t
assh_channel_data_alloc_ext(struct assh_channel_s *ch,
                            uint32_t ext_type,
                            uint8_t **data, size_t *size,
                            size_t min_size)
{
  assh_error_t err;
  struct assh_session_s *s = ch->session;

  ASSH_JMP_ON_ERR(assh_channel_data_alloc_chk(ch, size, min_size), err);

  struct assh_packet_s *pout;

  ASSH_JMP_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_CHANNEL_EXTENDED_DATA,
		 3 * 4 + *size, &pout) | ASSH_ERRSV_CONTINUE, err);
  ASSH_ASSERT(assh_packet_add_u32(pout, ch->remote_id));
  ASSH_ASSERT(assh_packet_add_u32(pout, ext_type));

  *data = pout->data + pout->data_size
    + /* room for data size */ 4;

  assh_packet_release(ch->data_pck);
  ch->data_pck = pout;

  return ASSH_OK;
 err:
  return assh_session_error(s, err);
}

assh_error_t
assh_channel_data_send(struct assh_channel_s *ch, size_t size)
{
  assh_error_t err;
  struct assh_session_s *s = ch->session;
  struct assh_connection_context_s *pv = s->srv_pv;

  assert(s->srv == &assh_service_connection);
  assert(pv->state == ASSH_CONNECTION_ST_IDLE);

  switch (ch->status)
    {
    case ASSH_CHANNEL_ST_OPEN_SENT:
    case ASSH_CHANNEL_ST_OPEN_SENT_FORCE_CLOSE:
    case ASSH_CHANNEL_ST_OPEN_RECEIVED:
    case ASSH_CHANNEL_ST_OPEN_RECEIVED_FORCE_CLOSE:
    case ASSH_CHANNEL_ST_EOF_SENT:
    case ASSH_CHANNEL_ST_EOF_CLOSE:
    case ASSH_CHANNEL_ST_CLOSE_CALLED:
    case ASSH_CHANNEL_ST_CLOSE_CALLED_CLOSING:
      ASSH_UNREACHABLE("call not allowed in current state");

    case ASSH_CHANNEL_ST_OPEN:
    case ASSH_CHANNEL_ST_EOF_RECEIVED:
      break;

    case ASSH_CHANNEL_ST_CLOSING:
    case ASSH_CHANNEL_ST_FORCE_CLOSE:
      return ASSH_NO_DATA;
    }

  struct assh_packet_s *pout = ch->data_pck;

  assert(pout != NULL);
  ASSH_JMP_IF_TRUE(size > pout->alloc_size - pout->data_size - 4,
	       ASSH_ERR_OUTPUT_OVERFLOW | ASSH_ERRSV_CONTINUE, err);

  ASSH_ASSERT(assh_packet_add_u32(pout, size));

  assert(ch->rwin_left >= size);

  pout->data_size += size;
  ch->rwin_left -= size;

  assh_transport_push(s, ch->data_pck);
  ch->data_pck = NULL;

  return ASSH_OK;
 err:
  return assh_session_error(s, err);
}

assh_error_t
assh_channel_dummy(struct assh_channel_s *ch, size_t size)
{
  assh_error_t err;
  struct assh_session_s *s = ch->session;
  struct assh_connection_context_s *pv = s->srv_pv;

  assert(s->srv == &assh_service_connection);
  assert(pv->state == ASSH_CONNECTION_ST_IDLE);

  switch (ch->status)
    {
    case ASSH_CHANNEL_ST_OPEN_SENT:
    case ASSH_CHANNEL_ST_OPEN_SENT_FORCE_CLOSE:
    case ASSH_CHANNEL_ST_OPEN_RECEIVED:
    case ASSH_CHANNEL_ST_OPEN_RECEIVED_FORCE_CLOSE:
    case ASSH_CHANNEL_ST_EOF_SENT:
    case ASSH_CHANNEL_ST_EOF_CLOSE:
    case ASSH_CHANNEL_ST_CLOSE_CALLED:
    case ASSH_CHANNEL_ST_CLOSE_CALLED_CLOSING:
      ASSH_UNREACHABLE("call not allowed in current state");

    case ASSH_CHANNEL_ST_OPEN:
    case ASSH_CHANNEL_ST_EOF_RECEIVED:
      break;

    case ASSH_CHANNEL_ST_CLOSING:
    case ASSH_CHANNEL_ST_FORCE_CLOSE:
      return ASSH_NO_DATA;
    }

  struct assh_packet_s *pout;

  ASSH_JMP_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_IGNORE,
		 2 * 4 + size, &pout) | ASSH_ERRSV_CONTINUE, err);

  assh_transport_push(s, pout);
  return ASSH_OK;

 err:
  return assh_session_error(s, err);
}

/************************************************* incoming channel close/eof */

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_connection_send_channel_close(struct assh_session_s *s,
                                   struct assh_channel_s *ch,
                                   uint8_t msg)
{
  assh_error_t err;

  struct assh_packet_s *pout;
  ASSH_RET_ON_ERR(assh_packet_alloc(s->ctx, msg, 4, &pout)
	       | ASSH_ERRSV_CONTINUE);
  ASSH_ASSERT(assh_packet_add_u32(pout, ch->remote_id));

  assh_transport_push(s, pout);

  return ASSH_OK;
}

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_connection_got_channel_close(struct assh_session_s *s,
                                  struct assh_packet_s *p)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;

  uint32_t ch_id = -1;
  const uint8_t *data;
  ASSH_RET_ON_ERR(assh_packet_check_u32(p, &ch_id, p->head.end, &data));

  struct assh_map_entry_s **chp;
  struct assh_channel_s *ch = (void*)assh_map_lookup(&pv->channel_map, ch_id, &chp);
  ASSH_RET_IF_TRUE(ch == NULL, ASSH_ERR_PROTOCOL);

  switch (ch->status)
    {
    case ASSH_CHANNEL_ST_OPEN_SENT:
    case ASSH_CHANNEL_ST_OPEN_RECEIVED:
      ASSH_RETURN(ASSH_ERR_PROTOCOL);

    case ASSH_CHANNEL_ST_OPEN:
    case ASSH_CHANNEL_ST_EOF_SENT:
    case ASSH_CHANNEL_ST_EOF_RECEIVED:
      ASSH_RET_ON_ERR(assh_connection_send_channel_close(s, ch, SSH_MSG_CHANNEL_CLOSE));
      ch->status = ASSH_CHANNEL_ST_CLOSING;
      break;

    case ASSH_CHANNEL_ST_CLOSE_CALLED:
      ch->status = ASSH_CHANNEL_ST_CLOSE_CALLED_CLOSING;
      break;

    case ASSH_CHANNEL_ST_EOF_CLOSE:
      ch->status = ASSH_CHANNEL_ST_CLOSING;
      break;

    case ASSH_CHANNEL_ST_CLOSING:
    case ASSH_CHANNEL_ST_CLOSE_CALLED_CLOSING:
    case ASSH_CHANNEL_ST_FORCE_CLOSE:
    case ASSH_CHANNEL_ST_OPEN_SENT_FORCE_CLOSE:
    case ASSH_CHANNEL_ST_OPEN_RECEIVED_FORCE_CLOSE:
      /* This channel id has been removed from the channel map
         when the close packet was received. */
      ASSH_UNREACHABLE("internal error");
    }

  /* move channel from id lookup map to closing queue */
  assh_map_remove(chp, (void*)ch);
  assh_queue_push_front(&pv->closing_queue, &ch->qentry);

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_event_channel_close_done)
{
  struct assh_connection_context_s *pv = s->srv_pv;

  assert(s->srv == &assh_service_connection);
  assert(pv->state == ASSH_CONNECTION_ST_EVENT_CHANNEL_CLOSE);

  pv->state = ASSH_CONNECTION_ST_IDLE;

  struct assh_channel_s *ch = e->connection.channel_close.ch;

  assh_channel_cleanup(ch);

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_event_channel_eof_done)
{
  struct assh_connection_context_s *pv = s->srv_pv;

  assert(s->srv == &assh_service_connection);
  assert(pv->state == ASSH_CONNECTION_ST_EVENT_CHANNEL_EOF);

  pv->state = ASSH_CONNECTION_ST_IDLE;

  return ASSH_OK;
}

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_connection_got_channel_eof(struct assh_session_s *s,
                                struct assh_packet_s *p,
                                struct assh_event_s *e)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;

  uint32_t ch_id = -1;
  const uint8_t *data;
  ASSH_RET_ON_ERR(assh_packet_check_u32(p, &ch_id, p->head.end, &data));

  struct assh_map_entry_s **chp;
  struct assh_channel_s *ch = (void*)assh_map_lookup(&pv->channel_map, ch_id, &chp);
  ASSH_RET_IF_TRUE(ch == NULL, ASSH_ERR_PROTOCOL);

  switch (ch->status)
    {
    case ASSH_CHANNEL_ST_OPEN_SENT:
    case ASSH_CHANNEL_ST_OPEN_RECEIVED:
    case ASSH_CHANNEL_ST_EOF_RECEIVED:
    case ASSH_CHANNEL_ST_EOF_CLOSE:
      ASSH_RETURN(ASSH_ERR_PROTOCOL);

    case ASSH_CHANNEL_ST_OPEN:
      ch->status = ASSH_CHANNEL_ST_EOF_RECEIVED;
      break;

    case ASSH_CHANNEL_ST_EOF_SENT:
      ASSH_RET_ON_ERR(assh_connection_send_channel_close(s, ch, SSH_MSG_CHANNEL_CLOSE));
      ch->status = ASSH_CHANNEL_ST_EOF_CLOSE;
      break;

    case ASSH_CHANNEL_ST_CLOSE_CALLED:
      return ASSH_OK;

    case ASSH_CHANNEL_ST_CLOSING:
    case ASSH_CHANNEL_ST_CLOSE_CALLED_CLOSING:
    case ASSH_CHANNEL_ST_FORCE_CLOSE:
    case ASSH_CHANNEL_ST_OPEN_SENT_FORCE_CLOSE:
    case ASSH_CHANNEL_ST_OPEN_RECEIVED_FORCE_CLOSE:
      /* This channel id has been removed from the channel map
         when the close packet was received. */
      ASSH_UNREACHABLE("internal error");
    }

  struct assh_event_channel_eof_s *ev =
    &e->connection.channel_eof;

  e->id = ASSH_EVENT_CHANNEL_EOF;
  e->f_done = assh_event_channel_eof_done;
  ev->ch = ch;

  pv->state = ASSH_CONNECTION_ST_EVENT_CHANNEL_EOF;

  return ASSH_OK;
}

/************************************************* outgoing channel close/eof */

assh_error_t
assh_channel_eof(struct assh_channel_s *ch)
{
  assh_error_t err;
  struct assh_session_s *s = ch->session;
  struct assh_connection_context_s *pv = s->srv_pv;

  assert(s->srv == &assh_service_connection);
  assert(pv->state == ASSH_CONNECTION_ST_IDLE);

  switch (ch->status)
    {
    case ASSH_CHANNEL_ST_OPEN_SENT:
    case ASSH_CHANNEL_ST_OPEN_SENT_FORCE_CLOSE:
    case ASSH_CHANNEL_ST_OPEN_RECEIVED:
    case ASSH_CHANNEL_ST_OPEN_RECEIVED_FORCE_CLOSE:
    case ASSH_CHANNEL_ST_EOF_SENT:
    case ASSH_CHANNEL_ST_EOF_CLOSE:
    case ASSH_CHANNEL_ST_CLOSE_CALLED:
    case ASSH_CHANNEL_ST_CLOSE_CALLED_CLOSING:
      ASSH_UNREACHABLE("call not allowed in current state");

    case ASSH_CHANNEL_ST_OPEN:
      ASSH_RET_ON_ERR(assh_connection_send_channel_close(s, ch, SSH_MSG_CHANNEL_EOF)
		   | ASSH_ERRSV_CONTINUE);
      ch->status = ASSH_CHANNEL_ST_EOF_SENT;
      break;

    case ASSH_CHANNEL_ST_EOF_RECEIVED:
      ASSH_RET_ON_ERR(assh_connection_send_channel_close(s, ch, SSH_MSG_CHANNEL_CLOSE)
		   | ASSH_ERRSV_CONTINUE);
      ch->status = ASSH_CHANNEL_ST_EOF_CLOSE;
      break;

    case ASSH_CHANNEL_ST_CLOSING:
    case ASSH_CHANNEL_ST_FORCE_CLOSE:
      break;
    }

  return ASSH_OK;
}

assh_error_t
assh_channel_close(struct assh_channel_s *ch)
{
  assh_error_t err;
  struct assh_session_s *s = ch->session;
  struct assh_connection_context_s *pv = s->srv_pv;

  assert(s->srv == &assh_service_connection);
  assert(pv->state == ASSH_CONNECTION_ST_IDLE);

  switch (ch->status)
    {
    case ASSH_CHANNEL_ST_OPEN_SENT:
    case ASSH_CHANNEL_ST_OPEN_RECEIVED:
    case ASSH_CHANNEL_ST_OPEN_SENT_FORCE_CLOSE:
    case ASSH_CHANNEL_ST_OPEN_RECEIVED_FORCE_CLOSE:
    case ASSH_CHANNEL_ST_CLOSE_CALLED:
    case ASSH_CHANNEL_ST_CLOSE_CALLED_CLOSING:
      ASSH_UNREACHABLE("call not allowed in current state");

    case ASSH_CHANNEL_ST_OPEN:
    case ASSH_CHANNEL_ST_EOF_SENT:
    case ASSH_CHANNEL_ST_EOF_RECEIVED:
      /** send a close packet, the actual closing will occur when
          the close reply packet will be received. */
      ASSH_JMP_ON_ERR(assh_connection_send_channel_close(s, ch, SSH_MSG_CHANNEL_CLOSE)
		   | ASSH_ERRSV_CONTINUE, err);

    case ASSH_CHANNEL_ST_EOF_CLOSE:
      ch->status = ASSH_CHANNEL_ST_CLOSE_CALLED;
      break;

    case ASSH_CHANNEL_ST_CLOSING:
      ch->status = ASSH_CHANNEL_ST_CLOSE_CALLED_CLOSING;
      break;

    case ASSH_CHANNEL_ST_FORCE_CLOSE:
      break;
    }

  return ASSH_OK;
 err:
  return assh_session_error(s, err);
}

/************************************************* connection service */

/* service initialization */
static ASSH_SERVICE_INIT_FCN(assh_connection_init)
{
  struct assh_connection_context_s *pv;
  assh_error_t err;

  ASSH_RET_ON_ERR(assh_alloc(s->ctx, sizeof(*pv),
                 ASSH_ALLOC_INTERNAL, (void**)&pv) | ASSH_ERRSV_CONTINUE);

  assh_queue_init(&pv->request_rqueue);
  assh_queue_init(&pv->request_lqueue);
  assh_queue_init(&pv->closing_queue);

  pv->channel_map = NULL;
  pv->pck = NULL;
  pv->ch_id_counter = 0;
  s->deadline = s->time + ASSH_TIMEOUT_KEEPALIVE;
  pv->in_data_left = 0;

  s->srv_pv = pv;

  pv->state = ASSH_CONNECTION_ST_IDLE;

  return ASSH_OK;
}

static void assh_channel_cleanup_i(struct assh_map_entry_s *ch_, void *unused)
{
  assh_channel_cleanup((struct assh_channel_s*)ch_);
}

static ASSH_SERVICE_CLEANUP_FCN(assh_connection_cleanup)
{
  struct assh_connection_context_s *pv = s->srv_pv;

  assh_packet_release(pv->pck);

  assh_request_queue_cleanup(s, &pv->request_rqueue);
  assh_request_queue_cleanup(s, &pv->request_lqueue);

  assh_map_iter(pv->channel_map, NULL, &assh_channel_cleanup_i);

  assh_channel_queue_cleanup(s, &pv->closing_queue);

  assh_free(s->ctx, pv);
}

static void assh_channel_force_close_i(struct assh_map_entry_s *ch_, void *pv_)
{
  struct assh_channel_s *ch = (struct assh_channel_s*)ch_;
  struct assh_connection_context_s *pv = pv_;

  switch (ch->status)
    {
    case ASSH_CHANNEL_ST_OPEN_SENT:
      ch->status = ASSH_CHANNEL_ST_OPEN_SENT_FORCE_CLOSE;
      break;

    case ASSH_CHANNEL_ST_OPEN_RECEIVED:
      ch->status = ASSH_CHANNEL_ST_OPEN_RECEIVED_FORCE_CLOSE;
      break;

    case ASSH_CHANNEL_ST_OPEN:
    case ASSH_CHANNEL_ST_EOF_SENT:
    case ASSH_CHANNEL_ST_EOF_RECEIVED:
    case ASSH_CHANNEL_ST_EOF_CLOSE:
    case ASSH_CHANNEL_ST_CLOSE_CALLED:
      ch->status = ASSH_CHANNEL_ST_FORCE_CLOSE;
      break;

    case ASSH_CHANNEL_ST_CLOSING:
    case ASSH_CHANNEL_ST_CLOSE_CALLED_CLOSING:
    case ASSH_CHANNEL_ST_FORCE_CLOSE:
    case ASSH_CHANNEL_ST_OPEN_SENT_FORCE_CLOSE:
    case ASSH_CHANNEL_ST_OPEN_RECEIVED_FORCE_CLOSE:
      ASSH_UNREACHABLE("internal error");
    }

  assh_queue_push_front(&pv->closing_queue, &ch->qentry);
}

static void assh_channel_pop_closing(struct assh_session_s *s,
                                     struct assh_event_s *e)
{
  struct assh_connection_context_s *pv = s->srv_pv;
  struct assh_channel_s *ch = (void*)assh_queue_back(&pv->closing_queue);

  switch (ch->status)
    {
    case ASSH_CHANNEL_ST_CLOSING:
    case ASSH_CHANNEL_ST_CLOSE_CALLED_CLOSING:
      /* from assh_connection_got_channel_close */

    case ASSH_CHANNEL_ST_FORCE_CLOSE: {

      if (assh_request_reply_flush(s, ch, e) ||
          assh_request_abort_flush(s, ch, e))
        return;

      struct assh_event_channel_close_s *ev =
        &e->connection.channel_close;

      /* report channel close event */
      e->id = ASSH_EVENT_CHANNEL_CLOSE;
      e->f_done = assh_event_channel_close_done;
      ev->ch = ch;
      break;
    }

     case ASSH_CHANNEL_ST_OPEN_RECEIVED_FORCE_CLOSE: {

      struct assh_event_channel_abort_s *ev =
        &e->connection.channel_abort;

      ASSH_FIRST_FIELD_ASSERT(assh_event_channel_abort_s, ch);
      ASSH_FIRST_FIELD_ASSERT(assh_event_channel_close_s, ch);
      ev->ch = ch;

      /* report channel close event */
      e->id = ASSH_EVENT_CHANNEL_ABORT;
      e->f_done = assh_event_channel_close_done;
      break;
    }

    case ASSH_CHANNEL_ST_OPEN_SENT_FORCE_CLOSE: {
      assert(assh_queue_isempty(&ch->request_lqueue));

      struct assh_event_channel_open_reply_s *ev =
        &e->connection.channel_open_reply;

      ASSH_FIRST_FIELD_ASSERT(assh_event_channel_open_reply_s, ch);
      ASSH_FIRST_FIELD_ASSERT(assh_event_channel_close_s, ch);
      ev->ch = ch;

      /* report channel open failed */
      e->id = ASSH_EVENT_CHANNEL_OPEN_REPLY;
      e->f_done = assh_event_channel_close_done;
      ev->reply = ASSH_CONNECTION_REPLY_FAILED;

      break;

    }

    default:
      ASSH_UNREACHABLE("internal error");
    }

  pv->state = ASSH_CONNECTION_ST_EVENT_CHANNEL_CLOSE;

  /* remove from pv->closing_queue */
  assh_queue_remove((void*)ch);
}

static ASSH_SERVICE_PROCESS_FCN(assh_connection_process)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;

  assert(pv->state == ASSH_CONNECTION_ST_IDLE);

  if (pv->in_data_left)
    {
      ASSH_RET_ON_ERR(assh_connection_more_channel_data(s, e)
                   | ASSH_ERRSV_DISCONNECT);
      return ASSH_NO_DATA;
    }

  /* handle incoming packet, if any */
  if (p != NULL)
    {
      s->deadline = s->time + ASSH_TIMEOUT_KEEPALIVE;

      switch (p->head.msg)
        {
        case SSH_MSG_GLOBAL_REQUEST:
          ASSH_RET_ON_ERR(assh_connection_got_request(s, p, e, 1)
                         | ASSH_ERRSV_DISCONNECT);
          break;

        case SSH_MSG_REQUEST_SUCCESS:
          ASSH_RET_ON_ERR(assh_connection_got_request_reply(s, p, e, 1, 1)
                         | ASSH_ERRSV_DISCONNECT);
          break;

        case SSH_MSG_REQUEST_FAILURE:
          ASSH_RET_ON_ERR(assh_connection_got_request_reply(s, p, e, 1, 0)
                         | ASSH_ERRSV_DISCONNECT);
          break;

        case SSH_MSG_CHANNEL_OPEN:
          ASSH_RET_ON_ERR(assh_connection_got_channel_open(s, p, e)
                         | ASSH_ERRSV_DISCONNECT);
          break;

        case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
          ASSH_RET_ON_ERR(assh_connection_got_channel_open_reply(s, p, e, 1)
                         | ASSH_ERRSV_DISCONNECT);
          break;

        case SSH_MSG_CHANNEL_OPEN_FAILURE:
          ASSH_RET_ON_ERR(assh_connection_got_channel_open_reply(s, p, e, 0)
                         | ASSH_ERRSV_DISCONNECT);
          break;

        case SSH_MSG_CHANNEL_WINDOW_ADJUST:
          ASSH_RET_ON_ERR(assh_connection_got_channel_window_adjust(s, p, e)
                         | ASSH_ERRSV_DISCONNECT);
          break;

        case SSH_MSG_CHANNEL_DATA:
        case SSH_MSG_CHANNEL_EXTENDED_DATA:
          ASSH_RET_ON_ERR(assh_connection_got_channel_data(s, p, e)
                         | ASSH_ERRSV_DISCONNECT);
          break;

        case SSH_MSG_CHANNEL_EOF:
          ASSH_RET_ON_ERR(assh_connection_got_channel_eof(s, p, e)
                         | ASSH_ERRSV_DISCONNECT);
          break;

        case SSH_MSG_CHANNEL_CLOSE:
          ASSH_RET_ON_ERR(assh_connection_got_channel_close(s, p)
                         | ASSH_ERRSV_DISCONNECT);
          break;

        case SSH_MSG_CHANNEL_REQUEST:
          ASSH_RET_ON_ERR(assh_connection_got_request(s, p, e, 0)
                         | ASSH_ERRSV_DISCONNECT);
          break;

        case SSH_MSG_CHANNEL_SUCCESS:
          ASSH_RET_ON_ERR(assh_connection_got_request_reply(s, p, e, 0, 1)
                         | ASSH_ERRSV_DISCONNECT);
          break;

        case SSH_MSG_CHANNEL_FAILURE:
          ASSH_RET_ON_ERR(assh_connection_got_request_reply(s, p, e, 0, 0)
                         | ASSH_ERRSV_DISCONNECT);
          break;

        case SSH_MSG_UNIMPLEMENTED:
          /* this service only send standard messages which must be
             supported by the remote side. */
          ASSH_RETURN(ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);

        default:
          /* handle non-standard messages gracefully */
          ASSH_RET_ON_ERR(assh_transport_unimp(s, p)
                         | ASSH_ERRSV_DISCONNECT);
        }
    }

  if (e->id != ASSH_EVENT_INVALID)
    return ASSH_OK;

  if (s->tr_st >= ASSH_TR_DISCONNECT)
    {
      /* close all channels */
      assh_map_iter(pv->channel_map, pv, &assh_channel_force_close_i);
      pv->channel_map = NULL;

      /* flush global requests */
      if (assh_request_reply_flush(s, NULL, e) ||
          assh_request_abort_flush(s, NULL, e))
        return ASSH_OK;
    }
  else if (s->deadline <= s->time)
    {
      /* send keep alive */
      struct assh_packet_s *pout;
      if (!assh_packet_alloc(s->ctx, SSH_MSG_IGNORE, 0, &pout))
        assh_transport_push(s, pout);
      s->deadline = s->time + ASSH_TIMEOUT_KEEPALIVE;
    }

  /* report channel closing related events */
  if (!assh_queue_isempty(&pv->closing_queue))
    assh_channel_pop_closing(s, e);

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

