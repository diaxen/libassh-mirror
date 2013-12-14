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

enum assh_connection_state_e
{
  ASSH_CN_STATE_INIT,       //< have to return connection start event
  ASSH_CN_STATE_PROCESS,    //< process incoming packet
  ASSH_CN_STATE_GLOBAL_REQUEST,
  ASSH_CN_STATE_GLOBAL_REQUEST_REPLY,
  ASSH_CN_STATE_CHANNEL_OPEN,
};

struct assh_connection_context_s
{
  enum assh_connection_state_e state;

  struct assh_queue_s channel_queue; //< channels waiting for open confirmation
  struct assh_queue_s request_queue; //< requests waiting for reply message

  struct assh_map_entry_s *channel_map;
  struct assh_packet_s *pck;
};

/************************************************* incoming channel data */

static assh_error_t
assh_connection_channel_data(struct assh_session_s *s,
			     struct assh_packet_s *p,
			     assh_bool_t extended)
{
  return ASSH_OK;
}

static assh_error_t
assh_connection_channel_window_adjust(struct assh_session_s *s,
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
assh_connection_channel_close(struct assh_session_s *s,
			      struct assh_packet_s *p,
			      struct assh_event_s *e)
{
  return ASSH_OK;
}

static assh_error_t
assh_connection_channel_eof(struct assh_session_s *s,
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

/************************************************* incoming channel open */

/* event done, reply to open */
static ASSH_EVENT_DONE_FCN(assh_connection_channel_open_done)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;

  assert(s->srv == &assh_service_connection);
  ASSH_ERR_RET(pv->state != ASSH_CN_STATE_CHANNEL_OPEN ? ASSH_ERR_STATE : 0);

  return ASSH_OK;
}

static assh_error_t
assh_connection_channel_open(struct assh_session_s *s,
			     struct assh_packet_s *p,
			     struct assh_event_s *e)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;

  /* parse packet */
  uint8_t *type = p->head.end, *want_reply, *data;
  ASSH_ERR_RET(assh_packet_check_string(p, type, &want_reply));
  ASSH_ERR_RET(assh_packet_check_array(p, want_reply, 1, &data));

  /* setup event */
  e->id = ASSH_EVENT_CONNECTION_GLOBAL_REQUEST;
  e->f_done = assh_connection_channel_open_done;

  struct assh_string_s *type_ = (void*)&e->connection.global_request.type;
  type_->str = (char*)type + 4;
  type_->len = want_reply - type - 4;

  *(assh_bool_t*)&e->connection.global_request.want_reply = *want_reply;

  struct assh_buffer_s *rq_data = (void*)&e->connection.global_request.rq_data;
  rq_data->size = p->data + p->data_size - data;
  rq_data->data = rq_data->size > 0 ? data : NULL;

  struct assh_buffer_s *rsp_data = &e->connection.global_request.rsp_data;
  rsp_data->data = NULL;
  rsp_data->size = 0;

  e->connection.global_request.success = 0;

  /* keep packet which contains request data */
  if (rq_data->size > 0)
    pv->pck = assh_packet_refinc(p);

  pv->state = ASSH_CN_STATE_GLOBAL_REQUEST;

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
assh_connection_channel_open_reply(struct assh_session_s *s,
				   struct assh_packet_s *p,
				   struct assh_event_s *e,
				   assh_bool_t success)
{
  return ASSH_OK;
}

/************************************************* incoming channel request */

static assh_error_t
assh_connection_channel_request(struct assh_session_s *s,
				struct assh_packet_s *p,
				struct assh_event_s *e)
{
  return ASSH_OK;
}

/************************************************* outgoing channel request */

assh_error_t
assh_channel_request(struct assh_channel_s *channel,
                     const char *type, size_t type_len,
                     const uint8_t *data, size_t data_len,
                     assh_bool_t want_reply,
                     struct assh_request_s **request)
{
  assh_error_t err;
  struct assh_session_s *s = channel->session;
  struct assh_connection_context_s *pv = s->srv_pv;
  ASSH_ERR_RET(s->srv != &assh_service_connection ? ASSH_ERR_SERVICE_NA : 0);

  return ASSH_OK;
}

static assh_error_t
assh_connection_channel_request_reply(struct assh_session_s *s,
				      struct assh_packet_s *p,
				      struct assh_event_s *e,
				      assh_bool_t success)
{
  return ASSH_OK;
}

/************************************************* incoming global request */

/* event done, reply to request */
static ASSH_EVENT_DONE_FCN(assh_connection_global_request_done)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;

  assert(s->srv == &assh_service_connection);
  ASSH_ERR_RET(pv->state != ASSH_CN_STATE_GLOBAL_REQUEST ? ASSH_ERR_STATE : 0);

  /* release request packet */
  assh_packet_release(pv->pck);
  pv->pck = NULL;
  pv->state = ASSH_CN_STATE_PROCESS;

  if (!e->connection.global_request.want_reply)
    return ASSH_OK;

  /* send reply packet */
  struct assh_packet_s *pout;

  if (e->connection.global_request.success)
    {
      size_t size = e->connection.global_request.rsp_data.size;
      ASSH_ERR_RET(assh_packet_alloc(s->ctx, SSH_MSG_REQUEST_SUCCESS, size, &pout));
      if (size > 0)
        {
          uint8_t *data;
          ASSH_ASSERT(assh_packet_add_bytes(pout, size, &data));
          memcpy(data, e->connection.global_request.rsp_data.data, size);
        }
    }
  else
    {
      ASSH_ERR_RET(assh_packet_alloc(s->ctx, SSH_MSG_REQUEST_FAILURE, 0, &pout));
    }

  assh_transport_push(s, pout);

  return ASSH_OK;
}

/* setup an event from incoming request */
static assh_error_t
assh_connection_global_request(struct assh_session_s *s,
			       struct assh_packet_s *p,
			       struct assh_event_s *e)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;

  /* parse packet */
  uint8_t *type = p->head.end, *want_reply, *data;
  ASSH_ERR_RET(assh_packet_check_string(p, type, &want_reply));
  ASSH_ERR_RET(assh_packet_check_array(p, want_reply, 1, &data));

  /* setup event */
  e->id = ASSH_EVENT_CONNECTION_GLOBAL_REQUEST;
  e->f_done = assh_connection_global_request_done;

  struct assh_string_s *type_ = (void*)&e->connection.global_request.type;
  type_->str = (char*)type + 4;
  type_->len = want_reply - type - 4;

  *(assh_bool_t*)&e->connection.global_request.want_reply = *want_reply;

  struct assh_buffer_s *rq_data = (void*)&e->connection.global_request.rq_data;
  rq_data->size = p->data + p->data_size - data;
  rq_data->data = rq_data->size > 0 ? data : NULL;

  struct assh_buffer_s *rsp_data = &e->connection.global_request.rsp_data;
  rsp_data->data = NULL;
  rsp_data->size = 0;

  e->connection.global_request.success = 0;

  /* keep packet which contains request data */
  if (rq_data->size > 0)
    pv->pck = assh_packet_refinc(p);

  pv->state = ASSH_CN_STATE_GLOBAL_REQUEST;

  return ASSH_OK;
}

/************************************************* outgoing global request */

/* send a new global request */
assh_error_t assh_global_request(struct assh_session_s *s,
				 const char *type, size_t type_len,
				 const uint8_t *data, size_t data_len,
				 assh_bool_t want_reply,
				 struct assh_request_s **request)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;
  ASSH_ERR_RET(s->srv != &assh_service_connection ? ASSH_ERR_SERVICE_NA : 0);

  /* send global request packet */
  struct assh_packet_s *pout;
  ASSH_ERR_RET(assh_packet_alloc(s->ctx, SSH_MSG_GLOBAL_REQUEST,
				 4 + type_len + 1 + 4 + data_len, &pout));

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
      struct assh_request_s *r;
      ASSH_ERR_RET(assh_alloc(s->ctx, sizeof(*r),
			      ASSH_ALLOC_INTERNAL, (void**)&r));

      assh_queue_push_front(&pv->request_queue, &r->entry);

      if (request != NULL)
	*request = r;
    }

  return ASSH_OK;
}

/* cleanup global request reply event */
static ASSH_EVENT_DONE_FCN(assh_connection_global_request_reply_done)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;

  assert(s->srv == &assh_service_connection);
  ASSH_ERR_RET(pv->state != ASSH_CN_STATE_GLOBAL_REQUEST_REPLY ? ASSH_ERR_STATE : 0);

  /* release packet */
  assh_packet_release(pv->pck);
  pv->pck = NULL;
  pv->state = ASSH_CN_STATE_PROCESS;

  /* release request */
  struct assh_queue_entry_s *q = assh_queue_back(&pv->request_queue);
  struct assh_request_s *r = (struct assh_request_s *)q;

  assert(e->connection.global_request_reply.request == r);

  assh_queue_remove(&pv->request_queue, q);
  assh_free(s->ctx, q, ASSH_ALLOC_INTERNAL);

  return ASSH_OK;
}

/* setup an event from incoming global request reply */
static assh_error_t
assh_connection_global_request_reply(struct assh_session_s *s,
				      struct assh_packet_s *p,
				      struct assh_event_s *e,
				      assh_bool_t success)
{
  assh_error_t err;
  struct assh_connection_context_s *pv = s->srv_pv;

  /* get next request in queue */
  ASSH_ERR_RET(pv->request_queue.count == 0 ? ASSH_ERR_PROTOCOL : 0);
  struct assh_queue_entry_s *q = assh_queue_back(&pv->request_queue);
  struct assh_request_s *r = (struct assh_request_s *)q;

  /* setup event */
  e->id = ASSH_EVENT_CONNECTION_GLOBAL_REQUEST_REPLY;
  e->f_done = assh_connection_global_request_reply_done;

  *(struct assh_request_s**)&e->connection.global_request_reply.request = r;
  *(assh_bool_t*)&e->connection.global_request_reply.success = success;

  struct assh_buffer_s *rsp_data = (void*)&e->connection.global_request_reply.rsp_data;
  rsp_data->size = success ? p->data + p->data_size - p->head.end : 0;
  rsp_data->data = rsp_data->size > 0 ? p->head.end : NULL;

  /* keep packet which contains response data */
  if (rsp_data->size > 0)
    pv->pck = assh_packet_refinc(p);

  pv->state = ASSH_CN_STATE_GLOBAL_REQUEST_REPLY;

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

  pv->state = ASSH_CN_STATE_INIT;

  assh_queue_init(&pv->channel_queue);
  assh_queue_init(&pv->request_queue);

  pv->channel_map = NULL;
  pv->pck = NULL;

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

  assh_connection_queue_cleanup(s, &pv->request_queue);
  assh_connection_queue_cleanup(s, &pv->channel_queue);

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
    case ASSH_CN_STATE_INIT:
      e->id = ASSH_EVENT_CONNECTION_START;
      e->f_done = NULL;
      pv->state = ASSH_CN_STATE_PROCESS;
      return ASSH_OK;

    case ASSH_CN_STATE_PROCESS:
      break;

    default:
      ASSH_ERR_RET(ASSH_ERR_STATE);
    }

  if (p != NULL)
    {
      switch (p->head.msg)
        {
        case SSH_MSG_GLOBAL_REQUEST:
          err = assh_connection_global_request(s, p, e);
          break;
        case SSH_MSG_REQUEST_SUCCESS:
          err = assh_connection_global_request_reply(s, p, e, 1);
          break;
        case SSH_MSG_REQUEST_FAILURE:
          err = assh_connection_global_request_reply(s, p, e, 0);
          break;
        case SSH_MSG_CHANNEL_OPEN:
          err = assh_connection_channel_open(s, p, e);
          break;
        case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
          err = assh_connection_channel_open_reply(s, p, e, 1);
          break;
        case SSH_MSG_CHANNEL_OPEN_FAILURE:
          err = assh_connection_channel_open_reply(s, p, e, 0);
          break;
        case SSH_MSG_CHANNEL_WINDOW_ADJUST:
          err = assh_connection_channel_window_adjust(s, p);
          break;
        case SSH_MSG_CHANNEL_DATA:
          err = assh_connection_channel_data(s, p, 0);
          break;
        case SSH_MSG_CHANNEL_EXTENDED_DATA:
          err = assh_connection_channel_data(s, p, 1);
          break;
        case SSH_MSG_CHANNEL_EOF:
          err = assh_connection_channel_eof(s, p, e);
          break;
        case SSH_MSG_CHANNEL_CLOSE:
          err = assh_connection_channel_close(s, p, e);
          break;
        case SSH_MSG_CHANNEL_REQUEST:
          err = assh_connection_channel_request(s, p, e);
          break;
        case SSH_MSG_CHANNEL_SUCCESS:
          err = assh_connection_channel_request_reply(s, p, e, 1);
          break;
        case SSH_MSG_CHANNEL_FAILURE:
          err = assh_connection_channel_request_reply(s, p, e, 0);
          break;
	default:
	  err = ASSH_ERR_PROTOCOL;
        }
      ASSH_ERR_RET(err);
      return ASSH_OK;
    }

  if (s->tr_st == ASSH_TR_DISCONNECTED)
    {
      if (pv->request_queue.count > 0)
        ASSH_ERR_RET(assh_connection_global_request_reply(s, NULL, e, 0));
      else if (pv->channel_queue.count > 0)
        /* ASSH_ERR_RET(assh_connection_channel_reply(s, NULL, e, 0)) */;
      //      else if (map.head)    return close event;
      return ASSH_OK;
    }

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

