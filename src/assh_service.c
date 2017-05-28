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
#include <assh/assh_session.h>
#include <assh/assh_service.h>
#include <assh/assh_packet.h>
#include <assh/assh_transport.h>

#include <assh/assh_userauth_client.h>
#include <assh/assh_userauth_server.h>
#include <assh/assh_connection.h>

#include <assh/assh_event.h>
#include <stdarg.h>
#include <string.h>

assh_error_t assh_service_register(struct assh_context_s *c,
				   struct assh_service_s *srv)
{
  assh_error_t err;

  ASSH_RET_IF_TRUE(srv->side != ASSH_CLIENT_SERVER &&
               srv->side != c->type, ASSH_ERR_NOTSUP);

  ASSH_RET_IF_TRUE(c->srvs_count == CONFIG_ASSH_MAX_SERVICES, ASSH_ERR_MEM);

  c->srvs[c->srvs_count++] = srv;
  return ASSH_OK;
}

assh_error_t
assh_service_register_va(struct assh_context_s *c, ...)
{
  assh_error_t err = ASSH_OK;
  va_list ap;
  va_start(ap, c);

  while (1)
    {
      struct assh_service_s *srv = va_arg(ap, void*);
      if (srv == NULL)
        break;
      ASSH_JMP_ON_ERR(assh_service_register(c, srv), err_);
    }
 err_:

  va_end(ap);
  return err;
}

assh_error_t assh_service_register_default(struct assh_context_s *c)
{
  assh_error_t err;

  switch (c->type)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_CLIENT:
      ASSH_RETURN(assh_service_register_va(c, &assh_service_userauth_client,
		    &assh_service_connection, NULL));
#endif

#ifdef CONFIG_ASSH_SERVER
    case ASSH_SERVER:
      ASSH_RETURN(assh_service_register_va(c, &assh_service_userauth_server,
		    &assh_service_connection, NULL));
#endif

    default:
      ASSH_UNREACHABLE();
    }
}

assh_error_t assh_service_by_name(struct assh_context_s *c,
                                  size_t name_len, const char *name,
                                  const struct assh_service_s **srv_)
{
  uint_fast8_t i;

  /* lookup service name */
  for (i = 0; i < c->srvs_count; i++)
    {
      const struct assh_service_s *srv = c->srvs[i];

      if (!strncmp(srv->name, name, name_len) &&
          srv->name[name_len] == '\0')
        {
          *srv_ = srv;
          return ASSH_OK;
        }
    }

  return ASSH_NOT_FOUND;
}

#ifdef CONFIG_ASSH_SERVER
assh_error_t assh_service_got_request(struct assh_session_s *s,
                                      struct assh_packet_s *p)
{
  assh_error_t err;

  ASSH_RET_IF_TRUE(s->srv != NULL, ASSH_ERR_PROTOCOL);

  const uint8_t *name = p->head.end, *name_end;
  ASSH_RET_ON_ERR(assh_packet_check_string(p, name, &name_end));

  size_t name_len = name_end - name - 4;

  /* lookup service */
  const struct assh_service_s *srv;
  ASSH_RET_IF_TRUE(assh_service_by_name(s->ctx, name_len,
		    (const char *)name + 4, &srv) != ASSH_OK,
               ASSH_ERR_SERVICE_NA);

  struct assh_packet_s *pout;
  ASSH_RET_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_SERVICE_ACCEPT,
				 name_len + 4, &pout));

  /* init service */
  ASSH_JMP_ON_ERR(srv->f_init(s), err_pkt);

  /* send accept packet */
  uint8_t *namep;
  ASSH_ASSERT(assh_packet_add_string(pout, name_len, &namep));
  memcpy(namep, srv->name, name_len);
  assh_transport_push(s, pout);

  return ASSH_OK;
 err_pkt:
  assh_packet_release(pout);
  return err;
}
#endif

#ifdef CONFIG_ASSH_CLIENT
assh_error_t assh_service_got_accept(struct assh_session_s *s,
                                     struct assh_packet_s *p)
{
  assh_error_t err;

  ASSH_RET_IF_TRUE(s->srv_rq == NULL || s->srv != NULL, ASSH_ERR_PROTOCOL);

  /* check accepted service name */
  const uint8_t *name = p->head.end, *name_end;
  ASSH_RET_ON_ERR(assh_packet_check_string(p, name, &name_end));

  ASSH_RET_IF_TRUE(assh_ssh_string_compare(name, s->srv_rq->name),
	       ASSH_ERR_PROTOCOL);

  /* init service */
  const struct assh_service_s *srv = s->srv_rq;
  s->srv_rq = NULL;

  ASSH_RETURN(srv->f_init(s));
}

assh_error_t assh_service_send_request(struct assh_session_s *s)
{
  assh_error_t err;

  /** get next service to request */
  ASSH_RET_IF_TRUE(s->srv_index >= s->ctx->srvs_count,
	       ASSH_ERR_NO_MORE_SERVICE | ASSH_ERRSV_DISCONNECT);

  const struct assh_service_s *srv = s->ctx->srvs[s->srv_index];

  /* send request packet */
  struct assh_packet_s *pout;
  size_t name_len = strlen(srv->name);
  uint8_t *name;

  ASSH_RET_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_SERVICE_REQUEST,
				 name_len + 4, &pout));
  ASSH_ASSERT(assh_packet_add_string(pout, name_len, &name));

  memcpy(name, srv->name, name_len);
  assh_transport_push(s, pout);

  s->srv_index++;
  s->srv_rq = srv;

  return ASSH_OK;
}
#endif

assh_error_t assh_service_loop(struct assh_session_s *s,
                               struct assh_packet_s *p,
                               struct assh_event_s *e)
{
  const struct assh_service_s *srv;
  assh_error_t err;

  do {
    srv = s->srv;

    if (srv == NULL)
      {
        /* do not start a service when disconnecting */
        if (s->tr_st >= ASSH_TR_DISCONNECT)
          break;

        ASSH_RET_IF_TRUE(p != NULL, ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);

#ifdef CONFIG_ASSH_CLIENT
        /* client send a service request if no service is currently running */
        if (s->ctx->type == ASSH_CLIENT && s->srv_rq == NULL)
          ASSH_RET_ON_ERR(assh_service_send_request(s) | ASSH_ERRSV_DISCONNECT);
#endif
        break;
      }

    /* call service processing function, p may be NULL */
    ASSH_RET_ON_ERR(srv->f_process(s, p, e));

    /* we have an event to report */
    if (e->id != ASSH_EVENT_INVALID)
      {
        if (p == NULL)
          err = ASSH_OK;
        return err;               /* err may be ASSH_OK or ASSH_NO_DATA */
      }

    if (err == ASSH_OK)
      p = NULL;

  } while (err == ASSH_NO_DATA || /* input packet not consumed by service */
           srv != s->srv          /* service has changed */);

  return ASSH_OK;
}
