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

#include <stdarg.h>
#include <string.h>

assh_error_t assh_service_register(struct assh_context_s *c,
				   struct assh_service_s *srv)
{
  assh_error_t err;

  ASSH_ERR_RET(srv->side != c->type ? ASSH_ERR_NOTSUP : 0);
  ASSH_ERR_RET(c->srvs_count == ASSH_MAX_SERVICES ? ASSH_ERR_OVERFLOW : 0);
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
      ASSH_ERR_GTO(assh_service_register(c, srv), err_);
    }
 err_:

  va_end(ap);
  return err;
}

assh_error_t assh_service_register_default(struct assh_context_s *c)
{
  switch (c->type)
    {
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_CLIENT:
      return assh_service_register_va(c, &assh_service_userauth_client,
                                      &assh_service_connection_client, NULL);
#endif

#ifdef CONFIG_ASSH_SERVER
    case ASSH_SERVER:
      return assh_service_register_va(c, &assh_service_userauth_server,
                                      &assh_service_connection_server, NULL);
#endif

    default:
      assert(!"possible");
    }
}

assh_error_t assh_service_by_name(struct assh_context_s *c,
                                  size_t name_len, const char *name,
                                  const struct assh_service_s **srv_)
{
  assh_error_t err;
  unsigned int i;

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

  ASSH_ERR_RET(ASSH_ERR_SERVICE_NA);
}

#ifdef CONFIG_ASSH_SERVER
assh_error_t assh_service_got_request(struct assh_session_s *s,
                                      struct assh_packet_s *p)
{
  assh_error_t err;

  ASSH_ERR_RET(s->srv != NULL ? ASSH_ERR_PROTOCOL : 0);

  uint8_t *name = p->head.end, *name_end;
  ASSH_ERR_RET(assh_packet_check_string(p, name, &name_end));
  size_t name_len = name_end - name - 4;

  /* lookup service */
  const struct assh_service_s *srv;
  ASSH_ERR_GTO(assh_service_by_name(s->ctx, name_len, (const char *)name + 4, &srv), err_lookup);

  /* init service */
  s->srv = srv;
  ASSH_ERR_GTO(srv->f_init(s), err_srv);

  /* send accept packet */
  struct assh_packet_s *pout;
  ASSH_ERR_RET(assh_packet_alloc(s, SSH_MSG_SERVICE_ACCEPT, name_len + 4, &pout));
  ASSH_ERR_RET(assh_packet_add_string(pout, name_len, &name));
  memcpy(name, srv->name, name_len);
  assh_transport_push(s, pout);

  return ASSH_OK;

 err_lookup:
  ASSH_ERR_RET(assh_transport_disconnect(s, SSH_DISCONNECT_SERVICE_NOT_AVAILABLE));
  return err;

 err_srv:
  s->srv = NULL;
  return err;
}
#endif

#ifdef CONFIG_ASSH_CLIENT
assh_error_t assh_service_got_accept(struct assh_session_s *s,
                                     struct assh_packet_s *p)
{
  assh_error_t err;

  ASSH_ERR_RET(s->srv_rq == NULL || s->srv != NULL ? ASSH_ERR_PROTOCOL : 0);

  /* check accepted service name */
  uint8_t *name = p->head.end, *name_end;
  ASSH_ERR_RET(assh_packet_check_string(p, name, &name_end));
  size_t name_len = name_end - name - 4;

  ASSH_ERR_RET(strncmp(s->srv_rq->name, (const char*)name + 4, name_len) ||
	       s->srv_rq->name[name_len] != '\0' ? ASSH_ERR_PROTOCOL : 0);

  /* init service */
  s->srv = s->srv_rq;
  s->srv_rq = NULL;
  ASSH_ERR_GTO(s->srv->f_init(s), err_srv);

  return ASSH_OK;
 err_srv:
  s->srv = NULL;
  return err;
}

assh_error_t assh_service_send_request(struct assh_session_s *s)
{
  assh_error_t err;

  /** get next service to request */
  ASSH_ERR_RET(s->srv_index >= s->ctx->srvs_count
	       ? ASSH_ERR_SERVICE_NA : 0);

  const struct assh_service_s *srv = s->ctx->srvs[s->srv_index];

  /* send request packet */
  struct assh_packet_s *pout;
  size_t name_len = strlen(srv->name);
  uint8_t *name;
  ASSH_ERR_RET(assh_packet_alloc(s, SSH_MSG_SERVICE_REQUEST, name_len + 4, &pout));
  ASSH_ERR_RET(assh_packet_add_string(pout, name_len, &name));
  memcpy(name, srv->name, name_len);
  assh_transport_push(s, pout);

  s->srv_index++;
  s->srv_rq = srv;

  return ASSH_OK;
}
#endif
