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
static assh_error_t
assh_service_got_request(struct assh_session_s *s,
                         struct assh_packet_s *p)
{
  assh_error_t err;

  const uint8_t *name = p->head.end, *name_end;
  ASSH_RET_ON_ERR(assh_packet_check_string(p, name, &name_end));

  size_t name_len = name_end - name - 4;

  /* lookup service */
  const struct assh_service_s *srv;
  ASSH_RET_IF_TRUE(assh_service_by_name(s->ctx, name_len,
		    (const char *)name + 4, &srv) != ASSH_OK,
               ASSH_ERR_SERVICE_NA);

  ASSH_RET_IF_TRUE(!s->user_auth_done && !srv->no_user_auth,
               ASSH_ERR_SERVICE_NA | ASSH_ERRSV_DISCONNECT);

  struct assh_packet_s *pout;
  ASSH_RET_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_SERVICE_ACCEPT,
				 name_len + 4, &pout));

  /* send accept packet */
  uint8_t *namep;
  ASSH_ASSERT(assh_packet_add_string(pout, name_len, &namep));
  memcpy(namep, srv->name, name_len);
  assh_transport_push(s, pout);

  s->srv = srv;

  return ASSH_OK;
}
#endif

#ifdef CONFIG_ASSH_CLIENT
static assh_error_t
assh_service_got_accept(struct assh_session_s *s,
                        struct assh_packet_s *p)
{
  assh_error_t err;

  /* check accepted service name */
  const uint8_t *name = p->head.end, *name_end;
  ASSH_RET_ON_ERR(assh_packet_check_string(p, name, &name_end));

  ASSH_RET_IF_TRUE(assh_ssh_string_compare(name, s->srv->name),
	       ASSH_ERR_PROTOCOL);

  return ASSH_OK;
}

static assh_error_t
assh_service_send_request(struct assh_session_s *s)
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
  s->srv = srv;
  s->srv_st = ASSH_SRV_REQUESTED;

  return ASSH_OK;
}
#endif

void assh_service_stop(struct assh_session_s *s)
{
  if (s->srv_st == ASSH_SRV_RUNNING)
    {
      const struct assh_service_s *srv = s->srv;

      srv->f_cleanup(s);

      s->srv_pv = NULL;
      s->srv_st = ASSH_SRV_NONE;
    }
}

void assh_service_start(struct assh_session_s *s,
                        const struct assh_service_s *next)
{
  assh_service_stop(s);

  s->srv = next;
  s->srv_st = ASSH_SRV_INIT;
}

#ifdef CONFIG_ASSH_CLIENT
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_service_next(struct assh_session_s *s,
                  const struct assh_service_s **srv)
{
  struct assh_context_s *c = s->ctx;
  assh_error_t err;

  assert(c->type == ASSH_CLIENT);

  ASSH_RET_IF_TRUE(s->srv_index >= c->srvs_count, ASSH_ERR_SERVICE_NA);
  *srv = c->srvs[s->srv_index++];

  return ASSH_OK;
}
#endif

static ASSH_EVENT_DONE_FCN(assh_event_service_start_done)
{
  assert(s->srv_st == ASSH_SRV_INIT_EVENT);
  s->srv_st = ASSH_SRV_RUNNING;

  return ASSH_OK;
}

assh_error_t assh_service_loop(struct assh_session_s *s,
                               struct assh_packet_s *p,
                               struct assh_event_s *e)
{
  assh_error_t err;

  while (1)
    {

    switch (s->srv_st)
      {
      case ASSH_SRV_NONE:
        if (p != NULL)
          {
            /* no service is currently running, we should receive a
               request packet on the server side. */
#ifdef CONFIG_ASSH_SERVER
            if (p->head.msg == SSH_MSG_SERVICE_REQUEST
# ifdef CONFIG_ASSH_CLIENT
                && s->ctx->type == ASSH_SERVER
# endif
               )
              {
                if (s->tr_st >= ASSH_TR_DISCONNECT)
                  return ASSH_OK;

                ASSH_RET_ON_ERR(assh_service_got_request(s, p)
                             | ASSH_ERRSV_DISCONNECT);

                s->srv_st = ASSH_SRV_INIT;
                p = NULL;
                continue;
              }
#endif
            ASSH_RETURN(ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);
          }

#ifdef CONFIG_ASSH_CLIENT
# ifdef CONFIG_ASSH_SERVER
        /* no service is currently running, we have to send a
           request packet on the client side. */
        if (s->ctx->type == ASSH_CLIENT)
# endif
          ASSH_RET_ON_ERR(assh_service_send_request(s) | ASSH_ERRSV_DISCONNECT);
#endif
        return ASSH_OK;

#ifdef CONFIG_ASSH_CLIENT
      case ASSH_SRV_REQUESTED:
        if (p != NULL)
          {
            /* we previously sent a service request packet, expecting the
               accept packet from the server. */
            if (p->head.msg == SSH_MSG_SERVICE_ACCEPT)
              {
                ASSH_RET_ON_ERR(assh_service_got_accept(s, p)
                             | ASSH_ERRSV_DISCONNECT);

                s->srv_st = ASSH_SRV_INIT;
                p = NULL;
                continue;
              }
            ASSH_RETURN(ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);
          }
        return ASSH_OK;
#endif

      case ASSH_SRV_INIT:
        if (s->tr_st >= ASSH_TR_DISCONNECT)
          return ASSH_OK;

        /* starts service and report event */
        ASSH_RET_ON_ERR(s->srv->f_init(s) | ASSH_ERRSV_DISCONNECT);

        e->id = ASSH_EVENT_SERVICE_START;
        e->f_done = assh_event_service_start_done;
        e->service.start.srv = s->srv;

        s->srv_st = ASSH_SRV_INIT_EVENT;

        /* packet not consumed by the init */
        return p != NULL ? ASSH_NO_DATA : ASSH_OK;

      case ASSH_SRV_INIT_EVENT:
        ASSH_UNREACHABLE();

      case ASSH_SRV_RUNNING:
        ASSH_RET_IF_TRUE(p != NULL &&
                     (p->head.msg == SSH_MSG_SERVICE_ACCEPT ||
                      p->head.msg == SSH_MSG_SERVICE_REQUEST),
                     ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);

        /* call service processing function, p may be NULL */
        ASSH_RET_ON_ERR(s->srv->f_process(s, p, e));

        /* Handle as a consumed packet when no packet passed to
           service. The pointer might have been set to NULL in a
           previous iteration. */
        if (p == NULL)
          err = ASSH_OK;

        /* report any event */
        if (e->id != ASSH_EVENT_INVALID)
          return err;    /* err may be ASSH_OK or ASSH_NO_DATA */

        /* need to start the next service or
           packet not consumed yet */
        if (s->srv_st == ASSH_SRV_INIT ||
            err == ASSH_NO_DATA)
          continue;

        return ASSH_OK;

      default:
        ASSH_UNREACHABLE();
      }
  }
}
