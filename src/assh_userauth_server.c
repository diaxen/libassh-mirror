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

#include "assh_userauth_server_pv.h"

#include <assh/assh_service.h>
#include <assh/assh_session.h>
#include <assh/assh_transport.h>
#include <assh/assh_event.h>
#include <assh/assh_packet.h>
#include <assh/assh_algo.h>
#include <assh/assh_sign.h>
#include <assh/assh_key.h>
#include <assh/assh_alloc.h>

ASSH_EVENT_SIZE_SASSERT(userauth_server);

#include <stdlib.h>

static const struct assh_userauth_server_method_s
*assh_userauth_server_methods[] = {
#ifdef CONFIG_ASSH_SERVER_AUTH_NONE
  &assh_userauth_server_none,
#endif
#ifdef CONFIG_ASSH_SERVER_AUTH_PASSWORD
  &assh_userauth_server_password,
#endif
#ifdef CONFIG_ASSH_SERVER_AUTH_PUBLICKEY
  &assh_userauth_server_publickey,
#endif
#ifdef CONFIG_ASSH_SERVER_AUTH_HOSTBASED
  &assh_userauth_server_hostbased,
#endif
#ifdef CONFIG_ASSH_SERVER_AUTH_KEYBOARD
  &assh_userauth_server_keyboard,
#endif
  NULL
};

static ASSH_SERVICE_INIT_FCN(assh_userauth_server_init)
{
  assh_error_t err;
  struct assh_userauth_context_s *pv;

  ASSH_RET_ON_ERR(assh_alloc(s->ctx, sizeof(*pv),
                ASSH_ALLOC_SECUR, (void**)&pv));

  s->srv_pv = pv;
  pv->deadline = s->time + ASSH_TIMEOUT_USERAUTH;
  pv->safety = 99;
  pv->method = NULL;
  pv->methods = 0;

  ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_METHODS);
  pv->srv = NULL;

  pv->pck = NULL;

#if defined(CONFIG_ASSH_SERVER_AUTH_HOSTBASED) || \
  defined(CONFIG_ASSH_SERVER_AUTH_PUBLICKEY)
  pv->pub_key = NULL;
#endif

#ifdef CONFIG_ASSH_SERVER_AUTH_PUBLICKEY
  ASSH_SET_STATE(pv, pubkey_state, ASSH_USERAUTH_PUBKEY_NONE);
#endif

#ifdef CONFIG_ASSH_SERVER_AUTH_KEYBOARD
  pv->keyboard_array = NULL;
#endif

  return ASSH_OK;
}

static void assh_userauth_server_flush_state(struct assh_session_s *s)
{
  struct assh_userauth_context_s *pv = s->srv_pv;

  pv->method = NULL;

#if defined(CONFIG_ASSH_SERVER_AUTH_HOSTBASED) || \
  defined(CONFIG_ASSH_SERVER_AUTH_PUBLICKEY)
  assh_key_flush(s->ctx, &pv->pub_key);
#endif

#ifdef CONFIG_ASSH_SERVER_AUTH_PUBLICKEY
  ASSH_SET_STATE(pv, pubkey_state, ASSH_USERAUTH_PUBKEY_NONE);
#endif

#ifdef CONFIG_ASSH_SERVER_AUTH_KEYBOARD
  assh_free(s->ctx, pv->keyboard_array);
  pv->keyboard_array = NULL;
#endif
}

static ASSH_SERVICE_CLEANUP_FCN(assh_userauth_server_cleanup)
{
  struct assh_userauth_context_s *pv = s->srv_pv;

  assh_userauth_server_flush_state(s);

  assh_packet_release(pv->pck);

  assh_free(s->ctx, pv);
}

/* send the authentication failure packet */
assh_error_t
assh_userauth_server_send_failure(struct assh_session_s *s,
                                  assh_bool_t partial)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  size_t psize = /* name-list size */ 4 + /* boolean */ 1;

  const struct assh_userauth_server_method_s *m;
  assh_bool_t first = 1;
  uint_fast8_t i;

  for (i = 0; (m = assh_userauth_server_methods[i]); i++)
    if (pv->methods & m->mask)
      {
        psize += strlen(m->name + first);
        first = 0;
      }

  struct assh_packet_s *pout;
  ASSH_RET_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_USERAUTH_FAILURE,
                                 psize, &pout));

  uint8_t *list, *partial_success;

  ASSH_ASSERT(assh_packet_add_string(pout, 0, &list));

  first = 1;
  for (i = 0; (m = assh_userauth_server_methods[i]); i++)
    {
      if (!(pv->methods & m->mask))
        continue;

      const char *mname = m->name + first;
      size_t mname_len = strlen(mname);
      uint8_t *s;
      ASSH_ASSERT(assh_packet_enlarge_string(pout, list, mname_len, &s));
      memcpy(s, mname, mname_len);
      first = 0;
    }

  ASSH_ASSERT(assh_packet_add_array(pout, 1, &partial_success));
  *partial_success = partial;
  assh_transport_push(s, pout);

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_server_success_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  assert(pv->state == ASSH_USERAUTH_ST_SUCCESS_DONE);

  /* promote event processing error */
  ASSH_RET_IF_TRUE(ASSH_ERR_ERROR(inerr), inerr | ASSH_ERRSV_DISCONNECT);

  const struct assh_event_userauth_server_success_s *ev =
    &e->userauth_server.success;

  pv->methods = ev->methods;

  if (pv->methods)              /* report partial success */
    {
      ASSH_RET_IF_TRUE(!(pv->methods & ASSH_USERAUTH_METHOD_SERVER_IMPLEMENTED),
                   ASSH_ERR_MISSING_ALGO | ASSH_ERRSV_DISCONNECT);

      assert(pv->pck == NULL);
      assh_userauth_server_flush_state(s);
      ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_WAIT_RQ);
      ASSH_RETURN(assh_userauth_server_send_failure(s, 1)
                     | ASSH_ERRSV_DISCONNECT);
    }

  /* send the authentication success packet */
  struct assh_packet_s *pout;
  ASSH_RET_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_USERAUTH_SUCCESS, 0, &pout)
	       | ASSH_ERRSV_DISCONNECT);
  assh_transport_push(s, pout);

  s->user_auth_done = 1;
  assh_service_start(s, pv->srv);

  return ASSH_OK;
}

/* handle authentication success */
assh_error_t assh_userauth_server_success(struct assh_session_s *s,
                                          struct assh_event_s *e)
{
  struct assh_userauth_context_s *pv = s->srv_pv;

  struct assh_event_userauth_server_success_s *ev =
    &e->userauth_server.success;

  ev->username.str = pv->username;
  ev->username.len = strlen(pv->username);
  ev->method = pv->method->mask;
  ev->sign_safety = pv->safety;
  ev->methods = 0;

  e->id = ASSH_EVENT_USERAUTH_SERVER_SUCCESS;
  e->f_done = assh_userauth_server_success_done;

  ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_SUCCESS_DONE);

  return ASSH_OK;
}

#if defined(CONFIG_ASSH_SERVER_AUTH_HOSTBASED) || \
  defined(CONFIG_ASSH_SERVER_AUTH_PUBLICKEY)

assh_error_t
assh_userauth_server_get_key(struct assh_session_s *s,
                             const uint8_t *algo_name,
                             const uint8_t *pub_blob,
                             const struct assh_algo_s **algo,
                             struct assh_key_s **pub_key,
                             const struct assh_algo_name_s **namep)
{
  assh_error_t err;

  /* check if we support the requested signature algorithm */
  if (assh_algo_by_name(s->ctx, ASSH_ALGO_SIGN, (char*)algo_name + 4,
			assh_load_u32(algo_name), algo, namep) != ASSH_OK)
    return ASSH_NO_DATA;

  /* load the public key from the client provided blob */
  const uint8_t *key_blob = pub_blob + 4;
  ASSH_RET_ON_ERR(assh_key_load(s->ctx, pub_key, (*algo)->key, ASSH_ALGO_SIGN,
                 ASSH_KEY_FMT_PUB_RFC4253, &key_blob,
                 assh_load_u32(pub_blob)));

  /* check if the key can be used by the algorithm */
  if (!assh_algo_suitable_key(s->ctx, *algo, *pub_key))
    {
      assh_key_drop(s->ctx, pub_key);
      return ASSH_NO_DATA;
    }

  return ASSH_OK;
}

assh_error_t
assh_userauth_server_sign_check(struct assh_session_s *s,
                                struct assh_packet_s *p,
                                const uint8_t *sign_str)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  uint8_t sid_len[4];   /* fake string header for session id */
  assh_store_u32(sid_len, s->session_id_len);

  /* buffers that have been signed by the client */
  struct assh_cbuffer_s data[3] = {
    { .data = sid_len,         .len = 4 },
    { .data = s->session_id,   .len = s->session_id_len },
    { .data = &p->head.msg,    .len = sign_str - &p->head.msg },
  };

  assh_safety_t sign_safety;

  /* check the signature */
  ASSH_RET_ON_ERR(assh_sign_check(s->ctx, pv->algo, pv->pub_key, 3,
                 data, sign_str + 4, assh_load_u32(sign_str), &sign_safety));

  pv->safety = ASSH_MIN(sign_safety, pv->safety);

  return ASSH_OK;
}

#endif

static assh_error_t assh_userauth_server_req(struct assh_session_s *s,
                                             struct assh_packet_s *p,
                                             struct assh_event_s *e)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  switch (p->head.msg)
    {
    default:
      if (p->head.msg < 80)
        ASSH_RETURN(assh_transport_unimp(s, p));

    case SSH_MSG_UNIMPLEMENTED:
      ASSH_RETURN(ASSH_ERR_PROTOCOL);

    case SSH_MSG_USERAUTH_REQUEST:
      break;
    }

  /* check auth attempts count */
  ASSH_RET_IF_TRUE(pv->tries == 0, ASSH_ERR_NO_AUTH | ASSH_ERRSV_DISCONNECT);

  uint8_t *username = p->head.end;
  const uint8_t *srv_name, *method_name, *auth_data;

  ASSH_RET_ON_ERR(assh_packet_check_string(p, username, &srv_name));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, srv_name, &method_name));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, method_name, &auth_data));

  const struct assh_userauth_server_method_s *m;
  uint_fast8_t i;

  for (i = 0; (m = assh_userauth_server_methods[i]); i++)
    {
      if (assh_ssh_string_compare(method_name, m->name + 1))
        continue;

      if (!(pv->methods & m->mask))
        break;

      if (pv->method != m ||
          assh_ssh_string_compare(srv_name, pv->srv->name) ||
          assh_ssh_string_compare(username, pv->username))
        {
          assert(pv->pck == NULL);
          assh_userauth_server_flush_state(s);

          /* lookup service name */
          if (assh_service_by_name(s->ctx, assh_load_u32(srv_name),
                                   (char*)srv_name + 4, &pv->srv))
            break;

          pv->method = m;

          /* keep user name */
          ASSH_RET_ON_ERR(assh_ssh_string_copy(username, pv->username, sizeof(pv->username)));
        }

      ASSH_RETURN(m->f_req(s, p, e, auth_data)
                    | ASSH_ERRSV_DISCONNECT);
    }

  assert(pv->pck == NULL);
  assh_userauth_server_flush_state(s);
  assert(pv->tries > 0);
  pv->tries--;

  ASSH_RET_ON_ERR(assh_userauth_server_send_failure(s, 0));
  ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_WAIT_RQ);

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_server_get_methods_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  assert(pv->state == ASSH_USERAUTH_ST_METHODS_DONE);

  /* promote event processing error */
  ASSH_RET_IF_TRUE(ASSH_ERR_ERROR(inerr), inerr | ASSH_ERRSV_DISCONNECT);

  const struct assh_event_userauth_server_methods_s *ev =
    &e->userauth_server.methods;

  pv->methods = ev->methods;
  pv->tries = ev->retries + 1;

  ASSH_RET_IF_TRUE(!(pv->methods & ASSH_USERAUTH_METHOD_SERVER_IMPLEMENTED),
               ASSH_ERR_MISSING_ALGO | ASSH_ERRSV_DISCONNECT);

  size_t bsize = ev->banner.size;
  size_t lsize = ev->bnlang.size;

  if (bsize)
    {
      struct assh_packet_s *pout;
      ASSH_RET_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_USERAUTH_BANNER,
                                     4 + bsize + 4 + lsize, &pout)
                   | ASSH_ERRSV_DISCONNECT);
      uint8_t *str;
      ASSH_ASSERT(assh_packet_add_string(pout, bsize, &str));
      memcpy(str, ev->banner.str, bsize);
      ASSH_ASSERT(assh_packet_add_string(pout, lsize, &str));
      memcpy(str, ev->bnlang.str, lsize);
      assh_transport_push(s, pout);
    }

  if (ev->failed)
    ASSH_RET_ON_ERR(assh_userauth_server_send_failure(s, 0)
                 | ASSH_ERRSV_DISCONNECT);

  ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_WAIT_RQ);

  return ASSH_OK;
}

static assh_error_t
assh_userauth_server_get_methods(struct assh_session_s *s,
                                 struct assh_event_s *e)
{
  struct assh_userauth_context_s *pv = s->srv_pv;

  struct assh_event_userauth_server_methods_s *ev =
    &e->userauth_server.methods;

  ev->failed = 0;

  ev->banner.size = 0;
  ev->bnlang.size = 0;

  ev->methods = ASSH_USERAUTH_METHOD_SERVER_IMPLEMENTED &
    (ASSH_USERAUTH_METHOD_PUBKEY |
     ASSH_USERAUTH_METHOD_PASSWORD);

  ev->retries = 10;

  e->id = ASSH_EVENT_USERAUTH_SERVER_METHODS;
  e->f_done = assh_userauth_server_get_methods_done;

  ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_METHODS_DONE);

  return ASSH_OK;
}

static void
assh_userauth_server_get_methods_failed(struct assh_session_s *s,
                                        struct assh_event_s *e)
{
  struct assh_userauth_context_s *pv = s->srv_pv;

  struct assh_event_userauth_server_methods_s *ev =
    &e->userauth_server.methods;

  ev->failed = 1;

  ev->banner.size = 0;
  ev->bnlang.size = 0;

  ev->methods = pv->methods;
  ev->retries = pv->tries - 1;

  e->id = ASSH_EVENT_USERAUTH_SERVER_METHODS;
  e->f_done = assh_userauth_server_get_methods_done;

  ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_METHODS_DONE);
}

/* handle authentication failure */
assh_error_t
assh_userauth_server_failure(struct assh_session_s *s,
                             struct assh_event_s *e)
{
  struct assh_userauth_context_s *pv = s->srv_pv;

  assert(pv->pck == NULL);
  assh_userauth_server_flush_state(s);

  if (e)
    assh_userauth_server_get_methods_failed(s, e);
  else
    ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_FAILURE);

  assert(pv->tries > 0);
  pv->tries--;

  return ASSH_OK;
}

static ASSH_SERVICE_PROCESS_FCN(assh_userauth_server_process)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  if (s->tr_st >= ASSH_TR_DISCONNECT)
    return ASSH_OK;

  s->deadline = pv->deadline;

  switch (pv->state)
    {
    case ASSH_USERAUTH_ST_METHODS:
      ASSH_RET_ON_ERR(assh_userauth_server_get_methods(s, e)
                   | ASSH_ERRSV_DISCONNECT);
      return ASSH_NO_DATA;

    case ASSH_USERAUTH_ST_FAILURE:
      assh_userauth_server_get_methods_failed(s, e);
      return ASSH_NO_DATA;

    case ASSH_USERAUTH_ST_SUCCESS:
      ASSH_RET_ON_ERR(assh_userauth_server_success(s, e)
                   | ASSH_ERRSV_DISCONNECT);
      return ASSH_NO_DATA;

#ifdef CONFIG_ASSH_SERVER_AUTH_PASSWORD
    case ASSH_USERAUTH_ST_PASSWORD_WAIT_CHANGE:
#endif
    case ASSH_USERAUTH_ST_WAIT_RQ:
      if (p == NULL)
        return ASSH_OK;
      ASSH_RETURN(assh_userauth_server_req(s, p, e)
                     | ASSH_ERRSV_DISCONNECT);

#ifdef CONFIG_ASSH_SERVER_AUTH_KEYBOARD
    case ASSH_USERAUTH_ST_KEYBOARD_INFO_SENT:
    case ASSH_USERAUTH_ST_KEYBOARD_CONTINUE:
#endif
    case ASSH_USERAUTH_ST_CONTINUE:
      ASSH_RETURN(pv->method->f_process(s, p, e)
                    | ASSH_ERRSV_DISCONNECT);

    default:
      ASSH_UNREACHABLE();
    }
}

const struct assh_service_s assh_service_userauth_server =
{
  .name = "ssh-userauth",
  .side = ASSH_SERVER,
  .no_user_auth = 1,
  .f_init = assh_userauth_server_init,
  .f_cleanup = assh_userauth_server_cleanup,
  .f_process = assh_userauth_server_process,
};

