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

#include "assh_userauth_client_pv.h"

#include <assh/assh_service.h>
#include <assh/assh_session.h>
#include <assh/assh_packet.h>
#include <assh/assh_transport.h>
#include <assh/assh_event.h>
#include <assh/assh_key.h>
#include <assh/assh_sign.h>
#include <assh/assh_alloc.h>

ASSH_EVENT_SIZE_SASSERT(userauth_client);

#include <stdlib.h>

static const struct assh_userauth_client_method_s
*assh_userauth_client_methods[] = {
  &assh_userauth_client_none,
#ifdef CONFIG_ASSH_CLIENT_AUTH_PASSWORD
  &assh_userauth_client_password,
#endif
#ifdef CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY
  &assh_userauth_client_publickey,
#endif
#ifdef CONFIG_ASSH_CLIENT_AUTH_HOSTBASED
  &assh_userauth_client_hostbased,
#endif
#ifdef CONFIG_ASSH_CLIENT_AUTH_KEYBOARD
  &assh_userauth_client_keyboard,
#endif
  NULL
};

static ASSH_SERVICE_INIT_FCN(assh_userauth_client_init)
{
  struct assh_userauth_context_s *pv;
  const struct assh_service_s *srv;
  assh_error_t err;

  ASSH_RET_ON_ERR(assh_service_next(s, &srv));

  ASSH_RET_ON_ERR(assh_alloc(s->ctx, sizeof(*pv),
                    ASSH_ALLOC_SECUR, (void**)&pv));

  pv->methods = 0;
  ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_GET_USERNAME);

  s->srv_pv = pv;

#ifdef CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY
  pv->pubkey.keys = NULL;
  pv->pubkey.auth_data = NULL;
#endif

#ifdef CONFIG_ASSH_CLIENT_AUTH_HOSTBASED
  pv->hostkey.keys = NULL;
  pv->hostkey.auth_data = NULL;
#endif

#ifdef CONFIG_ASSH_CLIENT_AUTH_KEYBOARD
  pv->keyboard_array = NULL;
#endif

  /* get next client requested service */
  pv->pck = NULL;
  pv->srv = srv;

  return ASSH_OK;
}

static ASSH_SERVICE_CLEANUP_FCN(assh_userauth_client_cleanup)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  struct assh_context_s *c = s->ctx;

#ifdef CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY
  assh_key_flush(c, &pv->pubkey.keys);
  assh_free(c, pv->pubkey.auth_data);
#endif

#ifdef CONFIG_ASSH_CLIENT_AUTH_HOSTBASED
  assh_key_flush(c, &pv->hostkey.keys);
  assh_free(c, pv->hostkey.auth_data);
#endif

#ifdef CONFIG_ASSH_CLIENT_AUTH_KEYBOARD
  assh_free(c, pv->keyboard_array);
#endif

  assh_packet_release(pv->pck);

  assh_free(c, pv);
}

ASSH_USERAUTH_CLIENT_RETRY(assh_userauth_client_no_retry)
{
  return ASSH_NO_DATA;
}

/* allocate a packet and append user name, service name and auth
   method name fields. */
assh_error_t
assh_userauth_client_pck_head(struct assh_session_s *s,
                              struct assh_packet_s **pout,
                              const char *method,
                              size_t extra_len)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  size_t srvname_len = strlen(pv->srv->name);
  size_t method_len = strlen(method);

  ASSH_RET_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_USERAUTH_REQUEST,
                 4 + pv->username_len + 4 + srvname_len +
                 4 + method_len + extra_len, pout));
  uint8_t *str;
  ASSH_ASSERT(assh_packet_add_string(*pout, pv->username_len, &str));
  memcpy(str, pv->username, pv->username_len);
  ASSH_ASSERT(assh_packet_add_string(*pout, srvname_len, &str));
  memcpy(str, pv->srv->name, srvname_len);
  ASSH_ASSERT(assh_packet_add_string(*pout, method_len, &str));
  memcpy(str, method, method_len);

  return ASSH_OK;
}

#if defined(CONFIG_ASSH_CLIENT_AUTH_HOSTBASED) || \
  defined(CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY)

/* drop used key before next authentications attempts */
void
assh_userauth_client_key_next(struct assh_session_s *s,
                              struct assh_userauth_keys_s *k)
{
  while (k->keys != NULL)
    {
      const struct assh_algo_s *algo;

      if (assh_algo_by_key(s->ctx, k->keys,
                           &k->algo_idx, &algo) != ASSH_OK)
        {
          /* drop used key */
          assh_key_drop(s->ctx, &k->keys);
          k->algo_idx = 0;
          k->algo_groups = 0;
          continue;
        }

      assert(algo->class_ == ASSH_ALGO_SIGN);
      k->algo = (void*)algo;

      k->algo_idx++;

      /* only try one algorithm per group */
      if (!(k->algo_groups & k->algo->groups))
        {
          k->algo_groups |= k->algo->groups;
          break;
        }
    }
}

/* register some keys for next authentications attempts */
void
assh_userauth_client_key_get(struct assh_session_s *s,
                             struct assh_userauth_keys_s *k,
                             struct assh_key_s *keys)
{
  while (keys != NULL)
    {
      /* check usable keys */
      k->algo_idx = 0;
      struct assh_key_s *next = keys->next;

      /* insert provided keys in internal list */
      const struct assh_algo_s *algo;
      if (keys->role == ASSH_ALGO_SIGN &&
          assh_algo_by_key(s->ctx, keys, &k->algo_idx, &algo) == ASSH_OK)
        {
          assh_key_insert(&k->keys, keys);

          assert(algo->class_ == ASSH_ALGO_SIGN);
          k->algo = (void*)algo;
          k->algo_groups = k->algo->groups;

          k->algo_idx++;
        }
      else
        {
          assh_key_drop(s->ctx, &keys);
        }

      keys = next;
    }
}

/* generate and send signature of authentication data */
assh_error_t
assh_userauth_client_send_sign(struct assh_session_s *s,
                               struct assh_userauth_keys_s *k,
                               struct assh_packet_s *pout,
                               size_t sign_len)
{
  assh_error_t err;

  uint8_t *sign;

  uint8_t sid_len[4];   /* fake string header for session id */
  assh_store_u32(sid_len, s->session_id_len);

  /* buffers that must be signed by the client */
  struct assh_cbuffer_s data[3] = {
    { .data = sid_len,         .len = 4 },
    { .data = s->session_id,   .len = s->session_id_len },
    { .data = &pout->head.msg, .len = pout->data_size - 5 },
  };

  /* append the signature */
  ASSH_ASSERT(assh_packet_add_string(pout, sign_len, &sign));
  ASSH_RET_ON_ERR(assh_sign_generate(s->ctx, k->algo, k->keys,
                                  3, data, sign, &sign_len));
  assh_packet_shrink_string(pout, sign, sign_len);

  assh_transport_push(s, pout);

  return ASSH_OK;
}

/* initializes an event which requests signature of authentication data */
assh_error_t
assh_userauth_client_get_sign(struct assh_session_s *s,
                              struct assh_event_userauth_client_sign_s *ev,
                              struct assh_userauth_keys_s *k,
                              struct assh_packet_s *pout,
                              size_t sign_len)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  uint8_t *sign;

  size_t data_len = 4 + s->session_id_len + pout->data_size - 5;
  uint8_t *data;

  ASSH_RET_ON_ERR(assh_alloc(s->ctx, data_len, ASSH_ALLOC_INTERNAL,
                          (void**)&data));

  assert(k->auth_data == NULL);
  k->auth_data = data;
  assert(pv->pck == NULL);
  pv->pck = pout;

  assh_store_u32(data, s->session_id_len);
  memcpy(data + 4, s->session_id, s->session_id_len);
  memcpy(data + 4 + s->session_id_len, &pout->head.msg, pout->data_size - 5);

  ASSH_ASSERT(assh_packet_add_string(pout, sign_len, &sign));

  ev->pub_key = k->keys;
  ev->algo = k->algo;
  ev->auth_data.data = data;
  ev->auth_data.len = data_len;
  ev->sign.data = sign;
  ev->sign.len = sign_len;

  return ASSH_OK;
}

#endif

static ASSH_EVENT_DONE_FCN(assh_userauth_client_username_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  assert(pv->state == ASSH_USERAUTH_ST_GET_USERNAME);

  /* promote event processing error */
  ASSH_RET_IF_TRUE(ASSH_ERR_ERROR(inerr), inerr | ASSH_ERRSV_DISCONNECT);

  const struct assh_event_userauth_client_user_s *ev = &e->userauth_client.user;

  /* keep username */
  size_t ulen = ev->username.len;
  ASSH_RET_IF_TRUE(ulen > sizeof(pv->username),
	       ASSH_ERR_OUTPUT_OVERFLOW | ASSH_ERRSV_DISCONNECT);
  memcpy(pv->username, ev->username.str, ulen);
  pv->username_len = ulen;

  /* first try with the "none" method */
  pv->method = &assh_userauth_client_none;

  ASSH_RETURN(pv->method->f_req(s, NULL) | ASSH_ERRSV_DISCONNECT);
}

static assh_error_t
assh_userauth_client_username(struct assh_session_s *s,
                              struct assh_event_s *e)
{
  struct assh_userauth_context_s *pv = s->srv_pv;

  struct assh_event_userauth_client_user_s *ev = &e->userauth_client.user;

  ev->username.str = NULL;
  ev->username.len = 0;

  e->id = ASSH_EVENT_USERAUTH_CLIENT_USER;
  e->f_done = &assh_userauth_client_username_done;

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_client_get_methods_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  assert(pv->state == ASSH_USERAUTH_ST_GET_METHODS);

  /* promote event processing error */
  ASSH_RET_IF_TRUE(ASSH_ERR_ERROR(inerr), inerr | ASSH_ERRSV_DISCONNECT);

  const struct assh_event_userauth_client_methods_s *ev =
    &e->userauth_client.methods;
  enum assh_userauth_methods_e select = ev->select;
  assert(!(select & ~ev->methods));
  assert(!(select & (select - 1)));

  const struct assh_userauth_client_method_s *m;

  for (uint_fast8_t i = 0;
       (m = assh_userauth_client_methods[i]); i++)
    {
      if (select & m->mask)
        {
          pv->method = m;
          ASSH_RETURN(m->f_req(s, ev) | ASSH_ERRSV_DISCONNECT);
        }
    }

   ASSH_RETURN(ASSH_ERR_NO_AUTH | ASSH_ERRSV_DISCONNECT);
}

assh_error_t
assh_userauth_client_get_methods(struct assh_session_s *s,
                                 struct assh_event_s *e,
                                 assh_bool_t partial_success)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  struct assh_event_userauth_client_methods_s *ev =
    &e->userauth_client.methods;

  assert(pv->pck == NULL);

  memset(ev, 0, sizeof(*ev));
  ev->methods = pv->methods;
  ev->partial_success = partial_success;
  e->id = ASSH_EVENT_USERAUTH_CLIENT_METHODS;
  e->f_done = &assh_userauth_client_get_methods_done;

  ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_GET_METHODS);
  pv->method = NULL;

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_client_success_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;

  assert(pv->state == ASSH_USERAUTH_ST_SUCCESS);

  /* cleanup the authentication service and start the next service. */
  s->user_auth_done = 1;
  assh_service_start(s, pv->srv);

  return ASSH_OK;
}

static assh_error_t
assh_userauth_client_success(struct assh_session_s *s,
                             struct assh_event_s *e)
{
  struct assh_userauth_context_s *pv = s->srv_pv;

  e->id = ASSH_EVENT_USERAUTH_CLIENT_SUCCESS;
  e->f_done = &assh_userauth_client_success_done;

  ASSH_SET_STATE(pv, state, ASSH_USERAUTH_ST_SUCCESS);

  return ASSH_OK;
}

/* extract the list of acceptable authentication methods from a failure packet */
static assh_error_t
assh_userauth_client_failure(struct assh_session_s *s,
                             struct assh_packet_s *p,
                             struct assh_event_s *e)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  const uint8_t *methods = p->head.end;
  const uint8_t *partial_success, *n;
  ASSH_RET_ON_ERR(assh_packet_check_string(p, methods, &partial_success));
  ASSH_RET_ON_ERR(assh_packet_check_array(p, partial_success, 1, NULL));

  enum assh_userauth_methods_e mask = 0;

  /* parse the new list of allowed methods sent by the server */
  for (methods += 4; methods < partial_success; methods = n + 1)
    {
      n = methods;
      while (*n != ',' && n < partial_success)
        n++;

      size_t nlen = n - methods;

      const struct assh_userauth_client_method_s *m;

      /* find in supported methods */
      for (uint_fast8_t i = 0;
           (m = assh_userauth_client_methods[i]); i++)
        {
          if (!m->name[nlen] &&
              !strncmp((const char*)methods, m->name, nlen))
            {
              pv->method = m;

              /* test if the method wants to retry authentication without
                 requesting the appliction to select other methods */
              ASSH_RET_ON_ERR(m->f_retry(s, e));
              if (ASSH_ERR_ERROR(err) != ASSH_NO_DATA)
                return ASSH_OK;

              mask |= m->mask;
            }
        }
    }

  ASSH_RET_IF_TRUE(mask == 0, ASSH_ERR_NO_AUTH);

  /* report an event with server proposed methods */
  pv->methods = mask;
  ASSH_RETURN(assh_userauth_client_get_methods(s, e, *partial_success));
}

static ASSH_EVENT_DONE_FCN(assh_userauth_client_banner_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;

  assh_packet_release(pv->pck);
  pv->pck = NULL;

  return ASSH_OK;
}

static assh_error_t assh_userauth_client_banner(struct assh_session_s *s,
                                                struct assh_packet_s *p,
                                                struct assh_event_s *e)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  const uint8_t *text = p->head.end;
  const uint8_t *lang;

  ASSH_RET_ON_ERR(assh_packet_check_string(p, text, &lang));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, lang, NULL));

  struct assh_event_userauth_client_banner_s *ev =
    &e->userauth_client.banner;

  ev->text.data = text + 4;
  ev->text.len = assh_load_u32(text);
  ev->lang.data = lang + 4;
  ev->lang.len = assh_load_u32(lang);

  e->id = ASSH_EVENT_USERAUTH_CLIENT_BANNER;
  e->f_done = &assh_userauth_client_banner_done;

  pv->pck = assh_packet_refinc(p);

  return ASSH_OK;
}

ASSH_USERAUTH_CLIENT_PROCESS(assh_userauth_client_default_process)
{
  assh_error_t err;

  if (p == NULL)
    return ASSH_OK;

  switch (p->head.msg)
    {
    case SSH_MSG_USERAUTH_BANNER:
      ASSH_RETURN(assh_userauth_client_banner(s, p, e));

    case SSH_MSG_USERAUTH_SUCCESS:
      ASSH_RETURN(assh_userauth_client_success(s, e));

    case SSH_MSG_USERAUTH_FAILURE:
      ASSH_RETURN(assh_userauth_client_failure(s, p, e));

    case SSH_MSG_UNIMPLEMENTED:
      ASSH_RETURN(ASSH_ERR_PROTOCOL);

    default:
      ASSH_RETURN(assh_transport_unimp(s, p));
    }
}

static ASSH_SERVICE_PROCESS_FCN(assh_userauth_client_process)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  if (s->tr_st >= ASSH_TR_DISCONNECT)
    return ASSH_OK;

  if (p != NULL)
    s->deadline = s->time + ASSH_TIMEOUT_USERAUTH;

  switch (pv->state)
    {
    case ASSH_USERAUTH_ST_GET_USERNAME:
      ASSH_RET_IF_TRUE(p != NULL, ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);
      ASSH_RETURN(assh_userauth_client_username(s, e)
                     | ASSH_ERRSV_DISCONNECT);

    default:
      ASSH_RETURN(pv->method->f_process(s, p, e)
                     | ASSH_ERRSV_DISCONNECT);
    }
}

const struct assh_service_s assh_service_userauth_client =
{
  .name = "ssh-userauth",
  .side = ASSH_CLIENT,
  .no_user_auth = 1,
  .f_init = assh_userauth_client_init,
  .f_cleanup = assh_userauth_client_cleanup,
  .f_process = assh_userauth_client_process,
};

