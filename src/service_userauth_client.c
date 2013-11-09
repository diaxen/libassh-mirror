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

#include <assh/assh_service.h>
#include <assh/assh_session.h>
#include <assh/assh_packet.h>
#include <assh/assh_transport.h>
#include <assh/assh_event.h>
#include <assh/assh_key.h>
#include <assh/assh_sign.h>

#ifdef CONFIG_ASSH_SERVER

#include <stdlib.h>

enum assh_userauth_state_e
{
  ASSH_USERAUTH_INIT,
  ASSH_USERAUTH_GET_USERNAME,
  ASSH_USERAUTH_SENT_NONE_RQ,
  ASSH_USERAUTH_SENT_USER_KEY_RQ,
  ASSH_USERAUTH_SENT_PASSWORD_RQ,
  ASSH_USERAUTH_GET_AUTHDATA,
  ASSH_USERAUTH_SENT_USER_KEY,
};

struct assh_userauth_context_s
{
  enum assh_userauth_state_e state;  
  char username[32+1];
  const struct assh_service_s *srv;
  const struct assh_algo_sign_s *algo;
  struct assh_key_s *user_keys;
};

static ASSH_SERVICE_INIT_FCN(assh_userauth_client_init)
{
  struct assh_userauth_context_s *pv;
  assh_error_t err;

  ASSH_ERR_RET(assh_alloc(s->ctx, sizeof(*pv),
                    ASSH_ALLOC_INTERNAL, (void**)&pv));

  s->srv = &assh_service_userauth_client;
  s->srv_pv = pv;

  pv->user_keys = NULL;
  pv->state = ASSH_USERAUTH_INIT;

  /* get next client requested service */
  ASSH_ERR_RET(s->srv_index >= s->ctx->srvs_count
	       ? ASSH_ERR_SERVICE_NA : 0);
  pv->srv = s->ctx->srvs[s->srv_index];

  return ASSH_OK;
}

static ASSH_SERVICE_CLEANUP_FCN(assh_userauth_client_cleanup)
{
  struct assh_userauth_context_s *pv = s->srv_pv;

  assh_key_flush(s->ctx, &pv->user_keys);

  assh_free(s->ctx, pv, ASSH_ALLOC_INTERNAL);

  s->srv_pv = NULL;
  s->srv = NULL;
}

/* allocate a packet and append user name, service name and auth method name fields. */
static assh_error_t assh_userauth_client_pck_head(struct assh_session_s *s,
                                                  struct assh_packet_s **pout,
                                                  const char *method,
                                                  size_t extra_len)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  size_t username_len = strlen(pv->username);
  size_t srvname_len = strlen(pv->srv->name);
  size_t method_len = strlen(method);

  ASSH_ERR_RET(assh_packet_alloc(s, SSH_MSG_USERAUTH_REQUEST,
                 4 + username_len + 4 + srvname_len +
                 4 + method_len + extra_len, pout));
  uint8_t *str;
  ASSH_ASSERT(assh_packet_add_string(*pout, username_len, &str));
  memcpy(str, pv->username, username_len);
  ASSH_ASSERT(assh_packet_add_string(*pout, srvname_len, &str));
  memcpy(str, pv->srv->name, srvname_len);
  ASSH_ASSERT(assh_packet_add_string(*pout, method_len, &str));
  memcpy(str, method, method_len);

  return ASSH_OK;
}

/* allocate a packet and append common fileds for a publickey request */
static assh_error_t assh_userauth_client_pck_pubkey(struct assh_session_s *s,
                                                    struct assh_packet_s **pout,
                                                    struct assh_key_s *user_key,
                                                    assh_bool_t second,
                                                    size_t extra_len)
{
  assh_error_t err;
  size_t algo_name_len = strlen(user_key->algo->name);

  size_t blob_len;
  ASSH_ERR_RET(user_key->f_output(s->ctx, user_key,
           NULL, &blob_len, ASSH_KEY_FMT_PUB_RFC4253_6_6));

  ASSH_ERR_RET(assh_userauth_client_pck_head(s, pout, "publickey",
                1 + 4 + algo_name_len + 4 + blob_len + extra_len));

  /* add boolean */
  uint8_t *str;
  ASSH_ASSERT(assh_packet_add_bytes(*pout, 1, &str));
  *str = second;

  /* add signature algorithm name */
  uint8_t *algo_name;
  ASSH_ASSERT(assh_packet_add_string(*pout, algo_name_len, &algo_name));
  memcpy(algo_name, user_key->algo->name, algo_name_len);

  /* add public key blob */
  uint8_t *blob;
  ASSH_ASSERT(assh_packet_add_string(*pout, blob_len, &blob));
  ASSH_ERR_GTO(user_key->f_output(s->ctx, user_key,
                 blob, &blob_len, ASSH_KEY_FMT_PUB_RFC4253_6_6), err_packet);
  assh_packet_shrink_string(*pout, blob, blob_len);

  return ASSH_OK;

 err_packet:
  assh_packet_release(*pout);
  return err;
}

/* send a password authentication request */
static assh_error_t assh_userauth_client_req_password(struct assh_session_s *s,
                                                      const char *passwd)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  size_t passwd_len = strlen(passwd);
  uint8_t *str;

  struct assh_packet_s *pout;
  ASSH_ERR_RET(assh_userauth_client_pck_head(s, &pout, "password", 1 + 4 + passwd_len));
  ASSH_ASSERT(assh_packet_add_bytes(pout, 1, &str));
  *str = 0; // FALSE

  ASSH_ASSERT(assh_packet_add_string(pout, passwd_len, &str));
  memcpy(str, passwd, passwd_len);
  assh_transport_push(s, pout);

  pv->state = ASSH_USERAUTH_SENT_PASSWORD_RQ;
  return ASSH_OK;
}

/* send a public key authentication request with signature */
static assh_error_t assh_userauth_client_req_pubkey_sign(struct assh_session_s *s)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  struct assh_packet_s *pout;
  ASSH_ERR_RET(assh_userauth_client_pck_pubkey(s, &pout, pv->user_keys, 1, 1024));

  uint8_t sid_len[4];   /* fake string header for session id */
  assh_store_u32(sid_len, s->session_id_len);

  /* buffers that must be signed by the client */
  const uint8_t *sign_ptrs[3] =
    { sid_len, s->session_id,     &pout->head.msg };
  size_t sign_sizes[3]        =
    { 4,       s->session_id_len, pout->data_size - 5 };

  const struct assh_algo_sign_s *algo = (const void *)pv->user_keys->algo;
  ASSH_ERR_GTO(algo->f_add_sign(s->ctx, pv->user_keys, 3, sign_ptrs, sign_sizes, pout), err_packet);

  assh_transport_push(s, pout);

  /* drop used key */
  assh_key_drop(s->ctx, &pv->user_keys);

  return ASSH_OK;

 err_packet:
  assh_packet_release(pout);
  return err;
}

/* send a public key authentication probing request */
static assh_error_t assh_userauth_client_req_pubkey(struct assh_session_s *s)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

#if 1 /* send the signature directly */
  ASSH_ERR_RET(assh_userauth_client_req_pubkey_sign(s));
  pv->state = ASSH_USERAUTH_SENT_USER_KEY_RQ;
#else /* send a public key request first */
  struct assh_packet_s *pout;
  ASSH_ERR_RET(assh_userauth_client_pck_pubkey(s, &pout, pv->user_keys, 0, 0));
  assh_transport_push(s, pout);
  pv->state = ASSH_USERAUTH_SENT_USER_KEY;
#endif
  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_client_username_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  struct assh_packet_s *pout;
  ASSH_ERR_RET(pv->state != ASSH_USERAUTH_GET_USERNAME ? ASSH_ERR_STATE : 0);

  /* keep username */
  size_t ulen = strlen(e->userauth_client_username.username);
  ASSH_ERR_RET(ulen + 1 > sizeof(pv->username) ? ASSH_ERR_OVERFLOW : 0);
  memcpy(pv->username, e->userauth_client_username.username, ulen + 1);

  /* send auth request with the "none" method */
  ASSH_ERR_RET(assh_userauth_client_pck_head(s, &pout, "none", 0));
  assh_transport_push(s, pout);

  pv->state = ASSH_USERAUTH_SENT_NONE_RQ;

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_client_methods_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  ASSH_ERR_RET(pv->state != ASSH_USERAUTH_GET_AUTHDATA ? ASSH_ERR_STATE : 0);

  const char *passwd = e->userauth_client_methods.password;
  struct assh_key_s *k = e->userauth_client_methods.user_keys;

  /* insert provided keys in internal list */
  while (k != NULL)
    {
      ASSH_ERR_RET(k->algo->class_ != ASSH_ALGO_SIGN ? ASSH_ERR_BAD_DATA : 0);

      struct assh_key_s *next = k->next;
      k->next = pv->user_keys;
      pv->user_keys = k;
      k = next;
    }

  if (passwd != NULL)
    ASSH_ERR_RET(assh_userauth_client_req_password(s, passwd));
  else if (pv->user_keys != NULL)
    ASSH_ERR_RET(assh_userauth_client_req_pubkey(s));
  else /* no authentication method */
    ASSH_ERR_RET(ASSH_ERR_CODE(ASSH_ERR_NO_AUTH,
                   SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE));
}

/* cleanup the authentication service and start the next service. */
static assh_error_t assh_userauth_client_success(struct assh_session_s *s)
{
  assh_error_t err;
  struct assh_userauth_context_s *pv = s->srv_pv;
  const struct assh_service_s *srv = pv->srv;

  assh_userauth_client_cleanup(s);

  ASSH_ERR_RET(srv->f_init(s));
  s->srv_index++;

  return ASSH_OK;
}

/* extract the list of acceptable authentication methods from a failure packet */
static assh_error_t assh_userauth_client_failure(struct assh_session_s *s,
                                                 struct assh_packet_s *p,
                                                 struct assh_event_s *e)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  uint8_t *methods = p->head.end;
  uint8_t *partial_success, *n;
  ASSH_ERR_RET(assh_packet_check_string(p, methods, &partial_success));
  ASSH_ERR_RET(assh_packet_check_array(p, partial_success, 1, NULL));

  e->userauth_client_methods.method_password = 0;
  e->userauth_client_methods.method_user_key = 0;
  int count = 0;

  for (methods += 4; methods < partial_success; methods = n + 1)
    {
      n = methods;
      while (*n != ',' && n < partial_success)
        n++;

      switch (n - methods)
        {
        case 8:
          if (!strncmp((const char*)methods, "password", 8))
            {
              e->userauth_client_methods.method_password = 1;
              count++;
            }
          break;

        case 9:
          if (!strncmp((const char*)methods, "publickey", 9))
            {
              if (pv->user_keys != NULL)
                {
                  /* some user keys are already available, do not need
                     to request more yet. */
                  ASSH_ERR_RET(assh_userauth_client_req_pubkey(s));
                  return ASSH_OK;
                }

              e->userauth_client_methods.method_user_key = 1;
              count++;
            }

        default:
          break;
        }
    }

  ASSH_ERR_RET(count == 0 ? ASSH_ERR_CODE(ASSH_ERR_NO_AUTH,
                 SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE) : 0);

  e->userauth_client_methods.password = NULL;
  e->userauth_client_methods.user_keys = NULL;
  e->id = ASSH_EVENT_USERAUTH_CLIENT_METHODS;
  e->f_done = &assh_userauth_client_methods_done;

  pv->state = ASSH_USERAUTH_GET_AUTHDATA;

  return ASSH_OK;
}

static ASSH_PROCESS_FCN(assh_userauth_client_process)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  if (s->tr_st != ASSH_TR_SERVICE)
    return ASSH_OK;

  switch (pv->state)
    {
    case ASSH_USERAUTH_INIT:
      ASSH_ERR_RET(p != NULL ? ASSH_ERR_PROTOCOL : 0);
      e->id = ASSH_EVENT_USERAUTH_CLIENT_USERNAME;
      e->f_done = &assh_userauth_client_username_done;
      e->userauth_client_username.username = NULL;
      pv->state = ASSH_USERAUTH_GET_USERNAME;
      return ASSH_OK;

    case ASSH_USERAUTH_SENT_NONE_RQ:
    case ASSH_USERAUTH_SENT_PASSWORD_RQ:
    case ASSH_USERAUTH_SENT_USER_KEY_RQ:
      if (p == NULL)
        return ASSH_OK;

      switch (p->head.msg)
        {
        case SSH_MSG_USERAUTH_SUCCESS:
          ASSH_ERR_RET(assh_userauth_client_success(s));
          return ASSH_OK;

        case SSH_MSG_USERAUTH_PASSWD_CHANGEREQ:
          ASSH_ERR_RET(pv->state != ASSH_USERAUTH_SENT_PASSWORD_RQ ? ASSH_ERR_PROTOCOL : 0);
        case SSH_MSG_USERAUTH_FAILURE:
          ASSH_ERR_RET(assh_userauth_client_failure(s, p, e));
          return ASSH_OK;

        default:
          ASSH_ERR_RET(ASSH_ERR_PROTOCOL);
        }

    case ASSH_USERAUTH_SENT_USER_KEY:
      if (p == NULL)
        return ASSH_OK;

      switch(p->head.msg)
        {
        case SSH_MSG_USERAUTH_PK_OK:
          ASSH_ERR_RET(assh_userauth_client_req_pubkey_sign(s));
          pv->state = ASSH_USERAUTH_SENT_USER_KEY_RQ;
          return ASSH_OK;

        case SSH_MSG_USERAUTH_FAILURE:
          ASSH_ERR_RET(assh_userauth_client_failure(s, p, e));
          return ASSH_OK;

        default:
          ASSH_ERR_RET(ASSH_ERR_PROTOCOL);
        }

    default:
      ASSH_ERR_RET(ASSH_ERR_STATE);
    }
}

const struct assh_service_s assh_service_userauth_client =
{
  .name = "ssh-userauth",
  .side = ASSH_CLIENT,
  .f_init = assh_userauth_client_init,
  .f_cleanup = assh_userauth_client_cleanup,
  .f_process = assh_userauth_client_process,
};

#endif

