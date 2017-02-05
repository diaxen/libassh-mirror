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

#include <assh/assh_userauth_client.h>

#include <assh/assh_service.h>
#include <assh/assh_session.h>
#include <assh/assh_packet.h>
#include <assh/assh_transport.h>
#include <assh/assh_event.h>
#include <assh/assh_key.h>
#include <assh/assh_sign.h>
#include <assh/assh_alloc.h>

#ifdef CONFIG_ASSH_CLIENT

ASSH_EVENT_SIZE_SASSERT(userauth_client);

#include <stdlib.h>

enum assh_userauth_state_e
{
  ASSH_USERAUTH_ST_INIT,
  ASSH_USERAUTH_ST_GET_USERNAME,
  ASSH_USERAUTH_ST_SENT_NONE_RQ,
#ifdef CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY
  ASSH_USERAUTH_ST_SENT_PUBKEY_RQ,
  ASSH_USERAUTH_ST_SEND_PUBKEY,
  ASSH_USERAUTH_ST_SENT_PUBKEY,
#endif
#ifdef CONFIG_ASSH_CLIENT_AUTH_PASSWORD
  ASSH_USERAUTH_ST_SENT_PASSWORD_RQ,
  ASSH_USERAUTH_ST_GET_PWCHANGE,
  ASSH_USERAUTH_ST_PWCHANGE_SKIP,
#endif
#ifdef CONFIG_ASSH_CLIENT_AUTH_KEYBOARD
  ASSH_USERAUTH_ST_KEYBOARD_SENT_RQ,
  ASSH_USERAUTH_ST_KEYBOARD_INFO,
  ASSH_USERAUTH_ST_KEYBOARD_SENT_INFO,
#endif
#ifdef CONFIG_ASSH_CLIENT_AUTH_HOSTBASED
  ASSH_USERAUTH_ST_SENT_HOSTBASED_RQ,
  ASSH_USERAUTH_ST_SEND_HOSTBASED,
#endif
  ASSH_USERAUTH_ST_GET_METHODS,
  ASSH_USERAUTH_ST_SUCCESS,
};

#define ASSH_USERAUTH_CLIENT_REQ(n)                             \
  assh_error_t (n)(struct assh_session_s *s,                    \
                   const struct assh_event_userauth_client_methods_s *ev)

typedef ASSH_USERAUTH_CLIENT_REQ(assh_userauth_client_req_t);

#define ASSH_USERAUTH_CLIENT_RETRY(n)           \
  assh_error_t (n)(struct assh_session_s *s,                    \
                   struct assh_event_s *e)

typedef ASSH_USERAUTH_CLIENT_RETRY(assh_userauth_client_retry_t);

#define ASSH_USERAUTH_CLIENT_PROCESS(n)                         \
  assh_error_t (n)(struct assh_session_s *s,                    \
                   struct assh_packet_s *p,                     \
                   struct assh_event_s *e)

typedef ASSH_USERAUTH_CLIENT_PROCESS(assh_userauth_client_process_t);

struct assh_userauth_client_method_s
{
  const char                   *name;
  enum assh_userauth_methods_e mask;
  assh_userauth_client_req_t   *f_req;
  assh_userauth_client_process_t *f_process;
  assh_userauth_client_retry_t *f_retry;
};

/* see at end of file */
extern const struct assh_userauth_client_method_s
assh_userauth_client_methods[];

struct assh_userauth_keys_s
{
  uint16_t algo_idx;
  const struct assh_algo_s *algo;
  struct assh_key_s *keys;
  uint8_t *auth_data;
};

struct assh_userauth_context_s
{
  const struct assh_service_s *srv;
  struct assh_packet_s *pck;
  const struct assh_userauth_client_method_s *method;

  char username[CONFIG_ASSH_AUTH_USERNAME_LEN];

  size_t username_len:16;

  enum assh_userauth_methods_e methods:8;
  enum assh_userauth_state_e state:8;
#ifdef CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY
  struct assh_userauth_keys_s pubkey;
#endif

#ifdef CONFIG_ASSH_CLIENT_AUTH_HOSTBASED
  struct assh_userauth_keys_s hostkey;
  char host_username[CONFIG_ASSH_AUTH_USERNAME_LEN];
  char hostname[CONFIG_ASSH_AUTH_HOSTNAME_LEN];
  size_t host_username_len:16;
  size_t hostname_len:16;
#endif

#ifdef CONFIG_ASSH_CLIENT_AUTH_KEYBOARD
  struct assh_cbuffer_s *keyboard_array;
#endif
};

static ASSH_USERAUTH_CLIENT_PROCESS(assh_userauth_client_default_process);

static assh_error_t
assh_userauth_client_get_methods(struct assh_session_s *s,
                                 struct assh_event_s *e,
                                 assh_bool_t partial_success);

static ASSH_USERAUTH_CLIENT_RETRY(assh_userauth_client_no_retry)
{
  return ASSH_NO_DATA;
}

static ASSH_SERVICE_INIT_FCN(assh_userauth_client_init)
{
  struct assh_userauth_context_s *pv;
  assh_error_t err;

  ASSH_RET_IF_TRUE(s->srv_index >= s->ctx->srvs_count, ASSH_ERR_SERVICE_NA);

  ASSH_RET_ON_ERR(assh_alloc(s->ctx, sizeof(*pv),
                    ASSH_ALLOC_SECUR, (void**)&pv));

  pv->methods = 0;
  pv->state = ASSH_USERAUTH_ST_INIT;

  s->srv = &assh_service_userauth_client;
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
  pv->srv = s->ctx->srvs[s->srv_index];
  pv->pck = NULL;

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

  s->srv_pv = NULL;
  s->srv = NULL;
}

/* allocate a packet and append user name, service name and auth
   method name fields. */
static assh_error_t
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
                 4 + method_len + extra_len, pout) | ASSH_ERRSV_DISCONNECT);
  uint8_t *str;
  ASSH_ASSERT(assh_packet_add_string(*pout, pv->username_len, &str));
  memcpy(str, pv->username, pv->username_len);
  ASSH_ASSERT(assh_packet_add_string(*pout, srvname_len, &str));
  memcpy(str, pv->srv->name, srvname_len);
  ASSH_ASSERT(assh_packet_add_string(*pout, method_len, &str));
  memcpy(str, method, method_len);

  return ASSH_OK;
}

static ASSH_USERAUTH_CLIENT_REQ(assh_userauth_client_none_req)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  struct assh_packet_s *pout;

  ASSH_RET_ON_ERR(assh_userauth_client_pck_head(s, &pout, "none",
                                             0) | ASSH_ERRSV_DISCONNECT);

  assh_transport_push(s, pout);

  pv->state = ASSH_USERAUTH_ST_SENT_NONE_RQ;

  return ASSH_OK;
}

#if defined(CONFIG_ASSH_CLIENT_AUTH_HOSTBASED) || \
  defined(CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY)

/* drop used key before next authentications attempts */
static void
assh_userauth_client_key_next(struct assh_session_s *s,
                              struct assh_userauth_keys_s *k)
{
  k->algo_idx++;
  while (k->keys != NULL &&
         assh_algo_by_key(s->ctx, k->keys,
                          &k->algo_idx, &k->algo) != ASSH_OK)
    {
      /* drop used key */
      assh_key_drop(s->ctx, &k->keys);
      k->algo_idx = 0;
    }
}

/* register some keys for next authentications attempts */
static void
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
      if (assh_algo_by_key(s->ctx, keys, &k->algo_idx, &k->algo) == ASSH_OK)
        assh_key_insert(&k->keys, keys);
      else
        assh_key_drop(s->ctx, &keys);

      keys = next;
    }
}

/* generate and send signature of authentication data */
static assh_error_t
assh_userauth_client_send_sign(struct assh_session_s *s,
                               struct assh_userauth_keys_s *k,
                               struct assh_packet_s *pout,
                               size_t sign_len)
{
  const struct assh_algo_sign_s *algo = (const void *)k->algo;
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
  ASSH_RET_ON_ERR(assh_sign_generate(s->ctx, algo, k->keys,
                                  3, data, sign, &sign_len)
               | ASSH_ERRSV_DISCONNECT);
  assh_packet_shrink_string(pout, sign, sign_len);

  assh_transport_push(s, pout);

  return ASSH_OK;
}

/* initializes an event which requests signature of authentication data */
static assh_error_t
assh_userauth_client_get_sign(struct assh_session_s *s,
                              struct assh_event_userauth_client_sign_s *ev,
                              struct assh_userauth_keys_s *k,
                              struct assh_packet_s *pout,
                              size_t sign_len)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  const struct assh_algo_sign_s *algo = (const void *)k->algo;
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
  ev->algo = algo;
  ev->auth_data.data = data;
  ev->auth_data.len = data_len;
  ev->sign.data = sign;
  ev->sign.len = sign_len;

  return ASSH_OK;
}

#endif

/******************************************************************* password */

#ifdef CONFIG_ASSH_CLIENT_AUTH_PASSWORD
/* send a password authentication request */
static assh_error_t
assh_userauth_client_send_password(struct assh_session_s *s,
                                   const struct assh_cbuffer_s *password,
                                   const struct assh_cbuffer_s *new_password)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  uint8_t *bool_, *str;

  struct assh_packet_s *pout;

  size_t pw_len = 4 + password->len
    + (new_password != NULL ? 4 + new_password->len : 0);

  /* Any password with a length less than 128 bytes will result in a
     packet of the same size. */
  size_t pw_hidden_len = ASSH_MAX((size_t)pw_len, 128);

  ASSH_RET_ON_ERR(assh_userauth_client_pck_head(s, &pout, "password",
	           1 + pw_hidden_len) | ASSH_ERRSV_DISCONNECT);
  pout->padding = ASSH_PADDING_MAX;

  ASSH_ASSERT(assh_packet_add_array(pout, 1, &bool_));
  *bool_ = (new_password != NULL);

  ASSH_ASSERT(assh_packet_add_string(pout, password->len, &str));
  memcpy(str, password->str, password->len);

  if (new_password)
    {
      ASSH_ASSERT(assh_packet_add_string(pout, new_password->len, &str));
      memcpy(str, new_password->str, new_password->len);
    }

  assh_transport_push(s, pout);

  pv->state = ASSH_USERAUTH_ST_SENT_PASSWORD_RQ;

  return ASSH_OK;
}

static ASSH_USERAUTH_CLIENT_REQ(assh_userauth_client_password_req)
{
  assh_error_t err;

  ASSH_RETURN(assh_userauth_client_send_password(s,
                &ev->password, NULL));
}

static ASSH_EVENT_DONE_FCN(assh_userauth_client_req_pwchange_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  const struct assh_event_userauth_client_pwchange_s *ev = &e->userauth_client.pwchange;
  assh_error_t err;

  ASSH_RET_IF_TRUE(pv->state != ASSH_USERAUTH_ST_GET_PWCHANGE,
	       ASSH_ERR_STATE | ASSH_ERRSV_FATAL);

  assh_packet_release(pv->pck);
  pv->pck = NULL;

  if (ev->old_password.len && ev->new_password.len)
    {
      ASSH_RET_ON_ERR(assh_userauth_client_send_password(s,
        &ev->old_password, &ev->new_password));
    }
  else
    {
      pv->state = ASSH_USERAUTH_ST_PWCHANGE_SKIP;
    }

  return ASSH_OK;
}

static assh_error_t
assh_userauth_client_req_pwchange(struct assh_session_s *s,
                                  struct assh_packet_s *p,
                                  struct assh_event_s *e)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
   assh_error_t err;

  const uint8_t *end, *lang, *prompt = p->head.end;

  ASSH_RET_ON_ERR(assh_packet_check_string(p, prompt, &lang) | ASSH_ERRSV_DISCONNECT);
  ASSH_RET_ON_ERR(assh_packet_check_string(p, lang, &end) | ASSH_ERRSV_DISCONNECT);

  struct assh_event_userauth_client_pwchange_s *ev = &e->userauth_client.pwchange;
  ev->prompt.data = prompt + 4;
  ev->prompt.len = assh_load_u32(prompt);
  ev->lang.data = lang + 4;
  ev->lang.len = assh_load_u32(lang);
  ev->old_password.len = 0;
  ev->new_password.len = 0;

  e->id = ASSH_EVENT_USERAUTH_CLIENT_PWCHANGE;
  e->f_done = assh_userauth_client_req_pwchange_done;
  pv->state = ASSH_USERAUTH_ST_GET_PWCHANGE;

  assert(pv->pck == NULL);
  pv->pck = assh_packet_refinc(p);

  return ASSH_OK;
}

static ASSH_USERAUTH_CLIENT_PROCESS(assh_userauth_client_password_process)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  switch (pv->state)
    {
    case ASSH_USERAUTH_ST_SENT_PASSWORD_RQ:
      if (p == NULL)
        return ASSH_OK;

      switch(p->head.msg)
        {
        case SSH_MSG_USERAUTH_PASSWD_CHANGEREQ:
          ASSH_RETURN(assh_userauth_client_req_pwchange(s, p, e)
                        | ASSH_ERRSV_DISCONNECT);

        default:
          ASSH_RETURN(assh_userauth_client_default_process(s, p, e));
        }

    case ASSH_USERAUTH_ST_PWCHANGE_SKIP:
      ASSH_RET_ON_ERR(assh_userauth_client_get_methods(s, e, 0));
      return ASSH_NO_DATA;

    default:
      ASSH_RETURN(ASSH_ERR_STATE | ASSH_ERRSV_FATAL);
    }
}

#endif

/******************************************************************* keyboard */

#ifdef CONFIG_ASSH_CLIENT_AUTH_KEYBOARD
/* send a password authentication request */
static ASSH_USERAUTH_CLIENT_REQ(assh_userauth_client_keyboard_req)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  uint8_t *bool_, *str;

  struct assh_packet_s *pout;

  size_t sub_len = ev->keyboard_sub.len;

  ASSH_RET_ON_ERR(assh_userauth_client_pck_head(s, &pout, "keyboard-interactive",
                                             4 + 4 + sub_len) | ASSH_ERRSV_DISCONNECT);

  ASSH_ASSERT(assh_packet_add_string(pout, 0, &str)); /* lang */
  ASSH_ASSERT(assh_packet_add_string(pout, sub_len, &str)); /* sub methods */
  memcpy(str, ev->keyboard_sub.str, sub_len);

  assh_transport_push(s, pout);

  pv->state = ASSH_USERAUTH_ST_KEYBOARD_SENT_RQ;

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_client_keyboard_info_done)
{
  struct assh_context_s *c = s->ctx;
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  ASSH_RET_IF_TRUE(pv->state != ASSH_USERAUTH_ST_KEYBOARD_INFO,
	       ASSH_ERR_STATE | ASSH_ERRSV_FATAL);

  assh_packet_release(pv->pck);
  pv->pck = NULL;

  struct assh_packet_s *pout;
  const struct assh_event_userauth_client_keyboard_s *ev = &e->userauth_client.keyboard;

  size_t i, count = ev->count;

  size_t psize = 4;
  for (i = 0; i < count; i++)
    psize += 4 + ev->responses[i].len;

  ASSH_RET_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_USERAUTH_INFO_RESPONSE,
                                 ASSH_MAX(psize, 256), &pout)
               | ASSH_ERRSV_DISCONNECT);
  pout->padding = ASSH_PADDING_MAX;

  uint8_t *str;
  ASSH_ASSERT(assh_packet_add_array(pout, 4, &str));
  assh_store_u32(str, count);

  for (i = 0; i < count; i++)
    {
      size_t len = ev->responses[i].len;
      ASSH_ASSERT(assh_packet_add_string(pout, len, &str));
      memcpy(str, ev->responses[i].str, len);
    }

  assh_transport_push(s, pout);
  pv->state = ASSH_USERAUTH_ST_KEYBOARD_SENT_INFO;

  assh_free(c, pv->keyboard_array);
  pv->keyboard_array = NULL;

  return ASSH_OK;
}

static assh_error_t
assh_userauth_client_req_keyboard_info(struct assh_session_s *s,
                                       struct assh_packet_s *p,
                                       struct assh_event_s *e)
{
  struct assh_context_s *c = s->ctx;
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  const uint8_t *name = p->head.end;
  const uint8_t *ins, *lang, *count_, *prompt, *echo;

  ASSH_RET_ON_ERR(assh_packet_check_string(p, name, &ins)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_RET_ON_ERR(assh_packet_check_string(p, ins, &lang)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_RET_ON_ERR(assh_packet_check_string(p, lang, &count_)
	       | ASSH_ERRSV_DISCONNECT);

  ASSH_RET_ON_ERR(assh_packet_check_array(p, count_, 4, &prompt)
	       | ASSH_ERRSV_DISCONNECT);

  size_t i, count = assh_load_u32(count_);
  ASSH_RET_IF_TRUE(count > 32, ASSH_ERR_INPUT_OVERFLOW | ASSH_ERRSV_DISCONNECT);

  struct assh_cbuffer_s *prompts = NULL;
  uint32_t echos = 0;

  if (count > 0)
    {
      ASSH_RET_ON_ERR(assh_alloc(c, sizeof(*prompts) * count,
                              ASSH_ALLOC_INTERNAL, (void**)&prompts));

      assert(pv->keyboard_array == NULL);
      pv->keyboard_array = prompts;

      for (i = 0; i < count; i++)
        {
          ASSH_RET_ON_ERR(assh_packet_check_string(p, prompt, &echo)
                       | ASSH_ERRSV_DISCONNECT);
          size_t len = assh_load_u32(prompt);
          ASSH_RET_IF_TRUE(len == 0, ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);
          prompts[i].data = prompt + 4;
          prompts[i].len = len;

          ASSH_RET_ON_ERR(assh_packet_check_array(p, echo, 1, &prompt)
                       | ASSH_ERRSV_DISCONNECT);

          echos |= !!*echo << i;
        }
    }

  struct assh_event_userauth_client_keyboard_s *ev = &e->userauth_client.keyboard;
  ev->name.data = name + 4;
  ev->name.len = assh_load_u32(name);
  ev->instruction.data = ins + 4;
  ev->instruction.len = assh_load_u32(ins);
  ev->count = count;
  ev->echos = echos;
  ev->prompts = prompts;
  e->id = ASSH_EVENT_USERAUTH_CLIENT_KEYBOARD;
  e->f_done = &assh_userauth_client_keyboard_info_done;

  pv->state = ASSH_USERAUTH_ST_KEYBOARD_INFO;

  assert(pv->pck == NULL);
  pv->pck = assh_packet_refinc(p);

  return ASSH_OK;
}

static ASSH_USERAUTH_CLIENT_PROCESS(assh_userauth_client_keyboard_process)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  if (p == NULL)
    return ASSH_OK;

  switch(p->head.msg)
    {
    case SSH_MSG_USERAUTH_INFO_REQUEST:
      ASSH_RETURN(assh_userauth_client_req_keyboard_info(s, p, e)
                    | ASSH_ERRSV_DISCONNECT);

    default:
      ASSH_RETURN(assh_userauth_client_default_process(s, p, e));
    }
}
#endif

/******************************************************************* hostbased */

#ifdef CONFIG_ASSH_CLIENT_AUTH_HOSTBASED

/* allocate a packet and append common fileds for a publickey request */
static assh_error_t
assh_userauth_client_pck_hostbased(struct assh_session_s *s,
                                   struct assh_packet_s **pout,
                                   size_t *sign_len)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  struct assh_key_s *pub_key = pv->hostkey.keys;
  assh_error_t err;

  const struct assh_algo_sign_s *algo = (const void *)pv->hostkey.algo;

  size_t algo_name_len = strlen(assh_algo_name(&algo->algo));

  size_t blob_len;
  ASSH_RET_ON_ERR(assh_key_output(s->ctx, pub_key,
           NULL, &blob_len, ASSH_KEY_FMT_PUB_RFC4253) | ASSH_ERRSV_DISCONNECT);

  ASSH_RET_ON_ERR(assh_sign_generate(s->ctx, algo, pv->hostkey.keys, 0,
    	     NULL, NULL, sign_len) | ASSH_ERRSV_DISCONNECT);

  ASSH_RET_ON_ERR(assh_userauth_client_pck_head(s, pout, "hostbased",
                 4 + algo_name_len + 4 + blob_len +
                 4 + pv->hostname_len + 4 + pv->host_username_len +
                 4 + *sign_len) | ASSH_ERRSV_DISCONNECT);

  /* add signature algorithm name */
  uint8_t *str;
  ASSH_ASSERT(assh_packet_add_string(*pout, algo_name_len, &str));
  memcpy(str, assh_algo_name(pv->hostkey.algo), algo_name_len);

  /* add public key blob */
  uint8_t *blob;
  ASSH_ASSERT(assh_packet_add_string(*pout, blob_len, &blob));
  ASSH_JMP_ON_ERR(assh_key_output(s->ctx, pub_key, blob, &blob_len,
                 ASSH_KEY_FMT_PUB_RFC4253) | ASSH_ERRSV_DISCONNECT, err_packet);
  assh_packet_shrink_string(*pout, blob, blob_len);

  /* add hostname */
  ASSH_ASSERT(assh_packet_add_string(*pout, pv->hostname_len, &str));
  memcpy(str, pv->hostname, pv->hostname_len);

  /* add host username */
  ASSH_ASSERT(assh_packet_add_string(*pout, pv->host_username_len, &str));
  memcpy(str, pv->host_username, pv->host_username_len);

  return ASSH_OK;

 err_packet:
  assh_packet_release(*pout);
  return err;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_client_hostbased_sign_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  struct assh_packet_s *pout = pv->pck;
  const struct assh_event_userauth_client_sign_s *ev = &e->userauth_client.sign;
  assh_packet_shrink_string(pout, ev->sign.data, ev->sign.len);

  assh_transport_push(s, pout);
  pv->pck = NULL;

  assh_free(s->ctx, pv->hostkey.auth_data);
  pv->hostkey.auth_data = NULL;

  pv->state = ASSH_USERAUTH_ST_SENT_HOSTBASED_RQ;

  return ASSH_OK;
}

/* send a public key authentication probing request */
static assh_error_t
assh_userauth_client_send_hostbased(struct assh_session_s *s,
                                    struct assh_event_s *e)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  struct assh_packet_s *pout;
  size_t sign_len;

  ASSH_RET_ON_ERR(assh_userauth_client_pck_hostbased(s, &pout, &sign_len)
               | ASSH_ERRSV_DISCONNECT);

  struct assh_userauth_keys_s *k = &pv->hostkey;

  if (k->keys->private)
    {
      ASSH_JMP_ON_ERR(assh_userauth_client_send_sign(s, k, pout, sign_len)
                   | ASSH_ERRSV_DISCONNECT, err_packet);
    }
  else
    {
      e->f_done = &assh_userauth_client_hostbased_sign_done;
      e->id = ASSH_EVENT_USERAUTH_CLIENT_SIGN;

      ASSH_JMP_ON_ERR(assh_userauth_client_get_sign(s, &e->userauth_client.sign,
                                                 k, pout, sign_len)
                   | ASSH_ERRSV_DISCONNECT, err_packet);
    }

  pv->state = ASSH_USERAUTH_ST_SENT_HOSTBASED_RQ;

  return ASSH_OK;

 err_packet:
  assh_packet_release(pout);
  return err;
}

static ASSH_USERAUTH_CLIENT_RETRY(assh_userauth_client_hostbased_retry)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  struct assh_userauth_keys_s *k = &pv->hostkey;
  assh_error_t err;

  assh_userauth_client_key_next(s, k);

  if (k->keys == NULL)
    return ASSH_NO_DATA;

  /* some user keys are already available */
  ASSH_RETURN(assh_userauth_client_send_hostbased(s, e)
                | ASSH_ERRSV_DISCONNECT);
}

/* send a public key authentication probing request */
static ASSH_USERAUTH_CLIENT_REQ(assh_userauth_client_hostbased_req)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  struct assh_userauth_keys_s *k = &pv->hostkey;
  assh_error_t err;

  assh_userauth_client_key_get(s, k, ev->keys);

  ASSH_RET_IF_TRUE(k->keys == NULL,
               ASSH_ERR_NO_AUTH | ASSH_ERRSV_DISCONNECT);

  size_t len = ev->host_name.len;
  pv->hostname_len = len;
  if (len)
    {
      ASSH_RET_IF_TRUE(len > sizeof(pv->hostname),
                   ASSH_ERR_OUTPUT_OVERFLOW | ASSH_ERRSV_DISCONNECT);
      memcpy(pv->hostname, ev->host_name.str, len);
    }

  len = ev->host_username.len;
  pv->host_username_len = len;
  if (len)
    {
      ASSH_RET_IF_TRUE(len > sizeof(pv->host_username),
                   ASSH_ERR_OUTPUT_OVERFLOW | ASSH_ERRSV_DISCONNECT);
      memcpy(pv->host_username, ev->host_username.str, len);
    }

  pv->state = ASSH_USERAUTH_ST_SEND_HOSTBASED;

  return ASSH_OK;
}

static ASSH_USERAUTH_CLIENT_PROCESS(assh_userauth_client_hostbased_process)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  switch (pv->state)
    {
    case ASSH_USERAUTH_ST_SEND_HOSTBASED:
      ASSH_RET_IF_TRUE(p != NULL, ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);
      ASSH_RETURN(assh_userauth_client_send_hostbased(s, e) | ASSH_ERRSV_DISCONNECT);

    default:
      ASSH_RETURN(assh_userauth_client_default_process(s, p, e));
    }
}

#endif

/******************************************************************* public key */

#ifdef CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY
/* allocate a packet and append common fileds for a publickey request */
static assh_error_t assh_userauth_client_pck_pubkey(struct assh_session_s *s,
                                                    struct assh_packet_s **pout,
                                                    assh_bool_t second,
                                                    size_t extra_len)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  struct assh_key_s *pub_key = pv->pubkey.keys;
  assh_error_t err;

  size_t algo_name_len = strlen(assh_algo_name(pv->pubkey.algo));

  size_t blob_len;
  ASSH_RET_ON_ERR(assh_key_output(s->ctx, pub_key,
           NULL, &blob_len, ASSH_KEY_FMT_PUB_RFC4253) | ASSH_ERRSV_DISCONNECT);

  ASSH_RET_ON_ERR(assh_userauth_client_pck_head(s, pout, "publickey",
                 1 + 4 + algo_name_len + 4 + blob_len + extra_len) | ASSH_ERRSV_DISCONNECT);

  /* add boolean */
  uint8_t *str;
  ASSH_ASSERT(assh_packet_add_array(*pout, 1, &str));
  *str = second;

  /* add signature algorithm name */
  uint8_t *algo_name;
  ASSH_ASSERT(assh_packet_add_string(*pout, algo_name_len, &algo_name));
  memcpy(algo_name, assh_algo_name(pv->pubkey.algo), algo_name_len);

  /* add public key blob */
  uint8_t *blob;
  ASSH_ASSERT(assh_packet_add_string(*pout, blob_len, &blob));
  ASSH_JMP_ON_ERR(assh_key_output(s->ctx, pub_key, blob, &blob_len,
                 ASSH_KEY_FMT_PUB_RFC4253) | ASSH_ERRSV_DISCONNECT, err_packet);
  assh_packet_shrink_string(*pout, blob, blob_len);

  return ASSH_OK;

 err_packet:
  assh_packet_release(*pout);
  return err;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_client_pubkey_sign_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  struct assh_packet_s *pout = pv->pck;
  const struct assh_event_userauth_client_sign_s *ev = &e->userauth_client.sign;

  assh_packet_shrink_string(pout, ev->sign.data, ev->sign.len);

  assh_transport_push(s, pout);
  pv->pck = NULL;

  assh_free(s->ctx, pv->pubkey.auth_data);
  pv->pubkey.auth_data = NULL;

  pv->state = ASSH_USERAUTH_ST_SENT_PUBKEY_RQ;

  return ASSH_OK;
}

/* send a public key authentication probing request */
static assh_error_t
assh_userauth_client_send_pubkey(struct assh_session_s *s,
                                 struct assh_event_s *e)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  struct assh_packet_s *pout;

#ifdef CONFIG_ASSH_CLIENT_AUTH_USE_PKOK /* send a public key lookup first */
  if (pv->state != ASSH_USERAUTH_ST_SENT_PUBKEY)
    {
      ASSH_RET_ON_ERR(assh_userauth_client_pck_pubkey(s, &pout,
                     0, 0) | ASSH_ERRSV_DISCONNECT);
      assh_transport_push(s, pout);
      pv->state = ASSH_USERAUTH_ST_SENT_PUBKEY;
    }
  else
#endif  /* compute and send the signature directly */
    {
      const struct assh_algo_sign_s *algo = (const void *)pv->pubkey.algo;

      size_t sign_len;
      ASSH_RET_ON_ERR(assh_sign_generate(s->ctx, algo, pv->pubkey.keys, 0,
		     NULL, NULL, &sign_len) | ASSH_ERRSV_DISCONNECT);

      ASSH_RET_ON_ERR(assh_userauth_client_pck_pubkey(s, &pout,
                     1, 4 + sign_len) | ASSH_ERRSV_DISCONNECT);

      struct assh_userauth_keys_s *k = &pv->pubkey;

      if (k->keys->private)
        {
          ASSH_JMP_ON_ERR(assh_userauth_client_send_sign(s, k, pout, sign_len)
                       | ASSH_ERRSV_DISCONNECT, err_packet);
        }
      else
        {
          e->f_done = &assh_userauth_client_pubkey_sign_done;
          e->id = ASSH_EVENT_USERAUTH_CLIENT_SIGN;

          ASSH_JMP_ON_ERR(assh_userauth_client_get_sign(s, &e->userauth_client.sign,
                                                     k, pout, sign_len)
                       | ASSH_ERRSV_DISCONNECT, err_packet);
        }

      pv->state = ASSH_USERAUTH_ST_SENT_PUBKEY_RQ;
    }

  return ASSH_OK;

 err_packet:
  assh_packet_release(pout);
  return err;
}

static ASSH_USERAUTH_CLIENT_RETRY(assh_userauth_client_pubkey_retry)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  struct assh_userauth_keys_s *k = &pv->pubkey;
  assh_error_t err;

  assh_userauth_client_key_next(s, k);

  if (k->keys == NULL)
    return ASSH_NO_DATA;

  /* some user keys are already available */
  ASSH_RETURN(assh_userauth_client_send_pubkey(s, e)
               | ASSH_ERRSV_DISCONNECT);
}

/* send a public key authentication probing request */
static ASSH_USERAUTH_CLIENT_REQ(assh_userauth_client_pubkey_req)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  struct assh_userauth_keys_s *k = &pv->pubkey;
  assh_error_t err;

  assh_userauth_client_key_get(s, k, ev->keys);

  ASSH_RET_IF_TRUE(k->keys == NULL,
               ASSH_ERR_NO_AUTH | ASSH_ERRSV_DISCONNECT);

  pv->state = ASSH_USERAUTH_ST_SEND_PUBKEY;

  return ASSH_OK;
}

static ASSH_USERAUTH_CLIENT_PROCESS(assh_userauth_client_pubkey_process)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  switch (pv->state)
    {
    case ASSH_USERAUTH_ST_SEND_PUBKEY:
      ASSH_RET_IF_TRUE(p != NULL, ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);
      ASSH_RETURN(assh_userauth_client_send_pubkey(s, e) | ASSH_ERRSV_DISCONNECT);

    case ASSH_USERAUTH_ST_SENT_PUBKEY:
      if (p == NULL)
        return ASSH_OK;
      switch(p->head.msg)
        {
        case SSH_MSG_USERAUTH_SUCCESS:
          ASSH_RETURN(ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);

        case SSH_MSG_USERAUTH_PK_OK:
          ASSH_RETURN(assh_userauth_client_send_pubkey(s, e)
                       | ASSH_ERRSV_DISCONNECT);
        }

    case ASSH_USERAUTH_ST_SENT_PUBKEY_RQ:
      if (p == NULL)
        return ASSH_OK;
      ASSH_RETURN(assh_userauth_client_default_process(s, p, e));

    default:
      ASSH_UNREACHABLE();
    }

  return ASSH_OK;
}

#endif

/********************************************************************/

static ASSH_EVENT_DONE_FCN(assh_userauth_client_username_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  ASSH_RET_IF_TRUE(pv->state != ASSH_USERAUTH_ST_GET_USERNAME,
	       ASSH_ERR_STATE | ASSH_ERRSV_FATAL);

  const struct assh_event_userauth_client_user_s *ev = &e->userauth_client.user;

  /* keep username */
  size_t ulen = ev->username.len;
  ASSH_RET_IF_TRUE(ulen > sizeof(pv->username),
	       ASSH_ERR_OUTPUT_OVERFLOW | ASSH_ERRSV_DISCONNECT);
  memcpy(pv->username, ev->username.str, ulen);
  pv->username_len = ulen;

  ASSH_RETURN(assh_userauth_client_none_req(s, NULL));
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

  pv->state = ASSH_USERAUTH_ST_GET_USERNAME;

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_client_get_methods_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  ASSH_RET_IF_TRUE(pv->state != ASSH_USERAUTH_ST_GET_METHODS,
	       ASSH_ERR_STATE | ASSH_ERRSV_FATAL);

  const struct assh_event_userauth_client_methods_s *ev =
    &e->userauth_client.methods;
  enum assh_userauth_methods_e select = ev->select;
  assert(!(select & ~ev->methods));
  assert(!(select & (select - 1)));

  const struct assh_userauth_client_method_s *m;

  for (m = assh_userauth_client_methods; m->name != NULL; m++)
    {
      if (select & m->mask)
        {
          pv->method = m;
          ASSH_RETURN(m->f_req(s, ev) | ASSH_ERRSV_DISCONNECT);
        }
    }

   ASSH_RETURN(ASSH_ERR_NO_AUTH | ASSH_ERRSV_DISCONNECT);
}

static assh_error_t
assh_userauth_client_get_methods(struct assh_session_s *s,
                                 struct assh_event_s *e,
                                 assh_bool_t partial_success)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  struct assh_event_userauth_client_methods_s *ev =
    &e->userauth_client.methods;

  memset(ev, 0, sizeof(*ev));
  ev->methods = pv->methods;
  ev->partial_success = partial_success;
  e->id = ASSH_EVENT_USERAUTH_CLIENT_METHODS;
  e->f_done = &assh_userauth_client_get_methods_done;

  pv->state = ASSH_USERAUTH_ST_GET_METHODS;
  pv->method = NULL;

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_client_success_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  const struct assh_service_s *srv = pv->srv;
  assh_error_t err;

  ASSH_RET_IF_TRUE(pv->state != ASSH_USERAUTH_ST_SUCCESS,
	       ASSH_ERR_STATE | ASSH_ERRSV_FATAL);

  /* cleanup the authentication service and start the next service. */
  assh_userauth_client_cleanup(s);

  ASSH_RET_ON_ERR(srv->f_init(s) | ASSH_ERRSV_DISCONNECT);
  s->srv_index++;

  return ASSH_OK;
}

static assh_error_t
assh_userauth_client_success(struct assh_session_s *s,
                             struct assh_event_s *e)
{
  struct assh_userauth_context_s *pv = s->srv_pv;

  e->id = ASSH_EVENT_USERAUTH_CLIENT_SUCCESS;
  e->f_done = &assh_userauth_client_success_done;

  pv->state = ASSH_USERAUTH_ST_SUCCESS;

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
  ASSH_RET_ON_ERR(assh_packet_check_string(p, methods, &partial_success)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_RET_ON_ERR(assh_packet_check_array(p, partial_success, 1, NULL)
	       | ASSH_ERRSV_DISCONNECT);

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
      for (m = assh_userauth_client_methods; m->name != NULL; m++)
        {
          if (!m->name[nlen] &&
              !strncmp((const char*)methods, m->name, nlen))
            {
              pv->method = m;

              /* test if the method wants to retry authentication on its own */
              ASSH_RET_ON_ERR(m->f_retry(s, e));
              if (err != ASSH_NO_DATA)
                return ASSH_OK;

              mask |= m->mask;
            }
        }
    }

  ASSH_RET_IF_TRUE(mask == 0, ASSH_ERR_NO_AUTH | ASSH_ERRSV_DISCONNECT);

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

  ASSH_RET_ON_ERR(assh_packet_check_string(p, text, &lang)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_RET_ON_ERR(assh_packet_check_string(p, lang, NULL)
	       | ASSH_ERRSV_DISCONNECT);

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

static ASSH_USERAUTH_CLIENT_PROCESS(assh_userauth_client_default_process)
{
  assh_error_t err;

  if (p == NULL)
    return ASSH_OK;

  switch (p->head.msg)
    {
    case SSH_MSG_USERAUTH_BANNER:
      ASSH_RETURN(assh_userauth_client_banner(s, p, e) | ASSH_ERRSV_DISCONNECT);

    case SSH_MSG_USERAUTH_SUCCESS:
      ASSH_RETURN(assh_userauth_client_success(s, e) | ASSH_ERRSV_DISCONNECT);

    case SSH_MSG_USERAUTH_FAILURE:
      ASSH_RETURN(assh_userauth_client_failure(s, p, e) | ASSH_ERRSV_DISCONNECT);

    case SSH_MSG_UNIMPLEMENTED:
      ASSH_RETURN(ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);

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
    case ASSH_USERAUTH_ST_INIT:
      ASSH_RET_IF_TRUE(p != NULL, ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);
      ASSH_RETURN(assh_userauth_client_username(s, e));

    case ASSH_USERAUTH_ST_SENT_NONE_RQ:
      ASSH_RETURN(assh_userauth_client_default_process(s, p, e));

    default:
      ASSH_RETURN(pv->method->f_process(s, p, e) | ASSH_ERRSV_DISCONNECT);
    }
}

const struct assh_userauth_client_method_s
assh_userauth_client_methods[] = {
    { "none",
      ASSH_USERAUTH_METHOD_NONE,
      .f_req = &assh_userauth_client_none_req,
      .f_process = &assh_userauth_client_default_process,
      .f_retry = &assh_userauth_client_no_retry },
#ifdef CONFIG_ASSH_CLIENT_AUTH_PASSWORD
    { "password",
      ASSH_USERAUTH_METHOD_PASSWORD,
      .f_req = &assh_userauth_client_password_req,
      .f_process = &assh_userauth_client_password_process,
      .f_retry = &assh_userauth_client_no_retry },
#endif
#ifdef CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY
    { "publickey",
      ASSH_USERAUTH_METHOD_PUBKEY,
      .f_req = &assh_userauth_client_pubkey_req,
      .f_process = &assh_userauth_client_pubkey_process,
      .f_retry = &assh_userauth_client_pubkey_retry },
#endif
#ifdef CONFIG_ASSH_CLIENT_AUTH_HOSTBASED
    { "hostbased",
      ASSH_USERAUTH_METHOD_HOSTBASED,
      .f_req = assh_userauth_client_hostbased_req,
      .f_process = assh_userauth_client_hostbased_process,
      .f_retry = &assh_userauth_client_hostbased_retry },
#endif
#ifdef CONFIG_ASSH_CLIENT_AUTH_KEYBOARD
    { "keyboard-interactive",
      ASSH_USERAUTH_METHOD_KEYBOARD,
      .f_req = &assh_userauth_client_keyboard_req,
      .f_process = &assh_userauth_client_keyboard_process,
      .f_retry = &assh_userauth_client_no_retry },
#endif
    { 0 }
};

const struct assh_service_s assh_service_userauth_client =
{
  .name = "ssh-userauth",
  .side = ASSH_CLIENT,
  .f_init = assh_userauth_client_init,
  .f_cleanup = assh_userauth_client_cleanup,
  .f_process = assh_userauth_client_process,
};

#endif

