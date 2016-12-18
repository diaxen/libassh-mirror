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
  ASSH_USERAUTH_ST_GET_METHODS,
  ASSH_USERAUTH_ST_SUCCESS,
};

#define ASSH_USERAUTH_CLIENT_REQ(n)                             \
  assh_error_t (n)(struct assh_session_s *s,                    \
                   struct assh_event_s *e)

typedef ASSH_USERAUTH_CLIENT_REQ(assh_userauth_client_req_t);

#define ASSH_USERAUTH_CLIENT_RETRY(n)           \
  assh_error_t (n)(struct assh_session_s *s)

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
  uint16_t algo_idx;
  const struct assh_algo_s *algo;
  struct assh_key_s *pub_keys;
#endif

#ifdef CONFIG_ASSH_CLIENT_AUTH_KEYBOARD
  struct assh_buffer_s *keyboard_array;
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

  ASSH_CHK_RET(s->srv_index >= s->ctx->srvs_count, ASSH_ERR_SERVICE_NA);

  ASSH_ERR_RET(assh_alloc(s->ctx, sizeof(*pv),
                    ASSH_ALLOC_SECUR, (void**)&pv));

  pv->methods = 0;
  pv->state = ASSH_USERAUTH_ST_INIT;

  s->srv = &assh_service_userauth_client;
  s->srv_pv = pv;

#ifdef CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY
  pv->pub_keys = NULL;
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
  assh_key_flush(c, &pv->pub_keys);
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

  ASSH_ERR_RET(assh_packet_alloc(s->ctx, SSH_MSG_USERAUTH_REQUEST,
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

  ASSH_ERR_RET(assh_userauth_client_pck_head(s, &pout, "none",
                                             0) | ASSH_ERRSV_DISCONNECT);

  assh_transport_push(s, pout);

  pv->state = ASSH_USERAUTH_ST_SENT_NONE_RQ;

  return ASSH_OK;
}

/******************************************************************* password */

#ifdef CONFIG_ASSH_CLIENT_AUTH_PASSWORD
/* send a password authentication request */
static assh_error_t
assh_userauth_client_send_password(struct assh_session_s *s,
                                   const struct assh_buffer_s *password,
                                   const struct assh_buffer_s *new_password)
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

  ASSH_ERR_RET(assh_userauth_client_pck_head(s, &pout, "password",
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

  ASSH_ERR_RET(assh_userauth_client_send_password(s,
               &e->userauth_client.methods.password, NULL));

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_client_req_pwchange_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  ASSH_CHK_RET(pv->state != ASSH_USERAUTH_ST_GET_PWCHANGE,
	       ASSH_ERR_STATE | ASSH_ERRSV_FATAL);

  assh_packet_release(pv->pck);
  pv->pck = NULL;

  if (e->userauth_client.pwchange.old_password.len &&
      e->userauth_client.pwchange.new_password.len)
    {
      ASSH_ERR_RET(assh_userauth_client_send_password(s,
        &e->userauth_client.pwchange.old_password,
        &e->userauth_client.pwchange.new_password));
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

  ASSH_ERR_RET(assh_packet_check_string(p, prompt, &lang) | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_string(p, lang, &end) | ASSH_ERRSV_DISCONNECT);

  e->userauth_client.pwchange.prompt.str = (char*)prompt + 4;
  e->userauth_client.pwchange.prompt.len = assh_load_u32(prompt);
  e->userauth_client.pwchange.lang.str = (char*)lang + 4;
  e->userauth_client.pwchange.lang.len = assh_load_u32(lang);
  e->userauth_client.pwchange.old_password.len = 0;
  e->userauth_client.pwchange.new_password.len = 0;

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
          ASSH_ERR_RET(assh_userauth_client_req_pwchange(s, p, e)
                       | ASSH_ERRSV_DISCONNECT);
          break;

        default:
          ASSH_ERR_RET(assh_userauth_client_default_process(s, p, e));
        }
      return ASSH_OK;

    case ASSH_USERAUTH_ST_PWCHANGE_SKIP:
      ASSH_ERR_RET(assh_userauth_client_get_methods(s, e, 0));
      return ASSH_NO_DATA;

    default:
      ASSH_ERR_RET(ASSH_ERR_STATE | ASSH_ERRSV_FATAL);
    }

  return ASSH_OK;
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

  size_t sub_len = e->userauth_client.methods.keyboard_sub.len;

  ASSH_ERR_RET(assh_userauth_client_pck_head(s, &pout, "keyboard-interactive",
                                             4 + 4 + sub_len) | ASSH_ERRSV_DISCONNECT);

  ASSH_ASSERT(assh_packet_add_string(pout, 0, &str)); /* lang */
  ASSH_ASSERT(assh_packet_add_string(pout, sub_len, &str)); /* sub methods */
  memcpy(str, e->userauth_client.methods.keyboard_sub.str, sub_len);

  assh_transport_push(s, pout);

  pv->state = ASSH_USERAUTH_ST_KEYBOARD_SENT_RQ;

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_client_keyboard_info_done)
{
  struct assh_context_s *c = s->ctx;
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  ASSH_CHK_RET(pv->state != ASSH_USERAUTH_ST_KEYBOARD_INFO,
	       ASSH_ERR_STATE | ASSH_ERRSV_FATAL);

  assh_packet_release(pv->pck);
  pv->pck = NULL;

  struct assh_packet_s *pout;

  size_t i, count = e->userauth_client.keyboard.count;

  size_t psize = 4;
  for (i = 0; i < count; i++)
    psize += 4 + e->userauth_client.keyboard.responses[i].len;

  ASSH_ERR_RET(assh_packet_alloc(s->ctx, SSH_MSG_USERAUTH_INFO_RESPONSE,
                                 ASSH_MAX(psize, 256), &pout)
               | ASSH_ERRSV_DISCONNECT);
  pout->padding = ASSH_PADDING_MAX;

  uint8_t *str;
  ASSH_ASSERT(assh_packet_add_array(pout, 4, &str));
  assh_store_u32(str, count);

  for (i = 0; i < count; i++)
    {
      size_t len = e->userauth_client.keyboard.responses[i].len;
      ASSH_ASSERT(assh_packet_add_string(pout, len, &str));
      memcpy(str, e->userauth_client.keyboard.responses[i].str, len);
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

  ASSH_ERR_RET(assh_packet_check_string(p, name, &ins)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_string(p, ins, &lang)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_string(p, lang, &count_)
	       | ASSH_ERRSV_DISCONNECT);

  ASSH_ERR_RET(assh_packet_check_array(p, count_, 4, &prompt)
	       | ASSH_ERRSV_DISCONNECT);

  size_t i, count = assh_load_u32(count_);
  ASSH_CHK_RET(count > 32, ASSH_ERR_INPUT_OVERFLOW | ASSH_ERRSV_DISCONNECT);

  struct assh_buffer_s *prompts = NULL;
  uint32_t echos = 0;

  if (count > 0)
    {
      ASSH_ERR_RET(assh_alloc(c, sizeof(*prompts) * count,
                              ASSH_ALLOC_INTERNAL, (void**)&prompts));

      assert(pv->keyboard_array == NULL);
      pv->keyboard_array = prompts;

      for (i = 0; i < count; i++)
        {
          ASSH_ERR_RET(assh_packet_check_string(p, prompt, &echo)
                       | ASSH_ERRSV_DISCONNECT);
          size_t len = assh_load_u32(prompt);
          ASSH_CHK_RET(len == 0, ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);
          prompts[i].str = (char*)prompt + 4;
          prompts[i].len = len;

          ASSH_ERR_RET(assh_packet_check_array(p, echo, 1, &prompt)
                       | ASSH_ERRSV_DISCONNECT);

          echos |= !!*echo << i;
        }
    }

  e->id = ASSH_EVENT_USERAUTH_CLIENT_KEYBOARD;
  e->f_done = &assh_userauth_client_keyboard_info_done;
  e->userauth_client.keyboard.name.str = (char*)name + 4;
  e->userauth_client.keyboard.name.len = assh_load_u32(name);
  e->userauth_client.keyboard.instruction.str = (char*)ins + 4;
  e->userauth_client.keyboard.instruction.len = assh_load_u32(ins);
  e->userauth_client.keyboard.count = count;
  e->userauth_client.keyboard.echos = echos;
  e->userauth_client.keyboard.prompts = prompts;
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
      ASSH_ERR_RET(assh_userauth_client_req_keyboard_info(s, p, e)
                   | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;

    default:
      ASSH_ERR_RET(assh_userauth_client_default_process(s, p, e));
      return ASSH_OK;
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
  struct assh_key_s *pub_key = pv->pub_keys;
  assh_error_t err;

  size_t algo_name_len = strlen(assh_algo_name(pv->algo));

  size_t blob_len;
  ASSH_ERR_RET(assh_key_output(s->ctx, pub_key,
           NULL, &blob_len, ASSH_KEY_FMT_PUB_RFC4253) | ASSH_ERRSV_DISCONNECT);

  ASSH_ERR_RET(assh_userauth_client_pck_head(s, pout, "publickey",
                 1 + 4 + algo_name_len + 4 + blob_len + extra_len) | ASSH_ERRSV_DISCONNECT);

  /* add boolean */
  uint8_t *str;
  ASSH_ASSERT(assh_packet_add_array(*pout, 1, &str));
  *str = second;

  /* add signature algorithm name */
  uint8_t *algo_name;
  ASSH_ASSERT(assh_packet_add_string(*pout, algo_name_len, &algo_name));
  memcpy(algo_name, assh_algo_name(pv->algo), algo_name_len);

  /* add public key blob */
  uint8_t *blob;
  ASSH_ASSERT(assh_packet_add_string(*pout, blob_len, &blob));
  ASSH_ERR_GTO(assh_key_output(s->ctx, pub_key, blob, &blob_len,
                 ASSH_KEY_FMT_PUB_RFC4253) | ASSH_ERRSV_DISCONNECT, err_packet);
  assh_packet_shrink_string(*pout, blob, blob_len);

  return ASSH_OK;

 err_packet:
  assh_packet_release(*pout);
  return err;
}

/* send a public key authentication request with signature */
static assh_error_t assh_userauth_client_req_pubkey_sign(struct assh_session_s *s)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  const struct assh_algo_sign_s *algo = (const void *)pv->algo;
  assh_error_t err;

  size_t sign_len;
  ASSH_ERR_RET(assh_sign_generate(s->ctx, algo, pv->pub_keys, 0,
		NULL, NULL, &sign_len) | ASSH_ERRSV_DISCONNECT);

  struct assh_packet_s *pout;
  ASSH_ERR_RET(assh_userauth_client_pck_pubkey(s, &pout,
                1, 4 + sign_len) | ASSH_ERRSV_DISCONNECT);

  uint8_t sid_len[4];   /* fake string header for session id */
  assh_store_u32(sid_len, s->session_id_len);

  /* buffers that must be signed by the client */
  struct assh_cbuffer_s data[3] = {
    { .data = sid_len,         .len = 4 },
    { .data = s->session_id,   .len = s->session_id_len },
    { .data = &pout->head.msg, .len = pout->data_size - 5 },
  };

  /* append the signature */
  uint8_t *sign;
  ASSH_ASSERT(assh_packet_add_string(pout, sign_len, &sign));
  ASSH_ERR_GTO(assh_sign_generate(s->ctx, algo, pv->pub_keys,
                 3, data, sign, &sign_len)
	       | ASSH_ERRSV_DISCONNECT, err_packet);
  assh_packet_shrink_string(pout, sign, sign_len);

  assh_transport_push(s, pout);

  pv->state = ASSH_USERAUTH_ST_SENT_PUBKEY_RQ;
  return ASSH_OK;

 err_packet:
  assh_packet_release(pout);
  return err;
}

/* send a public key authentication probing request */
static assh_error_t
assh_userauth_client_send_pubkey(struct assh_session_s *s)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

#ifdef CONFIG_ASSH_CLIENT_AUTH_USE_PKOK /* send a public key lookup first */
  struct assh_packet_s *pout;
  ASSH_ERR_RET(assh_userauth_client_pck_pubkey(s, &pout,
                 0, 0) | ASSH_ERRSV_DISCONNECT);
  assh_transport_push(s, pout);
  pv->state = ASSH_USERAUTH_ST_SENT_PUBKEY;
#else  /* compute and send the signature directly */
  ASSH_ERR_RET(assh_userauth_client_req_pubkey_sign(s) | ASSH_ERRSV_DISCONNECT);
#endif
  return ASSH_OK;
}

static ASSH_USERAUTH_CLIENT_RETRY(assh_userauth_client_pubkey_retry)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  pv->algo_idx++;
  while (pv->pub_keys != NULL &&
         assh_algo_by_key(s->ctx, pv->pub_keys,
                          &pv->algo_idx, &pv->algo) != ASSH_OK)
    {
      /* drop used key */
      assh_key_drop(s->ctx, &pv->pub_keys);
      pv->algo_idx = 0;
    }

  if (pv->pub_keys != NULL)
    {
      /* some user keys are already available */
      ASSH_ERR_RET(assh_userauth_client_send_pubkey(s)
                   | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;
    }

  return ASSH_NO_DATA;
}

/* send a public key authentication probing request */
static ASSH_USERAUTH_CLIENT_REQ(assh_userauth_client_pubkey_req)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  struct assh_key_s *k = e->userauth_client.methods.pub_keys;

  while (k != NULL)
    {
      /* check usable keys */
      pv->algo_idx = 0;
      struct assh_key_s *next = k->next;

      /* insert provided keys in internal list */
      if (assh_algo_by_key(s->ctx, k, &pv->algo_idx, &pv->algo) == ASSH_OK)
        assh_key_insert(&pv->pub_keys, k);
      else
        assh_key_drop(s->ctx, &k);

      k = next;
    }

  ASSH_CHK_RET(pv->pub_keys == NULL,
               ASSH_ERR_NO_AUTH | ASSH_ERRSV_DISCONNECT);

  ASSH_ERR_RET(assh_userauth_client_send_pubkey(s) | ASSH_ERRSV_DISCONNECT);

  return ASSH_OK;
}

static ASSH_USERAUTH_CLIENT_PROCESS(assh_userauth_client_pubkey_process)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  if (p == NULL)
    return ASSH_OK;

  switch (pv->state)
    {
    case ASSH_USERAUTH_ST_SENT_PUBKEY:
      switch(p->head.msg)
        {
        case SSH_MSG_USERAUTH_SUCCESS:
          ASSH_ERR_RET(ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);

        case SSH_MSG_USERAUTH_PK_OK:
          ASSH_ERR_RET(assh_userauth_client_req_pubkey_sign(s) | ASSH_ERRSV_DISCONNECT);
          return ASSH_OK;

        default:
          break;
        }

    case ASSH_USERAUTH_ST_SENT_PUBKEY_RQ:
      ASSH_ERR_RET(assh_userauth_client_default_process(s, p, e));
      return ASSH_OK;
    }
}

#endif

/********************************************************************/

static ASSH_EVENT_DONE_FCN(assh_userauth_client_username_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  ASSH_CHK_RET(pv->state != ASSH_USERAUTH_ST_GET_USERNAME,
	       ASSH_ERR_STATE | ASSH_ERRSV_FATAL);

  /* keep username */
  size_t ulen = e->userauth_client.user.username.len;
  ASSH_CHK_RET(ulen > sizeof(pv->username),
	       ASSH_ERR_OUTPUT_OVERFLOW | ASSH_ERRSV_DISCONNECT);
  memcpy(pv->username, e->userauth_client.user.username.str,
	 pv->username_len = ulen);

  ASSH_ERR_RET(assh_userauth_client_none_req(s, NULL));

  return ASSH_OK;
}

static assh_error_t
assh_userauth_client_username(struct assh_session_s *s,
                              struct assh_event_s *e)
{
  struct assh_userauth_context_s *pv = s->srv_pv;

  e->id = ASSH_EVENT_USERAUTH_CLIENT_USER;
  e->f_done = &assh_userauth_client_username_done;
  e->userauth_client.user.username.str = NULL;
  e->userauth_client.user.username.len = 0;
  pv->state = ASSH_USERAUTH_ST_GET_USERNAME;

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_client_get_methods_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  ASSH_CHK_RET(pv->state != ASSH_USERAUTH_ST_GET_METHODS,
	       ASSH_ERR_STATE | ASSH_ERRSV_FATAL);

  enum assh_userauth_methods_e select = e->userauth_client.methods.select;
  assert(!(select & ~e->userauth_client.methods.methods));
  assert(!(select & (select - 1)));

  const struct assh_userauth_client_method_s *m;

  for (m = assh_userauth_client_methods; m->name != NULL; m++)
    {
      if (select & m->mask)
        {
          pv->method = m;
          ASSH_ERR_RET(m->f_req(s, e)
                       | ASSH_ERRSV_DISCONNECT);
          return ASSH_OK;
        }
    }

   ASSH_ERR_RET(ASSH_ERR_NO_AUTH | ASSH_ERRSV_DISCONNECT);
}

static assh_error_t
assh_userauth_client_get_methods(struct assh_session_s *s,
                                 struct assh_event_s *e,
                                 assh_bool_t partial_success)
{
  struct assh_userauth_context_s *pv = s->srv_pv;

  memset(&e->userauth_client.methods, 0, sizeof(e->userauth_client.methods));
  e->userauth_client.methods.methods = pv->methods;
  e->userauth_client.methods.partial_success = partial_success;
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

  ASSH_CHK_RET(pv->state != ASSH_USERAUTH_ST_SUCCESS,
	       ASSH_ERR_STATE | ASSH_ERRSV_FATAL);

  /* cleanup the authentication service and start the next service. */
  assh_userauth_client_cleanup(s);

  ASSH_ERR_RET(srv->f_init(s) | ASSH_ERRSV_DISCONNECT);
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
  ASSH_ERR_RET(assh_packet_check_string(p, methods, &partial_success)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_array(p, partial_success, 1, NULL)
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
              ASSH_ERR_RET(m->f_retry(s));
              if (err != ASSH_NO_DATA)
                return ASSH_OK;

              mask |= m->mask;
            }
        }
    }

  ASSH_CHK_RET(mask == 0, ASSH_ERR_NO_AUTH | ASSH_ERRSV_DISCONNECT);

  /* report an event with server proposed methods */
  pv->methods = mask;
  ASSH_ERR_RET(assh_userauth_client_get_methods(s, e, *partial_success));

  return ASSH_OK;
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

  ASSH_ERR_RET(assh_packet_check_string(p, text, &lang)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_string(p, lang, NULL)
	       | ASSH_ERRSV_DISCONNECT);

  e->id = ASSH_EVENT_USERAUTH_CLIENT_BANNER;
  e->f_done = &assh_userauth_client_banner_done;
  e->userauth_client.banner.text.str = (char*)text + 4;
  e->userauth_client.banner.text.len = assh_load_u32(text);
  e->userauth_client.banner.lang.str = (char*)lang + 4;
  e->userauth_client.banner.lang.len = assh_load_u32(lang);

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
      ASSH_ERR_RET(assh_userauth_client_banner(s, p, e) | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;

    case SSH_MSG_USERAUTH_SUCCESS:
      ASSH_ERR_RET(assh_userauth_client_success(s, e) | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;

    case SSH_MSG_USERAUTH_FAILURE:
      ASSH_ERR_RET(assh_userauth_client_failure(s, p, e) | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;

    case SSH_MSG_UNIMPLEMENTED:
      ASSH_ERR_RET(ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);

    default:
      ASSH_ERR_RET(assh_transport_unimp(s, p));
      return ASSH_OK;
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
      ASSH_CHK_RET(p != NULL, ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);
      ASSH_ERR_RET(assh_userauth_client_username(s, e));
      return ASSH_OK;

    case ASSH_USERAUTH_ST_SENT_NONE_RQ:
      ASSH_ERR_RET(assh_userauth_client_default_process(s, p, e));
      return ASSH_OK;

    default:
      ASSH_ERR_RET(pv->method->f_process(s, p, e) | ASSH_ERRSV_DISCONNECT);
      return err;
    }

  return ASSH_OK;
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

