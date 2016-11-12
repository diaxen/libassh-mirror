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
  ASSH_USERAUTH_INIT,
  ASSH_USERAUTH_GET_USERNAME,
  ASSH_USERAUTH_SENT_NONE_RQ,
#ifdef CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY
  ASSH_USERAUTH_SENT_PUB_KEY_RQ,
  ASSH_USERAUTH_SENT_PUB_KEY,
#endif
#ifdef CONFIG_ASSH_CLIENT_AUTH_PASSWORD
  ASSH_USERAUTH_SENT_PASSWORD_RQ,
  ASSH_USERAUTH_GET_PWCHANGE,
  ASSH_USERAUTH_PWCHANGE_SKIP,
#endif
  ASSH_USERAUTH_GET_METHODS,
  ASSH_USERAUTH_SUCCESS,
};

struct assh_userauth_context_s
{
  const struct assh_service_s *srv;
  struct assh_packet_s *pck;
  char username[CONFIG_ASSH_AUTH_USERNAME_LEN];

  size_t username_len:16;

  enum assh_userauth_methods_e methods:8;
  enum assh_userauth_state_e state:8;
#ifdef CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY
  uint16_t algo_idx;
  const struct assh_algo_s *algo;
  struct assh_key_s *pub_keys;
#endif
};

static ASSH_SERVICE_INIT_FCN(assh_userauth_client_init)
{
  struct assh_userauth_context_s *pv;
  assh_error_t err;

  ASSH_CHK_RET(s->srv_index >= s->ctx->srvs_count, ASSH_ERR_SERVICE_NA);

  ASSH_ERR_RET(assh_alloc(s->ctx, sizeof(*pv),
                    ASSH_ALLOC_SECUR, (void**)&pv));

  pv->methods = 0;
  pv->state = ASSH_USERAUTH_INIT;

  s->srv = &assh_service_userauth_client;
  s->srv_pv = pv;

#ifdef CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY
  pv->pub_keys = NULL;
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


  assh_packet_release(pv->pck);

  assh_free(c, pv);

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

/******************************************************************* password */

#ifdef CONFIG_ASSH_CLIENT_AUTH_PASSWORD
/* send a password authentication request */
static assh_error_t
assh_userauth_client_req_password(struct assh_session_s *s,
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

  pv->state = ASSH_USERAUTH_SENT_PASSWORD_RQ;

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_client_req_pwchange_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  ASSH_CHK_RET(pv->state != ASSH_USERAUTH_GET_PWCHANGE,
	       ASSH_ERR_STATE | ASSH_ERRSV_FATAL);

  assh_packet_release(pv->pck);
  pv->pck = NULL;

  if (e->userauth_client.pwchange.old_password.len &&
      e->userauth_client.pwchange.new_password.len)
    {
      ASSH_ERR_RET(assh_userauth_client_req_password(s,
        &e->userauth_client.pwchange.old_password,
        &e->userauth_client.pwchange.new_password));
    }
  else
    {
      pv->state = ASSH_USERAUTH_PWCHANGE_SKIP;
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
  pv->state = ASSH_USERAUTH_GET_PWCHANGE;

  assert(pv->pck == NULL);
  pv->pck = assh_packet_refinc(p);

  return ASSH_OK;
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
#endif

#ifdef CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY
/* send a public key authentication request with signature */
static assh_error_t assh_userauth_client_req_pubkey_sign(struct assh_session_s *s)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  const struct assh_algo_sign_s *algo = (const void *)pv->algo;
  assh_error_t err;

  size_t sign_len;
  ASSH_ERR_RET(assh_sign_generate(s->ctx, algo, pv->pub_keys, 0,
		NULL, NULL, NULL, &sign_len) | ASSH_ERRSV_DISCONNECT);

  struct assh_packet_s *pout;
  ASSH_ERR_RET(assh_userauth_client_pck_pubkey(s, &pout,
                1, 4 + sign_len) | ASSH_ERRSV_DISCONNECT);

  uint8_t sid_len[4];   /* fake string header for session id */
  assh_store_u32(sid_len, s->session_id_len);

  /* buffers that must be signed by the client */
  const uint8_t *sign_ptrs[3] =
    { sid_len, s->session_id,     &pout->head.msg };
  size_t sign_sizes[3]        =
    { 4,       s->session_id_len, pout->data_size - 5 };

  /* append the signature */
  uint8_t *sign;
  ASSH_ASSERT(assh_packet_add_string(pout, sign_len, &sign));
  ASSH_ERR_GTO(assh_sign_generate(s->ctx, algo, pv->pub_keys,
                 3, sign_ptrs, sign_sizes, sign, &sign_len)
	       | ASSH_ERRSV_DISCONNECT, err_packet);
  assh_packet_shrink_string(pout, sign, sign_len);

  assh_transport_push(s, pout);

  pv->state = ASSH_USERAUTH_SENT_PUB_KEY_RQ;
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

#ifdef CONFIG_ASSH_CLIENT_AUTH_USE_PKOK /* send a public key lookup first */
  struct assh_packet_s *pout;
  ASSH_ERR_RET(assh_userauth_client_pck_pubkey(s, &pout,
                 0, 0) | ASSH_ERRSV_DISCONNECT);
  assh_transport_push(s, pout);
  pv->state = ASSH_USERAUTH_SENT_PUB_KEY;
#else  /* compute and send the signature directly */
  ASSH_ERR_RET(assh_userauth_client_req_pubkey_sign(s) | ASSH_ERRSV_DISCONNECT);
#endif
  return ASSH_OK;
}
#endif

/********************************************************************/

static ASSH_EVENT_DONE_FCN(assh_userauth_client_username_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  struct assh_packet_s *pout;
  ASSH_CHK_RET(pv->state != ASSH_USERAUTH_GET_USERNAME,
	       ASSH_ERR_STATE | ASSH_ERRSV_FATAL);

  /* keep username */
  size_t ulen = e->userauth_client.user.username.len;
  ASSH_CHK_RET(ulen > sizeof(pv->username),
	       ASSH_ERR_OUTPUT_OVERFLOW | ASSH_ERRSV_DISCONNECT);
  memcpy(pv->username, e->userauth_client.user.username.str,
	 pv->username_len = ulen);

  /* send auth request with the "none" method */
  ASSH_ERR_RET(assh_userauth_client_pck_head(s, &pout, "none", 0)
	       | ASSH_ERRSV_DISCONNECT);
  assh_transport_push(s, pout);

  pv->state = ASSH_USERAUTH_SENT_NONE_RQ;

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
  pv->state = ASSH_USERAUTH_GET_USERNAME;

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_client_methods_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  ASSH_CHK_RET(pv->state != ASSH_USERAUTH_GET_METHODS,
	       ASSH_ERR_STATE | ASSH_ERRSV_FATAL);

  enum assh_userauth_methods_e select = e->userauth_client.methods.select;
  assert(!(select & ~e->userauth_client.methods.methods));
  assert(!(select & (select - 1)));

#ifdef CONFIG_ASSH_CLIENT_AUTH_PASSWORD
  if (select & ASSH_USERAUTH_METHOD_PASSWORD)
    {
      ASSH_ERR_RET(assh_userauth_client_req_password(s,
                     &e->userauth_client.methods.password, NULL)
                   | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;
    }
#endif

#ifdef CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY
  if (select & ASSH_USERAUTH_METHOD_PUBKEY)
    {
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

      ASSH_ERR_RET(assh_userauth_client_req_pubkey(s) | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;
    }
#endif

   ASSH_ERR_RET(ASSH_ERR_NO_AUTH | ASSH_ERRSV_DISCONNECT);
}

static assh_error_t
assh_userauth_client_methods(struct assh_session_s *s,
                             struct assh_event_s *e,
                             assh_bool_t partial_success)
{
  struct assh_userauth_context_s *pv = s->srv_pv;

  memset(&e->userauth_client.methods, 0, sizeof(e->userauth_client.methods));
  e->userauth_client.methods.methods = pv->methods;
  e->userauth_client.methods.partial_success = partial_success;
  e->id = ASSH_EVENT_USERAUTH_CLIENT_METHODS;
  e->f_done = &assh_userauth_client_methods_done;

  pv->state = ASSH_USERAUTH_GET_METHODS;

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_client_success_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  const struct assh_service_s *srv = pv->srv;
  assh_error_t err;

  ASSH_CHK_RET(pv->state != ASSH_USERAUTH_SUCCESS,
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

  pv->state = ASSH_USERAUTH_SUCCESS;

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

  switch (pv->state)
    {
#ifdef CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY
    case ASSH_USERAUTH_SENT_PUB_KEY_RQ:
    case ASSH_USERAUTH_SENT_PUB_KEY:
      /* try next algorithm usable with the same key */
      pv->algo_idx++;
      while (pv->pub_keys != NULL &&
             assh_algo_by_key(s->ctx, pv->pub_keys,
                              &pv->algo_idx, &pv->algo) != ASSH_OK)
        {
          /* drop used key */
          assh_key_drop(s->ctx, &pv->pub_keys);
          pv->algo_idx = 0;
        }
      break;
#endif
    default:
      break;
    }

  const uint8_t *methods = p->head.end;
  const uint8_t *partial_success, *n;
  ASSH_ERR_RET(assh_packet_check_string(p, methods, &partial_success)
	       | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_array(p, partial_success, 1, NULL)
	       | ASSH_ERRSV_DISCONNECT);

  enum assh_userauth_methods_e m = 0;

  for (methods += 4; methods < partial_success; methods = n + 1)
    {
      n = methods;
      while (*n != ',' && n < partial_success)
        n++;

      switch (n - methods)
        {
#ifdef CONFIG_ASSH_CLIENT_AUTH_PASSWORD
        case 8:
          if (!strncmp((const char*)methods, "password", 8))
            m |= ASSH_USERAUTH_METHOD_PASSWORD;
          break;
#endif

#ifdef CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY
        case 9:
          if (!strncmp((const char*)methods, "publickey", 9))
            {
              if (pv->pub_keys != NULL)
                {
                  /* some user keys are already available */
                  ASSH_ERR_RET(assh_userauth_client_req_pubkey(s)
			       | ASSH_ERRSV_DISCONNECT);
                  return ASSH_OK;
                }
              m |= ASSH_USERAUTH_METHOD_PUBKEY;
              break;
            }
#endif

        default:
          break;
        }
    }

  ASSH_CHK_RET(m == 0, ASSH_ERR_NO_AUTH | ASSH_ERRSV_DISCONNECT);

  pv->methods = m;

  ASSH_ERR_RET(assh_userauth_client_methods(s, e, *partial_success));

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
    case ASSH_USERAUTH_INIT:
      ASSH_CHK_RET(p != NULL, ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);
      ASSH_ERR_RET(assh_userauth_client_username(s, e));
      return ASSH_OK;

    case ASSH_USERAUTH_SENT_NONE_RQ:
#ifdef CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY
    case ASSH_USERAUTH_SENT_PUB_KEY_RQ:
#endif
      if (p == NULL)
        return ASSH_OK;

    any:
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

#ifdef CONFIG_ASSH_CLIENT_AUTH_PASSWORD
    case ASSH_USERAUTH_SENT_PASSWORD_RQ:
      if (p == NULL)
        return ASSH_OK;

      switch(p->head.msg)
        {
        case SSH_MSG_USERAUTH_PASSWD_CHANGEREQ:
          ASSH_ERR_RET(assh_userauth_client_req_pwchange(s, p, e)
                       | ASSH_ERRSV_DISCONNECT);
          return ASSH_OK;

        default:
          goto any;
        }

    case ASSH_USERAUTH_PWCHANGE_SKIP:
      ASSH_ERR_RET(assh_userauth_client_methods(s, e, 0));
      return ASSH_NO_DATA;
#endif
#ifdef CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY
    case ASSH_USERAUTH_SENT_PUB_KEY:
      if (p == NULL)
        return ASSH_OK;

      switch(p->head.msg)
        {
        case SSH_MSG_USERAUTH_SUCCESS:
          ASSH_ERR_RET(ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);

        case SSH_MSG_USERAUTH_PK_OK:
          ASSH_ERR_RET(assh_userauth_client_req_pubkey_sign(s) | ASSH_ERRSV_DISCONNECT);
          return ASSH_OK;

        default:
          goto any;
        }
#endif

    default:
      ASSH_ERR_RET(ASSH_ERR_STATE | ASSH_ERRSV_FATAL);
    }

  return ASSH_OK;
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

