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

#include <assh/assh_userauth_server.h>

#include <assh/assh_service.h>
#include <assh/assh_session.h>
#include <assh/assh_transport.h>
#include <assh/assh_event.h>
#include <assh/assh_packet.h>
#include <assh/assh_algo.h>
#include <assh/assh_sign.h>
#include <assh/assh_key.h>
#include <assh/assh_alloc.h>

#ifdef CONFIG_ASSH_SERVER

ASSH_EVENT_SIZE_SASSERT(userauth_server);

#include <stdlib.h>

enum assh_userauth_state_e
{
  ASSH_USERAUTH_ST_METHODS,   //< intial state
  ASSH_USERAUTH_ST_METHODS_DONE,
  ASSH_USERAUTH_ST_FAILURE,
  ASSH_USERAUTH_ST_WAIT_RQ,
#ifdef CONFIG_ASSH_SERVER_AUTH_PASSWORD
  ASSH_USERAUTH_ST_PASSWORD,    //< the password event handler must check the user password
  ASSH_USERAUTH_ST_PASSWORD_WAIT_CHANGE,
#endif
#ifdef CONFIG_ASSH_SERVER_AUTH_PUBLICKEY
  ASSH_USERAUTH_ST_PUBKEY_PKOK,   //< the public key event handler may send PK_OK
  ASSH_USERAUTH_ST_PUBKEY_VERIFY , //< the public key event handler may check the signature
#endif
#ifdef CONFIG_ASSH_SERVER_AUTH_HOSTBASED
  ASSH_USERAUTH_ST_HOSTBASED,
#endif
#ifdef CONFIG_ASSH_SERVER_AUTH_KEYBOARD
  ASSH_USERAUTH_ST_KEYBOARD_INFO,
  ASSH_USERAUTH_ST_KEYBOARD_INFO_SENT,
  ASSH_USERAUTH_ST_KEYBOARD_RESPONSE,
  ASSH_USERAUTH_ST_KEYBOARD_CONTINUE,
#endif
  ASSH_USERAUTH_ST_SUCCESS,
  ASSH_USERAUTH_ST_SUCCESS_DONE,
};

#ifdef CONFIG_ASSH_SERVER_AUTH_PUBLICKEY
enum assh_userauth_pubkey_state_e
{
  ASSH_USERAUTH_PUBKEY_NONE,
  ASSH_USERAUTH_PUBKEY_NEW,
  ASSH_USERAUTH_PUBKEY_FOUND,
};
#endif

#define ASSH_USERAUTH_SERVER_REQ(n)                             \
  assh_error_t (n)(struct assh_session_s *s,                    \
                   struct assh_packet_s *p,                     \
                   struct assh_event_s *e,                      \
                   const uint8_t *auth_data)

typedef ASSH_USERAUTH_SERVER_REQ(assh_userauth_server_req_t);

struct assh_userauth_server_method_s
{
  const char                   *name;
  enum assh_userauth_methods_e mask;
  assh_userauth_server_req_t   *f_req;
};

/* see at end of file */
extern const struct assh_userauth_server_method_s
assh_userauth_server_methods[];

struct assh_userauth_context_s
{
  const struct assh_service_s *srv;
  const struct assh_userauth_server_method_s *method;
  struct assh_packet_s *pck;

#ifdef CONFIG_ASSH_SERVER_AUTH_KEYBOARD
  struct assh_buffer_s *keyboard_array;
  uint_fast8_t keyboard_count;
#endif

  char username[CONFIG_ASSH_AUTH_USERNAME_LEN + 1];

  enum assh_userauth_methods_e methods:8;
  uint_fast8_t retry;
  enum assh_userauth_state_e state:8;
  assh_safety_t safety;

#ifdef CONFIG_ASSH_SERVER_AUTH_PUBLICKEY
  enum assh_userauth_pubkey_state_e pubkey_state:8;
  const struct assh_algo_name_s *algo_name;
#endif

#if defined(CONFIG_ASSH_SERVER_AUTH_HOSTBASED) || \
  defined(CONFIG_ASSH_SERVER_AUTH_PUBLICKEY)
  const struct assh_algo_sign_s *algo;
  struct assh_key_s *pub_key;
  const uint8_t *sign;
#endif

  assh_time_t deadline;
};

static ASSH_SERVICE_INIT_FCN(assh_userauth_server_init)
{
  assh_error_t err;
  struct assh_userauth_context_s *pv;

  ASSH_ERR_RET(assh_alloc(s->ctx, sizeof(*pv),
                ASSH_ALLOC_SECUR, (void**)&pv));

  s->srv = &assh_service_userauth_server;
  s->srv_pv = pv;
  pv->deadline = s->time + ASSH_TIMEOUT_USERAUTH;
  pv->safety = 99;
  pv->method = NULL;
  pv->methods = 0;

  pv->state = ASSH_USERAUTH_ST_METHODS;
  pv->srv = NULL;

  pv->pck = NULL;

#if defined(CONFIG_ASSH_SERVER_AUTH_HOSTBASED) || \
  defined(CONFIG_ASSH_SERVER_AUTH_PUBLICKEY)
  pv->pub_key = NULL;
#endif

#ifdef CONFIG_ASSH_SERVER_AUTH_PUBLICKEY
  pv->pubkey_state = ASSH_USERAUTH_PUBKEY_NONE;
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
  pv->pubkey_state = ASSH_USERAUTH_PUBKEY_NONE;
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

  s->srv_pv = NULL;
  s->srv = NULL;
}

/* send the authentication failure packet */
static assh_error_t
assh_userauth_server_send_failure(struct assh_session_s *s,
                                  assh_bool_t partial)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  size_t psize = /* name-list size */ 4 + /* boolean */ 1;

  const struct assh_userauth_server_method_s *m;
  assh_bool_t first = 1;

  for (m = assh_userauth_server_methods; m->name != NULL; m++)
    if (pv->methods & m->mask)
      {
        psize += strlen(m->name + first);
        first = 0;
      }

  struct assh_packet_s *pout;
  ASSH_ERR_RET(assh_packet_alloc(s->ctx, SSH_MSG_USERAUTH_FAILURE,
                                 psize, &pout) | ASSH_ERRSV_DISCONNECT);

  uint8_t *list, *partial_success;

  ASSH_ASSERT(assh_packet_add_string(pout, 0, &list));

  first = 1;
  for (m = assh_userauth_server_methods; m->name != NULL; m++)
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

/* handle authentication failure */
static assh_error_t assh_userauth_server_failure(struct assh_session_s *s,
                                                 assh_bool_t get_methods)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  assh_userauth_server_flush_state(s);

  if (get_methods)
    {
      pv->state = ASSH_USERAUTH_ST_FAILURE;
    }
  else
    {
      ASSH_ERR_RET(assh_userauth_server_send_failure(s, 0));
      pv->state = ASSH_USERAUTH_ST_WAIT_RQ;
    }

  /* check auth attempts count */
  ASSH_CHK_RET(pv->retry && --pv->retry == 0,
               ASSH_ERR_NO_AUTH | ASSH_ERRSV_DISCONNECT);

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_server_success_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  const struct assh_service_s *srv = pv->srv;
  assh_error_t err;

  ASSH_CHK_RET(pv->state != ASSH_USERAUTH_ST_SUCCESS_DONE,
               ASSH_ERR_STATE | ASSH_ERRSV_FATAL);

  const struct assh_event_userauth_server_success_s *ev =
    &e->userauth_server.success;

  pv->methods = ev->methods;

  if (pv->methods)              /* report partial success */
    {
      ASSH_CHK_RET(!(pv->methods & ASSH_USERAUTH_METHOD_SERVER_IMPLEMENTED),
                   ASSH_ERR_MISSING_ALGO | ASSH_ERRSV_DISCONNECT);

      assh_userauth_server_flush_state(s);
      pv->state = ASSH_USERAUTH_ST_WAIT_RQ;
      ASSH_ERR_RET(assh_userauth_server_send_failure(s, 1));
      return ASSH_OK;
    }

  /* cleanup the authentication service */
  assh_userauth_server_cleanup(s);

  /* send the authentication success packet */
  struct assh_packet_s *pout;
  ASSH_ERR_RET(assh_packet_alloc(s->ctx, SSH_MSG_USERAUTH_SUCCESS, 0, &pout)
	       | ASSH_ERRSV_DISCONNECT);
  assh_transport_push(s, pout);

  /* start the next requested service */
  ASSH_ERR_RET(srv->f_init(s) | ASSH_ERRSV_DISCONNECT);

  return ASSH_OK;
}

/* handle authentication success */
static assh_error_t assh_userauth_server_success(struct assh_session_s *s,
                                                 struct assh_event_s *e)
{
  struct assh_userauth_context_s *pv = s->srv_pv;

  struct assh_event_userauth_server_success_s *ev =
    &e->userauth_server.success;

  ev->method = pv->method->mask;
  ev->sign_safety = pv->safety;
  ev->methods = 0;

  e->id = ASSH_EVENT_USERAUTH_SERVER_SUCCESS;
  e->f_done = assh_userauth_server_success_done;

  pv->state = ASSH_USERAUTH_ST_SUCCESS_DONE;

  return ASSH_OK;
}

#if defined(CONFIG_ASSH_SERVER_AUTH_HOSTBASED) || \
  defined(CONFIG_ASSH_SERVER_AUTH_PUBLICKEY)

static assh_error_t
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
  ASSH_ERR_RET(assh_key_load(s->ctx, pub_key, (*algo)->key, ASSH_ALGO_SIGN,
                 ASSH_KEY_FMT_PUB_RFC4253, &key_blob,
                 assh_load_u32(pub_blob)) | ASSH_ERRSV_DISCONNECT);

  /* check if the key can be used by the algorithm */
  if (!assh_algo_suitable_key(s->ctx, *algo, *pub_key))
    {
      assh_key_drop(s->ctx, pub_key);
      ASSH_ERR_RET(assh_userauth_server_failure(s, 1) | ASSH_ERRSV_DISCONNECT);
      return ASSH_NO_DATA;
    }

  return ASSH_OK;
}

static assh_error_t
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
  ASSH_ERR_RET(assh_sign_check(s->ctx, pv->algo, pv->pub_key, 3,
                 data, sign_str + 4, assh_load_u32(sign_str), &sign_safety)
               | ASSH_ERRSV_DISCONNECT);

  pv->safety = ASSH_MIN(sign_safety, pv->safety);

  return ASSH_OK;
}

#endif

/******************************************************************* none */

#ifdef CONFIG_ASSH_SERVER_AUTH_NONE
static ASSH_USERAUTH_SERVER_REQ(assh_userauth_server_req_none)
{
  return assh_userauth_server_success(s, e);
}
#endif

/******************************************************************* password */

#ifdef CONFIG_ASSH_SERVER_AUTH_PASSWORD

static assh_error_t
assh_userauth_server_pwchange(struct assh_session_s *s,
                              const struct assh_event_s *e)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  ASSH_CHK_RET(pv->retry && --pv->retry == 0,
               ASSH_ERR_NO_AUTH | ASSH_ERRSV_DISCONNECT);

  const struct assh_event_userauth_server_password_s *ev =
    &e->userauth_server.password;

  size_t prompt_len = ev->change_prompt.len;
  size_t lang_len = ev->change_lang.len;
  struct assh_packet_s *pout;

  ASSH_ERR_RET(assh_packet_alloc(s->ctx, SSH_MSG_USERAUTH_PASSWD_CHANGEREQ,
                 4 + prompt_len + 4 + lang_len, &pout) | ASSH_ERRSV_DISCONNECT);

  uint8_t *str;
  ASSH_ASSERT(assh_packet_add_string(pout, prompt_len, &str));
  if (prompt_len)
    memcpy(str, ev->change_prompt.str, prompt_len);

  ASSH_ASSERT(assh_packet_add_string(pout, lang_len, &str));
  if (lang_len)
    memcpy(str, ev->change_lang.str, lang_len);

  assh_transport_push(s, pout);

  pv->state = ASSH_USERAUTH_ST_PASSWORD_WAIT_CHANGE;

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_server_password_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  ASSH_CHK_RET(pv->state != ASSH_USERAUTH_ST_PASSWORD, ASSH_ERR_STATE | ASSH_ERRSV_FATAL);

  assh_packet_release(pv->pck);
  pv->pck = NULL;

  const struct assh_event_userauth_server_password_s *ev =
    &e->userauth_server.password;

  switch (ev->result)
    {
    case ASSH_SERVER_PWSTATUS_FAILURE:
      ASSH_ERR_RET(assh_userauth_server_failure(s, 1) | ASSH_ERRSV_DISCONNECT);
      break;
    case ASSH_SERVER_PWSTATUS_SUCCESS:
      pv->state = ASSH_USERAUTH_ST_SUCCESS;
      break;
    case ASSH_SERVER_PWSTATUS_CHANGE:
      ASSH_ERR_RET(assh_userauth_server_pwchange(s, e) | ASSH_ERRSV_DISCONNECT);
      break;
    }

  return ASSH_OK;
}

/* handle password request packet */
static ASSH_USERAUTH_SERVER_REQ(assh_userauth_server_req_password)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  const uint8_t *pwchange = auth_data;
  const uint8_t *password, *new_password;

  ASSH_ERR_RET(assh_packet_check_array(p, pwchange, 1, &password)
               | ASSH_ERRSV_DISCONNECT);

  ASSH_ERR_RET(assh_packet_check_string(p, password, &new_password)
               | ASSH_ERRSV_DISCONNECT);

  struct assh_event_userauth_server_password_s *ev =
    &e->userauth_server.password;

  ev->username.str = pv->username;
  ev->username.len = strlen(pv->username);
  ev->password.data = password + 4;
  ev->password.len = assh_load_u32(password);

  if (*pwchange)
    {
      ASSH_ERR_RET(assh_packet_check_string(p, new_password, NULL)
                   | ASSH_ERRSV_DISCONNECT);
      ev->new_password.data = new_password + 4;
      ev->new_password.len = assh_load_u32(new_password);
    }
  else if (pv->state == ASSH_USERAUTH_ST_PASSWORD_WAIT_CHANGE)
    {
      ASSH_ERR_RET(assh_userauth_server_failure(s, 1) | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;
    }
  else
    {
      ev->new_password.len = 0;
    }

  /* report a password checking event */
  ev->result = ASSH_SERVER_PWSTATUS_FAILURE;
  ev->change_prompt.len = 0;
  ev->change_lang.len = 0;

  e->id = ASSH_EVENT_USERAUTH_SERVER_PASSWORD;
  e->f_done = assh_userauth_server_password_done;

  pv->state = ASSH_USERAUTH_ST_PASSWORD;

  assert(pv->pck == NULL);
  pv->pck = assh_packet_refinc(p);

  return ASSH_OK;
}

#endif

/******************************************************************* hostbased */

#ifdef CONFIG_ASSH_SERVER_AUTH_HOSTBASED

static ASSH_EVENT_DONE_FCN(assh_userauth_server_hostbased_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  const struct assh_event_userauth_server_hostbased_s *ev =
    &e->userauth_server.hostbased;

  if (!ev->found)
    {
      ASSH_ERR_RET(assh_userauth_server_failure(s, 1)
                   | ASSH_ERRSV_DISCONNECT);
    }
  else
    {
      ASSH_ERR_RET(assh_userauth_server_sign_check(s, pv->pck, pv->sign)
                   | ASSH_ERRSV_DISCONNECT);

      pv->state = ASSH_USERAUTH_ST_SUCCESS;
    }

  assh_packet_release(pv->pck);
  pv->pck = NULL;

  return ASSH_OK;
}

static ASSH_USERAUTH_SERVER_REQ(assh_userauth_server_req_hostbased)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  const uint8_t *algo_name = auth_data;
  const uint8_t *pub_blob, *hostname, *husername, *sign;

  ASSH_ERR_RET(assh_packet_check_string(p, algo_name, &pub_blob) | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_string(p, pub_blob, &hostname) | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_string(p, hostname, &husername) | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_string(p, husername, &sign) | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_string(p, sign, NULL) | ASSH_ERRSV_DISCONNECT);

  const struct assh_algo_s *algo;
  struct assh_key_s *pub_key = NULL;

  ASSH_ERR_RET(assh_userauth_server_get_key(s, algo_name, pub_blob,
                 &algo, &pub_key, NULL) | ASSH_ERRSV_DISCONNECT);

  if (err == ASSH_NO_DATA)
    {
      ASSH_ERR_RET(assh_userauth_server_failure(s, 1) | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;
    }

  pv->algo = (void*)algo;
  pv->pub_key = pub_key;
  pv->pck = assh_packet_refinc(p);
  pv->sign = sign;

  struct assh_event_userauth_server_hostbased_s *ev =
    &e->userauth_server.hostbased;

  ev->username.str = pv->username;
  ev->username.len = strlen(pv->username);
  ev->host_key = pub_key;
  ev->hostname.data = hostname + 4;
  ev->hostname.len = assh_load_u32(hostname);
  ev->host_username.data = husername + 4;
  ev->host_username.len = assh_load_u32(husername);
  ev->found = 0;

  e->id = ASSH_EVENT_USERAUTH_SERVER_HOSTBASED;
  e->f_done = assh_userauth_server_hostbased_done;

  return err;
}

#endif

/******************************************************************* keyboard */

#ifdef CONFIG_ASSH_SERVER_AUTH_KEYBOARD

static ASSH_EVENT_DONE_FCN(assh_userauth_server_kbresponse_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  ASSH_CHK_RET(pv->state != ASSH_USERAUTH_ST_KEYBOARD_RESPONSE,
               ASSH_ERR_STATE | ASSH_ERRSV_FATAL);

  assh_free(s->ctx, pv->keyboard_array);
  pv->keyboard_array = NULL;

  assh_packet_release(pv->pck);
  pv->pck = NULL;

  const struct assh_event_userauth_server_kbresponse_s *ev =
    &e->userauth_server.kbresponse;

  switch (ev->result)
    {
    case ASSH_SERVER_KBSTATUS_FAILURE:
      ASSH_ERR_RET(assh_userauth_server_failure(s, 1) | ASSH_ERRSV_DISCONNECT);
      break;
    case ASSH_SERVER_KBSTATUS_SUCCESS:
      pv->state = ASSH_USERAUTH_ST_SUCCESS;
      break;
    case ASSH_SERVER_KBSTATUS_CONTINUE:
      pv->state = ASSH_USERAUTH_ST_KEYBOARD_CONTINUE;
      break;
    }

  return ASSH_OK;
}

static assh_error_t
assh_userauth_server_kbresponse(struct assh_session_s *s,
                                struct assh_packet_s *p,
                                struct assh_event_s *e)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  ASSH_CHK_RET(p->head.msg != SSH_MSG_USERAUTH_INFO_RESPONSE,
               ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);

  const uint8_t *count_ = p->head.end;
  const uint8_t *resp, *next;

  ASSH_ERR_RET(assh_packet_check_array(p, count_, 4, &resp)
               | ASSH_ERRSV_DISCONNECT);

  size_t i, count = assh_load_u32(count_);

  if (count != pv->keyboard_count)
    {
      ASSH_ERR_RET(assh_userauth_server_failure(s, 1) | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;
    }

  struct assh_buffer_s *responses = NULL;

  if (count > 0)
    {

      ASSH_ERR_RET(assh_alloc(s->ctx, sizeof(*responses) * count,
                              ASSH_ALLOC_INTERNAL, (void**)&responses));

      assert(pv->keyboard_array == NULL);
      pv->keyboard_array = responses;

      for (i = 0; i < count; i++)
        {
          ASSH_ERR_RET(assh_packet_check_string(p, resp, &next)
                       | ASSH_ERRSV_DISCONNECT);
          responses[i].data = resp + 4;
          responses[i].len = assh_load_u32(resp);
          resp = next;
        }

    }

  struct assh_event_userauth_server_kbresponse_s *ev =
    &e->userauth_server.kbresponse;

  ev->count = count;
  ev->responses = responses;
  ev->result = ASSH_SERVER_KBSTATUS_FAILURE;

  e->id = ASSH_EVENT_USERAUTH_SERVER_KBRESPONSE;
  e->f_done = assh_userauth_server_kbresponse_done;

  pv->state = ASSH_USERAUTH_ST_KEYBOARD_RESPONSE;

  assert(pv->pck == NULL);
  pv->pck = assh_packet_refinc(p);

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_server_kbinfo_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  assh_packet_release(pv->pck);
  pv->pck = NULL;

  ASSH_CHK_RET(pv->state != ASSH_USERAUTH_ST_KEYBOARD_INFO,
               ASSH_ERR_STATE | ASSH_ERRSV_FATAL);

  const struct assh_event_userauth_server_kbinfo_s *ev =
    &e->userauth_server.kbinfo;

  size_t i, count = ev->count;

  ASSH_CHK_RET(count > 32,
               ASSH_ERR_OUTPUT_OVERFLOW | ASSH_ERRSV_FATAL);

  pv->keyboard_count = count;

  size_t name_len = ev->name.len;
  size_t ins_len = ev->instruction.len;
  size_t psize = 4 + name_len + 4 + ins_len + 4 + 4;

  for (i = 0; i < count; i++)
    psize += 4 + ev->prompts[i].len + 1;

  struct assh_packet_s *pout;
  ASSH_ERR_RET(assh_packet_alloc(s->ctx, SSH_MSG_USERAUTH_INFO_REQUEST,
                 psize, &pout) | ASSH_ERRSV_DISCONNECT);

  uint8_t *str;

  ASSH_ASSERT(assh_packet_add_string(pout, name_len, &str));
  memcpy(str, ev->name.str, name_len);

  ASSH_ASSERT(assh_packet_add_string(pout, ins_len, &str));
  memcpy(str, ev->instruction.str, ins_len);

  ASSH_ASSERT(assh_packet_add_string(pout, 0, NULL)); /* empty lang */

  ASSH_ASSERT(assh_packet_add_array(pout, 4, &str));
  assh_store_u32(str, count);

  for (i = 0; i < count; i++)
    {
      size_t len = ev->prompts[i].len;
      ASSH_ASSERT(assh_packet_add_string(pout, len, &str));
      memcpy(str, ev->prompts[i].str, len);

      ASSH_ASSERT(assh_packet_add_array(pout, 1, &str));
      *str = (ev->echos >> i) & 1;
    }

  assh_transport_push(s, pout);
  pv->state = ASSH_USERAUTH_ST_KEYBOARD_INFO_SENT;

  return ASSH_OK;
}

static assh_error_t
assh_userauth_server_kbinfo(struct assh_session_s *s,
                            struct assh_packet_s *p,
                            struct assh_event_s *e,
                            const uint8_t *sub)
{
  struct assh_userauth_context_s *pv = s->srv_pv;

  struct assh_event_userauth_server_kbinfo_s *ev =
    &e->userauth_server.kbinfo;

  ev->username.str = pv->username;
  ev->username.len = strlen(pv->username);
  ev->sub.data = sub + 4;
  ev->sub.len = assh_load_u32(sub);

  ev->name.len = 0;
  ev->instruction.len = 0;
  ev->echos = 0;
  ev->count = 0;
  ev->prompts = NULL;

  e->id = ASSH_EVENT_USERAUTH_SERVER_KBINFO;
  e->f_done = assh_userauth_server_kbinfo_done;

  pv->state = ASSH_USERAUTH_ST_KEYBOARD_INFO;

  return ASSH_OK;
}

static ASSH_USERAUTH_SERVER_REQ(assh_userauth_server_req_kbinfo)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  const uint8_t *lang = auth_data;
  const uint8_t *sub;

  ASSH_ERR_RET(assh_packet_check_string(p, lang, &sub)
               | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_string(p, sub, NULL)
               | ASSH_ERRSV_DISCONNECT);

  assert(pv->pck == NULL);
  pv->pck = assh_packet_refinc(p);

  ASSH_ERR_RET(assh_userauth_server_kbinfo(s, p, e, sub));

  return ASSH_OK;
}
#endif

/******************************************************************* public key */

#ifdef CONFIG_ASSH_SERVER_AUTH_PUBLICKEY

static ASSH_EVENT_DONE_FCN(assh_userauth_server_userkey_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  const struct assh_event_userauth_server_userkey_s *ev =
    &e->userauth_server.userkey;

  switch (pv->state)
    {
    case ASSH_USERAUTH_ST_PUBKEY_PKOK: {      /* may need to send PK_OK */
      pv->state = ASSH_USERAUTH_ST_WAIT_RQ;

      if (!ev->found)
        {
          ASSH_ERR_RET(assh_userauth_server_failure(s, 1) | ASSH_ERRSV_DISCONNECT);
          return ASSH_OK;
        }

      /* alloc packet */
      size_t algo_name_len = strlen(pv->algo_name->name);

      size_t blob_len;
      ASSH_ERR_RET(assh_key_output(s->ctx, pv->pub_key,
                     NULL, &blob_len, ASSH_KEY_FMT_PUB_RFC4253) | ASSH_ERRSV_DISCONNECT);

      struct assh_packet_s *pout;
      ASSH_ERR_RET(assh_packet_alloc(s->ctx, SSH_MSG_USERAUTH_PK_OK,
                     4 + algo_name_len + 4 + blob_len, &pout) | ASSH_ERRSV_DISCONNECT);

      /* add sign algorithm name */
      uint8_t *algo_name;
      ASSH_ASSERT(assh_packet_add_string(pout, algo_name_len, &algo_name));
      memcpy(algo_name, pv->algo_name->name, algo_name_len);

      /* add public key blob */
      uint8_t *blob;
      ASSH_ASSERT(assh_packet_add_string(pout, blob_len, &blob));
      ASSH_ERR_GTO(assh_key_output(s->ctx, pv->pub_key,
                     blob, &blob_len, ASSH_KEY_FMT_PUB_RFC4253)
		   | ASSH_ERRSV_DISCONNECT, err_packet);
      assh_packet_shrink_string(pout, blob, blob_len);

      assh_transport_push(s, pout);
      pv->pubkey_state = ASSH_USERAUTH_PUBKEY_FOUND;

      return ASSH_OK;
     err_packet:
      assh_packet_release(pout);
      return err;
    }

    case ASSH_USERAUTH_ST_PUBKEY_VERIFY: {

      if (!ev->found)
        {
          ASSH_ERR_RET(assh_userauth_server_failure(s, 1)
                       | ASSH_ERRSV_DISCONNECT);
        }
      else
        {
          ASSH_ERR_RET(assh_userauth_server_sign_check(s, pv->pck, pv->sign)
                       | ASSH_ERRSV_DISCONNECT);

          pv->state = ASSH_USERAUTH_ST_SUCCESS;
        }

      assh_packet_release(pv->pck);
      pv->pck = NULL;

      return ASSH_OK;
    }

    default:
      ASSH_ERR_RET(ASSH_ERR_STATE | ASSH_ERRSV_FATAL);
    }

  return ASSH_OK;
}

/* handle public key request packet */
static ASSH_USERAUTH_SERVER_REQ(assh_userauth_server_req_pubkey)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  const uint8_t *second = auth_data;
  const uint8_t *algo_name, *pub_blob, *sign;

  ASSH_ERR_RET(assh_packet_check_array(p, second, 1, &algo_name) | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_string(p, algo_name, &pub_blob) | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_string(p, pub_blob, &sign) | ASSH_ERRSV_DISCONNECT);

  const struct assh_algo_s *algo;
  struct assh_key_s *pub_key = NULL;

  ASSH_ERR_RET(assh_userauth_server_get_key(s, algo_name, pub_blob,
                 &algo, &pub_key, &pv->algo_name) | ASSH_ERRSV_DISCONNECT);

  if (err == ASSH_NO_DATA)
    {
      ASSH_ERR_RET(assh_userauth_server_failure(s, 1) | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;
    }

  /* test if the key has been previously found in the list of authorized user keys. */
  assh_bool_t new_key = (pv->pubkey_state == ASSH_USERAUTH_PUBKEY_NONE ||
                         !assh_key_cmp(s->ctx, pub_key, pv->pub_key, 1));

  if (new_key)
    {
      assh_key_flush(s->ctx, &pv->pub_key);
      pv->pub_key = pub_key;
      pv->algo = (void*)algo;
      pv->pubkey_state = ASSH_USERAUTH_PUBKEY_NEW;
    }
  else
    {
      assh_key_drop(s->ctx, &pub_key);
    }

  /* the packet contains a signature to check */
  if (*second)
    {
      ASSH_ERR_RET(assh_packet_check_string(p, sign, NULL)
                   | ASSH_ERRSV_DISCONNECT);

      if (pv->pubkey_state == ASSH_USERAUTH_PUBKEY_FOUND)
        {
          ASSH_ERR_RET(assh_userauth_server_sign_check(s, p, sign)
		       | ASSH_ERRSV_DISCONNECT);
          ASSH_TAIL_CALL(assh_userauth_server_success(s, e)
                         | ASSH_ERRSV_DISCONNECT);
        }

      assert(pv->pck == NULL);
      pv->pck = assh_packet_refinc(p);
      pv->sign = sign;

      pv->state = ASSH_USERAUTH_ST_PUBKEY_VERIFY;
    }
  else
    {
      if (pv->pubkey_state == ASSH_USERAUTH_PUBKEY_FOUND)
        return ASSH_OK;

      pv->state = ASSH_USERAUTH_ST_PUBKEY_PKOK;
    }

  struct assh_event_userauth_server_userkey_s *ev =
    &e->userauth_server.userkey;

  ev->username.str = pv->username;
  ev->username.len = strlen(pv->username);
  ev->pub_key = pv->pub_key;
  ev->found = 0;

  /* return an event to lookup the key in the list of authorized user keys */
  e->id = ASSH_EVENT_USERAUTH_SERVER_USERKEY;
  e->f_done = assh_userauth_server_userkey_done;

  return ASSH_OK;
}
#endif

/********************************************************************/

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
        {
          ASSH_ERR_RET(assh_transport_unimp(s, p));
          return ASSH_OK;
        }
    case SSH_MSG_UNIMPLEMENTED:
      ASSH_ERR_RET(ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);
    case SSH_MSG_USERAUTH_REQUEST:
      break;
    }

  uint8_t *username = p->head.end;
  const uint8_t *srv_name, *method_name, *auth_data;

  ASSH_ERR_RET(assh_packet_check_string(p, username, &srv_name) | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_string(p, srv_name, &method_name) | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_string(p, method_name, &auth_data) | ASSH_ERRSV_DISCONNECT);

  const struct assh_userauth_server_method_s *m;

  for (m = assh_userauth_server_methods; m->name != NULL; m++)
    {
      if (assh_ssh_string_compare(method_name, m->name + 1))
        continue;

      if (!(pv->methods & m->mask))
        break;

      if (pv->method != m ||
          assh_ssh_string_compare(srv_name, pv->srv->name) ||
          assh_ssh_string_compare(username, pv->username))
        {
          assh_userauth_server_flush_state(s);

          /* lookup service name */
          if (assh_service_by_name(s->ctx, assh_load_u32(srv_name),
                                   (char*)srv_name + 4, &pv->srv))
            break;

          pv->method = m;

          /* keep user name */
          ASSH_ERR_RET(assh_ssh_string_copy(username, pv->username, sizeof(pv->username))
                       | ASSH_ERRSV_DISCONNECT);
        }

      ASSH_ERR_RET(m->f_req(s, p, e, auth_data)
                   | ASSH_ERRSV_DISCONNECT);

      return ASSH_OK;
    }

  ASSH_ERR_RET(assh_userauth_server_failure(s, 0) | ASSH_ERRSV_DISCONNECT);
  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_server_get_methods_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  ASSH_CHK_RET(pv->state != ASSH_USERAUTH_ST_METHODS_DONE,
               ASSH_ERR_STATE | ASSH_ERRSV_FATAL);

  const struct assh_event_userauth_server_methods_s *ev =
    &e->userauth_server.methods;

  pv->methods = ev->methods;
  pv->retry = ev->retries;

  ASSH_CHK_RET(!(pv->methods & ASSH_USERAUTH_METHOD_SERVER_IMPLEMENTED),
               ASSH_ERR_MISSING_ALGO | ASSH_ERRSV_DISCONNECT);

  size_t bsize = ev->banner.size;
  size_t lsize = ev->bnlang.size;

  if (bsize)
    {
      struct assh_packet_s *pout;
      ASSH_ERR_RET(assh_packet_alloc(s->ctx, SSH_MSG_USERAUTH_BANNER,
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
    ASSH_ERR_RET(assh_userauth_server_send_failure(s, 0));

  pv->state = ASSH_USERAUTH_ST_WAIT_RQ;

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

  pv->state = ASSH_USERAUTH_ST_METHODS_DONE;

  return ASSH_OK;
}

static assh_error_t
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
  ev->retries = pv->retry;

  e->id = ASSH_EVENT_USERAUTH_SERVER_METHODS;
  e->f_done = assh_userauth_server_get_methods_done;

  pv->state = ASSH_USERAUTH_ST_METHODS_DONE;

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
      ASSH_ERR_RET(assh_userauth_server_get_methods(s, e)
                   | ASSH_ERRSV_DISCONNECT);
      return ASSH_NO_DATA;

    case ASSH_USERAUTH_ST_FAILURE:
      ASSH_ERR_RET(assh_userauth_server_get_methods_failed(s, e)
                   | ASSH_ERRSV_DISCONNECT);
      return ASSH_NO_DATA;

    case ASSH_USERAUTH_ST_SUCCESS:
      ASSH_ERR_RET(assh_userauth_server_success(s, e)
                   | ASSH_ERRSV_DISCONNECT);
      return ASSH_NO_DATA;

#ifdef CONFIG_ASSH_SERVER_AUTH_PASSWORD
    case ASSH_USERAUTH_ST_PASSWORD_WAIT_CHANGE:
#endif
    case ASSH_USERAUTH_ST_WAIT_RQ:
      if (p != NULL)
        ASSH_ERR_RET(assh_userauth_server_req(s, p, e) | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;

#ifdef CONFIG_ASSH_SERVER_AUTH_KEYBOARD
    case ASSH_USERAUTH_ST_KEYBOARD_INFO_SENT:
      if (p != NULL)
        ASSH_ERR_RET(assh_userauth_server_kbresponse(s, p, e) | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;

    case ASSH_USERAUTH_ST_KEYBOARD_CONTINUE:
      ASSH_ERR_RET(assh_userauth_server_kbinfo(s, p, e, "\x00\x00\x00\x00")
                   | ASSH_ERRSV_DISCONNECT);
      return ASSH_NO_DATA;
#endif

    default:
      ASSH_ERR_RET(ASSH_ERR_STATE | ASSH_ERRSV_FATAL);
    }
}

const struct assh_userauth_server_method_s
assh_userauth_server_methods[] = {
#ifdef CONFIG_ASSH_SERVER_AUTH_NONE
    { ",none",
      ASSH_USERAUTH_METHOD_NONE,
      &assh_userauth_server_req_none },
#endif
#ifdef CONFIG_ASSH_SERVER_AUTH_PASSWORD
    { ",password",
      ASSH_USERAUTH_METHOD_PASSWORD,
      &assh_userauth_server_req_password },
#endif
#ifdef CONFIG_ASSH_SERVER_AUTH_PUBLICKEY
    { ",publickey",
      ASSH_USERAUTH_METHOD_PUBKEY,
      &assh_userauth_server_req_pubkey },
#endif
#ifdef CONFIG_ASSH_SERVER_AUTH_HOSTBASED
    { ",hostbased",
      ASSH_USERAUTH_METHOD_HOSTBASED,
      &assh_userauth_server_req_hostbased },
#endif
#ifdef CONFIG_ASSH_SERVER_AUTH_KEYBOARD
    { ",keyboard-interactive",
      ASSH_USERAUTH_METHOD_KEYBOARD,
      &assh_userauth_server_req_kbinfo },
#endif
    { 0 }
};

const struct assh_service_s assh_service_userauth_server =
{
  .name = "ssh-userauth",
  .side = ASSH_SERVER,
  .f_init = assh_userauth_server_init,
  .f_cleanup = assh_userauth_server_cleanup,
  .f_process = assh_userauth_server_process,
};

#endif

