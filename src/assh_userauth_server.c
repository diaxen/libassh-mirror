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

#ifdef CONFIG_ASSH_SERVER_AUTH_NONE
# warning CONFIG_ASSH_SERVER_AUTH_NONE is defined, server authentication is bypassed
# undef CONFIG_ASSH_SERVER_AUTH_PASSWORD
# undef CONFIG_ASSH_SERVER_AUTH_PUBLICKEY
#endif

#include <stdlib.h>

enum assh_userauth_state_e
{
  ASSH_USERAUTH_METHODS,   //< intial state
  ASSH_USERAUTH_METHODS_DONE,
  ASSH_USERAUTH_WAIT_RQ,
#ifdef CONFIG_ASSH_SERVER_AUTH_PASSWORD
  ASSH_USERAUTH_PASSWORD,    //< the password event handler must check the user password
  ASSH_USERAUTH_PASSWORD_SUCCESS,
  ASSH_USERAUTH_PASSWORD_WAIT_CHANGE,
#endif
#ifdef CONFIG_ASSH_SERVER_AUTH_PUBLICKEY
  ASSH_USERAUTH_PUBKEY_PKOK,   //< the public key event handler may send PK_OK
  ASSH_USERAUTH_PUBKEY_VERIFY , //< the public key event handler may check the signature
  ASSH_USERAUTH_PUBKEY_SUCCESS,
#endif
  ASSH_USERAUTH_SUCCESS_DONE,
};

#ifdef CONFIG_ASSH_SERVER_AUTH_PUBLICKEY
enum assh_userauth_pubkey_state_e
{
  ASSH_USERAUTH_PUBKEY_NONE,
  ASSH_USERAUTH_PUBKEY_NEW,
  ASSH_USERAUTH_PUBKEY_FOUND,
};
#endif

struct assh_userauth_context_s
{
  const struct assh_service_s *srv;
  char method_name[10];
  char username[CONFIG_ASSH_AUTH_USERNAME_LEN + 1];

  enum assh_userauth_methods_e methods:8;
  uint_fast8_t retry;
  enum assh_userauth_state_e state:8;
  assh_safety_t safety;

#ifdef CONFIG_ASSH_SERVER_AUTH_PUBLICKEY
  enum assh_userauth_pubkey_state_e pubkey_state:8;
  struct assh_key_s *pub_key;
  const struct assh_algo_sign_s *algo;
  const struct assh_algo_name_s *algo_name;
  struct assh_packet_s *sign_pck;
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
  pv->methods = 0;

  pv->state = ASSH_USERAUTH_METHODS;
  pv->srv = NULL;

#ifdef CONFIG_ASSH_SERVER_AUTH_PUBLICKEY
  pv->pub_key = NULL;
  pv->pubkey_state = ASSH_USERAUTH_PUBKEY_NONE;
  pv->sign_pck = NULL;  
#endif

  return ASSH_OK;
}

static void assh_userauth_server_flush_state(struct assh_session_s *s)
{
  struct assh_userauth_context_s *pv = s->srv_pv;

  pv->srv = NULL;

#ifdef CONFIG_ASSH_SERVER_AUTH_PUBLICKEY
  assh_key_flush(s->ctx, &pv->pub_key);
  pv->pubkey_state = ASSH_USERAUTH_PUBKEY_NONE;

  assh_packet_release(pv->sign_pck);
  pv->sign_pck = NULL;  
#endif
}

static ASSH_SERVICE_CLEANUP_FCN(assh_userauth_server_cleanup)
{
  struct assh_userauth_context_s *pv = s->srv_pv;

  assh_userauth_server_flush_state(s);

  assh_free(s->ctx, pv);

  s->srv_pv = NULL;
  s->srv = NULL;
}

static assh_error_t assh_userauth_server_send_failure(struct assh_session_s *s,
                                                      assh_bool_t partial)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  /* send the authentication failure packet */
  struct assh_packet_s *pout;
  ASSH_ERR_RET(assh_packet_alloc(s->ctx, SSH_MSG_USERAUTH_FAILURE,
		 4 + 64 + 1, &pout) | ASSH_ERRSV_DISCONNECT);

  uint8_t *list, *partial_success;

  ASSH_ASSERT(assh_packet_add_string(pout, 0, &list));

  static const struct {
    const char                   *name;
    enum assh_userauth_methods_e method;
  }                              array[] = {
#ifdef CONFIG_ASSH_SERVER_AUTH_NONE
    { ",none",      ASSH_USERAUTH_METHOD_NONE },
#endif
#ifdef CONFIG_ASSH_SERVER_AUTH_PASSWORD
    { ",password",  ASSH_USERAUTH_METHOD_PASSWORD },
#endif
#ifdef CONFIG_ASSH_SERVER_AUTH_PUBLICKEY
    { ",publickey", ASSH_USERAUTH_METHOD_PUBKEY },
#endif
  };

  uint_fast8_t i;
  assh_bool_t first = 1;

  for (i = 0; i < sizeof(array) / sizeof(array[0]); i++)
    {
      if (!(pv->methods & array[i].method))
        continue;

      const char *mname = array[i].name + first;
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
static assh_error_t assh_userauth_server_failure(struct assh_session_s *s)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  assh_userauth_server_flush_state(s);
  pv->state = ASSH_USERAUTH_WAIT_RQ;

  /* check auth attempts count */
  ASSH_CHK_RET(pv->retry && --pv->retry == 0,
               ASSH_ERR_NO_AUTH | ASSH_ERRSV_DISCONNECT);

  assh_userauth_server_send_failure(s, 0);

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_server_success_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  const struct assh_service_s *srv = pv->srv;
  assh_error_t err;

  ASSH_CHK_RET(pv->state != ASSH_USERAUTH_SUCCESS_DONE,
               ASSH_ERR_STATE | ASSH_ERRSV_FATAL);

  pv->methods = e->userauth_server.success.methods;

  if (pv->methods)              /* report partial success */
    {
      ASSH_CHK_RET(!(pv->methods & ASSH_USERAUTH_METHOD_IMPLEMENTED),
                   ASSH_ERR_MISSING_ALGO | ASSH_ERRSV_DISCONNECT);

      assh_userauth_server_flush_state(s);
      pv->state = ASSH_USERAUTH_WAIT_RQ;
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
                                                 struct assh_event_s *e,
                                                 enum assh_userauth_methods_e method)
{
  struct assh_userauth_context_s *pv = s->srv_pv;

  pv->state = ASSH_USERAUTH_SUCCESS_DONE;
  e->id = ASSH_EVENT_USERAUTH_SERVER_SUCCESS;
  e->f_done = assh_userauth_server_success_done;
  e->userauth_server.success.method = method;
  e->userauth_server.success.sign_safety = pv->safety;
  e->userauth_server.success.methods = 0;

  return ASSH_OK;
}

/******************************************************************* password */

#ifdef CONFIG_ASSH_SERVER_AUTH_PASSWORD

static assh_error_t
assh_userauth_server_pwchange(struct assh_session_s *s,
                              struct assh_event_s *e)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  ASSH_CHK_RET(pv->retry && --pv->retry == 0,
               ASSH_ERR_NO_AUTH | ASSH_ERRSV_DISCONNECT);

  size_t prompt_len = e->userauth_server.password.change_prompt.len;
  size_t lang_len = e->userauth_server.password.change_lang.len;
  struct assh_packet_s *pout;

  ASSH_ERR_RET(assh_packet_alloc(s->ctx, SSH_MSG_USERAUTH_PASSWD_CHANGEREQ,
                 4 + prompt_len + 4 + lang_len, &pout) | ASSH_ERRSV_DISCONNECT);

  uint8_t *str;
  ASSH_ASSERT(assh_packet_add_string(pout, prompt_len, &str));
  if (prompt_len)
    memcpy(str, e->userauth_server.password.change_prompt.str, prompt_len);

  ASSH_ASSERT(assh_packet_add_string(pout, lang_len, &str));
  if (lang_len)
    memcpy(str, e->userauth_server.password.change_lang.str, lang_len);

  assh_transport_push(s, pout);

  pv->state = ASSH_USERAUTH_PASSWORD_WAIT_CHANGE;

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_server_password_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  ASSH_CHK_RET(pv->state != ASSH_USERAUTH_PASSWORD, ASSH_ERR_STATE | ASSH_ERRSV_FATAL);

  switch (e->userauth_server.password.result)
    {
    case ASSH_SERVER_PWSTATUS_FAILURE:
      ASSH_ERR_RET(assh_userauth_server_failure(s) | ASSH_ERRSV_DISCONNECT);
      break;
    case ASSH_SERVER_PWSTATUS_SUCCESS:
      pv->state = ASSH_USERAUTH_PASSWORD_SUCCESS;
      break;
    case ASSH_SERVER_PWSTATUS_CHANGE:
      ASSH_ERR_RET(assh_userauth_server_pwchange(s, e) | ASSH_ERRSV_DISCONNECT);
      break;
    }

  return ASSH_OK;
}

/* handle password request packet */
static assh_error_t assh_userauth_server_req_password(struct assh_session_s *s,
                                                      struct assh_packet_s *p,
                                                      struct assh_event_s *e,
                                                      const uint8_t *auth_data)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  const uint8_t *pwchange = auth_data;
  const uint8_t *password, *new_password;

  ASSH_ERR_RET(assh_packet_check_array(p, pwchange, 1, &password)
               | ASSH_ERRSV_DISCONNECT);

  ASSH_ERR_RET(assh_packet_check_string(p, password, &new_password)
               | ASSH_ERRSV_DISCONNECT);

  e->userauth_server.password.username.str = pv->username;
  e->userauth_server.password.username.len = strlen(pv->username);
  e->userauth_server.password.password.str = (char*)password + 4;
  e->userauth_server.password.password.len = assh_load_u32(password);

  if (*pwchange)
    {
      ASSH_ERR_RET(assh_packet_check_string(p, new_password, NULL)
                   | ASSH_ERRSV_DISCONNECT);
      e->userauth_server.password.new_password.str = (char*)new_password + 4;
      e->userauth_server.password.new_password.len = assh_load_u32(new_password);
    }
  else if (pv->state == ASSH_USERAUTH_PASSWORD_WAIT_CHANGE)
    {
      ASSH_ERR_RET(assh_userauth_server_failure(s) | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;
    }
  else
    {
      e->userauth_server.password.new_password.len = 0;
    }

  /* report a password checking event */
  e->id = ASSH_EVENT_USERAUTH_SERVER_PASSWORD;
  e->f_done = assh_userauth_server_password_done;
  e->userauth_server.password.result = ASSH_SERVER_PWSTATUS_FAILURE;
  e->userauth_server.password.change_prompt.len = 0;
  e->userauth_server.password.change_lang.len = 0;

  pv->state = ASSH_USERAUTH_PASSWORD;
  return ASSH_OK;
}

#endif

/******************************************************************* public key */

#ifdef CONFIG_ASSH_SERVER_AUTH_PUBLICKEY

static assh_error_t assh_userauth_server_pubkey_check(struct assh_session_s *s,
                                                      struct assh_packet_s *p,
                                                      const uint8_t *sign)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  const uint8_t *end;
  ASSH_ERR_RET(assh_packet_check_string(p, sign, &end) | ASSH_ERRSV_DISCONNECT);

  uint8_t sid_len[4];   /* fake string header for session id */
  assh_store_u32(sid_len, s->session_id_len);

  /* buffers that have been signed by the client */
  const uint8_t *sign_ptrs[3] =
    { sid_len, s->session_id,     &p->head.msg };
  size_t sign_sizes[3]        =
    { 4,       s->session_id_len, sign - &p->head.msg };

  assh_safety_t sign_safety;

  /* check the signature */
  ASSH_ERR_RET(assh_sign_check(s->ctx, pv->algo, pv->pub_key, 3,
        sign_ptrs, sign_sizes, sign + 4, end - sign - 4, &sign_safety)
               | ASSH_ERRSV_DISCONNECT);

  pv->safety = ASSH_MIN(sign_safety, pv->safety);
  pv->state = ASSH_USERAUTH_PUBKEY_SUCCESS;

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_server_userkey_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  switch (pv->state)
    {
    case ASSH_USERAUTH_PUBKEY_PKOK: {      /* may need to send PK_OK */
      pv->state = ASSH_USERAUTH_WAIT_RQ;

      if (!e->userauth_server.userkey.found)
        {
          ASSH_ERR_RET(assh_userauth_server_failure(s) | ASSH_ERRSV_DISCONNECT);
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

    case ASSH_USERAUTH_PUBKEY_VERIFY: {
      pv->state = ASSH_USERAUTH_WAIT_RQ;

      if (!e->userauth_server.userkey.found)
        ASSH_ERR_RET(assh_userauth_server_failure(s)
		     | ASSH_ERRSV_DISCONNECT);
      else
        ASSH_ERR_RET(assh_userauth_server_pubkey_check(s, pv->sign_pck, pv->sign)
		     | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;
    }

    default:
      ASSH_ERR_RET(ASSH_ERR_STATE | ASSH_ERRSV_FATAL);
    }

  return ASSH_OK;
}

/* handle public key request packet */
static assh_error_t assh_userauth_server_req_pubkey(struct assh_session_s *s,
                                                    struct assh_packet_s *p,
                                                    struct assh_event_s *e,
                                                    const uint8_t *auth_data)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  const uint8_t *second = auth_data;
  const uint8_t *algo_name, *pub_blob, *sign;

  ASSH_ERR_RET(assh_packet_check_array(p, second, 1, &algo_name) | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_string(p, algo_name, &pub_blob) | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_packet_check_string(p, pub_blob, &sign) | ASSH_ERRSV_DISCONNECT);

  const struct assh_algo_s *algo;

  /* check if we support the requested signature algorithm */
  if (assh_algo_by_name(s->ctx, ASSH_ALGO_SIGN, (char*)algo_name + 4,
			pub_blob - algo_name - 4, &algo, &pv->algo_name) != ASSH_OK)
    {
      ASSH_ERR_RET(assh_userauth_server_failure(s) | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;
    }

  struct assh_key_s *pub_key = NULL;

  /* load the public key from the client provided blob */
  const uint8_t *key_blob = pub_blob + 4;
  ASSH_ERR_RET(assh_key_load(s->ctx, &pub_key, algo->key, ASSH_ALGO_SIGN,
                 ASSH_KEY_FMT_PUB_RFC4253, &key_blob,
                 sign - pub_blob - 4) | ASSH_ERRSV_DISCONNECT);

  /* check if the key can be used by the algorithm */
  if (!assh_algo_suitable_key(s->ctx, algo, pub_key))
    {
      assh_key_drop(s->ctx, &pub_key);
      ASSH_ERR_RET(assh_userauth_server_failure(s) | ASSH_ERRSV_DISCONNECT);
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
      if (pv->pubkey_state == ASSH_USERAUTH_PUBKEY_FOUND)
        {
          ASSH_ERR_RET(assh_userauth_server_pubkey_check(s, p, sign)
		       | ASSH_ERRSV_DISCONNECT);
          return ASSH_OK;
        }

      assh_packet_refinc(p);
      pv->sign_pck = p;
      pv->sign = sign;

      pv->state = ASSH_USERAUTH_PUBKEY_VERIFY;
    }
  else
    {
      if (pv->pubkey_state == ASSH_USERAUTH_PUBKEY_FOUND)
        return ASSH_OK;

      pv->state = ASSH_USERAUTH_PUBKEY_PKOK;
    }

  /* return an event to lookup the key in the list of authorized user keys */
  e->id = ASSH_EVENT_USERAUTH_SERVER_USERKEY;
  e->f_done = assh_userauth_server_userkey_done;
  e->userauth_server.userkey.username.str = pv->username;
  e->userauth_server.userkey.username.len = strlen(pv->username);
  e->userauth_server.userkey.pub_key = pv->pub_key;
  e->userauth_server.userkey.found = 0;

  return ASSH_OK;
}
#endif

/********************************************************************/

/* flush the authentication state on new request */
static assh_error_t assh_userauth_server_req_new(struct assh_session_s *s,
                                                 const uint8_t *srv_name,
                                                 const uint8_t *username,
                                                 const uint8_t *method_name)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  if (pv->srv != NULL)
   {
     if (!assh_ssh_string_compare(srv_name, pv->srv->name) &&
         !assh_ssh_string_compare(username, pv->username)  &&
         !assh_ssh_string_compare(method_name, pv->method_name))
       return ASSH_OK;

     assh_userauth_server_flush_state(s);
   }

  /* lookup service name */
  if (assh_service_by_name(s->ctx, assh_load_u32(srv_name),
                           (char*)srv_name + 4, &pv->srv))
    return ASSH_NO_DATA;

  /* keep method name and user name */
  ASSH_ERR_RET(assh_ssh_string_copy(username, pv->username, sizeof(pv->username))
               | ASSH_ERRSV_DISCONNECT);
  ASSH_ERR_RET(assh_ssh_string_copy(method_name, pv->method_name, sizeof(pv->method_name))
               | ASSH_ERRSV_DISCONNECT);

  return ASSH_OK;
}

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

  switch (/* method name len */ auth_data - method_name - 4)
    {
#ifdef CONFIG_ASSH_SERVER_AUTH_NONE
    case 4:
      if ((pv->methods & ASSH_USERAUTH_METHOD_NONE) &&
          !assh_ssh_string_compare(method_name, "none"))
        {
          ASSH_ERR_RET(assh_userauth_server_req_new(s, srv_name, username, method_name)
		       | ASSH_ERRSV_DISCONNECT);
          if (err == ASSH_NO_DATA)
            break;
          ASSH_ERR_RET(assh_userauth_server_success(s, e, ASSH_USERAUTH_METHOD_NONE)
		       | ASSH_ERRSV_DISCONNECT);
          return ASSH_OK;
        }
      break;
#endif

#ifdef CONFIG_ASSH_SERVER_AUTH_PASSWORD
    case 8:
      if (!assh_ssh_string_compare(method_name, "password"))
        {
          ASSH_CHK_RET(!(pv->methods & ASSH_USERAUTH_METHOD_PASSWORD),
                       ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);

          ASSH_ERR_RET(assh_userauth_server_req_new(s, srv_name, username, method_name)
		       | ASSH_ERRSV_DISCONNECT);
          if (err == ASSH_NO_DATA)
            break;
          ASSH_ERR_RET(assh_userauth_server_req_password(s, p, e, auth_data)
		       | ASSH_ERRSV_DISCONNECT);
          return ASSH_OK;
        }
      break;
#endif

#ifdef CONFIG_ASSH_SERVER_AUTH_PUBLICKEY
    case 9:
      if (!assh_ssh_string_compare(method_name, "publickey"))
        {
          ASSH_CHK_RET(!(pv->methods & ASSH_USERAUTH_METHOD_PUBKEY),
                       ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);

          ASSH_ERR_RET(assh_userauth_server_req_new(s, srv_name, username, method_name)
		       | ASSH_ERRSV_DISCONNECT);
          if (err == ASSH_NO_DATA)
            break;
          ASSH_ERR_RET(assh_userauth_server_req_pubkey(s, p, e, auth_data)
		       | ASSH_ERRSV_DISCONNECT);
          return ASSH_OK;
        }
      break;
#endif
    }

  ASSH_ERR_RET(assh_userauth_server_failure(s) | ASSH_ERRSV_DISCONNECT);
  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_server_methods_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  pv->methods = e->userauth_server.methods.methods;
  pv->retry = e->userauth_server.methods.retries;

  ASSH_CHK_RET(!(pv->methods & ASSH_USERAUTH_METHOD_IMPLEMENTED),
               ASSH_ERR_MISSING_ALGO | ASSH_ERRSV_DISCONNECT);

  size_t bsize = e->userauth_server.methods.banner.size;
  size_t lsize = e->userauth_server.methods.bnlang.size;

  if (bsize)
    {
      struct assh_packet_s *pout;
      ASSH_ERR_RET(assh_packet_alloc(s->ctx, SSH_MSG_USERAUTH_BANNER,
                                     4 + bsize + 4 + lsize, &pout)
                   | ASSH_ERRSV_DISCONNECT);
      uint8_t *str;
      ASSH_ASSERT(assh_packet_add_string(pout, bsize, &str));
      memcpy(str, e->userauth_server.methods.banner.str, bsize);
      ASSH_ASSERT(assh_packet_add_string(pout, lsize, &str));
      memcpy(str, e->userauth_server.methods.bnlang.str, lsize);
      assh_transport_push(s, pout);
    }

  pv->state = ASSH_USERAUTH_WAIT_RQ;

  return ASSH_OK;
}

static assh_error_t assh_userauth_server_methods(struct assh_session_s *s,
                                                 struct assh_event_s *e)
{
  struct assh_userauth_context_s *pv = s->srv_pv;

  pv->state = ASSH_USERAUTH_METHODS_DONE;
  e->id = ASSH_EVENT_USERAUTH_SERVER_METHODS;
  e->f_done = assh_userauth_server_methods_done;

  e->userauth_server.methods.banner.size = 0;
  e->userauth_server.methods.bnlang.size = 0;

  e->userauth_server.methods.methods = ASSH_USERAUTH_METHOD_IMPLEMENTED &
    (ASSH_USERAUTH_METHOD_PUBKEY |
     ASSH_USERAUTH_METHOD_PASSWORD);

  e->userauth_server.methods.retries = 10;

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
    case ASSH_USERAUTH_METHODS:
      ASSH_ERR_RET(assh_userauth_server_methods(s, e) | ASSH_ERRSV_DISCONNECT);
      return ASSH_NO_DATA;

#ifdef CONFIG_ASSH_SERVER_AUTH_PASSWORD
    case ASSH_USERAUTH_PASSWORD_SUCCESS:
      ASSH_ERR_RET(assh_userauth_server_success(s, e, ASSH_USERAUTH_METHOD_PASSWORD)
                   | ASSH_ERRSV_DISCONNECT);
      return ASSH_NO_DATA;

    case ASSH_USERAUTH_PASSWORD_WAIT_CHANGE:
#endif
    case ASSH_USERAUTH_WAIT_RQ:
      if (p != NULL)
        ASSH_ERR_RET(assh_userauth_server_req(s, p, e) | ASSH_ERRSV_DISCONNECT);
      return ASSH_OK;

#ifdef CONFIG_ASSH_SERVER_AUTH_PUBLICKEY
    case ASSH_USERAUTH_PUBKEY_SUCCESS:
      ASSH_ERR_RET(assh_userauth_server_success(s, e, ASSH_USERAUTH_METHOD_PUBKEY)
                   | ASSH_ERRSV_DISCONNECT);
      return ASSH_NO_DATA;
#endif

    default:
      ASSH_ERR_RET(ASSH_ERR_STATE | ASSH_ERRSV_FATAL);
    }
}

const struct assh_service_s assh_service_userauth_server =
{
  .name = "ssh-userauth",
  .side = ASSH_SERVER,
  .f_init = assh_userauth_server_init,
  .f_cleanup = assh_userauth_server_cleanup,
  .f_process = assh_userauth_server_process,
};

#endif

