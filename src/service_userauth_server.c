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
#include <assh/assh_context.h>
#include <assh/assh_session.h>
#include <assh/assh_packet.h>
#include <assh/assh_transport.h>
#include <assh/assh_algo.h>
#include <assh/assh_sign.h>
#include <assh/assh_key.h>

#ifdef CONFIG_ASSH_SERVER

#include <stdlib.h>

enum assh_userauth_state_e
{
  ASSH_USERAUTH_WAIT_RQ,  //< intial state
  ASSH_USERAUTH_PUBKEY,   //< the first public key request packet has been received
  ASSH_USERAUTH_PUBKEY_OK,   //< the first public key request packet has been received
  ASSH_USERAUTH_PASSWD,
  ASSH_USERAUTH_HOST,
  ASSH_USERAUTH_NONE,
};

struct assh_userauth_context_s
{
  enum assh_userauth_state_e state;
  const struct assh_service_s *srv;
  struct assh_algo_sign_s *algo;
  struct assh_key_s *pub_key;
  unsigned int retry;
  char username[32+1];
  char password[64];
};

static ASSH_SERVICE_INIT_FCN(assh_userauth_server_init)
{
  assh_error_t err;
  struct assh_userauth_context_s *pv;

  ASSH_ERR_RET(assh_alloc(s->ctx, sizeof(*pv),
                          ASSH_ALLOC_KEY, (void**)&pv));

  s->srv = &assh_service_userauth_server;
  s->srv_pv = pv;

  pv->state = ASSH_USERAUTH_WAIT_RQ;
  pv->srv = NULL;
  pv->pub_key = NULL;
  pv->retry = 10;

  return ASSH_OK;
}

static ASSH_SERVICE_CLEANUP_FCN(assh_userauth_server_cleanup)
{
  struct assh_userauth_context_s *pv = s->srv_pv;

  assh_key_flush(s->ctx, &pv->pub_key);

  assh_free(s->ctx, pv, ASSH_ALLOC_INTERNAL);

  s->srv_pv = NULL;
  s->srv = NULL;
}

static assh_error_t assh_userauth_server_failure(struct assh_session_s *s)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  ASSH_ERR_RET(pv->retry-- == 0 ? ASSH_ERR_CODE(ASSH_ERR_PROTOCOL,
                      SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE) : 0);

  struct assh_packet_s *pout;
  const char *list_ = "publickey,password";
  uint8_t *list, *partial_success;
  size_t list_len = strlen(list_);

  /* send the authentication failure packet */
  ASSH_ERR_RET(assh_packet_alloc(s, SSH_MSG_USERAUTH_FAILURE, 4 + list_len + 1, &pout));
  ASSH_ASSERT(assh_packet_add_string(pout, list_len, &list));
  memcpy(list, list_, list_len);
  ASSH_ASSERT(assh_packet_add_bytes(pout, 1, &partial_success));
  *partial_success = 0;
  assh_transport_push(s, pout);

  pv->srv = NULL;
  pv->state = ASSH_USERAUTH_WAIT_RQ;

  return ASSH_OK;
}

static assh_error_t assh_userauth_server_success(struct assh_session_s *s)
{
  assh_error_t err;
  struct assh_userauth_context_s *pv = s->srv_pv;
  const struct assh_service_s *srv = pv->srv;

  /* cleanup the authentication service and start the next requested service. */
  assh_userauth_server_cleanup(s);

  ASSH_ERR_RET(srv->f_init(s));

  /* send the authentication success packet */
  struct assh_packet_s *pout;
  ASSH_ERR_RET(assh_packet_alloc(s, SSH_MSG_USERAUTH_SUCCESS, 0, &pout));
  assh_transport_push(s, pout);

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_server_password_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  ASSH_ERR_RET(pv->state != ASSH_USERAUTH_PASSWD ? ASSH_ERR_STATE : 0);

  if (e->userauth_server_password.success)
    ASSH_ERR_RET(assh_userauth_server_success(s));
  else
    ASSH_ERR_RET(assh_userauth_server_failure(s));    

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_userauth_server_userkey_done)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  ASSH_ERR_RET(pv->state != ASSH_USERAUTH_PUBKEY ? ASSH_ERR_STATE : 0);

  if (!e->userauth_server_userkey.found)
    {
      ASSH_ERR_RET(assh_userauth_server_failure(s));
      return ASSH_OK;
    }

  /* alloc PK_OK packet */
  size_t algo_name_len = strlen(pv->pub_key->algo->name);

  size_t blob_len;
  ASSH_ERR_RET(pv->pub_key->f_output(s->ctx, pv->pub_key,
               NULL, &blob_len, ASSH_KEY_FMT_PUB_RFC4253_6_6));

  struct assh_packet_s *pout;
  ASSH_ERR_RET(assh_packet_alloc(s, SSH_MSG_USERAUTH_PK_OK,
                                 4 + algo_name_len + 4 + blob_len, &pout));

  /* add algorithm name */
  uint8_t *algo_name;
  ASSH_ERR_RET(assh_packet_add_string(pout, algo_name_len, &algo_name));
  memcpy(algo_name, pv->pub_key->algo->name, algo_name_len);

  /* add public key blob */
  uint8_t *blob;
  ASSH_ERR_RET(assh_packet_add_string(pout, blob_len, &blob));
  ASSH_ERR_RET(pv->pub_key->f_output(s->ctx, pv->pub_key,
               blob, &blob_len, ASSH_KEY_FMT_PUB_RFC4253_6_6));
  assh_packet_shrink_string(pout, blob, blob_len);

  assh_transport_push(s, pout);
  pv->state = ASSH_USERAUTH_PUBKEY_OK;

  return ASSH_OK;
}

static ASSH_PROCESS_FCN(assh_userauth_server_process)
{
  struct assh_userauth_context_s *pv = s->srv_pv;
  assh_error_t err;

  if (p == NULL)
    return ASSH_OK;

  ASSH_ERR_RET(p->head.msg != SSH_MSG_USERAUTH_REQUEST
               ? ASSH_ERR_PROTOCOL : 0);

  uint8_t *user_name = p->head.end;
  uint8_t *srv_name, *method_name, *second, *payload;

  ASSH_ERR_RET(assh_packet_check_string(p, user_name, &srv_name));
  ASSH_ERR_RET(assh_packet_check_string(p, srv_name, &method_name));
  ASSH_ERR_RET(assh_packet_check_string(p, method_name, &second));
  ASSH_ERR_RET(assh_packet_check_array(p, second, 1, &payload));

  if (!assh_string_compare(method_name, "none"))
    {
      ASSH_ERR_RET(assh_userauth_server_failure(s));
      return ASSH_OK;
    }

  if (*second == 0)
    {
      /* new request, cleanup old stuff */
      assh_key_flush(s->ctx, &pv->pub_key);

      /* lookup service name */
      if (assh_service_by_name(s->ctx, assh_load_u32(srv_name),
                               (char*)srv_name + 4, &pv->srv))
        {
          ASSH_ERR_RET(assh_userauth_server_failure(s));
          return ASSH_OK;
        }

      /* copy user name */
      size_t ulen = assh_load_u32(user_name);
      ASSH_ERR_RET(ulen + 1 > sizeof(pv->username) ? ASSH_ERR_OVERFLOW : 0);
      memcpy(pv->username, user_name + 4, ulen);
      pv->username[ulen] = '\0';

      pv->state = ASSH_USERAUTH_WAIT_RQ;
    }
  else
    {
      /* service/user sanity check */
      ASSH_ERR_RET(pv->srv == NULL ? ASSH_ERR_PROTOCOL : 0);
      ASSH_ERR_RET(assh_string_compare(srv_name, pv->srv->name) ? ASSH_ERR_PROTOCOL : 0);
      ASSH_ERR_RET(assh_string_compare(user_name, pv->username) ? ASSH_ERR_PROTOCOL : 0);
    }

  switch (second - method_name - 4)
    {
    case 8:
      if (!assh_string_compare(method_name, "password"))
        {
          uint8_t *passwd = payload, *end;

          ASSH_ERR_RET(*second != 0 ? ASSH_ERR_PROTOCOL : 0);

          /* copy password */
          ASSH_ERR_RET(assh_packet_check_string(p, passwd, &end));
          size_t passwd_len = end - passwd - 4;
          ASSH_ERR_RET(passwd_len + 1 > sizeof(pv->password) ? ASSH_ERR_OVERFLOW : 0);
          memcpy(pv->password, passwd + 4, passwd_len);
          pv->password[passwd_len] = '\0';

          /* return event to check the user password */
          e->id = ASSH_EVENT_USERAUTH_SERVER_PASSWORD;
          e->f_done = assh_userauth_server_password_done;
          e->done_pv = pv;
          e->userauth_server_password.username = pv->username;
          e->userauth_server_password.password = pv->password;
          e->userauth_server_password.success = 0;

          pv->state = ASSH_USERAUTH_PASSWD;
          return ASSH_OK;
        }
      break;

    case 9:
      if (!assh_string_compare(method_name, "publickey"))
        {
          uint8_t *algo_name = payload, *pub_blob, *sign;

          ASSH_ERR_RET(assh_packet_check_string(p, algo_name, &pub_blob));
          ASSH_ERR_RET(assh_packet_check_string(p, pub_blob, &sign));

          if (*second == 0)
            {
              /* lookup algorithm and load the public key from client provided blob */
              ASSH_ERR_RET(assh_algo_by_name(s->ctx, ASSH_ALGO_SIGN, (char*)algo_name + 4,
                             pub_blob - algo_name - 4, (const struct assh_algo_s**)&pv->algo));

              ASSH_ERR_RET(assh_key_load3(s->ctx, &pv->pub_key, (const struct assh_algo_s*)pv->algo,
                                          pub_blob + 4, sign - pub_blob - 4,
                                          ASSH_KEY_FMT_PUB_RFC4253_6_6));

              /* return event to lookup authorized user key */
              e->id = ASSH_EVENT_USERAUTH_SERVER_USERKEY;
              e->f_done = assh_userauth_server_userkey_done;
              e->done_pv = pv;
              e->userauth_server_userkey.username = pv->username;
              e->userauth_server_userkey.pub_key = pv->pub_key;
              e->userauth_server_userkey.found = 0;

              pv->state = ASSH_USERAUTH_PUBKEY;
            }
          else
            {
              ASSH_ERR_RET(pv->state != ASSH_USERAUTH_PUBKEY_OK ? ASSH_ERR_PROTOCOL : 0);

              ASSH_ERR_RET(assh_packet_check_string(p, sign, NULL));

              uint8_t sid_len[4];   /* fake string header for session id */
              assh_store_u32(sid_len, s->session_id_len);

              /* buffers that have been signed by the client */
              const uint8_t *sign_ptrs[3] =
                { sid_len, s->session_id,     &p->head.msg };
              size_t sign_sizes[3]        =
                { 4,       s->session_id_len, sign - &p->head.msg };

              /* check signature */
              assh_bool_t sign_ok;
              ASSH_ERR_RET(pv->algo->f_verify(s->ctx, pv->pub_key, 3,
                             sign_ptrs, sign_sizes, sign, &sign_ok));

              if (sign_ok)
                ASSH_ERR_RET(assh_userauth_server_success(s));
              else
                ASSH_ERR_RET(assh_userauth_server_failure(s));
            }

          return ASSH_OK;
        }
      break;
    }

  ASSH_ERR_RET(assh_userauth_server_failure(s));
  return ASSH_OK;
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

