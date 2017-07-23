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

#ifndef ASSH_SRV_USERAUTH_CLIENT_PV_H_
#define ASSH_SRV_USERAUTH_CLIENT_PV_H_

#include <assh/assh_userauth_client.h>

enum assh_userauth_state_e
{
  ASSH_USERAUTH_ST_INIT,
  ASSH_USERAUTH_ST_GET_USERNAME,
  ASSH_USERAUTH_ST_SENT_NONE_RQ,
#ifdef CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY
  ASSH_USERAUTH_ST_SENT_PUBKEY_RQ,
  ASSH_USERAUTH_ST_SENT_PUBKEY_RQ_DONE,
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
  ASSH_USERAUTH_ST_SENT_HOSTBASED_RQ_DONE,
  ASSH_USERAUTH_ST_SEND_HOSTBASED,
#endif
  ASSH_USERAUTH_ST_GET_METHODS,
  ASSH_USERAUTH_ST_SUCCESS,
};

#define ASSH_USERAUTH_CLIENT_REQ(n)					\
  ASSH_WARN_UNUSED_RESULT assh_error_t (n)(struct assh_session_s *s,	\
                   const struct assh_event_userauth_client_methods_s *ev)

typedef ASSH_USERAUTH_CLIENT_REQ(assh_userauth_client_req_t);

#define ASSH_USERAUTH_CLIENT_RETRY(n)					\
  ASSH_WARN_UNUSED_RESULT assh_error_t (n)(struct assh_session_s *s,	\
					   struct assh_event_s *e)

typedef ASSH_USERAUTH_CLIENT_RETRY(assh_userauth_client_retry_t);

#define ASSH_USERAUTH_CLIENT_PROCESS(n)					\
  ASSH_WARN_UNUSED_RESULT assh_error_t (n)(struct assh_session_s *s,	\
					   struct assh_packet_s *p,	\
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

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_userauth_client_pck_head(struct assh_session_s *s,
                              struct assh_packet_s **pout,
                              const char *method,
                              size_t extra_len);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_userauth_client_get_methods(struct assh_session_s *s,
                                 struct assh_event_s *e,
                                 assh_bool_t partial_success);

#if defined(CONFIG_ASSH_CLIENT_AUTH_HOSTBASED) || \
  defined(CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY)

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_userauth_client_send_sign(struct assh_session_s *s,
                               struct assh_userauth_keys_s *k,
                               struct assh_packet_s *pout,
                               size_t sign_len);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_userauth_client_get_sign(struct assh_session_s *s,
                              struct assh_event_userauth_client_sign_s *ev,
                              struct assh_userauth_keys_s *k,
                              struct assh_packet_s *pout,
                              size_t sign_len);

void
assh_userauth_client_key_next(struct assh_session_s *s,
                              struct assh_userauth_keys_s *k);

void
assh_userauth_client_key_get(struct assh_session_s *s,
                             struct assh_userauth_keys_s *k,
                             struct assh_key_s *keys);
#endif

ASSH_USERAUTH_CLIENT_PROCESS(assh_userauth_client_default_process);
ASSH_USERAUTH_CLIENT_RETRY(assh_userauth_client_no_retry);

extern const struct assh_userauth_client_method_s assh_userauth_client_none;
extern const struct assh_userauth_client_method_s assh_userauth_client_password;
extern const struct assh_userauth_client_method_s assh_userauth_client_publickey;
extern const struct assh_userauth_client_method_s assh_userauth_client_hostbased;
extern const struct assh_userauth_client_method_s assh_userauth_client_keyboard;

#endif

