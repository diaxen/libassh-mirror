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

#ifndef ASSH_SRV_USERAUTH_SERVER_PV_H_
#define ASSH_SRV_USERAUTH_SERVER_PV_H_

#include <assh/assh_userauth_server.h>

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
  ASSH_USERAUTH_ST_CONTINUE,
  ASSH_USERAUTH_ST_SUCCESS,
  ASSH_USERAUTH_ST_SUCCESS_DONE,
};

#define ASSH_USERAUTH_SERVER_REQ(n)                             \
  assh_error_t (n)(struct assh_session_s *s,                    \
                   struct assh_packet_s *p,                     \
                   struct assh_event_s *e,                      \
                   const uint8_t *auth_data)

typedef ASSH_USERAUTH_SERVER_REQ(assh_userauth_server_req_t);

#define ASSH_USERAUTH_SERVER_PROCESS(n)				\
  assh_error_t (n)(struct assh_session_s *s,                    \
                   struct assh_packet_s *p,                     \
                   struct assh_event_s *e)

typedef ASSH_USERAUTH_SERVER_PROCESS(assh_userauth_server_process_t);

struct assh_userauth_server_method_s
{
  const char                   *name;
  enum assh_userauth_methods_e mask;
  assh_userauth_server_req_t   *f_req;
  assh_userauth_server_process_t *f_process;
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
  const struct assh_userauth_server_method_s *method;
  struct assh_packet_s *pck;

#ifdef CONFIG_ASSH_SERVER_AUTH_KEYBOARD
  struct assh_cbuffer_s *keyboard_array;
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

/* send the authentication failure packet */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_userauth_server_send_failure(struct assh_session_s *s,
                                  assh_bool_t partial);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_userauth_server_failure(struct assh_session_s *s,
			     assh_bool_t get_methods);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_userauth_server_success(struct assh_session_s *s,
			     struct assh_event_s *e);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_userauth_server_get_key(struct assh_session_s *s,
                             const uint8_t *algo_name,
                             const uint8_t *pub_blob,
                             const struct assh_algo_s **algo,
                             struct assh_key_s **pub_key,
                             const struct assh_algo_name_s **namep);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_userauth_server_sign_check(struct assh_session_s *s,
                                struct assh_packet_s *p,
                                const uint8_t *sign_str);

extern const struct assh_userauth_server_method_s assh_userauth_server_none;
extern const struct assh_userauth_server_method_s assh_userauth_server_password;
extern const struct assh_userauth_server_method_s assh_userauth_server_publickey;
extern const struct assh_userauth_server_method_s assh_userauth_server_hostbased;
extern const struct assh_userauth_server_method_s assh_userauth_server_keyboard;

#endif

