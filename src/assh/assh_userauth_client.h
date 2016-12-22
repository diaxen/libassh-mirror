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

/**
   @file
   @short Implementation of the client side ssh-userauth service (rfc4252)

   This header file defines events which are reported to the
   application when the client side @tt ssh-userauth service is
   running.

   This standard service described in rfc4252 is implemented as a
   pluggable service module for libassh.
*/

#ifndef ASSH_SRV_USERAUTH_CLIENT_H_
#define ASSH_SRV_USERAUTH_CLIENT_H_

#ifdef ASSH_EVENT_H_
# warning The assh/assh_event.h header should be included after assh_userauth_client.h
#endif

#include "assh.h"
#include "assh_userauth.h"

/** This event is reported when the client-side user authentication
    service is running and the service needs to provide a user name
    to the server. 

    @see ASSH_EVENT_USERAUTH_CLIENT_USER
*/
struct assh_event_userauth_client_user_s
{
  struct assh_buffer_s    username;    //< output
};

/** This event is reported when the client-side user authentication
    service is running, before every authentication attempt.

    The @ref methods field indicates the authentication methods that
    are accepted by the server. One of these methods must be selected
    by setting the @ref select field.

    The @ref password, @ref pub_keys and @ref keyboard fields are
    initially set to zero and have to be updated depending on the
    retained authentication method.

    The @ref pub_keys linked list can be populated by calling either
    the @ref assh_key_load, @ref assh_load_key_file or @ref
    assh_load_key_filename functions. Multiple keys can be loaded. The
    assh library will take care of releasing the provided keys. If a
    public key is provided, the @ref ASSH_EVENT_USERAUTH_CLIENT_SIGN
    event will be reported. The library will take care of generating
    the signature when a private key is provided.

    When the @em keyboard-interactive method is enabled, the @ref
    keyboard_sub field will be used as @em submethods fields of the
    request.

    This event may be reported multiple times before the
    authentication is successful. This occurs when a previous
    authentication attempt has failed or when the server requires
    multi factor authentication. The @ref partial_success field
    is set in the later case.

    @see ASSH_EVENT_USERAUTH_CLIENT_METHODS
*/
struct assh_event_userauth_client_methods_s
{
  ASSH_EV_CONST assh_bool_t    partial_success; //< input
  ASSH_EV_CONST enum assh_userauth_methods_e methods; //< input
  enum assh_userauth_methods_e select;       //< output
  union {
    struct assh_buffer_s       password;     //< output
    struct assh_key_s          *keys;        //< output
    struct assh_buffer_s       keyboard_sub; //< output
  };
};

/** This event is reported when the client-side user authentication
    service is running and a @b public key has been provided for
    public key authentication.

    The private key must be used to generate a signature over the
    provided authentication data. The @tt sign buffer is allocated by
    the library. Its size must be reduced if the signature doesn't use
    the entire provided storage.

    @see ASSH_EVENT_USERAUTH_CLIENT_SIGN
 */
struct assh_event_userauth_client_sign_s
{
  struct assh_key_s * ASSH_EV_CONST pub_key;    //< input
  const struct assh_algo_sign_s * ASSH_EV_CONST algo; //< input
  ASSH_EV_CONST struct assh_cbuffer_s auth_data; //< input
  struct assh_buffer_s sign;                    //< output
};

/** This event is reported when the client-side user authentication
    service is running and a banner message is received.

    @see ASSH_EVENT_USERAUTH_CLIENT_BANNER
*/
struct assh_event_userauth_client_banner_s
{
  ASSH_EV_CONST struct assh_buffer_s text; //< output
  ASSH_EV_CONST struct assh_buffer_s lang;   //< output
};

/** This event is reported when the client-side user authentication
    service is running and a password change request message is
    received.

    The password change is skipped if the @ref new_password field is
    left empty.

    @see ASSH_EVENT_USERAUTH_CLIENT_PWCHANGE
*/
struct assh_event_userauth_client_pwchange_s
{
  ASSH_EV_CONST struct assh_buffer_s prompt;       //< output
  ASSH_EV_CONST struct assh_buffer_s lang;         //< output
  struct assh_buffer_s               old_password; //< input
  struct assh_buffer_s               new_password; //< input
};


/** This event is reported when the keyboard interactive
    authentication has been selected and the server sent a @ref
    SSH_MSG_USERAUTH_INFO_REQUEST message.

    The @ref prompts array contains @ref count entries which must be
    used to query the user. The @ref echos field is a bitmap which
    indicates user entered values that should be displayed.

    Pointers and lengths of user entered values must be stored in the
    @ref responses array. The prompt array may be reused or a pointer
    to an other array can be provided. In either cases, all entries must
    be initialized with user provided response buffers. These buffers
    can be released after calling the @ref assh_event_done function.

    @see ASSH_EVENT_USERAUTH_CLIENT_KEYBOARD
*/
struct assh_event_userauth_client_keyboard_s
{
  ASSH_EV_CONST struct assh_buffer_s name; //< input
  ASSH_EV_CONST struct assh_buffer_s instruction; //< input
  ASSH_EV_CONST uint32_t             echos; //< input
  ASSH_EV_CONST uint_fast8_t         count; //< input
  union {
    ASSH_EV_CONST struct assh_buffer_s * prompts; //< input
    struct assh_buffer_s *responses; //< output
  };
};

/** @This contains all client side user authentication related events */
union assh_event_userauth_client_u
{
  struct assh_event_userauth_client_user_s    user;
  struct assh_event_userauth_client_methods_s methods;
  struct assh_event_userauth_client_banner_s  banner;
  struct assh_event_userauth_client_pwchange_s pwchange;
  struct assh_event_userauth_client_keyboard_s keyboard;
  struct assh_event_userauth_client_sign_s    sign;
};

/** @This implements the standard client side @tt ssh-userauth service. */
extern const struct assh_service_s assh_service_userauth_client;

#endif

