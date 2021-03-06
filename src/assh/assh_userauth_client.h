/*

  libassh - asynchronous ssh2 client/server library.

  Copyright (C) 2013-2020 Alexandre Becoulet <alexandre.becoulet@free.fr>

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

   This header file defines @hl events which are reported to the
   application when the @ref assh_service_userauth_client service is
   running. This @hl service module is an implementation of the
   client side @hl{user authentication} protocol.

   This standard @hl service described in @sinvoke{4252}rfc is
   implemented as a pluggable service @hl module for @em{libassh}.

   @see{@assh/assh_userauth.h}
   @xsee{uamethods}
*/

#ifndef ASSH_SRV_USERAUTH_CLIENT_H_
#define ASSH_SRV_USERAUTH_CLIENT_H_

#ifdef ASSH_EVENT_H_
# warning The assh/assh_event.h header should be included after assh_userauth_client.h
#endif

#include "assh.h"
#include "assh_buffer.h"
#include "assh_userauth.h"

/** This event is reported when the client-side user authentication
    service is running and the service needs to provide a user name
    to the server. 

    @see ASSH_EVENT_USERAUTH_CLIENT_USER
*/
struct assh_event_userauth_client_user_s
{
  /** The user name transmitted to server (rw) */
  struct assh_cbuffer_s username;
};

/** This event is reported when the client-side user authentication
    service is running, before every authentication attempt.

    The @ref methods field indicates the authentication methods that
    are accepted by the server. One of these methods must be selected
    by setting the @ref select field.

    The other fields are initially set to zero and have to be updated
    depending on the retained authentication method:

    @list
      @item When the @em keyboard-interactive method is selected, the @tt
      keyboard_sub field will be used as @em submethods fields of the
      request.

      @item When the @em publickey method is selected, the @tt keys
      field is used.

      @item When the @em password method is selected, the @tt
      password field is used.

      @item When the @em hostbased method is selected, the @tt {keys},
      @ref host_name and @ref host_username fields are used.
    @end list

    The @tt keys linked list can be populated by calling either
    the @ref assh_key_load, @ref asshh_key_load_file or @ref
    asshh_key_load_filename functions. Multiple keys can be loaded. The
    assh library will take care of releasing the provided keys. If a
    public key is provided, the @ref ASSH_EVENT_USERAUTH_CLIENT_SIGN
    event will be reported. The library will take care of generating
    the signature when a private key is provided.

    This event may be reported multiple times before the
    authentication is successful. This occurs when a previous
    authentication attempt has failed or when the server requires
    multi factor authentication. The @ref partial_success field
    is set in the later case.

    @see ASSH_EVENT_USERAUTH_CLIENT_METHODS
*/
struct assh_event_userauth_client_methods_s
{
  /** Advertises multi-factor authentication. (ro) */
  ASSH_EV_CONST assh_bool_t partial_success;

  /** Methods accepted by the server. (ro) */
  ASSH_EV_CONST enum assh_userauth_methods_e methods;

  /** Must be set to the retained method. (rw) */
  enum assh_userauth_methods_e select;

  union {
    /** The password credential. (rw) */
    struct assh_cbuffer_s password;

    /** The user or host public key credential. (rw) */
    struct assh_key_s *keys;

    /** The keyboard sub-method. (rw) */
    struct assh_cbuffer_s keyboard_sub;
  };

  /** The host name. (rw) */
  struct assh_cbuffer_s host_name;

  /** The host user name. */
  struct assh_cbuffer_s host_username;
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
  /** The associated public key. (ro) */
  struct assh_key_s * ASSH_EV_CONST pub_key;

  /** The signature algorithm. (ro) */
  const struct assh_algo_sign_s * ASSH_EV_CONST algo;

  /** The data to authenticate. (ro) */
  ASSH_EV_CONST struct assh_cbuffer_s auth_data;

  /** Used to store the generated signature. (rw) */
  struct assh_buffer_s sign;
};

/** This event is reported when the client-side user authentication
    service is running and a banner message is received.

    @see ASSH_EVENT_USERAUTH_CLIENT_BANNER
*/
struct assh_event_userauth_client_banner_s
{
  /** The banner text transmitted by the server. (ro) */
  ASSH_EV_CONST struct assh_cbuffer_s text;

  /** The language tag. (ro) */
  ASSH_EV_CONST struct assh_cbuffer_s lang;
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
  /** The password change prompt string. (ro) */
  ASSH_EV_CONST struct assh_cbuffer_s prompt;

  /** The language tag. (ro) */
  ASSH_EV_CONST struct assh_cbuffer_s lang;

  /** The old password must be stored here. (rw) */
  struct assh_cbuffer_s old_password;

  /** The new password must be stored here. (rw) */
  struct assh_cbuffer_s new_password;
};


/** This event is reported when the keyboard interactive
    authentication has been selected and the server sent a @ref
    SSH_MSG_USERAUTH_INFO_REQUEST message.

    The @tt prompts array contains @tt count entries which must be
    used to query the user. The @tt echos field is a bitmap which
    indicates user entered values that should be displayed.

    Pointers and lengths of user entered values must be stored in the
    @tt responses array. The prompt array may be reused or a pointer
    to an other array can be provided. In either cases, all entries must
    be initialized with user provided response buffers. These buffers
    can be released after calling the @ref assh_event_done function.

    @see ASSH_EVENT_USERAUTH_CLIENT_KEYBOARD
*/
struct assh_event_userauth_client_keyboard_s
{
  /** The name transmitted by the server. (ro) */
  ASSH_EV_CONST struct assh_cbuffer_s name;

  /** The instructions transmitted by the server. (ro) */
  ASSH_EV_CONST struct assh_cbuffer_s instruction;

  /** Indicate fields that must be echoed. (ro) */
  ASSH_EV_CONST uint32_t echos;

  /** The number of fields. (ro) */
  ASSH_EV_CONST uint_fast8_t count;

  union {
    /** The array of prompt strings. (ro) */
    ASSH_EV_CONST struct assh_cbuffer_s *prompts;

    /** The array of response strings. (rw) */
    struct assh_cbuffer_s *responses;
  };
};

/** @This contains all client side user authentication related event
    structures. */
union assh_event_userauth_client_u
{
  struct assh_event_userauth_client_user_s user;
  struct assh_event_userauth_client_methods_s methods;
  struct assh_event_userauth_client_banner_s banner;
  struct assh_event_userauth_client_pwchange_s pwchange;
  struct assh_event_userauth_client_keyboard_s keyboard;
  struct assh_event_userauth_client_sign_s sign;
};

/** @This implements the standard client side @tt ssh-userauth service. */
extern const struct assh_service_s assh_service_userauth_client;

#endif

