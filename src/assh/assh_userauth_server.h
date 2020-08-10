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
   @short Implementation of the server side ssh-userauth service (rfc4252)

   This header file defines @hl events which are reported to the
   application when the @ref assh_service_userauth_server service is
   running. This @hl service module is an implementation of the
   server side @hl{user authentication} protocol.

   This standard @hl service described in @sinvoke{4252}rfc is
   implemented as a pluggable service @hl module for @em {libassh}.

   @see{@assh/assh_userauth.h}
   @xsee{uamethods}
*/

#ifndef ASSH_SRV_USERAUTH_SERVER_H_
#define ASSH_SRV_USERAUTH_SERVER_H_

#ifdef ASSH_EVENT_H_
# warning The assh/assh_event.h header should be included after assh_userauth_server.h
#endif

#include "assh.h"
#include "assh_buffer.h"
#include "assh_userauth.h"

/** This event is reported when the server-side user authentication
    service is running and some authentication methods must be
    selected.

    The @ref failed field indicates the authentication method that
    just failed. It is zero when the event is reported for the first
    time.

    Some implemented methods are initially selected as default.
    The number of authentication retries left can be checked and
    changed.

    This event is not reported again if the failure is due to the
    client requesting a method which has not been selected.

    A banner message will be sent if the @tt banner buffer size is
    changed to a value greater than zero.

    @see ASSH_EVENT_USERAUTH_SERVER_METHODS */
struct assh_event_userauth_server_methods_s
{
  /** The last failed method. (ro) */
  ASSH_EV_CONST enum assh_userauth_methods_e failed;

  /** The methods that will be proposed to the client. (rw) */
  enum assh_userauth_methods_e methods;

  /** The number of allowed retries. (rw) */
  uint_fast8_t retries;

  /** The banner text may be stored here when used. (rw) */
  struct assh_cbuffer_s banner;

  /** The banner language tag. (rw) */
  struct assh_cbuffer_s bnlang;
};

/** This event is reported when the server-side user authentication
    service is running and the client has selected the @em none
    method.

    The @tt accept field must be updated before calling the @ref
    assh_event_done function.

    @see ASSH_EVENT_USERAUTH_SERVER_NONE */
struct assh_event_userauth_server_none_s
{
  /** The user name transmitted by the client. (ro) */
  ASSH_EV_CONST struct assh_cbuffer_s username;

  /** A pointer to the service that the client wants to run. (ro) */
  const struct assh_service_s * ASSH_EV_CONST service;

  /** Accept login without credential when true. (rw) */
  assh_bool_t accept;
};

/** This event is reported when the server-side user authentication
    service is running and the client has selected the user public key
    method.

    The user public key @tt pub_key must be
    searched in the list of authorized keys for the user on this
    server. The @tt found field must be updated accordingly before
    calling the @ref assh_event_done function.

    @see ASSH_EVENT_USERAUTH_SERVER_USERKEY */
struct assh_event_userauth_server_userkey_s
{
  /** The user name transmitted by the client. (ro) */
  ASSH_EV_CONST struct assh_cbuffer_s username;

  /** A pointer to the service that the client wants to run. (ro) */
  const struct assh_service_s * ASSH_EV_CONST service;

  /** The user public key provided by the client. (ro) */
  struct assh_key_s * ASSH_EV_CONST pub_key;

  /** Acknowledge that the key is authorized when true. (rw) */
  assh_bool_t found;
};

/** @see assh_event_userauth_server_password_s */
enum assh_event_userauth_server_pwstatus_s
{
  /** Indicates password authentication failure. */
  ASSH_SERVER_PWSTATUS_FAILURE,
  /** Indicates password authentication success. */
  ASSH_SERVER_PWSTATUS_SUCCESS,
  /** Indicates that a password change request must be transmitted. */
  ASSH_SERVER_PWSTATUS_CHANGE,
};

/** This event is reported when the server-side user authentication
    service is running and the client has selected the password
    method.

    The user name and password pair must be
    checked and the @tt success field must be updated accordingly
    before calling the @ref assh_event_done function.

    The client requests a password change when the size of the @ref
    new_password buffer is not 0. The server can require this behavior
    for the next password event by setting the @tt pwchange field. In
    this case the @tt prompt and @tt lang fields may also be
    updated.

    @see ASSH_EVENT_USERAUTH_SERVER_PASSWORD */
struct assh_event_userauth_server_password_s
{
  /** The user name transmitted by the client. (ro) */
  ASSH_EV_CONST struct assh_cbuffer_s username;

  /** A pointer to the service that the client wants to run. (ro) */
  const struct assh_service_s * ASSH_EV_CONST service;

  /** The current password transmitted by the client. (ro) */
  ASSH_EV_CONST struct assh_cbuffer_s password;

  /** The new password transmitted by the client. (ro) */
  ASSH_EV_CONST struct assh_cbuffer_s new_password;

  /** A prompt string for the password change request. (rw) */
  struct assh_cbuffer_s change_prompt;

  /** The prompt language tag. (rw) */
  struct assh_cbuffer_s change_lang;

  /** Used to acknowledge that the password is correct. (rw) */
  enum assh_event_userauth_server_pwstatus_s result;
};

/** This event is reported when the server-side user authentication
    service is running and the client has selected the hostbased
    method.

    The host public key @tt host_key must be searched in the list of
    authorized keys for the spcified @tt hostname user on this
    server. The @tt found field must be updated accordingly before
    calling the @ref assh_event_done function.

    @see ASSH_EVENT_USERAUTH_SERVER_HOSTBASED */
struct assh_event_userauth_server_hostbased_s
{
  /** The user name transmitted by the client. (ro) */
  ASSH_EV_CONST struct assh_cbuffer_s username;

  /** A pointer to the service that the client wants to run. (ro) */
  const struct assh_service_s * ASSH_EV_CONST service;

  /** The host public key transmitted by the client. (ro) */
  struct assh_key_s * ASSH_EV_CONST host_key;

  /** The host name transmitted by the client. (ro) */
  ASSH_EV_CONST struct assh_cbuffer_s hostname;

  /** The host user name transmitted by the client. (ro) */
  ASSH_EV_CONST struct assh_cbuffer_s host_username;

  /** Used to acknowledge that the key is authorized. (rw) */
  assh_bool_t found;
};

/** This event is reported when the server-side user authentication
    service is running and the client has selected the
    keyboard interactive method.

    Most fields are used to build the @ref
    SSH_MSG_USERAUTH_INFO_REQUEST message that will be sent to the
    client. An array of prompt strings must be provided when the @tt
    count field is set to a value greater than 0. The @ref echos field
    is a bitmap which indicates user entered values that should be
    displayed.

    The allocation of the array @b{is not} handled by the
    library. This allows passing a statically allocated array of
    prompts. It can be released after calling the @ref assh_event_done
    function.

    A keyboard responses event should follow, unless the client has
    selected a new method.

    @see ASSH_EVENT_USERAUTH_SERVER_KBINFO
*/
struct assh_event_userauth_server_kbinfo_s
{
  /** The user name transmitted by the client. (ro) */
  ASSH_EV_CONST struct assh_cbuffer_s username;

  /** A pointer to the service that the client wants to run. (ro) */
  const struct assh_service_s * ASSH_EV_CONST service;

  /** The sub-method name transmitted by the client. (ro) */
  ASSH_EV_CONST struct assh_cbuffer_s sub;

  /** Used to store the name transmitted to the client. (rw) */
  struct assh_cbuffer_s name;

  /** Used to store the instructions transmitted to the client. (rw) */
  struct assh_cbuffer_s instruction;

  /** Used to indicate the fields that must be echoed. (rw) */
  uint32_t echos;

  /** Used to indicate the number of fields. (rw) */
  uint_fast8_t count;

  /** Must point to an array of prompt strings. (rw) */
  const struct assh_cbuffer_s *prompts;
};

/** @see assh_event_userauth_server_kbresponse_s */
enum assh_event_userauth_server_kbstatus_e
{
  /** Indicates keyboard authentication failure. */
  ASSH_SERVER_KBSTATUS_FAILURE,
  /** Indicates keyboard authentication success. */
  ASSH_SERVER_KBSTATUS_SUCCESS,
  /** Indicates that more fields queries must be transmitted. */
  ASSH_SERVER_KBSTATUS_CONTINUE,
};

/** This event is reported when the server-side user authentication
    service is running and the client has replied to a previous @ref
    SSH_MSG_USERAUTH_INFO_REQUEST message by sending a @ref
    SSH_MSG_USERAUTH_INFO_RESPONSE message.

    The @ref result field must be updated in order to make the
    authentication succeed or continue with an other info request.

    The allocation of the responses array is handled by the library.

    @see ASSH_EVENT_USERAUTH_SERVER_KBRESPONSE
    @see ASSH_EVENT_USERAUTH_SERVER_KBINFO
*/
struct assh_event_userauth_server_kbresponse_s
{
  /** The number of fields. (ro) */
  ASSH_EV_CONST uint_fast8_t count;

  /** The array of responses transmitted by the client. (ro) */
  ASSH_EV_CONST struct assh_cbuffer_s * responses;

  /** Used to decide what to do next. (rw) */
  enum assh_event_userauth_server_kbstatus_e result;
};

/** This event is reported when an user authentication request is
    successful. The @tt method field indicates which method has been
    used successfully.

    The @tt methods field is initially set to zero but can be updated
    in order to report a partial success to the client and continue
    the authentication process.

    The @tt sign_safety field indicates the lowest safety factor value
    of user key signature seen at this point.
    @see ASSH_EVENT_USERAUTH_SERVER_SUCCESS */
struct assh_event_userauth_server_success_s
{
  /** The user name transmitted by the client. (ro) */
  ASSH_EV_CONST struct assh_cbuffer_s username;

  /** A pointer to the service that will be started. (ro) */
  const struct assh_service_s * ASSH_EV_CONST service;

  /** Indicates the successfull authentication method. (ro) */
  ASSH_EV_CONST enum assh_userauth_methods_e method;

  /** May be updated to continue with multi-factor authentication. (rw) */
  enum assh_userauth_methods_e methods;

  /** The safety factor of authentication signatures. (ro) */
  ASSH_EV_CONST assh_safety_t sign_safety:8;
};

/** @This contains all server side user authentication related event
    structures. */
union assh_event_userauth_server_u
{
  struct assh_event_userauth_server_methods_s methods;
  struct assh_event_userauth_server_none_s none;
  struct assh_event_userauth_server_userkey_s  userkey;
  struct assh_event_userauth_server_password_s password;
  struct assh_event_userauth_server_hostbased_s hostbased;
  struct assh_event_userauth_server_kbinfo_s kbinfo;
  struct assh_event_userauth_server_kbresponse_s kbresponse;
  struct assh_event_userauth_server_success_s success;
};

/** @This implements the standard server side @tt ssh-userauth service. */
extern const struct assh_service_s assh_service_userauth_server;

#endif

