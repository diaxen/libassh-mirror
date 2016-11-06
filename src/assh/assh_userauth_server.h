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
   @short Implementation of the server side ssh-userauth service (rfc4252)

   This header file defines events which are reported to the
   application when the server side @tt ssh-userauth service is
   running.

   This standard service described in rfc4252 is implemented as a
   pluggable service module for libassh.
*/

#ifndef ASSH_SRV_USERAUTH_SERVER_H_
#define ASSH_SRV_USERAUTH_SERVER_H_

#ifdef ASSH_EVENT_H_
# warning The assh/assh_event.h header should be included after assh_userauth_server.h
#endif

#include "assh.h"
#include "assh_userauth.h"

/** This event is reported when the server-side user authentication
    service has started and some authentication methods must be
    selected. Some implemented methods are selected by default.

    The default allowed number of authentication retries can be
    changed as well. A banner message will be sent if the @tt banner
    buffer size is changed to a value greater than zero.

    @see ASSH_EVENT_USERAUTH_SERVER_METHODS */
struct assh_event_userauth_server_methods_s
{
  enum assh_userauth_methods_e methods; //< output
  uint_fast8_t                 retries; //< output
  struct assh_buffer_s         banner;  //< output
  struct assh_buffer_s         bnlang;  //< output
};

/** This event is reported when the server-side user authentication
    service is running. The user public key @tt pub_key must be
    searched in the list of authorized keys for the user on this
    server. The @tt found field must be updated accordingly before
    calling the @ref assh_event_done function.
    @see ASSH_EVENT_USERAUTH_SERVER_USERKEY */
struct assh_event_userauth_server_userkey_s
{
  ASSH_EV_CONST struct assh_buffer_s      username;  //< input
  struct assh_key_s * ASSH_EV_CONST       pub_key;   //< input
  assh_bool_t                             found;     //< output
};

/** This event is reported when the server-side user authentication
    service is running. The user name and password pair must be
    checked and the @tt success field must be updated accordingly
    before calling the @ref assh_event_done function.  @see
    ASSH_EVENT_USERAUTH_SERVER_PASSWORD */
struct assh_event_userauth_server_password_s
{
  ASSH_EV_CONST struct assh_buffer_s username;    //< input
  ASSH_EV_CONST struct assh_buffer_s password;    //< input
  assh_bool_t                        success;     //< output
};

/** This event is reported when a user authentication request is
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
  ASSH_EV_CONST enum assh_userauth_methods_e method; //< input
  enum assh_userauth_methods_e       methods;        //< output
  ASSH_EV_CONST assh_safety_t        sign_safety;    //< input
};

/** @This contains all server side user authentication related events */
union assh_event_userauth_server_u
{
  struct assh_event_userauth_server_methods_s methods;
  struct assh_event_userauth_server_userkey_s  userkey;
  struct assh_event_userauth_server_password_s password;
  struct assh_event_userauth_server_success_s success;
};

/** @This implements the standard server side @tt ssh-userauth service. */
extern const struct assh_service_s assh_service_userauth_server;

#endif

