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

   This header file defines events which are returned to the
   application when the client side @tt ssh-userauth service is
   running.

   This standard service described in rfc4252 is implemented as a
   pluggable service module for libassh.
*/

#ifndef ASSH_SRV_USERAUTH_CLIENT_H_
#define ASSH_SRV_USERAUTH_CLIENT_H_

#ifdef ASSH_EVENT_H_
# warning The assh/assh_event.h header should be included after srv_userauth_client.h
#endif

#include "assh.h"

/** This event is returned when the client-side user authentication
    service is running and the service needs to provide a user name
    to the server. 

    @see ASSH_EVENT_USERAUTH_CLIENT_USER
*/
struct assh_userauth_client_user_event_s
{
  struct assh_string_s    username;
};

/** This event is returned when the client-side user authentication
    service is running. The @ref use_password and @ref use_pub_key
    fields indicate the authentication methods that are accepted by
    the server.

    The @ref password and @ref pub_keys fields are initially set to
    @tt NULL and can be modified to enable one or more authentication
    methods among those supported.

    The @ref pub_keys linked list can be populated by calling either
    the @ref assh_key_load, @ref assh_load_key_file or @ref
    assh_load_key_filename functions. Multiple keys can be loaded. The
    assh library will take care of releasing the provided keys.

    This event may be returned multiple times until the authentication
    is successful. The authentication fails if no password or key is
    provided.

    @see ASSH_EVENT_USERAUTH_CLIENT_METHODS
*/
struct assh_userauth_client_methods_event_s
{
  const assh_bool_t       use_password;
  const assh_bool_t       use_pub_key;
  struct assh_string_s    password;
  struct assh_key_s       *pub_keys;
};

/** @This contains all client side user authentication related events */
union assh_userauth_client_event_u
{
  struct assh_userauth_client_user_event_s    user;
  struct assh_userauth_client_methods_event_s methods;
};

/** @This implements the standard client side @tt ssh-userauth service. */
extern const struct assh_service_s assh_service_userauth_client;

#endif

