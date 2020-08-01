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
   @short Common declarations for the ssh-userauth service (rfc4252)

   This header file contains declarations common the the client and
   server @hl{user authentication} services.

   @see{@assh/assh_userauth_client.h}
   @see{@assh/assh_userauth_server.h}
*/

#ifndef ASSH_SRV_USERAUTH_H_
#define ASSH_SRV_USERAUTH_H_

#include "assh_session.h"

/** @This specifies user authentication methods as flag values that
    can be ored together. @xsee{uamethods} */
enum assh_userauth_methods_e
{
  ASSH_USERAUTH_METHOD_NONE       = 0x01,
  /** @hl {Public key user authentication} */
  ASSH_USERAUTH_METHOD_PUBKEY     = 0x02,
  /** Password user authentication */
  ASSH_USERAUTH_METHOD_PASSWORD   = 0x04,
  /** @hl {Host based user authentication} */
  ASSH_USERAUTH_METHOD_HOSTBASED  = 0x08,
  /** @hl {Keyboard interactive user authentication} */
  ASSH_USERAUTH_METHOD_KEYBOARD   = 0x10,

  /** mask of all server methods with support enabled in build
      configuration @xsee {bldconfig} */
  ASSH_USERAUTH_METHOD_SERVER_IMPLEMENTED = 0
#ifdef CONFIG_ASSH_SERVER_AUTH_NONE
    | ASSH_USERAUTH_METHOD_NONE
#endif
#ifdef CONFIG_ASSH_SERVER_AUTH_PUBLICKEY
    | ASSH_USERAUTH_METHOD_PUBKEY
#endif
#ifdef CONFIG_ASSH_SERVER_AUTH_PASSWORD
    | ASSH_USERAUTH_METHOD_PASSWORD
#endif
#ifdef CONFIG_ASSH_SERVER_AUTH_HOSTBASED
    | ASSH_USERAUTH_METHOD_HOSTBASED
#endif
#ifdef CONFIG_ASSH_SERVER_AUTH_KEYBOARD
    | ASSH_USERAUTH_METHOD_KEYBOARD
#endif
  ,

  /** mask of all client methods with support enabled in build
      configuration @xsee {bldconfig} */
  ASSH_USERAUTH_METHOD_CLIENT_IMPLEMENTED =
      ASSH_USERAUTH_METHOD_NONE
#ifdef CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY
    | ASSH_USERAUTH_METHOD_PUBKEY
#endif
#ifdef CONFIG_ASSH_CLIENT_AUTH_PASSWORD
    | ASSH_USERAUTH_METHOD_PASSWORD
#endif
#ifdef CONFIG_ASSH_CLIENT_AUTH_HOSTBASED
    | ASSH_USERAUTH_METHOD_HOSTBASED
#endif
#ifdef CONFIG_ASSH_CLIENT_AUTH_KEYBOARD
    | ASSH_USERAUTH_METHOD_KEYBOARD
#endif
};

#endif
