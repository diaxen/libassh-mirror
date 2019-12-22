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

  As a special exception, for the purpose of developing applications
  using libassh, the content of helper_server.h and helper_server.c
  files may be freely reused without causing the resulting work to be
  covered by the GNU Lesser General Public License.

*/

/**
   @file
   @short SSH server application helpers

   This header file provides @hl helper functions designed to ease
   development of simple @em ssh2 server applications.

   Implementation of server applications may want to reuse and adapt
   code from this module, as allowed by the @hl license exception
   covering the source code of this module.
*/

#ifndef ASSH_HELPER_SERVER_H_
#define ASSH_HELPER_SERVER_H_

#include "assh.h"

/** @This loads some host keys from standard locations.  The function
    is successful when at least one key has been loaded. */
assh_status_t
asshh_server_load_hk(struct assh_context_s *c);

/** @This looks for a specific key in a pool of authorized user keys. */
assh_status_t
asshh_server_ak_lookup(struct assh_session_s *s,
			      const char *filename,
			      const struct assh_key_s *key);

/** @This handles the @ref ASSH_EVENT_USERAUTH_SERVER_USERKEY and @ref
    ASSH_EVENT_USERAUTH_SERVER_PASSWORD events.

    The public key authentication is handled by calling the @ref
    asshh_server_ak_lookup function on the user @tt
    authorized_keys file.

    The password authentication relies on the following libc
    functions: @tt getpwnam_r, @tt getspnam_r and @tt crypt_r.
    It requires access to the @tt /etc/shadow file.

    @This takes care of calling the @ref assh_event_done function in
    any case.
*/
assh_status_t
asshh_server_event_auth(struct assh_session_s *s,
			       struct assh_event_s *event);

/** This retrieves the user id and group id from a @ref
    ASSH_EVENT_USERAUTH_SERVER_SUCCESS event.

    @This takes care of calling the @ref assh_event_done function in
    any case.
*/
assh_status_t
asshh_server_event_user_id(struct assh_session_s *s,
			  uid_t *uid, gid_t *gid,
			  struct assh_event_s *event);

#endif
