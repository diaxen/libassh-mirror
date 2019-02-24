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

  As a special exception, for the purpose of developing applications
  using libassh, the content of helper_client.h and helper_client.c
  files may be freely reused without causing the resulting work to be
  covered by the GNU Lesser General Public License.

*/

/**
   @file
   @short SSH client application helpers

   This header file provides @xref{helper} functions designed to ease
   development of simple @em ssh2 client applications.

   Implementation of client applications may want to reuse and adapt
   code from this module, as allowed by the @xref{license} exception
   covering the source code of this module.
*/

#ifndef ASSH_HELPER_CLIENT_H_
#define ASSH_HELPER_CLIENT_H_

#include "assh_key.h"

#include <stdio.h>

#ifdef CONFIG_ASSH_CLIENT

/** @This loads all public keys associated to a given host name and
    recognized by one of the registered algorithms. The input file
    must be in openssh ssh_knwon_host file format.

    The keys are loaded by the @ref assh_load_key_file function and
    must be released by calling @ref assh_key_flush.

    A comment string containing the location (file name and line
    number) is attached to each loaded key.
*/
assh_error_t
assh_client_get_known_hosts(struct assh_context_s *c,
                                    struct assh_key_s **keys,
                                    const char *filename,
                                    const char *host);

/** @This adds a public key at the end of the ssh_knwon_host file. */
assh_error_t
assh_client_add_known_hosts(struct assh_context_s *c,
                                    const char *filename,
                                    const char *host,
                                    const struct assh_key_s *key);

/** @This handles the ASSH_EVENT_KEX_HOSTKEY_LOOKUP event by reading
    some known host files in openssh format. A @tt NULL terminated
    list of file names is expected.

    The user is queried the usual way about key verification and
    fingerprints. If the standard input is not a tty and user
    interaction is required, the host key is not accepted.

    @This takes care of calling the @ref assh_event_done function in
    any case.
*/
void
assh_client_event_hk_lookup_va(struct assh_session_s *s, FILE *out, FILE *in,
                                       const char *host,
                                       struct assh_event_s *event, ...);

/** @This calls the @ref assh_client_event_hk_lookup_va
    function with system and user known hosts files.

    @This takes care of calling the @ref assh_event_done function in
    any case.
*/
void
assh_client_event_hk_lookup(struct assh_session_s *s, FILE *out, FILE *in,
                                    const char *host,
                                    struct assh_event_s *event);

/** This handles the @ref ASSH_EVENT_KEX_DONE event by adding the host
    key to the openssh known hosts file if needed. This works along
    with the @ref assh_client_event_hk_lookup function.

    @This takes care of calling the @ref assh_event_done function in
    any case.
*/
void
assh_client_event_hk_add(struct assh_session_s *s,
                                 const char *host,
                                 struct assh_event_s *event);

/** @This is used to specify the list of user key files for the @ref
    assh_client_event_auth function.
    @see assh_client_user_key_default */
struct assh_client_user_key_s
{
  /** key filename to lookup in the .ssh user directory */
  const char *filename;
  const struct assh_key_algo_s *algo;
  enum assh_algo_class_e role;
  enum assh_key_format_e format;
};

/** @This contains a default list of user key file for use with
    the @ref assh_client_event_auth function. */
extern const struct assh_client_user_key_s
  assh_client_user_key_default[];

/** @This implements a default user authentication events handler
    which interacts with the user on the UNIX terminal and fetches
    keys in openssh standard locations.

    @This is designed to handle the following events:
    @list
      @item @ref ASSH_EVENT_USERAUTH_CLIENT_BANNER,
      @item @ref ASSH_EVENT_USERAUTH_CLIENT_USER,
      @item @ref ASSH_EVENT_USERAUTH_CLIENT_METHODS,
      @item @ref ASSH_EVENT_USERAUTH_CLIENT_PWCHANGE and
      @item @ref ASSH_EVENT_USERAUTH_CLIENT_KEYBOARD.
    @end list

    The authentication methods initially specified in @tt methods will
    be tried, provided that they are enabled by the server.

    The @tt key_files parameter specifies the list of user key files
    which will be loaded. The user keys are loaded from the
    user @tt .ssh directory. The @ref assh_client_user_key_default
    array can be passed as @tt key_files.

    @This takes care of calling the @ref assh_event_done function in
    any case.
*/
void
assh_client_event_auth(struct assh_session_s *s, FILE *out, FILE *in,
			       const char *user, const char *host,
			       enum assh_userauth_methods_e *methods,
			       const struct assh_client_user_key_s *key_files,
			       struct assh_event_s *event);

/** @This specifies the current state of an interactive session.
    @see assh_client_inter_session_s */
enum assh_client_inter_session_state_e
{
  ASSH_CLIENT_INTER_ST_INIT,
  ASSH_CLIENT_INTER_ST_SESSION,
  ASSH_CLIENT_INTER_ST_PTY,
  ASSH_CLIENT_INTER_ST_EXEC,
  ASSH_CLIENT_INTER_ST_OPEN,
  ASSH_CLIENT_INTER_ST_CLOSING,
  ASSH_CLIENT_INTER_ST_CLOSED,
};

/** @This stores the state of the simple interactive session helper
    between calls to the @ref assh_client_event_inter_session
    function.

    @This must be initialized by calling the @ref
    assh_client_init_inter_session function.
*/
struct assh_client_inter_session_s
{
  enum assh_client_inter_session_state_e state;
  const char *command;
  const char *term;
  struct assh_channel_s *channel;
  struct assh_request_s *request;
};

/** @This initializes an interactive session object for execution of
    the specified command. This must be used along with the @ref
    assh_client_event_inter_session event handler function.

    This is a simple helper designed to start a command on a remote
    server. The associated event handler takes care of sending the
    appropriate requests to the remote host when the @tt
    {ssh-connection} service is started.

    When the @tt command parameter is @tt NULL, execution of a shell
    is requested. When the @tt term parameter is @tt NULL, no pty
    allocation is requested.
*/
void
assh_client_init_inter_session(struct assh_client_inter_session_s *state,
                               const char *command, const char *term);

/** @This implements an events handler which starts an interactive
    session and requests execution of a command on the remote server.

    @This is designed to handle the following events:
    @list
      @item @ref ASSH_EVENT_SERVICE_START
      @item @ref ASSH_EVENT_CHANNEL_OPEN_REPLY
      @item @ref ASSH_EVENT_REQUEST_REPLY
    @end list

    @This takes care of calling the @ref assh_event_done function.
*/
void
assh_client_event_inter_session(struct assh_session_s *s,
                                struct assh_event_s *event,
                                struct assh_client_inter_session_s *state);

#endif

#endif
