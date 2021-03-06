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
   @short Event reporting structure and related functions

   The API of the library is event based, as explained in the @xref
   {evts} section.

   This header contains declaration of the @ref assh_event_s
   structure as well as event management functions.
*/

#ifndef ASSH_EVENT_H_
#define ASSH_EVENT_H_

#include "assh.h"

/** @This specifies event types. */
enum assh_event_id_e
{
  /** @internal This event id is not valid and can be used to mark
      non-initialized event objects. */
  ASSH_EVENT_INVALID                     = 0,

  /** @see assh_event_transport_read_s */
  ASSH_EVENT_READ                        = 1,
  /** @see assh_event_transport_write_s */
  ASSH_EVENT_WRITE                       = 2,
  /** @see assh_event_transport_disconnect_s */
  ASSH_EVENT_DISCONNECT                  = 3,
  /** @see assh_event_transport_debug_s */
  ASSH_EVENT_DEBUG                       = 4,

  /** @see assh_event_session_error_s */
  ASSH_EVENT_SESSION_ERROR               = 5,

  /** @see assh_event_kex_hostkey_lookup_s */
  ASSH_EVENT_KEX_HOSTKEY_LOOKUP          = 6,
  /** @see assh_event_kex_done_s */
  ASSH_EVENT_KEX_DONE                    = 7,

  /** @see assh_event_service_start_s */
  ASSH_EVENT_SERVICE_START               = 9,

  /** @see assh_event_userauth_client_user_s */
  ASSH_EVENT_USERAUTH_CLIENT_USER        = 10,
  /** @see assh_event_userauth_client_methods_s */
  ASSH_EVENT_USERAUTH_CLIENT_METHODS     = 11,
  /** @see assh_event_userauth_client_banner_s */
  ASSH_EVENT_USERAUTH_CLIENT_BANNER      = 12,
  /** @see assh_event_userauth_client_pwchange_s */
  ASSH_EVENT_USERAUTH_CLIENT_PWCHANGE    = 13,
  /** @see assh_event_userauth_client_keyboard_s */
  ASSH_EVENT_USERAUTH_CLIENT_KEYBOARD    = 14,
  ASSH_EVENT_USERAUTH_CLIENT_SUCCESS     = 15,
  /** @see assh_event_userauth_client_sign_s */
  ASSH_EVENT_USERAUTH_CLIENT_SIGN        = 16,

  /** @see assh_event_userauth_server_methods_s */
  ASSH_EVENT_USERAUTH_SERVER_METHODS     = 20,
  /** @see assh_event_userauth_server_none_s */
  ASSH_EVENT_USERAUTH_SERVER_NONE        = 21,
  /** @see assh_event_userauth_server_userkey_s */
  ASSH_EVENT_USERAUTH_SERVER_USERKEY     = 22,
  /** @see assh_event_userauth_server_password_s */
  ASSH_EVENT_USERAUTH_SERVER_PASSWORD    = 23,
  /** @see assh_event_userauth_server_kbinfo_s */
  ASSH_EVENT_USERAUTH_SERVER_KBINFO      = 24,
  /** @see assh_event_userauth_server_kbresponse_s */
  ASSH_EVENT_USERAUTH_SERVER_KBRESPONSE  = 25,
  /** @see assh_event_userauth_server_hostbased_s */
  ASSH_EVENT_USERAUTH_SERVER_HOSTBASED   = 26,
  /** @see assh_event_userauth_server_success_s */
  ASSH_EVENT_USERAUTH_SERVER_SUCCESS     = 27,

  /** @see assh_event_request_s */
  ASSH_EVENT_REQUEST                     = 30,
  /** @see assh_event_request_abort_s */
  ASSH_EVENT_REQUEST_ABORT               = 31,
  /** @see assh_event_request_success_s */
  ASSH_EVENT_REQUEST_SUCCESS             = 32,
  /** @see assh_event_request_failure_s */
  ASSH_EVENT_REQUEST_FAILURE             = 33,
  /** @see assh_event_channel_open_s */
  ASSH_EVENT_CHANNEL_OPEN                = 34,
  /** @see assh_event_channel_confirmation_s */
  ASSH_EVENT_CHANNEL_CONFIRMATION        = 35,
  /** @see assh_event_channel_failure_s */
  ASSH_EVENT_CHANNEL_FAILURE             = 36,
  /** @see assh_event_channel_data_s */
  ASSH_EVENT_CHANNEL_DATA                = 37,
  /** @see assh_event_channel_window_s */
  ASSH_EVENT_CHANNEL_WINDOW              = 38,
  /** @see assh_event_channel_eof_s */
  ASSH_EVENT_CHANNEL_EOF                 = 39,
  /** @see assh_event_channel_close_s */
  ASSH_EVENT_CHANNEL_CLOSE               = 40,
  /** @see assh_event_channel_abort_s */
  ASSH_EVENT_CHANNEL_ABORT               = 41,

  /** @internal */
  ASSH_EVENT_COUNT,
};

/** @internal @see assh_event_done_t */
#define ASSH_EVENT_DONE_FCN(n)                                          \
  ASSH_WARN_UNUSED_RESULT assh_status_t (n)(struct assh_session_s *s,    \
                                           const struct assh_event_s *e, \
                                           enum assh_status_e inerr)

/** @internal @This is called when the event has been processed.
    @see assh_event_done */
typedef ASSH_EVENT_DONE_FCN(assh_event_done_t);

union assh_event_transport_u;
union assh_event_kex_u;
union assh_event_userauth_client_u;
union assh_event_userauth_server_u;
union assh_event_connection_u;

/** @This holds an event reported by the @ref assh_event_get function. */
struct assh_event_s
{
  /** Id of the event. */
  enum assh_event_id_e id;

  /** @internal Pointer to the event acknowledge function, if any. */
  ASSH_PV assh_event_done_t *f_done;

  /** @internal Private data for the event acknowledge function. */
  ASSH_PV void *done_pv;

  union {

#ifdef ASSH_SESSION_H_
    union assh_event_session_u session;
#endif

#ifdef ASSH_TRANSPORT_H_
    union assh_event_transport_u transport;
#endif

#ifdef ASSH_KEX_H_
    union assh_event_kex_u kex;
#endif

#ifdef ASSH_SERVICE_H_
    union assh_event_service_u service;
#endif

#ifdef CONFIG_ASSH_CLIENT
# ifdef ASSH_SRV_USERAUTH_CLIENT_H_
    union assh_event_userauth_client_u userauth_client;
# endif
#endif

#ifdef CONFIG_ASSH_SERVER
# ifdef ASSH_SRV_USERAUTH_SERVER_H_
    union assh_event_userauth_server_u userauth_server;
# endif
#endif

#ifdef ASSH_SRV_CONNECTION_H_
    union assh_event_connection_u connection;
#endif

#ifdef ASSH_USER_EVENTS_UNION
    ASSH_USER_EVENTS_UNION;
#endif

    /** @internal Padding */
    uintptr_t params[16];
  };

};

/** @hidden check sizeof event union */
#define ASSH_EVENT_SIZE_SASSERT(name)					\
  typedef char assh_event_##name##_larger_than_padding			\
     [(sizeof(union assh_event_##name##_u)				\
       <= sizeof(((struct assh_event_s*)0)->params)) - 1];

/** @This runs the various state machines which implement the
    @em ssh2 protocol, including the currently running @hl service
    and @hl{key-exchange}. It then reports the next available
    @hl event to the caller.

    The @ref assh_event_done function must be called after each
    successful call to this function, before requesting the next event.

    @This can be called again unless @tt 0 is returned
    eventually. This occurs when the session terminates.

    When the function returns @tt 1, the passed object event is
    initialized and can be examined by the application.

    In order for the library to handle protocol timeouts properly, the
    current time in seconds has to be passed to this function. When
    this is the case, the @ref assh_session_deadline function can be
    used to get the next @em ssh2 protocol deadline.

    @xsee{fsms} @xsee{evts} @see assh_session_closed
*/
ASSH_WARN_UNUSED_RESULT assh_bool_t
assh_event_get(struct assh_session_s *s,
               struct assh_event_s *e,
               assh_time_t time);

/** @This acknowledges the last @hl event returned by the @ref
    assh_event_get function.

    If an error occurred during event processing by the caller, it
    should be reported to this function, especially if the error must
    terminate the session.

    When an error is reported, the content of the event object is
    considered undefined by the library. The error will later be
    reported by an @ref ASSH_EVENT_SESSION_ERROR event unless shadowed by an
    other error of higher severity.

    @xsee{fsms} @xsee{evts}
*/
void
assh_event_done(struct assh_session_s *s,
                struct assh_event_s *e,
                enum assh_status_e err);

#endif

