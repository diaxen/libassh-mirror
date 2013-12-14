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


#ifndef ASSH_EVENT_H_
#define ASSH_EVENT_H_

#include "assh.h"

enum assh_event_id_e
{
  /** @internal This event id is not valid and can be used to mark
      non-initialized event objects. */
  ASSH_EVENT_INVALID,

  /** @see assh_transport_event_read_s */
  ASSH_EVENT_READ,
  /** @see assh_transport_event_write_s */
  ASSH_EVENT_WRITE,

  /** This event is returned when the prng needs some entropy. The
      @ref assh_event_s::random::data field must be updated to point
      to a buffer containing random data before calling the @ref
      assh_event_done function. The @ref assh_event_s::random::size
      field gives the amount of requested data; it can be updated
      too if the amount of available random data is different. */
  ASSH_EVENT_RANDOM,

  /** This event is returned when a client needs to lookup a server
      host key in the local database. The @ref
      assh_event_s::userauth_client::hostkey_lookup::accept field must
      be updated accordingly before calling the @ref assh_event_done
      function. */
  ASSH_EVENT_HOSTKEY_LOOKUP,

  /** @see assh_userauth_client_user_event_s */
  ASSH_EVENT_USERAUTH_CLIENT_USER,
  /** @see assh_userauth_client_methods_event_s */
  ASSH_EVENT_USERAUTH_CLIENT_METHODS,

  /** @see assh_userauth_server_userkey_event_s */
  ASSH_EVENT_USERAUTH_SERVER_USERKEY,
  /** @see assh_userauth_server_password_event_s */
  ASSH_EVENT_USERAUTH_SERVER_PASSWORD,

  /** @see assh_connection_event_start_s */
  ASSH_EVENT_CONNECTION_START,
  /** @see assh_connection_event_global_request_s */
  ASSH_EVENT_CONNECTION_GLOBAL_REQUEST,
  /** @see assh_connection_event_global_request_reply_s */
  ASSH_EVENT_CONNECTION_GLOBAL_REQUEST_REPLY,
  /** @see assh_connection_event_channel_open_s */
  ASSH_EVENT_CONNECTION_CHANNEL_OPEN,
  /** @see assh_connection_event_channel_open_reply_s */
  ASSH_EVENT_CONNECTION_CHANNEL_OPEN_REPLY,
  /** @see assh_connection_event_channel_data_s */
  ASSH_EVENT_CONNECTION_CHANNEL_DATA,
  /** @see assh_connection_event_channel_request_s */
  ASSH_EVENT_CONNECTION_CHANNEL_REQUEST,
  /** @see assh_connection_event_channel_request_reply_s */
  ASSH_EVENT_CONNECTION_CHANNEL_REQUEST_REPLY,
  /** @see assh_connection_event_channel_eof_s */
  ASSH_EVENT_CONNECTION_CHANNEL_EOF,
  /** @see assh_connection_event_channel_close_s */
  ASSH_EVENT_CONNECTION_CHANNEL_CLOSE,

  /** @internal */
  ASSH_EVENT_COUNT,
};

#define ASSH_EVENT_DONE_FCN(n) \
  ASSH_WARN_UNUSED_RESULT assh_error_t (n)(struct assh_session_s *s,    \
                                           struct assh_event_s *e)
typedef ASSH_EVENT_DONE_FCN(assh_event_done_t);

struct assh_event_s
{
  /** Event id */
  enum assh_event_id_e id;

  /** Pointer to the event acknowledge function, if any. */
  assh_event_done_t *f_done;
  /** Private data for the event acknowledge function. */
  void *done_pv;

  union {

#ifdef ASSH_TRANSPORT_H_
    union assh_transport_event_u transport;
#endif

    /** Parameters for the @ref ASSH_EVENT_RANDOM event */
    struct {
      struct assh_buffer_s       buf;
    }                            random;

#ifdef CONFIG_ASSH_CLIENT
    /** Parameters for the @ref ASSH_EVENT_HOSTKEY_LOOKUP event */
    struct {
      const struct assh_key_s * const key;
      assh_bool_t               accept;
    }                           hostkey_lookup;

# ifdef ASSH_SRV_USERAUTH_CLIENT_H_
    union assh_userauth_client_event_u userauth_client;
# endif
#endif

#ifdef CONFIG_ASSH_SERVER
# ifdef ASSH_SRV_USERAUTH_SERVER_H_
    union assh_userauth_server_event_u userauth_server;
# endif
#endif

#ifdef ASSH_SRV_CONNECTION_H_
    union assh_connection_event_u connection;
#endif

#ifdef ASSH_USER_EVENTS_UNION
    ASSH_USER_EVENTS_UNION;
#endif

    /** @internal Padding */
    long params[10];
  };

};

/** @hidden check sizeof event union */
#define ASSH_EVENT_SIZE_SASSERT(name)					\
  typedef char assh_##name##_event_larger_than_padding			\
     [(sizeof(union assh_##name##_event_u)				\
       <= sizeof(((struct assh_event_s*)0)->params)) - 1];

/** This function runs the various state machines which implement the
    ssh protocol and returns the next event in queue.

    This function can be called in a loop until the @ref
    ASSH_ERR_DISCONNECTED error code is returned. Other error codes
    can be returned but calling this function again may still return
    more pending events. The @ref ASSH_ERR_DISCONNECTED error is only
    returned when no more events are pending.

    If the connection is running properly but no events are pending,
    the @ref ASSH_EVENT_IDLE event is returned which allows feeding
    input ssh stream data.
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_event_get(struct assh_session_s *s,
               struct assh_event_s *e);

/** This function acknowledge the last event returned by the @ref
    assh_event_get function. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_event_done(struct assh_session_s *s,
                struct assh_event_s *e);

#endif

