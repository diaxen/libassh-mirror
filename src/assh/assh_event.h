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

  /** This event is returned when there is nothing to do. The fields
      in @ref assh_event_s::read provide a buffer which can be filled
      with ssh stream data, if the requested amount is available. When
      this is the case, the @ref assh_event_done function can be
      called to indicate that the data have copied to the buffer. */
  ASSH_EVENT_IDLE,

  /** This event is returned when some ssh stream data are needed. The
      fields in @ref assh_event_s::read provide a buffer which
      must be filled with incoming data. The @ref assh_event_done
      function must be called once the data have been copied to the
      buffer. */
  ASSH_EVENT_READ,

  /** This event is returned when some ssh output stream data are
      available. The fields in @ref assh_event_s::write provide
      a buffer which contain the output data. The @ref
      assh_event_done function must be called once the output
      data have been sent, before requesting the next event. */
  ASSH_EVENT_WRITE,

  /** This event is returned when the prng needs some entropy. The
      @ref assh_event_s::random::data field must be updated to point
      to a buffer containing random data before calling the @ref
      assh_event_done function. The @ref assh_event_s::random::size
      field gives the amount of requested data; it can be updated
      too if the amount of available random data is different. */
  ASSH_EVENT_RANDOM,

#ifdef CONFIG_ASSH_CLIENT
  /** This event is returned when a client needs to lookup a server
      host key in the local database. The @ref
      assh_event_s::userauth_client::hostkey_lookup::accept field must
      be updated accordingly before calling the @ref assh_event_done
      function. */
  ASSH_EVENT_HOSTKEY_LOOKUP,

  /** This event is returned when the client-side user authentication
      service is running and the service needs to provide a user name
      to the server. */
  ASSH_EVENT_USERAUTH_CLIENT_USER,

  /** This event is returned when the client-side user authentication
      service is running. The @ref
      assh_event_s::userauth_client::method_password and @ref
      assh_event_s::userauth_client::method_user_key fields indicate
      the authentication methods that are accepted by the server.

      Other fields are initially set to @tt NULL and can be modified
      to enable one or more authentication methods among those
      supported.

      The assh_event_s::userauth_client::password string must be NUL
      terminated when present. The @ref
      assh_event_s::userauth_client::user_key field can be setup by
      calling either the @ref assh_key_load, @ref assh_load_key_file
      or @ref assh_load_key_filename functions. Multiple keys can be
      loaded. The assh library will take care of releasing the
      provided keys.

      This event may be returned multiple times until the
      authentication is successful. The authentication fails if no
      password or key is provided.
  */
  ASSH_EVENT_USERAUTH_CLIENT_METHODS,

#endif

#ifdef CONFIG_ASSH_SERVER

  /** This event is returned when the server-side user authentication
      service is running. The user public key given in @ref
      assh_event_s::userauth_server::userkey must be searched in the
      list of authorized keys for the user on this server. The @tt
      found field must be updated accordingly before calling the @ref
      assh_event_done function. */
  ASSH_EVENT_USERAUTH_SERVER_USERKEY,

  /** This event is returned when the server-side user authentication
      service is running. The user name and password pair in @ref
      assh_event_s::userauth_server::password must be checked and the
      @tt success field must be updated accordingly before calling the
      @ref assh_event_done function. */
  ASSH_EVENT_USERAUTH_SERVER_PASSWORD,

#endif

  /** This event is returned when the @tt ssh-connection service has just
      started. The channel related functions can be used from this point. */
  ASSH_EVENT_CONNECTION_START,

  /** This event is returned when the @tt ssh-connection service is
      running and a @ref SSH_MSG_GLOBAL_REQUEST message has been
      received. The request type name and associated specific data are
      available in @ref assh_event_s::connection::global_request.

      The @tt success field can be set before calling the @ref
      assh_event_done function if the remote host expect a reply. The
      default value of this field is 0. */
  ASSH_EVENT_CONNECTION_GLOBAL_REQUEST,

  /** This event is returned for every successful call to the @ref
      assh_global_request function. The @tt success field indicates if
      the request has been successfully acknowledged by the remote
      host. In this case, response specific data may be available in
      @tt rsp_data.  @see
      assh_event_s::connection::global_request_status. */
  ASSH_EVENT_CONNECTION_GLOBAL_REQUEST_STATUS,

  /** This event is returned when the @tt ssh-connection service is
      running and a @ref SSH_MSG_CHANNEL_OPEN message is received
      from the remote host. The channel type name and associated
      specific data are available in @ref
      assh_event_s::connection::channel_open. The @tt success field
      must be set before calling the @ref assh_event_done function if
      the channel open request is accepted. In this case, a new
      @ref assh_channel_s object will be allocated and the @tt pv
      field of the event will be used to setup the channel private pointer. */
  ASSH_EVENT_CONNECTION_CHANNEL_OPEN,

  /** This event is returned for every successful call to the @ref
      assh_channel_open function. The @ref
      assh_event_s::connection::channel_status::success field indicates
      if the channel has been successfully opened. If the request was
      not successful, the associated @ref assh_channel_s object will
      be released when calling the @ref assh_event_done function. */
  ASSH_EVENT_CONNECTION_CHANNEL_STATUS,

  /** This event is returned when when the @tt ssh-connection service is
      running and some incoming channel data are available. */
  ASSH_EVENT_CONNECTION_CHANNEL_DATA,

  /** This event is returned when the @tt ssh-connection service is
      running and a @ref SSH_MSG_CHANNEL_REQUEST message is received
      from the remote host. The request type name and associated
      specific data are available in @ref
      assh_event_s::connection::channel_request. The @tt success field
      can be set before calling the @ref assh_event_done function if
      the remote host expect a reply. The default value of this field is 0. */
  ASSH_EVENT_CONNECTION_CHANNEL_REQUEST,

  /** This event is returned for each successful call to the @ref
      assh_channel_request function. The @tt success field
      indicates if the channel request was successful. */
  ASSH_EVENT_CONNECTION_CHANNEL_REQUEST_STATUS,

  /** This event is returned when the @tt ssh-connection service is
      running and the remote host has sent the @ref
      SSH_MSG_CHANNEL_EOF message for an open channel.

      If the channel has already been half-closed in the other
      direction when receiving this messages, an @ref
      SSH_MSG_CHANNEL_CLOSE message is sent. */
  ASSH_EVENT_CONNECTION_CHANNEL_EOF,

  /** This event is returned for open channels when the remote
      host has sent the @ref SSH_MSG_CHANNEL_CLOSE message or when a
      disconnection occurs. */
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

  /** Parameters for the @ref ASSH_EVENT_IDLE and @ref ASSH_EVENT_READ events */
  struct {
    const struct assh_buffer_s buf;
  }                            read;

  /** Parameters for the @ref ASSH_EVENT_WRITE event */
  struct {
    const struct assh_buffer_s buf;
  }                            write;

  /** Parameters for the @ref ASSH_EVENT_RANDOM event */
  struct {
    struct assh_buffer_s     buf;
  }                          random;

#ifdef CONFIG_ASSH_CLIENT
  /** Parameters for the @ref ASSH_EVENT_HOSTKEY_LOOKUP event */
  struct {
    const struct assh_key_s * const key;
    assh_bool_t               accept;
  }                           hostkey_lookup;

  union {
    /** @see ASSH_EVENT_USERAUTH_CLIENT_USER */
    struct {
      struct assh_string_s    username;
    }                         user;

    /** @see ASSH_EVENT_USERAUTH_CLIENT_METHODS */
    struct userauth_client_s {
      const assh_bool_t       use_password;
      const assh_bool_t       use_pub_key;
      struct assh_string_s    password;
      struct assh_key_s       *pub_keys;
    }                         methods;

  }                           userauth_client;
#endif

#ifdef CONFIG_ASSH_SERVER

  union {
    /** @see ASSH_EVENT_USERAUTH_SERVER_USERKEY */
    struct {
      const struct assh_string_s username;
      const struct assh_key_s  * const pub_key;
      assh_bool_t        found;
    }                    userkey;

    /** @see ASSH_EVENT_USERAUTH_SERVER_PASSWORD */
    struct {
      const struct assh_string_s username;
      const struct assh_string_s password;
      assh_bool_t        success;
    }                    password;

  }                      userauth_server;
#endif

  union {

    /** @see ASSH_EVENT_CONNECTION_GLOBAL_REQUEST */
    struct {
      const struct assh_string_s     type;
      const assh_bool_t              want_reply;
      const struct assh_buffer_s     rq_data;
      struct assh_buffer_s           rsp_data;
      assh_bool_t                    success;
    }                                global_request;

    /** @see ASSH_EVENT_CONNECTION_GLOBAL_REQUEST_STATUS */
    struct {
      struct assh_request_s          *request;
      const assh_bool_t              success;
      const struct assh_buffer_s     rsp_data;
    }                                global_request_status;

    /** @see ASSH_EVENT_CONNECTION_CHANNEL_OPEN */
    struct {
      const struct assh_string_s     type;
      const struct assh_buffer_s     data;
      assh_bool_t                    success;
      void                           *pv;
    }                                channel_open;

    /** @see ASSH_EVENT_CONNECTION_CHANNEL_STATUS */
    struct {
      struct assh_channel_s          *channel;
      const assh_bool_t              success;
      const struct assh_buffer_s     data;
    }                                channel_status;

    /** @see ASSH_EVENT_CONNECTION_CHANNEL_DATA */
    struct {
      struct assh_channel_s          *channel;
      const assh_bool_t              extended;
      const uint32_t                 extended_type;
      const struct assh_buffer_s     data;
    }                                channel_data;

    /** @see ASSH_EVENT_CONNECTION_CHANNEL_REQUEST */
    struct {
      struct assh_channel_s          *channel;
      const struct assh_string_s     type;
      const assh_bool_t              want_reply;
      const struct assh_buffer_s     rq_data;
      struct assh_buffer_s           rsp_data;
      assh_bool_t                    success;
    }                                channel_request;

    /** @see ASSH_EVENT_CONNECTION_CHANNEL_REQUEST_STATUS */
    struct {
      struct assh_request_s          *request;
      struct assh_channel_s          *channel;
      const assh_bool_t              success;
    }                                channel_request_status;

    /** @see ASSH_EVENT_CONNECTION_CHANNEL_EOF */
    struct {
      struct assh_channel_s          *channel;
    }                                channel_eof;

    /** @see ASSH_EVENT_CONNECTION_CHANNEL_CLOSE */
    struct {
      struct assh_channel_s          *channel;
      const uint32_t                 reason;
    }                                channel_close;

  }                                  connection;

};

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

/** @internal This function must be called to indicate that a @ref
    ASSH_EVENT_RANDOM event has been processed. */
ASSH_EVENT_DONE_FCN(assh_event_random_done);

#endif

