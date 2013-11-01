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
  ASSH_EVENT_INVALID,

  /** This event is returned when there is nothing to do. The fields
      in @ref assh_event_s::read provide a buffer which can be
      filled with ssh stream data, if the requested amount is
      available. When this is the case, the @ref assh_event_done
      function can be called to indicate that the data have been read
      in the buffer. */
  ASSH_EVENT_IDLE,

  /** This event is returned when some ssh stream data are needed. The
      fields in @ref assh_event_s::read provide a buffer which
      must be filled with incoming data. The @ref assh_event_done
      function must be called once the data have been copied in the
      buffer, before requesting the next event. */
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
      assh_event_s::hostkey_lookup::accept field must be updated
      accordingly before calling the @ref assh_event_done function. */
  ASSH_EVENT_HOSTKEY_LOOKUP,

  /** This event is returned when the client-side user authentication
      service is running. The @ref
      assh_event_s::userauth_client::method_pwd, @ref
      assh_event_s::userauth_client::method_pk and @ref
      assh_event_s::userauth_client::method_host fields indicates the
      authentication methods that are accepted by the server.

      The assh_event_s::userauth_client::username field must be
      updated to point to a NUL terminated string before calling the
      @ref assh_event_done function. Other fields are initially set to
      @tt NULL and can be modified to enable one or more
      authentication methods among those supported.

      The assh_event_s::userauth_client::password string must be NUL
      terminated when present. The @ref
      assh_event_s::userauth_client::user_key @ref and
      assh_event_s::userauth_client::host_key fields can be setup by
      calling either the @ref assh_key_load, @ref assh_load_key_file
      or @ref assh_load_key_filename functions. The assh library will
      take care of releasing the provided keys.

      This event may be returned multiple times until the
      authentication is successful. The authentication fails is no
      methods are enabled by providing a value.
  */
  ASSH_EVENT_USERAUTH_CLIENT,

#endif

#ifdef CONFIG_ASSH_SERVER

  /** This event is returned when the server-side user authentication
      service is running. The NUL terminated @ref
      assh_event_s::username string and the @ref assh_event_s::pub_key
      fields indicate which key must be searched among authorized keys
      for this user on this server. The @ref assh_event_s::found field
      must be updated accordingly before calling the @ref
      assh_event_done function. */
  ASSH_EVENT_USERAUTH_SERVER_USERKEY,

  /** This event is returned when the server-side user authentication
      service is running. The NUL terminated @ref
      assh_event_s::username and @ref assh_event_s::password strings
      pair must be checked and the @ref assh_event_s::success field
      must be updated accordingly before calling the @ref
      assh_event_done function. */
  ASSH_EVENT_USERAUTH_SERVER_PASSWORD,

#endif
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

  /** Parameters for the @ref #ASSH_EVENT_IDLE and @ref ASSH_EVENT_READ events */
  struct {
    void *data;
    size_t size;
  }                    read;

  /** Parameters for the @ref #ASSH_EVENT_WRITE event */
  struct {
    const void *data;
    size_t size;
  }                    write;

  /** Parameters for the @ref #ASSH_EVENT_RANDOM event */
  struct {
    const void *data;
    size_t size;
  }                    random;

#ifdef CONFIG_ASSH_CLIENT
  /** Parameters for the @ref #ASSH_EVENT_HOSTKEY_LOOKUP event */
  struct {
    struct assh_key_s *key;
    assh_bool_t        accept;
  }                    hostkey_lookup;

  /** Parameters for the @ref #ASSH_EVENT_USERAUTH_CLIENT event */
  struct {
    const char         *username;
    const char         *password;
    struct assh_key_s  *user_key;
    struct assh_key_s  *host_key;
    assh_bool_t        method_pwd:1;
    assh_bool_t        method_pk:1;
    assh_bool_t        method_host:1;
  }                    userauth_client;
#endif

#ifdef CONFIG_ASSH_SERVER
  /** Parameters for the @ref #ASSH_EVENT_USERAUTH_SERVER_USERKEY event */
  struct {
    const char         *username;
    struct assh_key_s  *pub_key;
    assh_bool_t        found;
  }                    userauth_server_userkey;

  /** Parameters for the @ref #ASSH_EVENT_USERAUTH_SERVER_PASSWORD event */
  struct {
    const char         *username;
    const char         *password;
    assh_bool_t        success;
  }                    userauth_server_password;
#endif
};

/** This function runs the various state machines which implement the
    ssh protocol and returns the next event in queue.

    This function can be called in a loop until the @ref
    ASSH_ERR_DISCONNECTED error code is returned. Other error codes
    can be returned but calling this function again may allows
    flushing more data from the internal queues after some error. */
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

