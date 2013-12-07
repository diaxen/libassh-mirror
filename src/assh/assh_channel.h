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


#ifndef ASSH_CHANNEL_H_
#define ASSH_CHANNEL_H_

#include "assh.h"
#include "assh_map.h"

/** @internal */
enum assh_channel_status_e
{
  ASSH_CHANNEL_REQUESTED,
  ASSH_CHANNEL_OPEN,
  ASSH_CHANNEL_EOF_SENT,
  ASSH_CHANNEL_EOF_RECEIVED,
  ASSH_CHANNEL_CLOSE_SENT,
  ASSH_CHANNEL_CLOSED,
};

/** @internal */
struct assh_channel_s
{
  union {
    /** channel queue entry, valid when the channel is waiting for open confirmation. */
    struct assh_queue_entry_s qentry;
    /** channel map entry, valid when the channel is open. */
    struct assh_map_entry_s mentry;
  };

  uint32_t remote_id;
  enum assh_channel_status_e status;
  struct assh_session_s *session;
  void *pv;

  size_t max_pkt_size;
  uint32_t window_size;
};

/** @internal */
struct assh_request_s
{
  struct assh_queue_entry_s entry;
  void *pv;
};

/** This function allocates an @ref assh_channel_s and send a @ref
    SSH_MSG_CHANNEL_OPEN message to the remote host. If the function
    returns @ref ASSH_OK, an @ref ASSH_EVENT_CONNECTION_CHANNEL_STATUS
    event will later indicate if the remote host has accepted the
    channel open request.

    Every successfully opened channel will generate an @ref
    ASSH_EVENT_CONNECTION_CHANNEL_CLOSE event either when the remote
    host close the channel or when a disconnection occurs.

    In any case, is this function call returns @ref ASSH_OK, one of
    this event will be returned before the @ref assh_event_get
    function returns the @ref ASSH_ERR_DISCONNECTED error code.

    This function will fail if the @tt ssh-connection service is
    not started.
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_channel_open(struct assh_session_s *s, const char *type, size_t type_len,
                  size_t max_pkt_size, struct assh_channel_s **channel);

/** This function transfers data to the remote host through a opened
    channel. Incoming channel data from the remote host are passed
    using the @ref ASSH_EVENT_CONNECTION_CHANNEL_DATA event.

    A @ref SSH_MSG_CHANNEL_EXTENDED_DATA message is used instead of a
    @ref SSH_MSG_CHANNEL_DATA message if the @tt extended parameter is
    set. In this case, the @tt extended_type parameter is relevant.

    This function will fail if the @tt ssh-connection service is
    not started.
 */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_channel_data(struct assh_channel_s *channel,
                  assh_bool_t extended, uint32_t extended_type,
                  const uint8_t *data, size_t size);

/** This function sends a @ref SSH_MSG_CHANNEL_EOF message and mark
    the channel as half-closed. The @ref assh_channel_data function
    can not be called successfully on the same channel once this
    function has been called.

    If the channel is already half-closed in the other direction, this
    function acts as the @ref assh_channel_close function instead.

    This function will fail if the @tt ssh-connection service is
    not started.
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_channel_eof(struct assh_channel_s *channel);

/** This function sends a @ref SSH_MSG_CHANNEL_CLOSE message to the
    remote host. Some data may still be available from the channel in
    the internal buffers, that's why the @ref
    ASSH_EVENT_CONNECTION_CHANNEL_DATA event and other channel related
    events can still be returned by the @ref assh_get_event function
    for this channel after the call. The channel is released when the
    @ref ASSH_EVENT_CONNECTION_CHANNEL_CLOSE event is returned.

    This function will fail if the @tt ssh-connection service is
    not started.
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_channel_close(struct assh_channel_s *channel);

/** This function sends a @ref SSH_MSG_CHANNEL_REQUEST message to the
    remote host.

    If the @tt want_reply parameter is set and the function returns
    @ref ASSH_OK, a new @ref assh_request_s object is allocated and an
    @ref ASSH_EVENT_CONNECTION_CHANNEL_REQUEST_STATUS event will later
    indicate if this request was successfully acknowledged by the
    remote side.

    Even if an error occurs, the expected event will be returned
    before the @ref assh_event_get function returns the @ref
    ASSH_ERR_DISCONNECTED error code.

    This function will fail if the @tt ssh-connection service is
    not started.
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_channel_request(struct assh_channel_s *channel,
                     const char *type, size_t type_len,
                     const uint8_t *data, size_t data_len,
                     assh_bool_t want_reply,
                     struct assh_request_s **request);

/** This function sends a @ref SSH_MSG_GLOBAL_REQUEST message to the
    remote host. 

    If the @tt want_reply parameter is set and the function returns
    @ref ASSH_OK, a new @ref assh_request_s object is allocated and an
    @ref ASSH_EVENT_CONNECTION_CHANNEL_REQUEST_STATUS event will later
    indicate if this request was successfully acknowledged by the
    remote side.

    Even if an error occurs, the expected event will be returned
    before the @ref assh_event_get function returns the @ref
    ASSH_ERR_DISCONNECTED error code.

    This function will fail if the @tt ssh-connection service is
    not started.
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_global_request(struct assh_session_s *s,
                    const char *type, size_t type_len,
                    const uint8_t *data, size_t data_len,
                    assh_bool_t want_reply,
                    struct assh_request_s **request);

/** This function sets the value of the channel private pointer. */
static inline void assh_channel_set_pv(struct assh_channel_s *channel, void *pv)
{
  channel->pv = pv;
}

/** This function returns the value of the channel private pointer. */
static inline void *assh_channel_get_pv(const struct assh_channel_s *channel)
{
  return channel->pv;
}

/** This function sets the value of the request private pointer. */
static inline void assh_request_set_pv(struct assh_request_s *request, void *pv)
{
  request->pv = pv;
}

/** This function returns the value of the request private pointer. */
static inline void *assh_request_get_pv(const struct assh_request_s *request)
{
  return request->pv;
}

#endif

