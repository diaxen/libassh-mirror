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
   @short Implementation of the ssh-connection service (rfc4254)

   This header file defines events and functions which are used
   when the @tt ssh-connection service is running.

   This standard service described in rfc4254 is implemented as a
   pluggable service module for libassh.
*/

#ifndef ASSH_SRV_CONNECTION_H_
#define ASSH_SRV_CONNECTION_H_

#ifdef ASSH_EVENT_H_
# warning The assh/assh_event.h header should be included after srv_connection.h
#endif

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

/** @This specifies standard values for channel open failure reason code. */
enum assh_channel_open_reason_e
{
  SSH_OPEN_SUCCESS                     = 0,
  SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1,
  SSH_OPEN_CONNECT_FAILED              = 2,
  SSH_OPEN_UNKNOWN_CHANNEL_TYPE        = 3,
  SSH_OPEN_RESOURCE_SHORTAGE           = 4,
};

/** This event is returned when the @tt ssh-connection service has
    just started. The channel related and request related functions
    can be used from this point.

    @see ASSH_EVENT_CONNECTION_START
*/
struct assh_connection_event_start_s
{
};

/** This event is returned when the @tt ssh-connection service is
    running and a @ref SSH_MSG_GLOBAL_REQUEST message has been
    received. The request type name and associated specific
    request data are available in the @ref type and @ref rq_data
    fields.

    If the @ref want_reply field is set, the @ref success field can be
    set to 1 before calling the @ref assh_event_done function. In this
    case, the @ref rsp_data field can also be updated in order to
    include specfic data in the response.

    @See ASSH_EVENT_CONNECTION_GLOBAL_REQUEST
*/
struct assh_connection_event_global_request_s
{
  const struct assh_string_s      type;
  const assh_bool_t               want_reply;
  const struct assh_buffer_s      rq_data;
  struct assh_buffer_s            rsp_data;
  assh_bool_t                     success;
};

/** This event is returned for every successful call to the @ref
    assh_global_request function with the @tt want_reply parameter
    set.

    The @ref success field indicates if the request has been
    successfully acknowledged by the remote host. In this case, some
    response specific data may be available in the @ref rsp_data
    field.

    The @ref request field can be used to retrieve the private pointer
    previously attached to the request.

    @see ASSH_EVENT_CONNECTION_GLOBAL_REQUEST_REPLY
*/
struct assh_connection_event_global_request_reply_s
{
  struct assh_request_s           * const request;
  const assh_bool_t               success;
  const struct assh_buffer_s      rsp_data;
};

/** This event is returned when the @tt ssh-connection service is
    running and a @ref SSH_MSG_CHANNEL_OPEN message is received from
    the remote host. The channel type name and associated specific
    data are available in the @ref type and @ref rq_data fields.

    The @ref success field must be set to 1 before calling the @ref
    assh_event_done function if the channel open is confirmed. In this
    case, a new @ref assh_channel_s object will be allocated and the
    @ref pv field of the event will be used to setup the channel
    private pointer. The @ref rsp_data field can also be updated in
    order to include specfic data in the response.

    If the open request is denied, the @ref reason field can be
    updated; the default reason code is @ref
    SSH_OPEN_UNKNOWN_CHANNEL_TYPE.

    @see ASSH_EVENT_CONNECTION_CHANNEL_OPEN
*/
struct assh_connection_event_channel_open_s
{
  const struct assh_string_s      type;      //< input
  const struct assh_buffer_s      rq_data;   //< input
  assh_bool_t                     success;   //< output
  void                            *pv;       //< output
  struct assh_buffer_s            rsp_data;  //< output
  enum assh_channel_open_reason_e reason;    //< output
};

/** This event is returned for every successful call to the @ref
    assh_channel_open function. The @ref success field indicates if
    the channel open has been confirmed by the remote side.

    When the open is confirmed, some response specific data may be
    available in the @ref rsp_data field.

    If the open has failed, the associated @ref assh_channel_s object
    will be released when calling the @ref assh_event_done function.

    @see ASSH_EVENT_CONNECTION_CHANNEL_OPEN_REPLY
*/
struct assh_connection_event_channel_open_reply_s
{
  struct assh_channel_s           * const channel;  //< input
  const assh_bool_t               success;          //< input
  const struct assh_buffer_s      rsp_data;         //< input
};

/** This event is returned when the @tt ssh-connection service is
    running and some incoming channel data are available.

    @see ASSH_EVENT_CONNECTION_CHANNEL_DATA
*/
struct assh_connection_event_channel_data_s
{
  struct assh_channel_s           * const channel; //< input
  const assh_bool_t               extended;        //< input
  const uint32_t                  extended_type;   //< input
  const struct assh_buffer_s      data;            //< input
};

/** This event is returned when the @tt ssh-connection service is
    running and a @ref SSH_MSG_CHANNEL_REQUEST message is received
    from the remote host.  The request type name and associated
    specific request data are available in the @ref type and @ref
    rq_data fields.

    If the @ref want_reply field is set, the @ref success field can be
    set to 1 before calling the @ref assh_event_done function. In this
    case, the @ref rsp_data field can also be updated in order to
    include specfic data in the response.

    @see ASSH_EVENT_CONNECTION_CHANNEL_REQUEST
*/
struct assh_connection_event_channel_request_s
{
  struct assh_channel_s           * const channel; //< input
  const struct assh_string_s      type;        //< input
  const assh_bool_t               want_reply;  //< input
  const struct assh_buffer_s      rq_data;     //< input
  struct assh_buffer_s            rsp_data;    //< output
  assh_bool_t                     success;     //< output
};

/** This event is returned for each successful call to the @ref
    assh_channel_request function with the @tt want_reply parameter
    set. The @ref success field indicates if the channel request was
    successful.

    The @ref request field can be used to retrieve the private pointer
    previously attached to the request.

    @see ASSH_EVENT_CONNECTION_CHANNEL_REQUEST_REPLY
*/
struct assh_connection_event_channel_request_reply_s
{
  struct assh_channel_s           * const channel; //< input
  struct assh_request_s           * const request; //< input
  const assh_bool_t               success;         //< input
};

/** This event is returned when the @tt ssh-connection service is
    running and the remote host has sent the @ref
    SSH_MSG_CHANNEL_EOF message for an open channel.

    If the channel has already been half-closed in the other
    direction when receiving this messages, an @ref
    SSH_MSG_CHANNEL_CLOSE message is sent. 

    @see ASSH_EVENT_CONNECTION_CHANNEL_EOF
*/
struct assh_connection_event_channel_eof_s
{
  struct assh_channel_s           * const channel; //< input
}                                 channel_eof;

/** This event is returned for open channels when the remote
    host has sent the @ref SSH_MSG_CHANNEL_CLOSE message or when a
    disconnection occurs. 

    @see ASSH_EVENT_CONNECTION_CHANNEL_CLOSE
*/
struct assh_connection_event_channel_close_s
{
  struct assh_channel_s           * const channel; //< input
};

/** This function allocates an @ref assh_channel_s and send a @ref
    SSH_MSG_CHANNEL_OPEN message to the remote host. If the function
    returns @ref ASSH_OK, an @ref ASSH_EVENT_CONNECTION_CHANNEL_REPLY
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
    @ref ASSH_EVENT_CONNECTION_CHANNEL_REQUEST_REPLY event will later
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
    @ref assh_connection_event_global_request_reply_s event will later
    indicate if this request was successfully acknowledged by the
    remote side.

    Even if an error occurs, the expected event will be returned
    before the @ref assh_event_get function returns the @ref
    ASSH_ERR_DISCONNECTED error code.

    If the @tt want_reply parameter is set and the @tt request
    parameter is not @tt NULL, a pointer to the enqueued request
    object is returned. This allows to attach a private pointer to the
    request by calling the @ref assh_request_set_pv function.

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

/** @This contains all @tt ssh-connection service related events */
union assh_connection_event_u
{
  struct assh_connection_event_start_s          start;
  struct assh_connection_event_global_request_s global_request;
  struct assh_connection_event_global_request_reply_s global_request_reply;
  struct assh_connection_event_channel_open_s channel_open;
  struct assh_connection_event_channel_open_reply_s channel_open_reply;
  struct assh_connection_event_channel_data_s channel_data;
  struct assh_connection_event_channel_request_s channel_request;
  struct assh_connection_event_channel_request_reply_s channel_request_reply;
  struct assh_connection_event_channel_eof_s channel_eof;
  struct assh_connection_event_channel_close_s channel_close;
};

/** @This is the @tt ssh-connection service module descriptor. */
extern const struct assh_service_s assh_service_connection;

#endif

