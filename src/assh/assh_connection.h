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
   @short SSH connection service (rfc4254 channels and requests)

   This header file defines @hl events and functions which are used
   when the @ref assh_service_connection service is running. This
   @hl service module is an implementation of the @hl{connection
   protocol}.

   Functions declared in this header must not be called when the
   service is not running.

   Functions which support the @hl{interactive session} and
   @hl{port forwarding} features are declared in the @ref
   {@assh/helper_interactive.h} and @ref {@assh/helper_portfwd.h}
   header files.

   @xsee {connmap} @xsee{connapi}
*/

#ifndef ASSH_SRV_CONNECTION_H_
#define ASSH_SRV_CONNECTION_H_

#include <string.h>

#ifdef ASSH_EVENT_H_
# warning The assh/assh_event.h header should be included after assh_connection.h
#endif

#include "assh.h"
#include "assh_map.h"
#include "assh_buffer.h"
#include "assh_queue.h"

/** @visible @This is the @em ssh-connection service @hl request
    object.

    Requests are created either by calling the @ref assh_request
    function or when the @ref ASSH_EVENT_REQUEST event is reported.

    The library user does not have to destroy request objects
    explicitly.

    @xsee{connapi}
*/
struct assh_request_s;

/** @This specifies @ref assh_request_s status. */
enum assh_request_state_e
{
  /** Outgoing request; not replied by remote host. */
  ASSH_REQUEST_ST_WAIT_REPLY,
  /** Incoming request; reply postponed by the library user. */
  ASSH_REQUEST_ST_REPLY_POSTPONED,
  /** Incoming request; blocked by previous requests in the queue. */
  ASSH_REQUEST_ST_REPLY_READY,
};

/** @This specifies @ref assh_channel_s status.
    @xsee{connapi} */
enum assh_channel_state_e
{
  /** An open message has been sent to the remote host */
  ASSH_CHANNEL_ST_OPEN_SENT,
  /** An open reply message has been received, action must be taken in
      order to acknowledge the channel open. */
  ASSH_CHANNEL_ST_OPEN_RECEIVED,
  /** The channel is open. */
  ASSH_CHANNEL_ST_OPEN,
  /** The channel is open half way. */
  ASSH_CHANNEL_ST_EOF_SENT,
  /** The channel is open half way. */
  ASSH_CHANNEL_ST_EOF_RECEIVED,
  /** A pair of channel EOF messages has been exchanged, a channel
      close message was sent. */
  ASSH_CHANNEL_ST_EOF_CLOSE,
  /** The @ref assh_channel_close function has been called and a close
      message was sent but the remote host has not replied yet. */
  ASSH_CHANNEL_ST_CLOSE_CALLED,
  /** A channel close message has been received and a reply was
      sent. Some request/data related events may still be reported
      before the channel object is released. */
  ASSH_CHANNEL_ST_CLOSING,
  /** The connection is ending, an @ref ASSH_EVENT_CHANNEL_CLOSE event
      will be reported for this channel. */
  ASSH_CHANNEL_ST_FORCE_CLOSE,
  /** The connection is ending, an @ref ASSH_EVENT_CHANNEL_FAILURE
      event will be reported for this channel. */
  ASSH_CHANNEL_ST_OPEN_SENT_FORCE_CLOSE,
  /** The connection is ending, an @ref ASSH_EVENT_CHANNEL_ABORT
      event will be reported for this channel. */
  ASSH_CHANNEL_ST_OPEN_RECEIVED_FORCE_CLOSE
};

/** @visible @This is the @em ssh-connection service @hl channel object.

    Channels are created either by calling the @ref assh_channel_open
    function or when the @ref ASSH_EVENT_CHANNEL_OPEN event is reported.
    The library user does not have to destroy channel objects explicitly.

    @xsee{connapi} */
struct assh_channel_s;

/** @This specifies standard values for channel open failure reason
    code as defined in @invoke{4254}rfc section 5.1 . */
enum assh_channel_open_reason_e
{
  SSH_OPEN_SESSION_DISCONNECTED        = -1,
  SSH_OPEN_SUCCESS                     = 0,
  SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1,
  SSH_OPEN_CONNECT_FAILED              = 2,
  SSH_OPEN_UNKNOWN_CHANNEL_TYPE        = 3,
  SSH_OPEN_RESOURCE_SHORTAGE           = 4,
};

/** @This specifies request reply failure reasons. */
enum assh_request_reason_e
{
  ASSH_REQUEST_SESSION_DISCONNECTED,
  ASSH_REQUEST_FAILED,
};

/** @This specifies reply codes used by request and channel events. */
enum assh_connection_reply_e
{
  /** Failure report by/to remote host. */
  ASSH_CONNECTION_REPLY_FAILED,
  /** Success report by/to remote host. */
  ASSH_CONNECTION_REPLY_SUCCESS,
  /** Reply will be sent later */
  ASSH_CONNECTION_REPLY_POSTPONED,
  /** The remote host has closed the channel/connection */
  ASSH_CONNECTION_REPLY_CLOSED,
};

/** @This specifies the maximum payload size usable to transfer data
    with @ref assh_channel_s objects. This is 12 bytes less than the
    value of the @ref #CONFIG_ASSH_MAX_PAYLOAD macro. */
#define ASSH_CHANNEL_MAX_PKTSIZE (CONFIG_ASSH_MAX_PAYLOAD \
             - /* extended data message header */ 3 * 4)

/** @This sets the value of the channel private pointer.
    This shares the storage with the private integer.
    @see assh_channel_set_pvi */
void assh_channel_set_pv(struct assh_channel_s *ch, void *pv);

/** @This returns the value of the channel private pointer. */
void * assh_channel_pv(const struct assh_channel_s *ch);

/** @This sets the value of the channel private integer.
    This shares the storage with the private pointer.
    @see assh_channel_set_pv */
void assh_channel_set_pvi(struct assh_channel_s *ch, uintptr_t pv);

/** @This returns the value of the channel private integer. */
uintptr_t assh_channel_pvi(const struct assh_channel_s *ch);

/** @This returns the session associated to a channel. */
struct assh_session_s *
assh_channel_session(const struct assh_channel_s *ch);

/** @This returns the current channel status. */
enum assh_channel_state_e
assh_channel_state(const struct assh_channel_s *ch);

/** @This returns the size of the channel local and remote windows in bytes. */
void assh_channel_get_win_size(const struct assh_channel_s *ch,
                               uint32_t *local, uint32_t *remote);

/** @This returns the maximum packet size for a channel. */
void assh_channel_get_pkt_size(const struct assh_channel_s *ch,
                               uint32_t *local, uint32_t *remote);

/** @This sets the value of the request private pointer.
    This shares the storage with the private integer.
    @see assh_request_set_pvi */
void assh_request_set_pv(struct assh_request_s *rq, void *pv);

/** @This returns the value of the request private pointer. */
void * assh_request_pv(const struct assh_request_s *rq);

/** @This sets the value of the request private integer.
    This shares the storage with the private pointer.
    @see assh_request_set_pv */
void assh_request_set_pvi(struct assh_request_s *rq, uintptr_t pv);

/** @This returns the value of the request private integer. */
uintptr_t assh_request_pvi(const struct assh_request_s *rq);

/** @This returns the session associated to a request. */
struct assh_session_s *
assh_request_session(const struct assh_request_s *rq);

/** @This returns the channel associated to a request.
    It returns @tt NULL for global requests. */
struct assh_channel_s *
assh_request_channel(const struct assh_request_s *rq);

/** @This returns the current channel status */
enum assh_request_state_e
assh_request_state(struct assh_request_s *rq);

/************************************************* incoming request */

/**
   This event is reported when the @ref assh_service_connection service
   is running and an @ref SSH_MSG_GLOBAL_REQUEST message or an @ref
   SSH_MSG_CHANNEL_REQUEST message has been received. The request type
   name and associated specific request data are available in the @ref
   type and @ref rq_data fields. These buffers will not remain valid
   after the call to @ref assh_event_done.

   The @ref ch field is @tt NULL for global requests.

   If the @ref rq pointer field is not @tt NULL, the remote host
   excepts a reply for this request. In this case, the @ref reply
   field can be set to @ref ASSH_CONNECTION_REPLY_SUCCESS in order to
   successfully acknowledge the request and some response data may
   optionally be passed in the @ref rsp_data field. The default value
   of the @ref reply field is @ref ASSH_CONNECTION_REPLY_FAILED. In
   both cases, the @ref assh_request_s object will be release when
   calling the @ref assh_event_done function.

   When it's not possible decide how to acknowledge the request before
   calling the @ref assh_event_done function, the @ref
   ASSH_CONNECTION_REPLY_POSTPONED value can be used. In this
   case, either the @ref assh_request_success_reply function or the
   @ref assh_request_failed_reply function must be called later in
   order to release the @ref assh_request_s object and send the reply
   expected by the remote host.  Care should be taken not to postpone
   too many requests in order to avoid resource-exhaustion attacks.

   Unlike channel open messages, the protocol requires that request
   replies are sent in order. This means that a postponed request
   reply will prevent subsequent request reply messages on the same
   channel from being transmitted to the remote host.

   When some incoming requests are left unreplied when the channel is
   closing or the connection is ending, @ref ASSH_EVENT_REQUEST_ABORT
   events are reported.

   @see ASSH_EVENT_REQUEST
*/
struct assh_event_request_s
{
  /** A pointer to the associated channel object if any. (ro) */
  struct assh_channel_s * ASSH_EV_CONST ch;

  /** A pointer to the request object. (ro) */
  struct assh_request_s * ASSH_EV_CONST rq;

  /** The textual type of the request. (ro) */
  ASSH_EV_CONST struct assh_cbuffer_s type;

  /** The associated data if any. (ro) */
  ASSH_EV_CONST struct assh_cbuffer_s rq_data;

  /** Used to store the request reply. (rw) */
  enum assh_connection_reply_e reply;

  /** Used to store the request reply data if any. (rw) */
  struct assh_cbuffer_s rsp_data;
};

/**
   This event is reported when a channel is closing or the connection
   is ending and some associated requests have been postponed.

   The @ref assh_request_s object will be released when calling the
   @ref assh_event_done function.

   @see ASSH_EVENT_REQUEST_ABORT
*/
struct assh_event_request_abort_s
{
  /** A pointer to the associated channel object if any. (ro) */
  struct assh_channel_s * ASSH_EV_CONST ch;

  /** A pointer to the request object. (ro) */
  struct assh_request_s * ASSH_EV_CONST rq;
};

/**
   @This acknowledges and releases a previously received global
   or channel request which has not been replied yet due to the use of
   the @ref ASSH_CONNECTION_REPLY_POSTPONED value in the @tt reply
   field of the @ref ASSH_EVENT_REQUEST event.

   Response data may optionally be included in the response by using
   the @tt rsp_data and @tt rsp_data_len parameters, as allowed by the
   protocol.

   If multiple requests on the same queue (global or per channel) are
   waiting for a reply, the replies will be sent in the received order
   as required by the ssh protocol. @This can be called in any
   order but any unreplied request will further postpone replies to
   subsequent requests.

   If this function is called on a closing channel which has not yet
   been reported by the appropriate event, this function returns @ref
   ASSH_NO_DATA to indicate that it was not able to send the reply.

   @This must not be called if the last event has not been
   acknowledged by calling the @ref assh_event_done function.

   @see assh_request_failed_reply
*/
assh_status_t
assh_request_success_reply(struct assh_request_s *rq,
                           const uint8_t *rsp_data,
                           size_t rsp_data_len);

/**
   @This has the same behavior as @ref assh_request_success_reply but
   reports a request failure to the remote host.
*/
assh_status_t
assh_request_failed_reply(struct assh_request_s *rq);

/************************************************* outgoing request */

/**
   This event is reported after a successful call to the @ref
   assh_request function when the @tt want_reply parameter was set and
   the remote host replied with a success message.

   Some response specific data may be available in the @ref rsp_data
   field.

   The @ref ch field is @tt NULL for global requests.

   The request object is released when the @ref assh_event_done
   function is called.

   @see ASSH_EVENT_REQUEST_SUCCESS
*/
struct assh_event_request_success_s
{
  /** A pointer to the associated channel object if any. (ro) */
  struct assh_channel_s * ASSH_EV_CONST ch;

  /** A pointer to the request object. (ro) */
  struct assh_request_s * ASSH_EV_CONST rq;

  /** The request reply associated data if any. (ro) */
  ASSH_EV_CONST struct assh_cbuffer_s rsp_data;
};

/**
   This event is reported after a successful call to the @ref
   assh_request function when the @tt want_reply parameter was set and
   the remote host replied with a failure message.

   The @ref ch field is @tt NULL for global requests.

   The request object is released when the @ref assh_event_done
   function is called.

   @see ASSH_EVENT_REQUEST_FAILURE
*/
struct assh_event_request_failure_s
{
  /** A pointer to the associated channel object if any. (ro) */
  struct assh_channel_s * ASSH_EV_CONST ch;

  /** A pointer to the request object. (ro) */
  struct assh_request_s * ASSH_EV_CONST rq;

  /** The request failure reason. (ro) */
  ASSH_EV_CONST enum assh_request_reason_e reason;
};


/**
   @This sends either an @ref SSH_MSG_GLOBAL_REQUEST message
   or an @ref SSH_MSG_CHANNEL_REQUEST message to the remote host.
   If the @tt ch parameter is @tt NULL, a global request is sent.

   If the @tt rq parameter is not @tt NULL, a reply from the remote
   host is expected.

   If this function is called after disconnection or on a closing
   channel which has not yet been reported by the appropriate event,
   this function returns @ref ASSH_NO_DATA to indicate that it was not
   able to send the request.

   When this function is successful and the request expects a reply,
   either an @ref ASSH_EVENT_REQUEST_SUCCESS event or an @ref
   ASSH_EVENT_REQUEST_FAILURE event will be reported at some point by
   the @ref assh_event_get function.

   @This must not be called if the last event has not been
   acknowledged by calling the @ref assh_event_done function.
*/
ASSH_WARN_UNUSED_RESULT assh_status_t
assh_request(struct assh_session_s *s,
             struct assh_channel_s *ch,
             const char *type, size_t type_len,
             const uint8_t *data, size_t data_len,
             struct assh_request_s **rq);

/************************************************* incoming channel open */

/**
   This event is reported when the @ref assh_service_connection service is
   running and an @ref SSH_MSG_CHANNEL_OPEN message is received from
   the remote host. The channel type name and specific data are
   available in the @ref type and @ref rq_data fields. These buffers
   will not remain valid after the call to @ref assh_event_done.

   The @ref reply field can be set to @ref
   ASSH_CONNECTION_REPLY_SUCCESS in order to successfully acknowledge
   the channel open. In this case, response data may optionally
   be passed in the @ref rsp_data field, as allowed by the protocol.

   The default value of the @ref reply field is @ref
   ASSH_CONNECTION_REPLY_FAILED. If an open failure is sent, the @ref
   assh_channel_s object will be release when calling the @ref
   assh_event_done function.

   When it's not possible to decide if the channel open is accepted
   before calling the @ref assh_event_done function, the @ref
   ASSH_CONNECTION_REPLY_POSTPONED value can be used. In this
   case, either the @ref assh_channel_open_success_reply or the @ref
   assh_channel_open_failed_reply function must be called later to
   send the reply expected by the remote host. Care should be taken
   not to postpone or accept too many channel open requests in order
   to avoid resource-exhaustion attacks.

   If some channel open are left postponed when the connection is
   ending, related @ref ASSH_EVENT_CHANNEL_ABORT events are reported.

   Ths @ref rpkt_size and @ref rwin_size fields contains the initially
   available window size and the packet size advertised by the remote
   host for sending data through the channel.

   The @ref pkt_size and @ref win_size fields are used to advertise
   our receive window and packet size and can be modified. The meaning
   of these fields is as described in @ref assh_channel_open. They are
   initially set to @tt {-1}.

   @see ASSH_EVENT_CHANNEL_OPEN
   @xsee{connapi}
*/
struct assh_event_channel_open_s
{
  /** A pointer to the channel object. (ro) */
  struct assh_channel_s * ASSH_EV_CONST ch;

  /** The textual type of the channel. (ro) */
  ASSH_EV_CONST struct assh_cbuffer_s type;

  /** The associated data if any. (ro) */
  ASSH_EV_CONST struct assh_cbuffer_s rq_data;

  /** Used to store the channel open reply. (rw) */
  enum assh_connection_reply_e reply;

  /** Used to store the channel open failure reason. (rw) */
  enum assh_channel_open_reason_e reason;

  /** The requested initial window size. (rw) */
  int32_t win_size;

  /** The requested packet size. (rw) */
  int32_t pkt_size;

  /** The remote window size. (ro) */
  ASSH_EV_CONST uint32_t rwin_size;

  /** The remote packet size. (ro) */
  ASSH_EV_CONST uint32_t rpkt_size;

  /** Used to store the reply data if any. (rw) */
  struct assh_cbuffer_s rsp_data;
};

/**
   This event is reported when the connection is ending and some
   channel open have been postponed.

   The @ref assh_channel_s object will be released when calling the
   @ref assh_event_done function.

   @see ASSH_EVENT_CHANNEL_ABORT
   @xsee{connapi}
*/
struct assh_event_channel_abort_s
{
  /** A pointer to the channel object. (ro) */
  struct assh_channel_s * ASSH_EV_CONST ch;
};

/**
   @This is similar to @ref assh_channel_open_success_reply
   but allows overriding the maximum packet size and the initial
   local window size specified when the @ref ASSH_EVENT_CHANNEL_OPEN
   event has been reported.

   @see assh_channel_open_success_reply
   @xsee{connapi}
*/
assh_status_t
assh_channel_open_success_reply2(struct assh_channel_s *ch,
                                 int32_t pkt_size, int32_t win_size,
                                 const uint8_t *rsp_data,
                                 size_t rsp_data_len);

/**
   @This acknowledges a channel open message which has not been
   replied yet due to the use of the @ref ASSH_CONNECTION_REPLY_POSTPONED
   value in the @tt reply field of the @ref ASSH_EVENT_CHANNEL_OPEN event.

   Response data may optionally be included by using the @tt rsp_data
   and @tt rsp_data_len parameters, as allowed by the protocol.

   Channel open replies can be send in any order.

   If this function is called on a closing channel which has not yet
   been reported by an @ref ASSH_EVENT_CHANNEL_CLOSE event, this
   function returns @ref ASSH_NO_DATA to indicate that it was not able
   to send the reply.  This occurs on disconnection.

   @This must not be called if the last event has not been
   acknowledged by calling the @ref assh_event_done function.

   @see assh_channel_open_failed_reply
   @xsee{connapi}
*/
assh_status_t
assh_channel_open_success_reply(struct assh_channel_s *ch,
                                const uint8_t *rsp_data,
                                size_t rsp_data_len);

/**
   @This acknowledges a channel open message which has not been
   replied yet due to the use of the @ref ASSH_CONNECTION_REPLY_POSTPONED
   value in the @tt reply field of the @ref ASSH_EVENT_CHANNEL_OPEN event.

   Channel open replies can be sent in any order.

   If this function is called on a closing channel which has not yet
   been reported by an @ref ASSH_EVENT_CHANNEL_CLOSE event, this
   function returns @ref ASSH_NO_DATA to indicate that it was not able
   to send the reply.  This occurs on disconnection.

   The @ref assh_channel_s object is released if the function reports
   no error.

   @This must not be called if the last event has not been
   acknowledged by calling the @ref assh_event_done function.

   @see assh_channel_open_success_reply
   @xsee{connapi}
*/
assh_status_t
assh_channel_open_failed_reply(struct assh_channel_s *ch,
                               enum assh_channel_open_reason_e reason);

/************************************************* outgoing channel open */

/**
   This event is reported after a successful call to the @ref
   assh_channel_open function when the channel open is accepted
   by the remote host.

   Some response specific data may be available in the @ref rsp_data
   field. The @ref rwin_size and @ref rpkt_size fields also contain
   the initially available window size and the packet size advertised
   by the remote host for sending to data through the channel.

   If the open has failed, the @ref ASSH_EVENT_CHANNEL_FAILURE
   event is reported instead.

   @see ASSH_EVENT_CHANNEL_CONFIRMATION
   @xsee{connapi}
*/
struct assh_event_channel_confirmation_s
{
  /** A pointer to the channel object. (ro) */
  struct assh_channel_s * ASSH_EV_CONST ch;

  /** The associated data if any. (ro) */
  ASSH_EV_CONST struct assh_cbuffer_s rsp_data;

  /** The remote window size. (ro) */
  ASSH_EV_CONST uint32_t rwin_size;

  /** The remote packet size. (ro) */
  ASSH_EV_CONST uint32_t rpkt_size;
};

/**
   This event is reported after a successful call to the @ref
   assh_channel_open function when the channel open is rejected
   by the remote host.

   The associated @ref assh_channel_s object is released when the
   @ref assh_event_done function is called.

   @see ASSH_EVENT_CHANNEL_FAILURE
   @xsee{connapi}
*/
struct assh_event_channel_failure_s
{
  /** A pointer to the channel object. (ro) */
  struct assh_channel_s * ASSH_EV_CONST ch;

  /** The channel open failure reason. (ro) */
  ASSH_EV_CONST enum assh_channel_open_reason_e reason;
};

/**
   @This allocates an @ref assh_channel_s object and send a
   @ref SSH_MSG_CHANNEL_OPEN message to the remote host.

   When this function is successful, either an @ref
   ASSH_EVENT_CHANNEL_CONFIRMATION event or an @ref
   ASSH_EVENT_CHANNEL_FAILURE event will be reported at some point by
   the @ref assh_event_get function.

   The @tt data and @tt data_len parameters allow sending channel type
   specific data along with the channel open message, as allowed by
   the protocol.

   The maximum packet size and the initial size of the channel local
   window may be specified. When the @tt pkt_size parameter is
   negative, a default value is used. When the @tt win_size parameter
   is negative, automatic local window adjustment is enabled for the
   channel. When a positive value is used instead, it specifies the
   initial size of the local window. In the later case, calls to the
   @ref assh_channel_window_adjust function have to be performed in
   order to keep the size of the local window above 0.

   If this function is called after disconnection, this function
   returns @ref ASSH_NO_DATA to indicate that it was not able to open
   the channel.

   @This must not be called if the last event has not been
   acknowledged by calling the @ref assh_event_done function.

   @xsee{connapi}
*/
ASSH_WARN_UNUSED_RESULT assh_status_t
assh_channel_open(struct assh_session_s *s,
                  const char *type, size_t type_len,
                  const uint8_t *data, size_t data_len,
                  int32_t pkt_size, int32_t win_size,
                  struct assh_channel_s **ch);

/************************************************* incoming channel data */

/**
   This event is reported when the @ref assh_service_connection service
   is running and some incoming channel data are available.

   The @tt transferred field should be set to the amount of consumed
   data. The event will be reported again if the field is not updated
   or if the value is less than @tt {data.size}. In the other case,
   the data buffers will not remain valid after the call to @ref
   assh_event_done.

   The size of the local window for the channel is decreased by the
   amount of received bytes when the event is first reported. When
   automatic local window adjustment is not enabled for the channel,
   the @ref assh_channel_window_adjust function must be called as soon
   as it becomes possible to receive more data.

   It's not possible to receive data from other channels until all
   data provided by the event are consumed. When this is a problem,
   automatic adjustment of the local window must not be used so that
   the amount of data sent by the remote host can be kept under
   control for all channels.

   @see ASSH_EVENT_CHANNEL_DATA
   @see assh_channel_more_data
*/
struct assh_event_channel_data_s
{
  /** A pointer to the channel object. (ro) */
  struct assh_channel_s * ASSH_EV_CONST ch;

  /** Indicate extended data. (ro) */
  ASSH_EV_CONST assh_bool_t ext;

  /** The type of extended data. (ro) */
  ASSH_EV_CONST uint32_t ext_type;

  /** The actual data transmitted over the channel. (ro) */
  ASSH_EV_CONST struct assh_cbuffer_s data;

  /** Must be set to the amount of data copied from the buffer. (rw) */
  size_t transferred;

  /** The new size of the local window.
      @see assh_channel_window_adjust */
  ASSH_EV_CONST size_t win_size;
};

/** @This returns a pointer to a channel with pending data.
    This occurs when the @ref ASSH_EVENT_CHANNEL_DATA event will be
    reported again because the @ref
    assh_event_channel_data_s::transferred field of the previous event
    has not been set to the maximum value.

    It returns @tt NULL when there is no channel with pending data. */
struct assh_channel_s *
assh_channel_more_data(struct assh_session_s *s);

/** @This can be used to advertise the remote host that we are
    ready to receive more data over the channel.

    @This increases the local window size and sends an @ref
    SSH_MSG_CHANNEL_WINDOW_ADJUST message to the remote host.

    This must be used when automatic local window adjustment is not
    enabled for the channel, as explained in @ref assh_channel_open.
 */
ASSH_WARN_UNUSED_RESULT assh_status_t
assh_channel_window_adjust(struct assh_channel_s *ch, size_t add);

/**
   This event is reported when the @ref assh_service_connection service
   is running and an @ref SSH_MSG_CHANNEL_WINDOW_ADJUST message has
   been received.

   This event indicates that the size of the remote window has
   increased. This means that more data can be sent over the channel.

   @see ASSH_EVENT_CHANNEL_WINDOW
*/
struct assh_event_channel_window_s
{
  /** A pointer to the channel object. (ro) */
  struct assh_channel_s * ASSH_EV_CONST ch;

  /** The previous window size. (ro) */
  ASSH_EV_CONST uint32_t old_size;

  /** The new window size. (ro) */
  ASSH_EV_CONST uint32_t new_size;
};

/************************************************* outgoing channel data */

/**
   @This internally pre-allocates a data packet suitable to
   transmit at least @tt min_size bytes and up to @tt *size bytes
   through an open channel.

   If the function is successful, the @tt size parameter is updated
   with the actual size of the available data buffer and the @tt data
   parameter is updated with the address of the buffer. The data will
   be sent when calling the @ref assh_channel_data_send function.

   @This returns @ref ASSH_NO_DATA if @tt min_size is larger than the
   current channel remote window. When @tt min_size is larger than the
   maximum packet size for the channel, @ref ASSH_ERR_OUTPUT_OVERFLOW
   is returned. In either case, no packet is allocated but the @tt size
   parameter is still updated with the current largest possible
   size. The largest possible size is 0 either if there is no window
   space left or if the channel is closing.

   It's ok to call this function more than once without actually
   sending the packet in order to change the requested packet size.

   The user does not have to release the allocated data packet
   explicitly.

   Unlike most functions of this module, it is ok to call this
   function between calls to the @ref assh_event_get and @ref
   assh_event_done functions. This allows forging a reply while the
   incoming data are still available.

   @see assh_channel_window_size
   @see assh_channel_data_alloc_ext
*/
ASSH_WARN_UNUSED_RESULT assh_status_t
assh_channel_data_alloc(struct assh_channel_s *ch,
                        uint8_t **data, size_t *size,
                        size_t min_size);

/**
   @This is similar to the @ref assh_channel_data_alloc
   function. It prepares an @ref SSH_MSG_CHANNEL_EXTENDED_DATA message
   instead of an @ref SSH_MSG_CHANNEL_DATA message

   @see assh_channel_data_alloc
*/
ASSH_WARN_UNUSED_RESULT assh_status_t
assh_channel_data_alloc_ext(struct assh_channel_s *ch,
                            uint32_t ext_type,
                            uint8_t **data, size_t *size,
                            size_t min_size);

/**
   @This sends the data packet previously allocated by the
   @ref assh_channel_data_alloc function. The @tt size parameter must
   not be greater than what has been pre-allocated.

   If this function is called on a closing channel, @ref ASSH_NO_DATA
   is returned to indicate that it was not able to send data.

   @This must not be called if the last event has not been
   acknowledged by calling the @ref assh_event_done function.
*/
assh_status_t
assh_channel_data_send(struct assh_channel_s *ch, size_t size);

/**
   @This transmits data to the remote host through an open
   channel. It's a convenience function which calls @ref
   assh_channel_data_alloc then @tt memcpy and finally @ref
   assh_channel_data_send.

   This @tt size parameter is updated with the actually transmitted
   size.

   @This must not be called if the last event has not been
   acknowledged by calling the @ref assh_event_done function.

   @see assh_channel_data_ext
*/
ASSH_INLINE assh_status_t
assh_channel_data(struct assh_channel_s *ch,
                  const uint8_t *data, size_t *size)
{
  uint8_t *d;
  assh_status_t err;
  if ((err = assh_channel_data_alloc(ch, &d, size, 1)))
    return err;
  memcpy(d, data, *size);
  return assh_channel_data_send(ch, *size);
}

/**
   @This is similar to the @ref assh_channel_data function. It
   sends an @ref SSH_MSG_CHANNEL_EXTENDED_DATA message instead of an
   @ref SSH_MSG_CHANNEL_DATA message

   @see assh_channel_data
*/
ASSH_INLINE assh_status_t
assh_channel_data_ext(struct assh_channel_s *ch, uint32_t ext_type,
                      const uint8_t *data, size_t *size)
{
  uint8_t *d;
  assh_status_t err;
  if ((err = assh_channel_data_alloc_ext(ch, ext_type, &d, size, 1)))
    return err;
  memcpy(d, data, *size);
  return assh_channel_data_send(ch, *size);
}

/**
   @This returns the amount of data size that can be written
   to the channel.
*/
size_t assh_channel_window_size(struct assh_channel_s *ch);

/**
   @This allocates and transmits a dummy packet ignored by the
   remote host. Once enciphered, the packet looks similar to a channel
   data packet of the specified size.

   @This must not be called if the last event has not been
   acknowledged by calling the @ref assh_event_done function.
*/
assh_status_t
assh_channel_dummy(struct assh_channel_s *ch, size_t size);

/** When @tt *data_size is initially zero, @this returns the amount of
    channel data that can be stored in a single ssh2 binary packet of
    the given size, as generated by the transport layer. When instead
    @tt *packet_size is initially zero, @this returns the size of the
    binary packet that will be generated to transfer the specified
    amount of data over the channel.

    The @tt ext parameter must indicate if use of extended channel
    data is assumed.

    The returned value depends on the @hl algorithms in use so that it
    is likely to change after completion of the @hl key-exchange
    process.

    An error is returned if no data would fit in the specified packet
    size. */
ASSH_WARN_UNUSED_RESULT assh_status_t
assh_channel_overhead(struct assh_session_s *s, size_t *data_size,
		      size_t *packet_size, assh_bool_t ext);

/************************************************* incoming channel close/eof */

/**
   This event is reported when the  @ref assh_service_connection service is
   running and the remote host has sent the @ref
   SSH_MSG_CHANNEL_EOF message.

   If the channel has already been half-closed in the other direction
   when receiving this messages, an @ref SSH_MSG_CHANNEL_CLOSE
   message is sent and the channel state changes to @ref ASSH_CHANNEL_ST_CLOSING.

   @see ASSH_EVENT_CHANNEL_EOF
   @xsee{connapi}
*/
struct assh_event_channel_eof_s
{
  /** A pointer to the channel object. (ro) */
  struct assh_channel_s   * ASSH_EV_CONST ch;
};


/**
   This event is reported for open channels when the channel is in
   @ref ASSH_CHANNEL_ST_CLOSING state and all data and requests
   associated with the channel have been reported using appropriate
   events.

   @see ASSH_EVENT_CHANNEL_CLOSE
   @xsee{connapi}
*/
struct assh_event_channel_close_s
{
  /** A pointer to the channel object. (ro) */
  struct assh_channel_s * ASSH_EV_CONST ch;
};

/************************************************* outgoing channel close/eof */

/**
   @This sends an @ref SSH_MSG_CHANNEL_EOF message and marks
   the channel as half-closed. The @ref assh_channel_data function
   can not be called successfully on the channel once this
   function has been called.

   If the channel is already half-closed in the other direction, this
   function acts as the @ref assh_channel_close function.

   @This must not be called if the last event has not been
   acknowledged by calling the @ref assh_event_done function.

   @xsee{connapi}
*/
assh_status_t
assh_channel_eof(struct assh_channel_s *ch);

/**
   @This sends an @ref SSH_MSG_CHANNEL_CLOSE message to the
   remote host.

   When this function is successful, the channel is not released until
   the @ref ASSH_EVENT_CHANNEL_CLOSE event acknowledges this call. In
   the mean time, some request and data related events can still be
   reported for the channel.

   @This must not be called if the last event has not been
   acknowledged by calling the @ref assh_event_done function.

   @xsee{connapi}
*/
assh_status_t
assh_channel_close(struct assh_channel_s *ch);

/**************************************************/

/** @This contains all @ref assh_service_connection service related
    event structures. */
union assh_event_connection_u
{
  struct assh_event_request_s           request;
  struct assh_event_request_abort_s     request_abort;
  struct assh_event_request_success_s   request_success;
  struct assh_event_request_failure_s   request_failure;
  struct assh_event_channel_open_s      channel_open;
  struct assh_event_channel_confirmation_s channel_confirmation;
  struct assh_event_channel_failure_s   channel_failure;
  struct assh_event_channel_data_s      channel_data;
  struct assh_event_channel_window_s    channel_window;
  struct assh_event_channel_eof_s       channel_eof;
  struct assh_event_channel_close_s     channel_close;
  struct assh_event_channel_abort_s     channel_abort;
};

/** @This is the @hl{connection protocol} service module
    descriptor. @xsee{coremod} */
extern const struct assh_service_s assh_service_connection;

#endif

