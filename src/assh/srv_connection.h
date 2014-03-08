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
enum assh_request_status_e
{
  ASSH_REQUEST_ST_WAIT_REPLY,      //< outgoing request not replied by remote host
  ASSH_REQUEST_ST_REPLY_POSTPONED, //< incoming request reply not yet acknowledged by user
  ASSH_REQUEST_ST_REPLY_READY,     //< incoming request acknowledged, blocked by queue order
};

/** @hidecontent
    @This is the @em ssh-connection service request object.

    Requests are created either by calling the @ref assh_request
    function or when the @ref ASSH_EVENT_REQUEST event is reported.
    The library user does not have to destroy request objects.
 */
struct assh_request_s
{
  struct assh_queue_entry_s qentry;

  enum assh_request_status_e status;
  struct assh_session_s *session;
  struct assh_channel_s *ch;
  struct assh_packet_s *reply_pck;
  void *pv;
};

/** @This specify channel status */
enum assh_channel_status_e
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
  /** The @ref assh_channel_close function was called at some point
      and the channel is closing as in @ref ASSH_CHANNEL_ST_CLOSING state. */
  ASSH_CHANNEL_ST_CLOSE_CALLED_CLOSING,
};

/** @hidecontent
    @This is the @em ssh-connection service channel object.

    Channels are created either by calling the @ref assh_channel_open
    function or when the @ref ASSH_EVENT_CHANNEL_OPEN event is reported.
    The library user does not have to destroy channel objects.
*/
struct assh_channel_s
{
  union {
    /** channel queue entry, valid when the channel is waiting for close. */
    struct assh_queue_entry_s qentry;
    /** channel map entry, valid when the channel is open. */
    struct assh_map_entry_s mentry;
  };

  enum assh_channel_status_e status;
  struct assh_session_s *session;
  void *pv;

  struct assh_queue_s request_rqueue; //< requests we have to acknowledge
  struct assh_queue_s request_lqueue; //< requests waiting for a reply from the remote host

  uint32_t remote_id;
  uint32_t rpkt_size;		//< remote packet size
  uint32_t rwin_size;		//< remote window size
  uint32_t lpkt_size;		//< local packet size
  uint32_t lwin_size;		//< local window size
};

/** @This specifies standard values for channel open failure reason
    code as defined in rfc4254 section 5.1 */
enum assh_channel_open_reason_e
{
  SSH_OPEN_SUCCESS                     = 0,
  SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1,
  SSH_OPEN_CONNECT_FAILED              = 2,
  SSH_OPEN_UNKNOWN_CHANNEL_TYPE        = 3,
  SSH_OPEN_RESOURCE_SHORTAGE           = 4,
};

/** @This specifies reply codes used by request and channel events */
enum assh_connection_reply_e
{
  /** Failure report by/to remote host. */
  ASSH_CONNECTION_REPLY_FAILED,
  /** Success report by/to remote host. */
  ASSH_CONNECTION_REPLY_SUCCESS,
  /** Reply will be send later */
  ASSH_CONNECTION_REPLY_POSTPONED,
  /** The remote host has closed the channel/connection */
  ASSH_CONNECTION_REPLY_CLOSED,
};

/** This function sets the value of the channel private pointer. */
static inline void
assh_channel_set_pv(struct assh_channel_s *ch, void *pv)
{
  ch->pv = pv;
}

/** This function returns the value of the channel private pointer. */
static inline void *
assh_channel_pv(const struct assh_channel_s *ch)
{
  return ch->pv;
}

/** This function sets the value of the request private pointer. */
static inline void
assh_request_set_pv(struct assh_request_s *rq, void *pv)
{
  rq->pv = pv;
}

/** This function returns the value of the request private pointer. */
static inline void *
assh_request_pv(const struct assh_request_s *rq)
{
  return rq->pv;
}

/** This returns the current channel state */
static inline enum assh_channel_status_e
assh_channel_status(struct assh_channel_s *ch)
{
  return ch->status;
}

/************************************************* service start */

/**
   This event is reported when the @tt ssh-connection service has
   just started. The channel related and request related functions
   can be used from this point.

   @see ASSH_EVENT_CONNECTION_START
*/
struct assh_event_connection_start_s
{
};

/************************************************* incoming request */

/**
   This event is reported when the @tt ssh-connection service is
   running and a @ref SSH_MSG_GLOBAL_REQUEST message or a @ref
   SSH_MSG_CHANNEL_REQUEST message has been received. The request type
   name and associated specific request data are available in the @ref
   type and @ref rq_data fields. These buffers will not remain valid
   after the call to @ref assh_event_done.

   The @ref channel field is @tt NULL for global requests.

   If the @ref rq pointer field is not @tt NULL, the remote host
   excepts a reply for this request. In this case, the @ref reply
   field can be set to @ref ASSH_CONNECTION_REPLY_SUCCESS in order to
   successfully acknowledge the request and some response data may
   optionally be passed in the @ref rsp_data field. The default value
   of the @ref reply field is @ref ASSH_CONNECTION_REPLY_FAILED. In
   both cases, the @ref assh_request_s object will be release when
   calling the @ref assh_event_done function.

   If it's not possible to acknowledge the request when calling the
   @ref assh_event_done function, the @ref
   ASSH_CONNECTION_REPLY_POSTPONED value must be used instead. In this
   case, either the @ref assh_request_success_reply function or the
   @ref assh_request_failed_reply function must be called later in
   order to release the @ref assh_request_s object and send the reply
   expected by the remote host.  Care should be taken not to postpone
   too many requests in order to avoid resource-exhaustion attacks.

   If some incoming requests are left unreplied when the @ref
   ASSH_EVENT_CHANNEL_CLOSE event is reported, all postponed request
   objects associated with the channel are released along with the
   channel.

   @see ASSH_EVENT_REQUEST
*/
struct assh_event_request_s
{
  struct assh_channel_s * ASSH_EV_CONST ch;         //< input
  struct assh_request_s * ASSH_EV_CONST rq;         //< input
  ASSH_EV_CONST struct assh_string_s    type;       //< input
  ASSH_EV_CONST struct assh_buffer_s    rq_data;    //< input
  enum assh_connection_reply_e          reply;      //< output
  struct assh_buffer_s                  rsp_data;   //< output
};

/**
   This function acknowledge and release a previously received global
   or channel request which has not been replied yet due to the use of
   the @ref ASSH_CONNECTION_REPLY_POSTPONED value in the @tt reply
   field of the associated event.

   Some response data may optionally be included in the response by
   using the @tt rsp_data and @tt rsp_data_len parameters.

   If multiple requests on the same queue (global or per channel) are
   waiting for a reply, the replies will be sent in the received
   order. This function can be called in any order but a non replied
   request may further postpone replies to subsequent requests.

   If this function is called after the remote host disconnected or
   sent a channel close message which has not yet been reported by the
   appropriate event, this function returns @ref ASSH_NO_DATA to
   indicate that it was not able to send the reply.

   @see assh_request_failed_reply
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_request_success_reply(struct assh_request_s *rq,
                           const uint8_t *rsp_data,
                           size_t rsp_data_len);

/**
   @This has the same behavior as @ref assh_request_success_reply but
   reports a request failure to the remote host.
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_request_failed_reply(struct assh_request_s *rq);

/************************************************* outgoing request */

/**
   This event is reported for every successful call to the @ref
   assh_connection_request function with the @tt want_reply parameter
   set.

   The @ref reply field indicates if the request has been successfully
   acknowledged by the remote host. In this case, some response
   specific data may be available in the @ref rsp_data field. This
   field may also indicate that the request has failed or that the
   connection or channel associated with the request has been closed.

   The @ref channel field is @tt NULL for global requests.

   The request object is released when the @ref assh_event_done
   function is called.

   @see ASSH_EVENT_REQUEST_REPLY
*/
struct assh_event_request_reply_s
{
  struct assh_channel_s      * ASSH_EV_CONST ch;        //< input
  struct assh_request_s      * ASSH_EV_CONST rq;        //< input
  ASSH_EV_CONST enum assh_connection_reply_e reply;     //< input
  ASSH_EV_CONST struct assh_buffer_s         rsp_data;  //< input
};


/**
   This function sends either a @ref SSH_MSG_GLOBAL_REQUEST message
   or a @ref SSH_MSG_CHANNEL_REQUEST message to the remote host.
   If the @tt ch parameter is @tt NULL, a global request is sent.

   If the @tt rq parameter is not @tt NULL, a reply from the remote
   host is expected.

   If a reply is expected and the function returns @ref ASSH_OK, a new
   @ref assh_request_s object is allocated and an @ref
   ASSH_EVENT_REQUEST_REPLY event will later indicate if this
   request is successful.

   Even if a channel close or disconnection occurs, the expected event
   will be reported at some point by the @ref assh_event_get function.

   This function will fail if the @tt ssh-connection service is
   not started.
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_request(struct assh_session_s *s,
             struct assh_channel_s *ch,
             const char *type, size_t type_len,
             const uint8_t *data, size_t data_len,
             struct assh_request_s **rq);

/************************************************* incoming channel open */

/**
   This event is reported when the @tt ssh-connection service is
   running and a @ref SSH_MSG_CHANNEL_OPEN message is received from
   the remote host. The channel type name and specific data are
   available in the @ref type and @ref rq_data fields. These buffers
   will not remain valid after the call to @ref assh_event_done.

   The @ref pkt_size and the @ref win_size fields initially contain
   the maximum packet size accepted by the remote host for this
   channel and the initial window data size. The values can be
   modified if they need to be different for the other channel
   direction. The maximum packet size value will be reduced if larger
   than what the libassh transport layer can handle.

   The @ref reply field can be set to @ref
   ASSH_CONNECTION_REPLY_SUCCESS in order to successfully acknowledge
   the channel open. In this case, some response data may optionally
   be passed in the @ref rsp_data field.

   The default value of the @ref reply field is @ref
   ASSH_CONNECTION_REPLY_FAILED. If an open failure is sent, the @ref
   assh_channel_s object will be release when calling the @ref
   assh_event_done function.

   If it's not possible to reply to the channel open when calling the
   @ref assh_event_done function, the @ref ASSH_CONNECTION_REPLY_POSTPONED
   value must be used instead. In this case, the @ref assh_channel_open_reply
   function must be called later to send the reply expected by the
   remote host. Care should be taken not to postpone or accept too many
   channel open requests in order to avoid resource-exhaustion attacks.

   @see ASSH_EVENT_CHANNEL_OPEN
*/
struct assh_event_channel_open_s
{
  struct assh_channel_s * ASSH_EV_CONST ch;       //< input
  ASSH_EV_CONST struct assh_string_s    type;     //< input
  ASSH_EV_CONST struct assh_buffer_s    rq_data;  //< input
  enum assh_connection_reply_e          reply;    //< output
  enum assh_channel_open_reason_e       reason;   //< output
  uint32_t                              win_size; //< input/output
  uint32_t                              pkt_size; //< input/output
  struct assh_buffer_s                  rsp_data; //< output
};

/**
   This function acknowledge a channel open message which has not been
   replied yet due to the use of the @ref ASSH_CONNECTION_REPLY_POSTPONED
   value in the @tt reply field of the @ref ASSH_EVENT_CHANNEL_OPEN event.

   Some response data may optionally be included in the response by
   using the @tt rsp_data and @tt rsp_data_len parameters.

   Channel open replies can be send in any order.

   @see assh_channel_open_failed_reply
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_channel_open_success_reply(struct assh_channel_s *ch,
                                uint32_t win_size, uint32_t pkt_size,
                                const uint8_t *rsp_data,
                                size_t rsp_data_len);

/**
   This function acknowledge a channel open message which has not been
   replied yet due to the use of the @ref ASSH_CONNECTION_REPLY_POSTPONED
   value in the @tt reply field of the @ref ASSH_EVENT_CHANNEL_OPEN event.

   Channel open replies can be send in any order.

   @see assh_channel_open_success_reply
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_channel_open_failed_reply(struct assh_channel_s *ch,
                               enum assh_channel_open_reason_e reason);

/************************************************* outgoing channel open */

/**
   This event is reported for every successful call to the @ref
   assh_channel_open function. The @ref success field indicates if
   the channel open has been confirmed by the remote side.

   If the open is successful, some response specific data may be
   available in the @ref rsp_data field.

   If the open has failed, the associated @ref assh_channel_s object
   will be released when the @ref assh_event_done function is called.

   @see ASSH_EVENT_CHANNEL_OPEN_REPLY
*/
struct assh_event_channel_open_reply_s
{
  struct assh_channel_s * ASSH_EV_CONST         ch;         //< input
  ASSH_EV_CONST enum assh_connection_reply_e    reply;      //< input
  ASSH_EV_CONST enum assh_channel_open_reason_e reason;     //< input
  ASSH_EV_CONST struct assh_buffer_s            rsp_data;   //< input
};

/**
   This function allocates an @ref assh_channel_s object and send a
   @ref SSH_MSG_CHANNEL_OPEN message to the remote host. If the
   function returns @ref ASSH_OK, an @ref ASSH_EVENT_CHANNEL_OPEN
   event will later indicate if the remote host has accepted the
   channel open request.

   Even if a disconnection occurs, the expected event will be reported
   at some point by the @ref assh_event_get function.

   This function will fail if the @tt ssh-connection service is
   not started.
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_channel_open(struct assh_session_s *s,
                  const char *type, size_t type_len,
                  const uint8_t *data, size_t data_len,
                  size_t pkt_size, size_t win_size,
                  struct assh_channel_s **ch);

/************************************************* incoming channel data */

/**
   This event is reported when the @tt ssh-connection service is
   running and some incoming channel data are available. The data
   buffers will not remain valid after the call to @ref
   assh_event_done.

   @see ASSH_EVENT_CHANNEL_DATA
*/
struct assh_event_channel_data_s
{
  struct assh_channel_s * ASSH_EV_CONST   ch;         //< input
  ASSH_EV_CONST assh_bool_t               ext;        //< input
  ASSH_EV_CONST uint32_t                  ext_type;   //< input
  ASSH_EV_CONST struct assh_buffer_s      data;       //< input
};

/************************************************* outgoing channel data */

/**
   This function transfers data to the remote host through an opened
   channel. Incoming channel data from the remote host are passed
   using the @ref ASSH_EVENT_CHANNEL_DATA event.

   A @ref SSH_MSG_CHANNEL_EXTENDED_DATA message is used instead of a
   @ref SSH_MSG_CHANNEL_DATA message if the @tt ext parameter is
   set. In this case, the @tt ext_type parameter is relevant.

   If not all data have been transfered, the function returns @ref
   ASSH_NO_DATA and the size parameter is set to the amount of
   data which has been transfered.

   This function will fail if the @tt ssh-connection service is
   not started.
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_channel_data(struct assh_channel_s *ch,
                  assh_bool_t ext, uint32_t ext_type,
                  const uint8_t *data, size_t *size);

/************************************************* incoming channel close/eof */

/**
   This event is reported when the @tt ssh-connection service is
   running and the remote host has sent the @ref
   SSH_MSG_CHANNEL_EOF message.

   If the channel has already been half-closed in the other direction
   when receiving this messages, an @ref SSH_MSG_CHANNEL_CLOSE
   message is sent and the channel state changes to @ref ASSH_CHANNEL_ST_CLOSING.

   @see ASSH_EVENT_CHANNEL_EOF
*/
struct assh_event_channel_eof_s
{
  struct assh_channel_s   * ASSH_EV_CONST ch; //< input
};


/**
   This event is reported for open channels when the channel is in
   @ref ASSH_CHANNEL_ST_CLOSING state and all data and requests
   associated with the channel have been reported using appropriate
   events.

   @see ASSH_EVENT_CHANNEL_CLOSE
*/
struct assh_event_channel_close_s
{
  struct assh_channel_s           * ASSH_EV_CONST ch; //< input
};

/************************************************* outgoing channel close/eof */

/**
   This function sends a @ref SSH_MSG_CHANNEL_EOF message and marks
   the channel as half-closed. The @ref assh_channel_data function
   can not be called successfully on the channel once this
   function has been called.

   If the channel is already half-closed in the other direction, this
   function acts as the @ref assh_channel_close function.

   This function will fail if the @tt ssh-connection service is
   not started.
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_channel_eof(struct assh_channel_s *ch);

/**
   This function sends a @ref SSH_MSG_CHANNEL_CLOSE message to the
   remote host. The channel state will change to @ref
   ASSH_CHANNEL_ST_CLOSING when the channel close reply is received.

   The channel is not released until the @ref ASSH_EVENT_CHANNEL_CLOSE
   event is reported. In the mean time, some request and data related
   events can still be reported for the channel.

   This function will fail if the @tt ssh-connection service is
   not started.
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_channel_close(struct assh_channel_s *ch);

/**************************************************/

/** @This contains all @tt ssh-connection service related events */
union assh_event_connection_u
{
  struct assh_event_connection_start_s  start;
  struct assh_event_request_s           request;
  struct assh_event_request_reply_s     request_reply;
  struct assh_event_channel_open_s      channel_open;
  struct assh_event_channel_open_reply_s channel_open_reply;
  struct assh_event_channel_data_s      channel_data;
  struct assh_event_channel_eof_s       channel_eof;
  struct assh_event_channel_close_s     channel_close;
};

/** @This is the @tt ssh-connection service module descriptor. */
extern const struct assh_service_s assh_service_connection;

#endif

