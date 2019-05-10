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
   @short Session structure and related functions

   This header file provides declaration of the @ref assh_session_s
   structure and related functions, used to create and manage @em ssh2
   @hl sessions.
*/

#ifndef ASSH_SESSION_H_
#define ASSH_SESSION_H_

#include "assh_transport.h"
#include "assh_service.h"
#include "assh_queue.h"
#include "assh_packet.h"

/** @see assh_kex_filter_t */
#define ASSH_KEX_FILTER_FCN(n)                          \
  assh_bool_t (n)(struct assh_session_s *s,             \
                  const struct assh_algo_s *algo,       \
                  const struct assh_algo_name_s *name,  \
                  assh_bool_t out)

/** This is a per session algorithm filtering function.

    @tt 1 must be returned in order to make the algorithm available for
    the session. The result of this function must not vary for a given
    algorithm unless the @ref assh_session_algo_filter function has
    been called successfully.

    The @tt out parameter specifies the direction and is relevant for
    cipher, mac and compression algorithms.

    @xsee {suppalgos} */
typedef ASSH_KEX_FILTER_FCN(assh_kex_filter_t);

#if CONFIG_ASSH_IDENT_SIZE < 8 || CONFIG_ASSH_IDENT_SIZE > 255
# error CONFIG_ASSH_IDENT_SIZE out of range
#endif

/** @internalmembers @This is the @em ssh2 @hl session state
    structure.

    A @hl session instance is associated to an @ref assh_context_s
    object which holds resources shared between multiple sessions.

    It is @b not related to @hl{interactive sessions} which are
    part of the @hl{connection protocol}. */
struct assh_session_s
{
  /** User private pointer */
  void *user_pv;

  /** Pointer to associated main context. */
  struct assh_context_s *ctx;

  /** Key exchange algorithm. This pointer is setup when the @ref
      assh_kex_got_init function select a new key exchange algorithm. */
  const struct assh_algo_kex_s *kex;
  /** Key exchange private context used during key exchange only. */
  void *kex_pv;

  /** Pointer to the last key exechange packet sent by client. Valid
      during key exechange. */
  struct assh_packet_s *kex_init_local;
  /** Pointer to the last key exechange packet sent by client. Valid
      during key exechange. */
  struct assh_packet_s *kex_init_remote;
  /** remote side prefered kex and host signature algorithms */
  const struct assh_algo_s *kex_preferred[2];

  /** per session algorithm filter */
  assh_kex_filter_t *kex_filter;

  /** amount of data transfered since last kex */
  uint32_t kex_bytes;

  /** kex re-exchange threshold */
  uint32_t kex_max_bytes;

  /** Host keys signature algorithm */
  const struct assh_algo_sign_s *host_sign_algo;

  /** Current service. */
  const struct assh_service_s *srv;
  /** Current service private data. */
  void *srv_pv;
#ifdef CONFIG_ASSH_CLIENT
  /** Host key sent by server. The key is loaded by @ref
      assh_kex_client_get_key and released when the @ref
      ASSH_EVENT_KEX_DONE event is acknowledged.  */
  struct assh_key_s *kex_host_key;
#endif

  /** Queue of ssh output packets. Packets in this queue will be
      enciphered and sent. */
  struct assh_queue_s out_queue;
  /** Alternate queue of ssh output packets, used to store services
      packets during a key exchange. */
  struct assh_queue_s alt_queue;

  /** Pointer to output keys and algorithms in current use. */
  struct assh_kex_keys_s *cur_keys_out;
  /** Pointer to next output keys and algorithms on SSH_MSG_NEWKEYS transmitted. */
  struct assh_kex_keys_s *new_keys_out;

  /** Current input ssh stream packet. This packet is currently being
      read from the input ssh stream and has not yet been deciphered. */
  struct assh_packet_s *stream_in_pck;

  /** Current ssh input packet. This packet is the last deciphered
      packets and is waiting for dispatch and processing. */
  struct assh_packet_s *in_pck;

  /** Pointer to input keys and algorithms in current use. */
  struct assh_kex_keys_s *cur_keys_in;
  /** Pointer to next input keys and algorithms on SSH_MSG_NEWKEYS received. */
  struct assh_kex_keys_s *new_keys_in;

  /** last error reported to @ref assh_session_error. This will be
      reported as an @ref ASSH_EVENT_SESSION_ERROR event. */
  assh_error_t last_err;

  /** Current date as reported by the last IO request. */
  assh_time_t time;

  /** The session will terminate with the @ref ASSH_ERR_TIMEOUT error
      if this field contains a value less than the @ref time field. It
      is updated by the transport layer. */
  assh_time_t tr_deadline;

  /** The running service may update this field and check when this
      field contains a value less than the @ref time field. When not
      used, it must be set to 0 so that it is excluded from the
      computation of the next protocol timeout reported to the
      application. */
  assh_time_t srv_deadline;

  /** The key-exchange process will be stated again when this field
      contains a value less then the @ref time field and the transport
      state is @ref ASSH_TR_SERVICE. */
  assh_time_t rekex_deadline;

  /** Size of valid data in the @ref stream_in_pck packet */
  size_t stream_in_size:32;
  /** Size of already sent data of the top packet in the @ref out_queue queue. */
  size_t stream_out_size:32;

  /** Input packet sequence number */
  uint32_t in_seq;
  /** Output packet sequence number */
  uint32_t out_seq;

  /** Current input ssh stream header buffer. */
  union  {
    uint8_t data[ASSH_MAX_BLOCK_SIZE];
    struct assh_packet_head_s head;
  } stream_in_stub;

  /** Session id is first "exchange hash" H */
  uint8_t session_id[ASSH_MAX_HASH_SIZE];
  /** Session id length */
  size_t session_id_len:8;

  /** Copy of the ident string sent by the remote host. */
  uint8_t ident_str[CONFIG_ASSH_IDENT_SIZE];
  /** Size of the ident string sent by the remote host. */
  size_t ident_len:8;

#ifdef CONFIG_ASSH_CLIENT
  /** Index of the next service to request in the context services array. */
  size_t srv_index:5;
#endif

  /** user authentication success packet has been handled by the
      transport layer */
  assh_bool_t tr_user_auth_done:1;
  /** user authentication success */
  assh_bool_t user_auth_done:1;

  /** initial key exchange done. */
  assh_bool_t kex_done:1;

  /** Currrent output ssh stream generator state. */
  enum assh_stream_out_state_e stream_out_st:3;

  /** Current input ssh stream parser state. */
  enum assh_stream_in_state_e stream_in_st:3;

  /** Current state of the transport layer. */
  enum assh_transport_state_e tr_st:4;

  /** Current state of service execution. */
  enum assh_service_state_e srv_st:3;

#ifndef NDEBUG
  assh_bool_t event_done:1;
#endif
};

/** The @ref ASSH_EVENT_SESSION_ERROR event is reported when an error
    occurs. Because not all errors are fatal, the event may be
    reported multiple times during a single session.

    @see #ASSH_ERR_ERROR @see #ASSH_ERR_SEVERITY */
struct assh_event_session_error_s
{
  assh_error_t code;
};

/** @This contains all session related event structures. */
union assh_event_session_u
{
  struct assh_event_session_error_s error;
};

/** @This sets the user private pointer of the session.
    @see assh_session_get_pv */
void assh_session_set_pv(struct assh_session_s *ctx,
                         void *private);

/** @This retrieves the user private pointer of the session.
    @see assh_session_set_pv */
void * assh_session_get_pv(struct assh_session_s *ctx);

/** @This initializes an user allocated session
    instance.  When a stable ABI is needed, the @ref
    assh_session_create function muse be used instead.

    @see assh_session_cleanup
*/
ASSH_ABI_UNSAFE ASSH_WARN_UNUSED_RESULT assh_error_t
assh_session_init(struct assh_context_s *c,
		  struct assh_session_s *s);

/** @This allocates and initializes an @ref assh_session_s instance.

    @see assh_session_release
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_session_create(struct assh_context_s *c,
		    struct assh_session_s **s);

/** @This releases the resources associated with an user allocated
    @ref assh_session_s instance. */
ASSH_ABI_UNSAFE void
assh_session_cleanup(struct assh_session_s *s);

/** @This releases an @ref assh_session_s instance created by the
    @ref assh_session_create function as well as associated
    resources. */
void assh_session_release(struct assh_session_s *s);

/** @internal This changes the session state according to the provided
    error code and associated severity level.

    This function returns the original error code but the error
    severity level may be increased. This function is responsible for
    sending the session close message to the remote hsot.

    This function is called from the @ref assh_event_get, @ref
    assh_event_done function. It is also called from other functions
    of the public API which can modify the session state.

    @see assh_error_e @see assh_error_severity_e
*/
void assh_session_error(struct assh_session_s *s, assh_error_t err);

/** @This schedules the end of the session and sends an
    SSH_MSG_DISCONNECT message to the remote host. The @ref
    assh_event_get function must still be called until no more events
    are available. */
assh_error_t
assh_session_disconnect(struct assh_session_s *s,
                        enum assh_ssh_disconnect_e reason,
                        const char *desc);

/** @This returns the current session safety factor which depends on
    algorithms and keys involved in the last @hl{key-exchange}
    process. The safety factor may change during the session
    lifetime.  @see assh_algo_register_va */
assh_safety_t assh_session_safety(struct assh_session_s *s);

/** @This setups a per session algorithm filter. The @tt filter
    parameter may be @tt NULL to disable filtering. It will fail if a
    key exchange in ongoing. @xsee{suppalgos} */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_session_algo_filter(struct assh_session_s *s,
                         assh_kex_filter_t *filter);

/** @This returns the next protocol deadline. In order for the
    library to handle protocol timeouts properly, the process must not
    wait forever on a blocking io operation. The @ref assh_event_get
    function must be called again when the deadline is reached.

    @see assh_session_delay
*/
assh_time_t
assh_session_deadline(struct assh_session_s *s);

/** @This returns the delay between the next protocol deadline and the
    current time. The current time must be passed to the function in
    second units. If the next deadline is in the past, the function
    returns 0.

    @see assh_session_deadline
*/
ASSH_INLINE assh_time_t
assh_session_delay(struct assh_session_s *s, assh_time_t time)
{
  assh_time_t d = assh_session_deadline(s);
  return time < d ? d - time : 0;
}

/** @This returns true when the @ref assh_event_get function will not
    report more events. */
ASSH_INLINE assh_bool_t
assh_session_closed(struct assh_session_s *s)
{
  return s->tr_st == ASSH_TR_CLOSED;
}

#endif

