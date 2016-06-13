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
*/

#ifndef ASSH_SESSION_H_
#define ASSH_SESSION_H_

#include "assh_transport.h"
#include "assh_queue.h"

/** @see assh_kex_filter_t */
#define ASSH_KEX_FILTER_FCN(n)                          \
  assh_bool_t (n)(struct assh_session_s *s,             \
                  const struct assh_algo_s *algo,       \
                  const struct assh_algo_name_s *name,  \
                  assh_bool_t out)

/** This is a per session algorithm filtering function.

    True must be returned in order to make the algorithm available for
    the session. The result of this function must not vary for a given
    algorithm unless the @ref assh_session_algo_filter function has
    been called successfully.

    The @tt out parameter specifies the direction and is relevant for
    cipher, mac and compression algorithms. */
typedef ASSH_KEX_FILTER_FCN(assh_kex_filter_t);

/** @internalmembers @This is the session context structure. */
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
  /** Requested service. */
  const struct assh_service_s *srv_rq;
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

  /** Size of valid data in the @ref stream_in_pck packet */
  size_t stream_in_size:32;
  /** Size of already sent data of the top packet in the @ref out_queue queue. */
  size_t stream_out_size:32;

  /** Input packet sequence number */
  uint32_t in_seq;
  /** Output packet sequence number */
  uint32_t out_seq;

  /** Current input ssh stream header buffer. */
  uint8_t stream_in_pck_head[ASSH_MAX_BLOCK_SIZE];

  /** Session id is first "exchange hash" H */
  uint8_t session_id[ASSH_MAX_HASH_SIZE];
  /** Session id length */
  size_t session_id_len:8;

  /** Copy of the ident string sent by the remote host. */
  uint8_t ident_str[255];
  /** Size of the ident string sent by the remote host. */
  size_t ident_len:8;

#ifdef CONFIG_ASSH_CLIENT
  /** Index of the next service to request in the context services array. */
  size_t srv_index:6;
#endif

  /** Currrent output ssh stream generator state. */
  enum assh_stream_out_state_e stream_out_st:3;

  /** Current input ssh stream parser state. */
  enum assh_stream_in_state_e stream_in_st:3;

  /** Current state of the transport layer. */
  enum assh_transport_state_e tr_st:3;

  /** This flag indicates if we have to skip the first kex packet from
      the remote side. */
  assh_bool_t kex_bad_guess:1;
};

/** @This set the user private pointer of the session. */
ASSH_INLINE void
assh_session_set_pv(struct assh_session_s *ctx,
                    void *private)
{
  ctx->user_pv = private;
}

/** @This get the user private pointer of the session. */
ASSH_INLINE void *
assh_session_get_pv(struct assh_session_s *ctx)
{
  return ctx->user_pv;
}

/** @This initializes a new ssh session object. When a stable ABI is
    needed, use the @ref assh_context_create function instead. This
    can be used to initialize a statically allocated session
    object. The @tt alloc parameter may be @tt NULL. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_session_init(struct assh_context_s *c,
		  struct assh_session_s *s);

/** @This allocates and initializes a ssh session. The @tt alloc
    parameter may be @tt NULL. @see assh_session_init */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_session_create(struct assh_context_s *c,
		    struct assh_session_s **s);

/** @This cleanups a ssh session object. */
void assh_session_cleanup(struct assh_session_s *s);

/** @This cleanups and releases a session created by the @ref
    assh_session_create function. */
void assh_session_release(struct assh_session_s *s);

/** @internal This changes the session state according to the provided
    error code and associated severity level.

    This function returns the original error code but the error
    severity level may be increased. This function is responsible for
    sending the session close message to the remote hsot.

    This function is called from the @ref assh_event_get, @ref
    assh_event_done and @ref assh_event_table_run functions. It is
    also called from other functions of the public API which can
    modify the session state.

    @see assh_error_e @see assh_error_severity_e
*/
assh_error_t assh_session_error(struct assh_session_s *s, assh_error_t err);

/** @This returns the current session safety factor which depends on
    algorithms chosen during the last key exchange. The safety
    factor may change during the session lifetime.
    @see assh_algo_register_va
*/
assh_safety_t assh_session_safety(struct assh_session_s *s);

/** @This setups a per session algorithm filter. The @tt filter
    parameter may be @tt NULL to disable filtering. It will fail if a
    key exchange in ongoing. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_session_algo_filter(struct assh_session_s *s,
                         assh_kex_filter_t *filter);

#endif

