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

#include "assh.h"
#include "assh_queue.h"

/** @internal @This specifies the transport status of an ssh session. */
enum assh_transport_state_e
{
  /** send a @ref SSH_MSG_KEXINIT packet then go to @ref ASSH_TR_KEX_WAIT */
  ASSH_TR_KEX_INIT,
  /** We wait for a @ref SSH_MSG_KEXINIT packet. */
  ASSH_TR_KEX_WAIT,
  /** Both @ref SSH_MSG_KEXINIT packet were sent, the key exchange is taking place. */
  ASSH_TR_KEX_RUNNING,
  /** The key exchange is over and a @ref SSH_MSG_NEWKEYS packet is expected. */
  ASSH_TR_NEWKEY,
  /** No key exchange is running, service packets are allowed. */
  ASSH_TR_SERVICE,
  /** Key re-exchange packet sent but not received, service packets are allowed. */
  ASSH_TR_SERVICE_KEX,
  /** Do not exchange packets with the remote side anymore. Report last events. */
  ASSH_TR_FIN,
  /** Session closed, no more event will be reported. */
  ASSH_TR_CLOSED,
};

/** @internal @This specifies state of the input stream parser */
enum assh_stream_in_state_e
{
  ASSH_TR_IN_IDENT,
  ASSH_TR_IN_IDENT_DONE,
  ASSH_TR_IN_HEAD,
  ASSH_TR_IN_HEAD_DONE,
  ASSH_TR_IN_PAYLOAD,
  ASSH_TR_IN_PAYLOAD_DONE,
};

/** @internal @This specifies state of the output stream generator */
enum assh_stream_out_state_e
{
  ASSH_TR_OUT_IDENT,
  ASSH_TR_OUT_IDENT_PAUSE,
  ASSH_TR_OUT_IDENT_DONE,
  ASSH_TR_OUT_PACKETS,
  ASSH_TR_OUT_PACKETS_ENCIPHERED,
  ASSH_TR_OUT_PACKETS_PAUSE,
  ASSH_TR_OUT_PACKETS_DONE,
};

/** @internalmembers @This is the session context structure. */
struct assh_session_s
{
  /** Pointer to associated main context. */
  struct assh_context_s *ctx;

  /** Current state of the transport layer. */
  enum assh_transport_state_e tr_st;

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

  /** amount of data transfered since last kex */
  uint32_t kex_bytes;

  /** kex re-exchange threshold */
  uint32_t kex_max_bytes;

  /** This flag indicates if we have to skip the first kex packet from
      the remote side. */
  assh_bool_t kex_bad_guess;

  /** Session id is first "exchange hash" H */
  uint8_t session_id[ASSH_MAX_HASH_SIZE];
  /** Session id length */
  size_t session_id_len;

  /** Copy of the ident string sent by the remote host. */
  uint8_t ident_str[255];
  /** Size of the ident string sent by the remote host. */
  int ident_len;

  /** Host keys signature algorithm */
  const struct assh_algo_sign_s *host_sign_algo;

#ifdef CONFIG_ASSH_CLIENT
  /** Index of the next service to request in the context services array. */
  unsigned int srv_index;
  /** Requested service. */
  const struct assh_service_s *srv_rq;
#endif
  /** Current service. */
  const struct assh_service_s *srv;
  /** Current service private data. */
  void *srv_pv;

  /** User private pointer */
  void *pv;

  /****************** ssh output stream state */

  /** Currrent output ssh stream generator state. */
  enum assh_stream_out_state_e stream_out_st;

  /** Queue of ssh output packets. Packets in this queue will be
      enciphered and sent. */
  struct assh_queue_s out_queue;
  /** Alternate queue of ssh output packets, used to store services
      packets during a key exchange. */
  struct assh_queue_s alt_queue;
  /** Size of already sent data of the top packet in the @ref out_queue queue. */
  size_t stream_out_size;

  /** Pointer to output keys and algorithms in current use. */
  struct assh_kex_keys_s *cur_keys_out;
  /** Pointer to next output keys and algorithms on SSH_MSG_NEWKEYS transmitted. */
  struct assh_kex_keys_s *new_keys_out;
  /** Output packet sequence number */
  uint32_t out_seq;

  /****************** ssh input stream state */

  /** Current input ssh stream parser state. */
  enum assh_stream_in_state_e stream_in_st;

  /** Current input ssh stream header buffer. */
  uint8_t stream_in_pck_head[ASSH_MAX_BLOCK_SIZE];
  /** Current input ssh stream packet. This packet is currently being
      read from the input ssh stream and has not yet been deciphered. */
  struct assh_packet_s *stream_in_pck;
  /** Size of valid data in the @ref stream_in_pck packet */
  size_t stream_in_size;

  /** Current ssh input packet. This packet is the last deciphered
      packets and is waiting for dispatch and processing. */
  struct assh_packet_s *in_pck;

  /** Pointer to input keys and algorithms in current use. */
  struct assh_kex_keys_s *cur_keys_in;
  /** Pointer to next input keys and algorithms on SSH_MSG_NEWKEYS received. */
  struct assh_kex_keys_s *new_keys_in;
  /** Input packet sequence number */
  uint32_t in_seq;
};

/** @This set the user private pointer of the session. */
ASSH_INLINE void
assh_session_set_pv(struct assh_session_s *ctx,
                    void *private)
{
  ctx->pv = private;
}

/** @This get the user private pointer of the session. */
ASSH_INLINE void *
assh_session_get_pv(struct assh_session_s *ctx)
{
  return ctx->pv;
}

/** @internal This changes the current transport state */
ASSH_INLINE void assh_transport_state(struct assh_session_s *s,
                                        enum assh_transport_state_e st)
{
#ifdef CONFIG_ASSH_DEBUG_PROTOCOL
  ASSH_DEBUG("transport state=%u\n", st);
#endif
  s->tr_st = st;
}

/** @This initializes a new ssh session object. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_session_init(struct assh_context_s *c,
		  struct assh_session_s *s);

/** @This cleanups a ssh session object. */
void assh_session_cleanup(struct assh_session_s *s);

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

#endif

