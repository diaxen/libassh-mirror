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

#ifndef ASSH_SESSION_H_
#define ASSH_SESSION_H_

#include "assh.h"

/** This specifies the current status of an ssh session. */
enum assh_transport_state_e
{
  ASSH_TR_KEX_INIT,         //< We will send a KEX_INIT packet.
  ASSH_TR_KEX_WAIT,         //< We wait for a KEX_INIT packet.
  ASSH_TR_KEX_WAIT_REPLY,   //< We wait for a KEX_INIT packet and send a KEX_INIT packet.
  ASSH_TR_KEX_RUNNING,     //< Both KEX_INIT packet were sent, the key exchange is taking place.
  ASSH_TR_NEWKEY,       //< The key exchange is over and a @ref SSH_MSG_NEWKEYS packet is expected.
  ASSH_TR_SERVICE,      //< No key exchange is running, service packets are allowed.
  ASSH_TR_DISCONNECTED, //< Disconnected.
  ASSH_TR_ERROR,        //< Session in error state. Can not be used anymore.
};

enum assh_stream_in_state_e
{
  ASSH_TR_IN_HELLO,
  ASSH_TR_IN_HELLO_DONE,
  ASSH_TR_IN_HEAD,
  ASSH_TR_IN_PAYLOAD,
  ASSH_TR_IN_PAYLOAD_DONE,
};

enum assh_stream_out_state_e
{
  ASSH_TR_OUT_HELLO,
  ASSH_TR_OUT_HELLO_DONE,
  ASSH_TR_OUT_PACKETS,
  ASSH_TR_OUT_PACKETS_DONE,
};

struct assh_session_s
{
  struct assh_context_s *ctx;

  /** Key exchange current state. */
  enum assh_transport_state_e tr_st;

  /** Key exchange algorithm. This pointer is setup when the @ref
      assh_kex_got_init select a new key exchange algorithm. */
  const struct assh_algo_kex_s *kex;
  /** Key exchange private context used during key exchange
      only. Freed on sessions cleanup if not @tt NULL. */
  void *kex_pv;

  /** Pointer to the last key exechange packet sent by client. Valid
      during key exechange. Freed on sessions cleanup if not @tt NULL. */
  struct assh_packet_s *kex_init_local;
  /** Pointer to the last key exechange packet sent by client. Valid
      during key exechange. Freed on sessions cleanup if not @tt NULL. */
  struct assh_packet_s *kex_init_remote;

  /** Session id is first "exchange hash" H */
  uint8_t session_id[ASSH_MAX_HASH_SIZE];
  size_t session_id_len;

  /** Input packet sequence number */
  uint32_t in_seq;
  /** Output packet sequence number */
  uint32_t out_seq;

  /** Pointer to keys and algorithms in current use, if any. */
  struct assh_kex_keys_s *cur_keys_in;
  struct assh_kex_keys_s *cur_keys_out;
  /** Pointer to next keys and algorithms to use when a New Keys packet is received. */
  struct assh_kex_keys_s *new_keys_in;
  struct assh_kex_keys_s *new_keys_out;

  /** host keys signature algorithm */
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

  /** Current ssh input packet. This packet is the last deciphered
      packets and is waiting for dispatch and processing. */
  struct assh_packet_s *in_pck;
  /** Queue of ssh output packets. Packets in this queue will be
      enciphered and sent. */
  struct assh_queue_s out_queue;
  /** Alternate queue of ssh output packets, used to store services
      packets during a key exechange. */
  struct assh_queue_s alt_queue;

  /** Copy of the hello string sent by the remote host. */
  uint8_t hello_str[255];
  /** Size of the hello string sent by the remote host. */
  int hello_len;

  /** Currrent output ssh stream generator state. */
  enum assh_stream_out_state_e stream_out_st;
  /** Current input ssh stream parser state. */
  enum assh_stream_in_state_e stream_in_st;
  /** Current input ssh stream header buffer. */
  uint8_t stream_in_pck_head[16];
  /** Current input ssh stream packet. This packet is currently being
      read from the input ssh stream and has not yet been deciphered. */
  struct assh_packet_s *stream_in_pck;
};

/** This function initialize a new ssh session object. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_session_init(struct assh_context_s *c,
		  struct assh_session_s *s);

/** This function cleanup a ssh session object. */
void assh_session_cleanup(struct assh_session_s *s);

#endif

