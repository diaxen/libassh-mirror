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
typedef enum assh_session_status_e
{
  ASSH_STATE_HELLO,
  ASSH_STATE_KEX,
  ASSH_STATE_AUTH,
  ASSH_STATE_OPENED,
  ASSH_STATE_CLOSED,
} assh_session_status_t;

/** This specifies the current status of an ssh session. */
typedef enum assh_algo_kex_status_e
{
  ASSH_KEX_INIT,       //< will send a KEX_INIT packet
  ASSH_KEX_WAIT,       //< wait for a KEX_INIT packet
  ASSH_KEX_WAIT_REPLY, //< wait for a KEX_INIT packet and send a KEX_INIT packet
  ASSH_KEX_EXCHANGE,   //< both KEX_INIT packet were sent
  ASSH_KEX_NEWKEY,     //< 
  ASSH_KEX_DONE,       //< key exchange is over
} assh_algo_kex_status_t;

/** This specifies the type of ssh session. */
typedef enum assh_session_type_e
{
  ASSH_SERVER,
  ASSH_CLIENT,
} assh_session_type_t;

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
  /** Client/server session type. */
  assh_session_type_t type;

  struct assh_context_s *ctx;

  /** Key exchange current state. */
  assh_algo_kex_status_t kex_st;

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

  /** Service processing function, may be NULL. */
  assh_process_t *f_srv_process;

  /** Number of channels in the chans array. */
  size_t chans_size;
  /** Array of channels indexed by channel local id. */
  struct assh_channel_s *chans;

  /** Queue of ssh packets */
  struct assh_packet_s *in_packet;
  /** Queue of ssh packets */
  struct assh_queue_s out_queue;

  /** Copy of the hello string sent by the remote host. */
  uint8_t hello_str[255];
  /** Size of the hello string sent by the remote host. */
  int hello_len;

  /** Currrent output ssh stream generator state. */
  int stream_out_st;
  /** Current input ssh stream parser state. */
  int stream_in_st;
  /** Current input ssh stream buffer. */
  uint8_t stream_in_pck_head[16];
  /** Current input ssh stream packet. */
  struct assh_packet_s *stream_in_pck;
};

/** This function initialize a new ssh session object. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_session_init(struct assh_context_s *c,
		  struct assh_session_s *s,
		  enum assh_session_type_e type);

/** This function cleanup a ssh session object. */
void assh_session_cleanup(struct assh_session_s *s);

#endif

