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


#ifndef ASSH_CONNECTION_H_
#define ASSH_CONNECTION_H_

enum assh_cn_event_e
{
  ASSH_EV_GLOBAL_RQ,
  ASSH_EV_GLOBAL_RQ_RSP,
  ASSH_EV_CHANNEL_INDATA,
  ASSH_EV_CHANNEL_EOF,
  ASSH_EV_CHANNEL_CLOSED,
};

#define ASSH_CN_GLOBAL_EVENT(n) void n(struct assh_session_s *session,		\
				       enum assh_cn_event_e ev, void *ev_private, \
				       const void *data, size_t len);
typedef ASSH_CN_GLOBAL_EVENT(assh_cn_global_event_t);

#define ASSH_CN_CHANNEL_EVENT(n) void n(struct assh_channel_s *chan,		\
				     enum assh_cn_event_e ev, void *ev_private, \
				     const void *data, size_t len);
typedef ASSH_CN_CHANNEL_EVENT(assh_cn_channel_event_t);

/** This function setups the connection protocol events handler. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_cn_set_handler(struct session_s *s, assh_cn_global_event_t *ev, void *ev_private);

/** This function calls @ref assh_tr_packet_pop and handle connection protocol events. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_cn_process(struct session_s *s);

/** This function enqueues a global request packet. The channel
    state is changed to ASSH_CHANNEL_WAITING. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_cn_global_request(struct session_s *s, const char *name, int want_reply,
                       void *data, size_t size);

/** This function enqueues a channel open request packet. The channel
    state is changed to ASSH_CHANNEL_WAITING. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_cn_channel_open(struct chan_s *chan, void *data, size_t size,
                     assh_cn_channel_event_t *ev, void *ev_private);

/** This function enqueues a channel data packet. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_cn_channel_write(struct chan_s *chan, void *data, size_t size);

/** This function enqueues a channel eof packet. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_cn_channel_eof(struct chan_s *chan);

/** This function enqueues a channel close packet and changes the
    channel state to @ref ASSH_CHANNEL_CLOSE_SENT. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_cn_channel_close(struct chan_s *chan);

#endif

