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

enum assh_channel_status_e
{
  ASSH_CHANNEL_WAITING,
  ASSH_CHANNEL_OPENED,
  ASSH_CHANNEL_EOF_SENT,
  ASSH_CHANNEL_EOF_RECEIVED,
  ASSH_CHANNEL_CLOSE_SENT,
  ASSH_CHANNEL_CLOSED,
};

struct assh_channel_s
{
  struct assh_session_s *session;

  int chan_id, rchan_id;
  size_t max_pkt_size;
};

/** This function initializes a channel. The channel type string is
    not duplicated and must remain valid after the function call. The
    initial channel state is @ref ASSH_CHANNEL_CLOSED. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_channel_init(struct assh_channel_s *chan, struct assh_session_s *s,
                  const char *type, size_t max_pkt_size);

/** This function cleanup resources associated with a channel. The
    channel must be in @ref ASSH_CHANNEL_CLOSED state when this function
    is called. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_channel_cleanup(struct assh_channel_s *chan);

#endif

