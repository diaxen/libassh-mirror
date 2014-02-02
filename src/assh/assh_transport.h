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


#ifndef ASSH_TRANSPORT_H_
#define ASSH_TRANSPORT_H_

#ifdef ASSH_EVENT_H_
# warning The assh/assh_event.h header should be included after assh_transport.h
#endif

#include "assh.h"

/** The @ref ASSH_EVENT_READ event is returned when more incoming ssh
    stream data from the remote host is needed to complete the current
    input packet.

    The @ref buf field have to be filled with incoming data
    stream. The @ref assh_event_done function must be called once the
    data have been copied to the buffer and the @ref transferred field
    have been set to 1.

    If not enough data is available yet, the event can still be
    acknowledged by calling the @ref assh_event_done function without
    setting the @ref transferred field. The buffer will remain valid and
    will be provided again the next time this event is returned. This
    allows filling the buffer as more data become available, even
    after calling @ref assh_event_done.
*/
struct assh_event_transport_read_s
{
  const struct assh_buffer_s buf;
  size_t                     transferred;
};

/** The @ref ASSH_EVENT_WRITE event is returned when some ssh stream
    data is available for sending to the remote host. The @ref buf
    field provides a buffer which contain the output data. The @ref
    assh_event_done function must be called once the output data have
    been sent.

    If no data can be sent yet, the event can still be acknowledged by
    calling the @ref assh_event_done without setting the @ref
    transferred field.  The buffer will remain valid and will be
    provided again the next time this event is returned. This allows
    sending the buffer even after calling @ref assh_event_done.
*/
struct assh_event_transport_write_s
{
  const struct assh_buffer_s buf;
  size_t                     transferred;
};

/** @internal */
union assh_event_transport_u
{
  struct assh_event_transport_read_s  read;
  struct assh_event_transport_write_s write;
};

/** @internal */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_transport_disconnect(struct assh_session_s *s, uint32_t code);

/** @internal This function puts a packet in the output queue. The
    packet will be released once it has been enciphered and sent. */
void assh_transport_push(struct assh_session_s *s,
			 struct assh_packet_s *p);

/** @internal This function dispatches incoming packets depending
    on packet message id and transport internal state. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_transport_write(struct assh_session_s *s,
                     struct assh_event_s *e);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_transport_read(struct assh_session_s *s,
                    struct assh_event_s *e);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_transport_dispatch(struct assh_session_s *s,
			struct assh_packet_s *p,
			struct assh_event_s *e);

/** @internal This function returns the address and size of the buffer
    which contains the next ssh binary output stream. This function
    returns @ref ASSH_NO_DATA if no data is available yet. The @ref
    assh_tr_stream_out_done function must be called once the data has
    been processed. */
/** @internal This function returns the address and size of the buffer
    where the next ssh binary input data must be stored. This function
    returns @ref ASSH_NO_DATA if no data needs to be read yet. */
#endif

