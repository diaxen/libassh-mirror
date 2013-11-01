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

#include "assh_event.h"

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
assh_transport_dispatch(struct assh_session_s *s,
			struct assh_packet_s *p,
			struct assh_event_s *e);

/** @internal This function returns the address and size of the buffer
    which contains the next ssh binary output stream. This function
    returns @ref ASSH_NO_DATA if no data is available yet. The @ref
    assh_tr_stream_out_done function must be called once the data has
    been processed. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_event_write(struct assh_session_s *s,
		 const void **data, size_t *size);

/** @internal This function must be called to indicate that a @ref
    ASSH_EVENT_WRITE event has been processed. */
ASSH_EVENT_DONE_FCN(assh_event_write_done);

/** @internal This function returns the address and size of the buffer
    where the next ssh binary input data must be stored. This function
    returns @ref ASSH_NO_DATA if no data needs to be read yet. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_event_read(struct assh_session_s *s,
		void **data, size_t *size);

/** @internal This function must be called to indicate that either a
    @ref ASSH_EVENT_IDLE or @ref ASSH_EVENT_READ event has been
    processed. */
ASSH_EVENT_DONE_FCN(assh_event_read_done);

#endif

