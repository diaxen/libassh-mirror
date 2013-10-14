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


#ifndef ASSH_EVENT_H_
#define ASSH_EVENT_H_

#include "assh.h"

enum assh_event_id_e
{
  ASSH_EVENT_INVALID,

  /** This event is returned when there is nothing to do. The fields
      in @ref assh_event_s::read provide a buffer which can be
      filled with ssh stream data, if the requested amount is
      available. When this is the case, the @ref assh_event_done
      function can be called to indicate that the data have been read
      in the buffer. */
  ASSH_EVENT_IDLE,

  /** This event is returned when some ssh stream data are needed. The
      fields in @ref assh_event_s::read provide a buffer which
      must be filled with incoming data. The @ref assh_event_done
      function must be called once the data have been copied in the
      buffer, before requesting the next event. */
  ASSH_EVENT_READ,

  /** This event is returned when some ssh output stream data are
      available. The fields in @ref assh_event_s::write provide
      a buffer which contain the output data. The @ref
      assh_event_done function must be called once the output
      data have been sent, before requesting the next event. */
  ASSH_EVENT_WRITE,

  /** This event is returned when the prng needs some entropy. The
      @ref assh_event_s::random::data field must be updated to point
      to a buffer containing random data before calling the @ref
      assh_event_done function. The @ref assh_event_s::random::size
      field gives the amount of requested data; it can be updated
      too if the amount of available random data is different. */
  ASSH_EVENT_RANDOM,

#ifdef CONFIG_ASSH_CLIENT
  /** This event is returned when a client needs to lookup a server host
      key in the local database. The @ref assh_event_s::hostkey_lookup::accept
      field must be updated accordingly before calling the
      @ref assh_event_done function. */
  ASSH_EVENT_HOSTKEY_LOOKUP,
#endif
};

#define ASSH_EVENT_DONE_FCN(n) assh_error_t (n)(struct assh_session_s *s, \
						struct assh_event_s *e)
typedef ASSH_EVENT_DONE_FCN(assh_event_done_t);

struct assh_event_s
{
  /** Event id */
  enum assh_event_id_e id;

  /** Pointer to the event acknowledge function, if any. */
  assh_event_done_t *f_done;
  /** Private data for the event acknowledge function. */
  void *done_pv;

  /** Parameters for the @ref ASSH_EVENT_IDLE and @ref ASSH_EVENT_READ events */
  struct {
    void *data;
    size_t size;
  }                    read;

  /** Parameters for the @ref ASSH_EVENT_WRITE event */
  struct {
    const void *data;
    size_t size;
  }                    write;

  /** Parameters for the @ref ASSH_EVENT_RANDOM event */
  struct {
    const void *data;
    size_t size;
  }                    random;

#ifdef CONFIG_ASSH_CLIENT
  /** Parameters for the @ref ASSH_EVENT_HOSTKEY_LOOKUP event */
  struct {
    struct assh_key_s *key;
    assh_bool_t        accept;
  }                    hostkey_lookup;
#endif
};

/** This function runs the various state machines which implement the
    ssh protocol and returns the next event in queue. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_event_get(struct assh_session_s *s,
               struct assh_event_s *e);

/** This function acknowledge the last event returned by the @ref
    assh_event_get function. */
static inline ASSH_WARN_UNUSED_RESULT assh_error_t
assh_event_done(struct assh_session_s *s,
                struct assh_event_s *e)
{
  if (e->f_done != NULL)
    return e->f_done(s, e);
  return ASSH_OK;
}

/** @internal This function must be called to indicate that either a
    @ref ASSH_EVENT_IDLE or @ref ASSH_EVENT_READ event has been
    processed. */
ASSH_WARN_UNUSED_RESULT
ASSH_EVENT_DONE_FCN(assh_event_read_done);

/** @internal This function must be called to indicate that a @ref
    ASSH_EVENT_WRITE event has been processed. */
ASSH_WARN_UNUSED_RESULT
ASSH_EVENT_DONE_FCN(assh_event_write_done);

/** @internal This function must be called to indicate that a @ref
    ASSH_EVENT_RANDOM event has been processed. */
ASSH_WARN_UNUSED_RESULT
ASSH_EVENT_DONE_FCN(assh_event_random_done);

/** @internal */
assh_error_t assh_event_process_packet(struct assh_session_s *s,
				       struct assh_packet_s *p,
				       struct assh_event_s *e);

/** @internal This function returns the address and size of the buffer
    which contains the next ssh binary output stream. This function
    returns @ref ASSH_NO_DATA if no data is available yet. The @ref
    assh_tr_stream_out_done function must be called once the data has
    been processed. */
assh_error_t assh_event_write(struct assh_session_s *s,
			      const void **data, size_t *size);

/** @internal This function returns the address and size of the buffer
    where the next ssh binary input data must be stored. This function
    returns @ref ASSH_NO_DATA if no data needs to be read yet. */
assh_error_t assh_event_read(struct assh_session_s *s,
			     void **data, size_t *size);

#endif

