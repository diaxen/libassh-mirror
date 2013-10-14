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


#ifndef ASSH_HELPER_FD_H_
#define ASSH_HELPER_FD_H_

#include "assh_event.h"

/** This function keeps calling the read system call until the buffer
    if filled with the requested amount of data. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_fd_read(int fd, void *data, size_t size);

/** This function keeps calling the write system call until the whole
    buffer has been processed. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_fd_write(int fd, const void *data, size_t size);

/** This function returns the next event just like the @ref
    assh_event_get function but the @ref ASSH_EVENT_IDLE, @ref
    ASSH_EVENT_READ and @ref ASSH_EVENT_WRITE events are processed
    internally by transferring data using the specified file
    descriptor. If the @tt rand_fd parameter is not negative, the @ref
    ASSH_EVENT_RANDOM is also handled by reading random data from a
    file descriptor. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_fd_event_get(struct assh_session_s *s,
		  int ssh_fd, int rand_fd,
		  struct assh_event_s *event);

#endif

