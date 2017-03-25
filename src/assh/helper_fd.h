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
   @short IO using UNIX file descriptor
*/

#ifndef ASSH_HELPER_FD_H_
#define ASSH_HELPER_FD_H_

#include "assh.h"

/** @This can be used to handle the @ref ASSH_EVENT_READ event by
    reading data from a file descriptor. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_fd_event_read(struct assh_session_s *s,
                   struct assh_event_s *e, int fd);

/** @This can be used to handle the @ref ASSH_EVENT_WRITE event by
    writing data to a file descriptor. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_fd_event_write(struct assh_session_s *s,
                    struct assh_event_s *e, int fd);

#endif
