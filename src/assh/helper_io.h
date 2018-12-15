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

#include <stdio.h>

/** @This can be used to handle the @ref ASSH_EVENT_READ and @ref
    ASSH_EVENT_WRITE events by reading from and writing to a file
    descriptor.

    @This takes care of calling the @ref assh_event_done function.
*/
void
assh_fd_event(struct assh_session_s *s,
	      struct assh_event_s *e, int fd);

/** @This read characters on the file descriptor until a new line is
    found. The terminal echo is disabled. Characters beyond the
    specified length are read but ignored. This function fails if the
    file descriptor is not a tty. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_fd_get_password(struct assh_context_s *c, const char **pass,
		     size_t max_len, int fd, assh_bool_t echo);

/** @This writes a string to the passed stream, filtering out terminal
    control characters. */
void
assh_print_string(FILE *out, const struct assh_cbuffer_s *str);

/** @This prints a list of algorithms selected by the kex exchange. */
void
assh_print_kex_details(struct assh_session_s *s, FILE *out,
		       const struct assh_event_s *event);

#endif