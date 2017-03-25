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

#include <unistd.h>
#include <errno.h>
#include <sys/fcntl.h>
#include <poll.h>

#include <assh/assh_session.h>
#include <assh/assh_transport.h>
#include <assh/assh_alloc.h>

#include <assh/helper_fd.h>

assh_error_t
assh_fd_event_read(struct assh_session_s *s,
                   struct assh_event_s *e, int fd)
{
  assh_error_t err;
  struct assh_event_transport_read_s *te = &e->transport.read;
  struct pollfd p;
  p.events = POLLIN | POLLPRI;
  p.fd = fd;

  ASSH_DEBUG("read delay %u\n", te->delay);
  switch (poll(&p, 1, (int)te->delay * 1000))
    {
    case 0:
      te->transferred = 0;
      break;
    case 1: {
      ssize_t r = read(fd, te->buf.data, te->buf.size);
      switch (r)
        {
        case -1:
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            break;
        case 0:
          ASSH_RETURN(ASSH_ERR_IO | ASSH_ERRSV_FIN);
        default:
          te->transferred = r;
          break;
        }
      break;
    }
    default:
      ASSH_RETURN(ASSH_ERR_IO | ASSH_ERRSV_FIN);
    }

  te->time = time(NULL);
  return ASSH_OK;
}

assh_error_t
assh_fd_event_write(struct assh_session_s *s,
                    struct assh_event_s *e, int fd)
{
  assh_error_t err;
  struct assh_event_transport_write_s *te = &e->transport.write;
  struct pollfd p;
  p.events = POLLOUT;
  p.fd = fd;

  ASSH_DEBUG("write delay %u\n", te->delay);
  switch (poll(&p, 1, (int)te->delay * 1000))
    {
    case 0:
      te->transferred = 0;
      break;
    case 1: {
      ssize_t r = write(fd, te->buf.data, te->buf.size);
      switch (r)
        {
        case -1:
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            break;
        case 0:
          ASSH_RETURN(ASSH_ERR_IO | ASSH_ERRSV_FIN);
        default:
          te->transferred = r;
          break;
        }
      break;
    }
    default:
      ASSH_RETURN(ASSH_ERR_IO | ASSH_ERRSV_FIN);
    }

  te->time = time(NULL);
  return ASSH_OK;
}


