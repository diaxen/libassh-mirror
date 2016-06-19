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

ASSH_EVENT_HANDLER_FCN(assh_fd_event_read)
{
  assh_error_t err;
  struct assh_fd_context_s *ctx_ = ctx;
  struct assh_event_transport_read_s *te = &e->transport.read;
  struct pollfd p;
  p.events = POLLIN | POLLPRI;
  p.fd = ctx_->ssh_fd;

  ASSH_DEBUG("read delay %u\n", te->delay);
  switch (poll(&p, 1, (int)te->delay * 1000))
    {
    case 0:
      te->transferred = 0;
      break;
    case 1: {
      ssize_t r = read(ctx_->ssh_fd, te->buf.data, te->buf.size);
      switch (r)
        {
        case -1:
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            break;
        case 0:
          ASSH_ERR_RET(ASSH_ERR_IO | ASSH_ERRSV_FIN);
        default:
          te->transferred = r;
          break;
        }
      break;
    }
    default:
      ASSH_ERR_RET(ASSH_ERR_IO | ASSH_ERRSV_FIN);
    }

  te->time = time(NULL);
  return ASSH_OK;
}

ASSH_EVENT_HANDLER_FCN(assh_fd_event_write)
{
  assh_error_t err;
  struct assh_fd_context_s *ctx_ = ctx;
  struct assh_event_transport_write_s *te = &e->transport.write;
  struct pollfd p;
  p.events = POLLOUT;
  p.fd = ctx_->ssh_fd;

  ASSH_DEBUG("write delay %u\n", te->delay);
  switch (poll(&p, 1, (int)te->delay * 1000))
    {
    case 0:
      te->transferred = 0;
      break;
    case 1: {
      ssize_t r = write(ctx_->ssh_fd, te->buf.data, te->buf.size);
      switch (r)
        {
        case -1:
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            break;
        case 0:
          ASSH_ERR_RET(ASSH_ERR_IO | ASSH_ERRSV_FIN);
        default:
          te->transferred = r;
          break;
        }
      break;
    }
    default:
      ASSH_ERR_RET(ASSH_ERR_IO | ASSH_ERRSV_FIN);
    }

  te->time = time(NULL);
  return ASSH_OK;
}

void assh_fd_events_register(struct assh_event_hndl_table_s *t,
			     struct assh_fd_context_s *ctx,
			     int ssh_fd)
{
  ctx->ssh_fd = ssh_fd;

  assh_event_table_register(t, ASSH_EVENT_READ, &ctx->h_read,
			    assh_fd_event_read, ctx);

  assh_event_table_register(t, ASSH_EVENT_WRITE, &ctx->h_write,
			    assh_fd_event_write, ctx);
}

