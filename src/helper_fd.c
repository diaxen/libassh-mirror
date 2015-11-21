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

#include <assh/assh_session.h>
#include <assh/assh_transport.h>
#include <assh/assh_prng.h>
#include <assh/assh_alloc.h>

#include <assh/helper_fd.h>

ASSH_EVENT_HANDLER_FCN(assh_fd_event_read)
{
  assh_error_t err;
  struct assh_fd_context_s *ctx_ = ctx;
  struct assh_event_transport_read_s *te = &e->transport.read;
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
    }
  return ASSH_OK;
}

ASSH_EVENT_HANDLER_FCN(assh_fd_event_write)
{
  assh_error_t err;
  struct assh_fd_context_s *ctx_ = ctx;
  struct assh_event_transport_write_s *te = &e->transport.write;
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
    }
  return ASSH_OK;
}

ASSH_EVENT_HANDLER_FCN(assh_fd_event_prng_feed)
{
  assh_error_t err;
  struct assh_fd_context_s *ctx_ = ctx;

  ssize_t r = read(ctx_->rand_fd, e->prng.feed.buf, e->prng.feed.size);
  switch (r)
    {
    case -1:
      if (errno == EAGAIN || errno == EWOULDBLOCK)
	break;
    case 0:
      ASSH_ERR_RET(ASSH_ERR_IO | ASSH_ERRSV_FIN);
    default:
      e->prng.feed.size = r;
    }
  return ASSH_OK;
}

void assh_fd_events_register(struct assh_event_hndl_table_s *t,
			     struct assh_fd_context_s *ctx,
			     int ssh_fd, int rand_fd)
{
  ctx->ssh_fd = ssh_fd;

  assh_event_table_register(t, ASSH_EVENT_READ, &ctx->h_read,
			    assh_fd_event_read, ctx);

  assh_event_table_register(t, ASSH_EVENT_WRITE, &ctx->h_write,
			    assh_fd_event_write, ctx);

  if (rand_fd >= 0)
    {
      ctx->rand_fd = rand_fd;

      assh_event_table_register(t, ASSH_EVENT_PRNG_FEED, &ctx->h_prng_feed,
				assh_fd_event_prng_feed, ctx);
    }
}

assh_error_t assh_prng_fd_feed(struct assh_context_s *c,
                               int fd, size_t len)
{
  assh_error_t err;
  ASSH_SCRATCH_ALLOC(c, uint8_t, sc, len, ASSH_ERRSV_CONTINUE, err_);
  uint8_t *d = sc;
  size_t l = len;

  while (l)
    {
      int r = read(fd, d, l);
      ASSH_CHK_RET(r <= 0, ASSH_ERR_IO);
      l -= r;
      d += r;
    }

  ASSH_ERR_RET(assh_prng_feed(c, sc, len));

  err = ASSH_OK;
 err_:
  ASSH_SCRATCH_FREE(c, sc);
  return err;
}

assh_error_t assh_prng_file_feed(struct assh_context_s *c,
                                 const char *filename, size_t len)
{
  assh_error_t err;
  int rand_fd = open(filename, O_RDONLY);

  ASSH_CHK_RET(rand_fd < 0, ASSH_ERR_IO);
  ASSH_ERR_GTO(assh_prng_fd_feed(c, rand_fd, len), err_);

  err = ASSH_OK;
 err_:
  close(rand_fd);
  return err;
}

