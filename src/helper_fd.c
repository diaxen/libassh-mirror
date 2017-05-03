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
#include <assh/assh_event.h>

#include <termios.h>

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_fd_get_password(struct assh_context_s *c, const char **pass,
		     size_t max_len, int fd, assh_bool_t echo)
{
  struct termios t;
  assh_error_t err;
  char *p;
  int_fast8_t i = 0;

  ASSH_RET_IF_TRUE(!isatty(fd), ASSH_ERR_IO);

  ASSH_RET_ON_ERR(assh_alloc(c, max_len, ASSH_ALLOC_SECUR, (void**)&p));
  *pass = p;

  if (!echo)
    {
      tcgetattr(fd, &t);
      t.c_lflag &= ~ECHO;
      tcsetattr(fd, 0, &t);
    }

  while (1)
    {
      char c;
      ssize_t r = read(fd, &c, 1);

      ASSH_JMP_IF_TRUE(r != 1, ASSH_ERR_IO, err_);

      switch (c)
        {
        case '\n':
        case '\r':
          p[i] = 0;
	  err = ASSH_OK;
	  goto done;
        default:
          if (i + 1 < max_len)
            p[i++] = c;
        }
    }

 err_:
  assh_free(c, p);
 done:
  if (!echo)
    {
      t.c_lflag |= ECHO;
      tcsetattr(fd, 0, &t);
    }
  return err;
}

void
assh_fd_event(struct assh_session_s *s,
              struct assh_event_s *e, int fd)
{
  assh_error_t err = ASSH_OK;

  switch (e->id)
    {
    case ASSH_EVENT_READ: {
      struct assh_event_transport_read_s *te = &e->transport.read;
      ssize_t r = read(fd, te->buf.data, te->buf.size);
      switch (r)
        {
        case -1:
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            break;
        case 0:
          err = ASSH_ERR_IO | ASSH_ERRSV_FIN;
          goto err_;
        default:
          te->transferred = r;
          break;
        }
      break;
    }

    case ASSH_EVENT_WRITE: {
      struct assh_event_transport_write_s *te = &e->transport.write;
      ssize_t r = write(fd, te->buf.data, te->buf.size);
      switch (r)
        {
        case -1:
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            break;
        case 0:
          err = ASSH_ERR_IO | ASSH_ERRSV_FIN;
          goto err_;
        default:
          te->transferred = r;
          break;
        }
      break;
    }

    default:
      abort();
    }

 err_:
  assh_event_done(s, e, err);
}

