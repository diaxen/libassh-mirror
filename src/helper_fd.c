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

#include <assh/helper_fd.h>

assh_error_t assh_fd_read(int fd, void *data, size_t size)
{
  assh_error_t err;
  ssize_t r;

  while (size > 0)
    {
      r = read(fd, data, size);

      switch (r)
        {
        case -1:
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            continue;
        case 0:
          ASSH_ERR_RET(ASSH_ERR_IO);
        default:
          size -= r;
          data = (uint8_t*)data + r;
        }
    }

  return ASSH_OK;
}

assh_error_t assh_fd_write(int fd, const void *data, size_t size)
{
  assh_error_t err;
  ssize_t r;

  while (size > 0)
    {
      r = write(fd, data, size);

      switch (r)
        {
        case -1:
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            continue;
        case 0:
          ASSH_ERR_RET(ASSH_ERR_IO);
        default:
          size -= r;
          data = (uint8_t*)data + r;
        }
    }

  return ASSH_OK;
}

assh_error_t assh_fd_event_get(struct assh_session_s *s,
			       int ssh_fd, int rand_fd,
			       struct assh_event_s *e)
{
  assh_error_t err;

  while (1)
    {
      ASSH_ERR_RET(assh_event_get(s, e));

      ASSH_DEBUG("event %u\n", e->id);

      switch (e->id)
        {
        case ASSH_EVENT_IDLE:
        case ASSH_EVENT_READ:
          ASSH_ERR_RET(assh_fd_read(ssh_fd, e->read.data, e->read.size));
          ASSH_ERR_RET(assh_event_done(s, e));
          break;

        case ASSH_EVENT_WRITE:
          ASSH_ERR_RET(assh_fd_write(ssh_fd, e->write.data, e->write.size));
          ASSH_ERR_RET(assh_event_done(s, e));
          break;

        case ASSH_EVENT_RANDOM: {
          if (rand_fd < 0)
            return ASSH_OK;
	  uint8_t data[e->random.size];
	  e->random.data = data;
	  ASSH_ERR_RET(assh_fd_read(rand_fd, data, e->random.size));
          ASSH_ERR_RET(assh_event_done(s, e));
	  break;
	}

	default:
	  return ASSH_OK;
        }
    }  
}

