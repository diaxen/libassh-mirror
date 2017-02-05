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

#include <assh/assh_prng.h>

#include <unistd.h>
#include <poll.h>
#include <sys/fcntl.h>

static ASSH_PRNG_INIT_FCN(assh_prng_dev_random_init)
{
  c->prng_pvl = -1;
  return ASSH_OK;
}

static ASSH_PRNG_GET_FCN(assh_prng_dev_random_get)
{
  assh_error_t err;
  int fd = c->prng_pvl;

  if (fd < 0)
    {
      fd = open("/dev/random", O_RDONLY);
      ASSH_RET_IF_TRUE(fd < 0, ASSH_ERR_IO);

      struct pollfd fds = {
	.fd = fd,
	.events = POLLIN,
      };

      /* get random from /dev/random in case we need to wait for more
	 entropy, typically after system startup. */
      if (poll(&fds, 1, 0) == 1)
	{
	  /* get random from /dev/urandom instead from now if the
	     entropy pool is not empty. */
	  int fd2 = open("/dev/urandom", O_RDONLY);
	  if (fd2 >= 0)
	    {
	      close(fd);
	      fd = fd2;
	    }

	  /* keep random source for next call */
	  c->prng_pvl = fd;
	}
    }

  size_t l = rdata_len;
  while (l)
    {
      int r = read(fd, rdata, l);
      ASSH_JMP_IF_TRUE(r <= 0, ASSH_ERR_IO, end);
      l -= r;
      rdata += r;
    }

  err = ASSH_OK;
 end:
  if (c->prng_pvl != fd)
    close(fd);

  return err;
}

static ASSH_PRNG_CLEANUP_FCN(assh_prng_dev_random_cleanup)
{
  if (c->prng_pvl >= 0)
    close(c->prng_pvl);
}

const struct assh_prng_s assh_prng_dev_random =
{
  .f_init = assh_prng_dev_random_init,
  .f_get = assh_prng_dev_random_get,
  .f_cleanup = assh_prng_dev_random_cleanup,
};

