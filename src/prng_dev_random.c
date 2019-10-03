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
#include <assh/assh_alloc.h>

#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <sys/fcntl.h>

struct assh_prng_pv_s
{
  int rfd;
  int ufd;
};

static ASSH_PRNG_INIT_FCN(assh_prng_dev_random_init)
{
  assh_status_t err;

  ASSH_RET_ON_ERR(assh_alloc(c, sizeof(struct assh_prng_pv_s),
                          ASSH_ALLOC_INTERNAL, &c->prng_pv));
  struct assh_prng_pv_s *pv = c->prng_pv;
  pv->rfd = pv->ufd = -1;

  return ASSH_OK;
}

static ASSH_PRNG_GET_FCN(assh_prng_dev_random_get)
{
  struct assh_prng_pv_s *pv = c->prng_pv;
  assh_status_t err;

  if (pv->ufd < 0 && pv->rfd < 0)
    {
      pv->rfd = open("/dev/random", O_RDONLY);
      ASSH_RET_IF_TRUE(pv->rfd < 0, ASSH_ERR_IO);
    }

  if (pv->ufd < 0)
    {
      struct pollfd fds = {
	.fd = pv->rfd,
	.events = POLLIN,
      };

      /* get random from /dev/random in case we need to wait for more
	 entropy, typically after system startup. */
      if (poll(&fds, 1, 0) == 1)
	{
	  /* get random from /dev/urandom instead from now if the
	     entropy pool is not empty. */
	  pv->ufd = open("/dev/urandom", O_RDONLY);
	  if (pv->ufd >= 0)
	    {
	      close(pv->rfd);
	      pv->rfd = -1;
	    }
	}
    }

  int fd = pv->ufd >= 0 ? pv->ufd : pv->rfd;
  size_t l = rdata_len;

  while (l)
    {
      int r = read(fd, rdata, l);

      if (r < 0)
	{
	  if (errno == EAGAIN)
	    continue;

	  close(fd);
	  pv->ufd = pv->rfd = -1;
	  ASSH_RETURN(ASSH_ERR_IO);
	}

      l -= r;
      rdata += r;
    }

  return ASSH_OK;
}

static ASSH_PRNG_CLEANUP_FCN(assh_prng_dev_random_cleanup)
{
  struct assh_prng_pv_s *pv = c->prng_pv;

  if (pv->rfd >= 0)
    close(pv->rfd);
  if (pv->ufd >= 0)
    close(pv->ufd);

  assh_free(c, pv);
}

const struct assh_prng_s assh_prng_dev_random =
{
  .f_init = assh_prng_dev_random_init,
  .f_get = assh_prng_dev_random_get,
  .f_cleanup = assh_prng_dev_random_cleanup,
};

