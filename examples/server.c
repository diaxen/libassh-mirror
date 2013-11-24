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

#include <assh/assh_session.h>
#include <assh/assh_context.h>
#include <assh/assh_service.h>
#include <assh/assh_prng.h>
#include <assh/helper_fd.h>
#include <assh/helper_key.h>
#include <assh/assh_event.h>
#include <assh/assh_algo.h>

#ifdef CONFIG_ASSH_USE_GCRYPT
# include <gcrypt.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>

int main()
{
#ifdef CONFIG_ASSH_USE_GCRYPT
  if (!gcry_check_version(GCRYPT_VERSION))
    return -1;
#endif

  int sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  assert(sock >= 0);

  int		tmp = 1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(tmp));

  struct sockaddr_in	addr = 
    {
      .sin_port = htons(22222),
      .sin_family = AF_INET,
    };

  if (bind(sock, (struct sockaddr*)&addr, sizeof (struct sockaddr_in)) < 0)
    abort();

  if (listen(sock, 8) < 0)
    abort();


  struct assh_context_s context;
  assh_context_init(&context, ASSH_SERVER);

  if (assh_service_register_default(&context))
    return -1;

  if (assh_algo_register_default(&context) != ASSH_OK)
    return -1;

  if (assh_context_prng(&context, &assh_prng_xswap) != ASSH_OK)
    return -1;

  if (assh_load_hostkey_filename(&context, "ssh-dss", "host_keys",
				 ASSH_KEY_FMT_PV_RFC2440_PEM_ASN1) != ASSH_OK)
    return -1;

  signal(SIGPIPE, SIG_IGN);

  int rnd_fd = open("/dev/urandom", O_RDONLY);
  assert(rnd_fd >= 0);

  while (1)
    {
      struct sockaddr_in con_addr;
      socklen_t addr_size = sizeof(con_addr);

      int conn = accept(sock, (struct sockaddr*)&con_addr, &addr_size);

      struct assh_session_s session;
      if (assh_session_init(&context, &session) != ASSH_OK)
	return -1;

      time_t t = time(0);
      fprintf(stderr, "============== %s\n", ctime(&t));

      fprintf(stderr, "assh loop\n");
      while (1)
	{
	  struct assh_event_s event;

	  assh_error_t err = assh_fd_event_get(&session, conn, rnd_fd, &event);
	  if (ASSH_ERR_ERROR(err) != ASSH_OK)
	    {
	      fprintf(stderr, "assh error %i in main loop (errno=%i)\n", err, errno);

	      if (ASSH_ERR_ERROR(err) == ASSH_ERR_DISCONNECTED)
		{
		  close(conn);
		  break;
		}

	      continue;
	    }

	  switch (event.id)
	    {
	    case ASSH_EVENT_USERAUTH_SERVER_USERKEY: {
	      /* XXX check that event public key is in the list of
		 user authorized keys. */
	      event.userauth_server.userkey.found = 1;
	      break;
	    }

	    case ASSH_EVENT_USERAUTH_SERVER_PASSWORD:
	      /* XXX check that event user/password pair matches. */
	      event.userauth_server.password.success = 1;
	      break;

	    default:
	      assert(!"Don't know how to handle this event");
	    }

	  err = assh_event_done(&session, &event);
	  if (ASSH_ERR_ERROR(err) != ASSH_OK)
	    fprintf(stderr, "assh error %i in main loop (errno=%i)\n", err, errno);
	}

      assh_session_cleanup(&session);
      break;
    }

  assh_context_cleanup(&context);

  return 0;
}

