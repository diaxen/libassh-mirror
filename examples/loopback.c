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

  As a special exception, for the purpose of developing applications
  using libassh, the content of the examples/server.c file may be
  freely reused without causing the resulting work to be covered by
  the GNU Lesser General Public License.

*/

/*
  This implements a tiny ssh server which accept session channels and
  echo data sent on such channels.
*/

#include "config.h"

#include <assh/assh_session.h>
#include <assh/assh_context.h>
#include <assh/assh_service.h>
#include <assh/assh_userauth_server.h>
#include <assh/assh_connection.h>
#include <assh/assh_kex.h>
#include <assh/assh_event.h>
#include <assh/assh_algo.h>
#include <assh/assh_packet.h>
#include <assh/key_eddsa.h>

#include <assh/helper_key.h>
#include <assh/helper_server.h>
#include <assh/helper_fd.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>

#define ERROR(...) do { fprintf(stderr, __VA_ARGS__); exit(1); } while (0)

int main(int argc, char **argv)
{
  /* perform initialization of third party libraries */
  if (assh_deps_init())
    ERROR("initialization error\n");

  /* create listening socket */
  int sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0)
    ERROR("Unable to create socket: %s\n", strerror(errno));

  int tmp = 1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(tmp));

  struct sockaddr_in addr =
    {
      .sin_port = htons(22222),
      .sin_family = AF_INET,
    };

  if (bind(sock, (struct sockaddr*)&addr, sizeof (struct sockaddr_in)) < 0)
    ERROR("Unable to bind: %s\n", strerror(errno));

  if (listen(sock, 8) < 0)
    ERROR("Unable to listen: %s\n", strerror(errno));

  /* init an assh server context */
  struct assh_context_s *context;

  fprintf(stderr, "Listening on port 22222\n");

  if (assh_context_create(&context, ASSH_SERVER,
			  NULL, NULL, NULL, NULL) != ASSH_OK ||
      assh_service_register_default(context) != ASSH_OK ||
      assh_algo_register_default(context, 50, 20, 0) != ASSH_OK)
    ERROR("Unable to create an assh context.\n");

  /* load or create host key(s) */
  if (assh_server_openssh_load_hk(context)
#ifdef CONFIG_ASSH_KEY_CREATE
      && assh_key_create(context, &context->keys, 255, &assh_key_ed25519, ASSH_ALGO_SIGN)
#endif
      )
    ERROR("Unable to load or create host key.\n");

  signal(SIGPIPE, SIG_IGN);

  while (1)
    {
      struct sockaddr_in con_addr;
      socklen_t addr_size = sizeof(con_addr);

      /** wait for client connection */
      int conn = accept(sock, (struct sockaddr*)&con_addr, &addr_size);
      if (conn < 0)
	continue;

      /** init a session for the incoming connection */
      struct assh_session_s *session;

      if (assh_session_create(context, &session) != ASSH_OK)
	ERROR("Unable to create an assh session.\n");

      fprintf(stderr, "Incoming connection\n");

      struct assh_event_s event;

      /** get events from the core. */
      while (assh_event_get(session, &event, time(NULL)))
	{
	  switch (event.id)
	    {
	    case ASSH_EVENT_READ:
	    case ASSH_EVENT_WRITE:
	      /* use helpers to read/write the ssh stream from/to our
		 socket file descriptor */
	      assh_fd_event(session, &event, conn);
	      break;

	    case ASSH_EVENT_ERROR:
	      /* report any error to the terminal */
	      fprintf(stderr, "SSH error: %s\n",
		      assh_error_str(event.error.code));
	      assh_event_done(session, &event, ASSH_OK);
	      break;

	    case ASSH_EVENT_USERAUTH_SERVER_USERKEY:
	    case ASSH_EVENT_USERAUTH_SERVER_PASSWORD:
	      /* let some helpers handle user authentication */
	      assh_server_event_openssh_auth(session, &event);
	      break;

	    case ASSH_EVENT_CHANNEL_OPEN: {
	      struct assh_event_channel_open_s *ev =
		&event.connection.channel_open;

	      /* make our server accept interactive sessions from the client */
	      if (!assh_buffer_strcmp(&ev->type, "session"))
		ev->reply = ASSH_CONNECTION_REPLY_SUCCESS;

	      assh_event_done(session, &event, ASSH_OK);
	      break;
	    }

	    case ASSH_EVENT_REQUEST: {
	      struct assh_event_request_s *ev = &event.connection.request;

	      /* accept a shell execution request on any open channel */
	      if (ev->ch)
		if (!assh_buffer_strcmp(&ev->type, "shell"))
		  ev->reply = ASSH_CONNECTION_REPLY_SUCCESS;

	      assh_event_done(session, &event, ASSH_OK);
	      break;
	    }

	    case ASSH_EVENT_CHANNEL_DATA: {
	      struct assh_event_channel_data_s *ev = &event.connection.channel_data;

	      /* size of incoming channel data */
	      size_t size = ev->data.size;

	      /* allocate output data packet */
	      uint8_t *data;
	      assh_error_t perr = assh_channel_data_alloc(ev->ch, &data, &size, size);

	      /* copy input data to the output buffer */
	      if (perr == ASSH_OK)
		{
		  memcpy(data, ev->data.data, size);
		  ev->transferred = size;
		}

	      /* acknowledge input data event before sending */
	      assh_event_done(session, &event, ASSH_OK);

	      if (perr == ASSH_OK)  /* send back output data */
		assh_channel_data_send(ev->ch, size);

	      break;
	    }

	    default:
	      /* acknowledge any unhandled event */
	      assh_event_done(session, &event, ASSH_OK);
	    }
	}

      fprintf(stderr, "Connection closed\n");
      assh_session_release(session);
    }

  assh_context_release(context);

  return 0;
}