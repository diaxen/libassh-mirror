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
  using libassh, the content of the examples/client.c file may be
  freely reused without causing the resulting work to be covered by
  the GNU Lesser General Public License.

*/

/*
  This implements a simple ssh client which executes a remote command.
  It relies on many helper functions provided by helper_client.c.
*/

#include <assh/assh_session.h>
#include <assh/assh_context.h>
#include <assh/assh_service.h>
#include <assh/assh_userauth_client.h>
#include <assh/assh_compress.h>
#include <assh/assh_connection.h>
#include <assh/helper_key.h>
#include <assh/helper_interactive.h>
#include <assh/helper_client.h>
#include <assh/assh_kex.h>
#include <assh/helper_io.h>
#include <assh/assh_event.h>
#include <assh/assh_algo.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#define ERROR(...) do { fprintf(stderr, __VA_ARGS__); exit(1); } while (0)

                                                        /* anchor main */
int main(int argc, char **argv)
{
  /* perform initialization of third party libraries */
  if (assh_deps_init())
    ERROR("initialization error\n");
                                                        /* anchor args */
  if (argc < 3)
    ERROR("usage: ./rexec host 'command'\n");

  const char *user = getenv("USER");
  if (user == NULL)
    ERROR("Unspecified user name\n");

  const char *hostname = argv[1];
  const char *command = argv[2];
  const char *port = "22";

  /* resolve host name and open socket */
  struct addrinfo hints = {
    .ai_family = AF_UNSPEC,
    .ai_socktype = SOCK_STREAM,
  };

  int sock = -1;
  struct addrinfo *servinfo, *si;
  if (!getaddrinfo(hostname, port, &hints, &servinfo))
    {
      for (si = servinfo; si != NULL; si = si->ai_next)
        {
          sock = socket(si->ai_family, si->ai_socktype, si->ai_protocol);
          if (sock < 0)
            continue;

          if (connect(sock, si->ai_addr, si->ai_addrlen))
            {
              close(sock);
              sock = -1;
              continue;
            }

          break;
        }

      freeaddrinfo(servinfo);
    }

  if (sock < 0)
    ERROR("Unable to connect: %s\n", strerror(errno));

  signal(SIGPIPE, SIG_IGN);

                                                        /* anchor initc */
  /* initialize an assh context, register services and algorithms */
  struct assh_context_s *context;

  if (assh_context_create(&context, ASSH_CLIENT,
                          NULL, NULL, NULL, NULL) != ASSH_OK ||
      assh_service_register_default(context) != ASSH_OK ||
      assh_algo_register_default(context, 50, 20, 0) != ASSH_OK)
    ERROR("Unable to create an assh context.\n");

                                                        /* anchor inits */
  /* initialize an assh session object */
  struct assh_session_s *session;

  if (assh_session_create(context, &session) != ASSH_OK)
    ERROR("Unable to create an assh session.\n");

                                                        /* anchor inita */
  /* specify user authentication methods to use */
  enum assh_userauth_methods_e auth_methods =
    ASSH_USERAUTH_METHOD_PASSWORD |
    ASSH_USERAUTH_METHOD_PUBKEY |
    ASSH_USERAUTH_METHOD_KEYBOARD;

                                                        /* anchor initi */
  /* initializes an interactive session state machine object */
  struct assh_client_inter_session_s inter;
  assh_client_init_inter_session(&inter, command, NULL);

                                                        /* anchor loop */

  /** get events from the core. */
  struct assh_event_s event;

  while (assh_event_get(session, &event, time(NULL)))
    {
      switch (event.id)
	{
                                                        /* anchor evio */
	case ASSH_EVENT_READ:
	case ASSH_EVENT_WRITE:
	  /* use helpers to read/write the ssh stream from/to our
	     socket file descriptor */
	  assh_fd_event(session, &event, sock);
	  break;

                                                        /* anchor everr */
	case ASSH_EVENT_SESSION_ERROR:
	  /* report any error to the terminal */
	  fprintf(stderr, "SSH error: %s\n",
		  assh_error_str(event.session.error.code));
	  assh_event_done(session, &event, ASSH_OK);
	  break;

                                                        /* anchor evhk */
        case ASSH_EVENT_KEX_HOSTKEY_LOOKUP:
          /* let an helper function lookup host key in openssh
             standard files and query the user */
          assh_client_event_hk_lookup(session, stderr, stdin, hostname, &event);
          break;

                                                        /* anchor evua */
        case ASSH_EVENT_USERAUTH_CLIENT_BANNER:
        case ASSH_EVENT_USERAUTH_CLIENT_USER:
        case ASSH_EVENT_USERAUTH_CLIENT_METHODS:
        case ASSH_EVENT_USERAUTH_CLIENT_PWCHANGE:
        case ASSH_EVENT_USERAUTH_CLIENT_KEYBOARD:
          /* let an helper function handle user authentication events */
          assh_client_event_auth(session, stderr, stdin, user, hostname,
             &auth_methods, assh_client_user_key_default, &event);
          break;

                                                        /* anchor evcn */
        case ASSH_EVENT_SERVICE_START:
        case ASSH_EVENT_CHANNEL_OPEN_REPLY:
        case ASSH_EVENT_REQUEST_REPLY:
        case ASSH_EVENT_CHANNEL_CLOSE:
          /* let an helper function start and manage an interactive
             session. */
          assh_client_event_inter_session(session, &event, &inter);

	  /* terminate the connection when we are done with this session */
	  if (inter.state == ASSH_CLIENT_INTER_ST_CLOSED)
	    assh_session_disconnect(session, SSH_DISCONNECT_BY_APPLICATION, NULL);
          break;

                                                        /* anchor evdata */
	case ASSH_EVENT_CHANNEL_DATA: {
          struct assh_event_channel_data_s *ev = &event.connection.channel_data;
          assh_error_t err = ASSH_OK;

	  /* write remote command output sent over the channel to the
	     standard output. */
          ssize_t r = write(1, ev->data.data, ev->data.size);
          if (r < 0)
            err = ASSH_ERR_IO;
          else
            ev->transferred = r;

          assh_event_done(session, &event, err);
          break;
	}

                                                        /* anchor evdflt */
	default:
	  /* acknowledge any unhandled event */
	  assh_event_done(session, &event, ASSH_OK);
	}
    }

                                                        /* anchor cleanup */
  fprintf(stderr, "Connection closed\n");

  assh_session_release(session);
  assh_context_release(context);

  return 0;
}
