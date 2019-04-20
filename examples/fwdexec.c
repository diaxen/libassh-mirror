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
  This implements a pair of ssh clients. The first client requests
  port forwarding on the first server and use the forwarding to
  connect the second client on a second server. The second client
  executes a remote command like in the rexec example.
*/

#include <assh/assh_session.h>
#include <assh/assh_context.h>
#include <assh/assh_service.h>
#include <assh/assh_userauth_client.h>
#include <assh/assh_connection.h>
#include <assh/helper_interactive.h>
#include <assh/helper_portfwd.h>
#include <assh/helper_client.h>
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

                                                        /* anchor fifo */
struct fifo_s
{
  uint8_t buf[128];
  size_t ptr;
  size_t size;
};

static size_t
fifo_read(struct fifo_s *f, uint8_t *data, size_t size);

static size_t
fifo_write(struct fifo_s *f, const uint8_t *data, size_t size);
                                                        /* anchor fifoimplem */
static size_t
fifo_read(struct fifo_s *f, uint8_t *data, size_t size)
{
  size_t osize = size;
  while (f->size > 0 && size > 0)
    {
      *data++ = f->buf[f->ptr++ % sizeof(f->buf)];
      f->size--, size--;
    }
  return osize - size;
}

static size_t
fifo_write(struct fifo_s *f, const uint8_t *data, size_t size)
{
  size_t osize = size;

  while (f->size < sizeof(f->buf) && size > 0)
    {
      f->buf[(f->ptr + f->size++) % sizeof(f->buf)] = *data++;
      size--;
    }
  return osize - size;
}
                                                        /* anchor rexecvars */
static const char            *rexec_hostname;
static struct assh_session_s *rexec_session;
static struct assh_client_inter_session_s rexec_inter;

/* specify user authentication methods to use */
static enum assh_userauth_methods_e rexec_auth_methods =
  ASSH_USERAUTH_METHOD_PASSWORD |
  ASSH_USERAUTH_METHOD_PUBKEY |
  ASSH_USERAUTH_METHOD_KEYBOARD;
                                                        /* anchor fwdvars */
static const char             *username;
static const char            *fwd_hostname;
static struct assh_session_s *fwd_session;
static int                    fwd_sock = -1;

static enum assh_userauth_methods_e fwd_auth_methods =
  ASSH_USERAUTH_METHOD_PASSWORD |
  ASSH_USERAUTH_METHOD_PUBKEY |
  ASSH_USERAUTH_METHOD_KEYBOARD;
                                                        /* anchor fwdvars2 */
static struct assh_channel_s *fwd_channel = NULL;
static struct fifo_s          fwd_to_rexec = { };
                                                        /* anchor fwdloop */
static assh_bool_t
ssh_loop_fwd(void)
{
  struct assh_event_s fwd_event;

  while (assh_event_get(fwd_session, &fwd_event, time(NULL)))
    {
      switch (fwd_event.id)
	{
                                                        /* anchor fwdevio */
	case ASSH_EVENT_READ:
	case ASSH_EVENT_WRITE:
	  /* use helpers to read/write the ssh stream from/to our
	     socket file descriptor */
	  assh_fd_event(fwd_session, &fwd_event, fwd_sock);
	  break;

                                                        /* anchor fwdevother */
	case ASSH_EVENT_SESSION_ERROR:
	  fprintf(stderr, "SSH forwarder error: %s\n",
		  assh_error_str(fwd_event.session.error.code));
	  assh_event_done(fwd_session, &fwd_event, ASSH_OK);
	  break;

        case ASSH_EVENT_KEX_HOSTKEY_LOOKUP:
          /* rely on helper as in the rexec example */
          assh_client_event_hk_lookup(fwd_session, stderr, stdin,
                                      fwd_hostname, &fwd_event);
          break;

        case ASSH_EVENT_USERAUTH_CLIENT_BANNER:
        case ASSH_EVENT_USERAUTH_CLIENT_USER:
        case ASSH_EVENT_USERAUTH_CLIENT_METHODS:
        case ASSH_EVENT_USERAUTH_CLIENT_PWCHANGE:
        case ASSH_EVENT_USERAUTH_CLIENT_KEYBOARD:
          /* rely on helper as in the rexec example */
          assh_client_event_auth(fwd_session, stderr, stdin, username, fwd_hostname,
             &fwd_auth_methods, assh_client_user_key_default, &fwd_event);
          break;

                                                        /* anchor fwdevsrvstart */
        case ASSH_EVENT_SERVICE_START: {
          const struct assh_service_s *srv = fwd_event.service.start.srv;

          assh_event_done(fwd_session, &fwd_event, ASSH_OK);

          /* setup a TCP port forwarding as soon as the ssh-connection
             service has started. */
          if (srv == &assh_service_connection)
            {
              struct assh_portfwd_direct_tcpip_s fwd_rq;

              assh_buffer_strset(&fwd_rq.conn_addr, rexec_hostname);
              fwd_rq.conn_port = 22;
              assh_buffer_strset(&fwd_rq.orig_addr, "127.0.0.1");
              fwd_rq.orig_port = 22;

              if (assh_portfwd_open_direct_tcpip(fwd_session,
                                                 &fwd_channel, &fwd_rq))
                goto disconnect;
            }
          break;
        }
                                                        /* anchor fwdevchopen */
        case ASSH_EVENT_CHANNEL_CONFIRMATION:
          fprintf(stderr, "SSH port forwarding ok\n");
	  assh_event_done(fwd_session, &fwd_event, ASSH_OK);
          break;

        case ASSH_EVENT_CHANNEL_FAILURE:
          fprintf(stderr, "SSH port forwarding denied\n");
	  assh_event_done(fwd_session, &fwd_event, ASSH_OK);
          goto disconnect;
                                                        /* anchor fwdevchdata */
	case ASSH_EVENT_CHANNEL_DATA: {
          struct assh_event_channel_data_s *ev =
            &fwd_event.connection.channel_data;

          /* write incoming forwarded ssh stream to our software fifo */
          ev->transferred =
            fifo_write(&fwd_to_rexec, ev->data.data, ev->data.size);

	  assh_event_done(fwd_session, &fwd_event, ASSH_OK);
          return 1;
        }
                                                        /* anchor fwdevchclose */
        case ASSH_EVENT_CHANNEL_CLOSE:
          fwd_channel = NULL;
	  assh_event_done(fwd_session, &fwd_event, ASSH_OK);
          /* initiate a disconnect when the port forwarding terminates */
          goto disconnect;
                                                        /* anchor fwdevdefault */
	default:
	  /* acknowledge any unhandled event */
	  assh_event_done(fwd_session, &fwd_event, ASSH_OK);
	}
    }

  return 0;       /* session terminated, no more events */

 disconnect:
  assh_session_disconnect(fwd_session, SSH_DISCONNECT_BY_APPLICATION, NULL);
  return 1;
}
                                                        /* anchor rexecloop */
static assh_bool_t
ssh_loop_rexec(void)
{
  struct assh_event_s rexec_event;

  while (assh_event_get(rexec_session, &rexec_event, time(NULL)))
    {
      switch (rexec_event.id)
	{
                                                        /* anchor rexecevread */
	case ASSH_EVENT_READ: {
          struct assh_event_transport_read_s *ev =
            &rexec_event.transport.read;

          /* read ssh stream from our software fifo */
          size_t s = fifo_read(&fwd_to_rexec, ev->buf.data, ev->buf.size);
          ev->transferred = s;

	  assh_event_done(rexec_session, &rexec_event, ASSH_OK);

          if (s == 0)
            return 1;           /* yield to forwarder event loop */
          break;
        }
                                                        /* anchor rexecevwrite */
	case ASSH_EVENT_WRITE: {
          struct assh_event_transport_write_s *ev =
            &rexec_event.transport.write;
          uint8_t *d;
          size_t s = ev->buf.size;

          if (fwd_channel != NULL &&
              assh_channel_state(fwd_channel) >= ASSH_CHANNEL_ST_OPEN &&
              assh_channel_data_alloc(fwd_channel, &d, &s, 0) == ASSH_OK)
            {
              /* write our ssh stream to the port forwarding channel of
                 the other session */
              memcpy(d, ev->buf.data, s);
              assh_channel_data_send(fwd_channel, s);
              ev->transferred = s;
            }

	  assh_event_done(rexec_session, &rexec_event, ASSH_OK);

          if (ev->transferred == 0)
            return 1;           /* yield to forwarder event loop */
          break;
        }
                                                        /* anchor rexecevother */
	case ASSH_EVENT_SESSION_ERROR:
	  /* report any error to the terminal */
	  fprintf(stderr, "SSH rexec error: %s\n",
		  assh_error_str(rexec_event.session.error.code));
	  assh_event_done(rexec_session, &rexec_event, ASSH_OK);
	  break;

        case ASSH_EVENT_KEX_HOSTKEY_LOOKUP:
          /* rely on helper as in the rexec example */
          assh_client_event_hk_lookup(rexec_session, stderr, stdin,
                                      rexec_hostname, &rexec_event);
          break;

        case ASSH_EVENT_USERAUTH_CLIENT_BANNER:
        case ASSH_EVENT_USERAUTH_CLIENT_USER:
        case ASSH_EVENT_USERAUTH_CLIENT_METHODS:
        case ASSH_EVENT_USERAUTH_CLIENT_PWCHANGE:
        case ASSH_EVENT_USERAUTH_CLIENT_KEYBOARD:
          /* rely on helper as in the rexec example */
          assh_client_event_auth(rexec_session, stderr, stdin, username, rexec_hostname,
             &rexec_auth_methods, assh_client_user_key_default, &rexec_event);
          break;

                                                        /* anchor rexecevinter */
        case ASSH_EVENT_SERVICE_START:
        case ASSH_EVENT_CHANNEL_CONFIRMATION:
        case ASSH_EVENT_CHANNEL_FAILURE:
        case ASSH_EVENT_REQUEST_REPLY:
        case ASSH_EVENT_CHANNEL_CLOSE:
          /* rely on helper as in the rexec example */
          assh_client_event_inter_session(rexec_session, &rexec_event, &rexec_inter);

	  if (rexec_inter.state == ASSH_CLIENT_INTER_ST_CLOSED)
	    assh_session_disconnect(rexec_session, SSH_DISCONNECT_BY_APPLICATION, NULL);
          break;

                                                        /* anchor rexecevchdata */
	case ASSH_EVENT_CHANNEL_DATA: {
          struct assh_event_channel_data_s *ev =
            &rexec_event.connection.channel_data;
          assh_error_t err = ASSH_OK;

	  /* write remote command output sent over the channel to the
	     standard output. */
          ssize_t r = write(1, ev->data.data, ev->data.size);
          if (r < 0)
            err = ASSH_ERR_IO;
          else
            ev->transferred = r;

          assh_event_done(rexec_session, &rexec_event, err);
          break;
	}
                                                        /* anchor rexecevdefault */
	default:
	  /* acknowledge any unhandled event */
	  assh_event_done(rexec_session, &rexec_event, ASSH_OK);
	}
    }

  return 0;       /* session terminated, no more events */
}
                                                        /* anchor main */
int main(int argc, char **argv)
{
  /* perform initialization of third party libraries */
  if (assh_deps_init())
    ERROR("initialization error\n");

  if (argc < 3)
    ERROR("usage: ./fwdexec forward_host host 'command'\n");

  username = getenv("USER");
  if (username == NULL)
    ERROR("Unspecified user name\n");

  fwd_hostname = argv[1];
  rexec_hostname = argv[2];
  const char *command = argv[3];
  const char *port = "22";

  /* resolve host name and open socket */
  struct addrinfo hints = {
    .ai_family = AF_UNSPEC,
    .ai_socktype = SOCK_STREAM,
  };

  struct addrinfo *servinfo, *si;
  if (!getaddrinfo(fwd_hostname, port, &hints, &servinfo))
    {
      for (si = servinfo; si != NULL; si = si->ai_next)
        {
          fwd_sock = socket(si->ai_family, si->ai_socktype, si->ai_protocol);
          if (fwd_sock < 0)
            continue;

          if (connect(fwd_sock, si->ai_addr, si->ai_addrlen))
            {
              close(fwd_sock);
              fwd_sock = -1;
              continue;
            }

          break;
        }

      freeaddrinfo(servinfo);
    }

  if (fwd_sock < 0)
    ERROR("Unable to connect: %s\n", strerror(errno));

  signal(SIGPIPE, SIG_IGN);

                                                        /* anchor init */
  /* initialize an assh context, register services and algorithms */
  struct assh_context_s *context;

  if (assh_context_create(&context, ASSH_CLIENT,
                          NULL, NULL, NULL, NULL) != ASSH_OK ||
      assh_service_register_default(context) != ASSH_OK ||
      assh_algo_register_default(context, 50, 20, 0) != ASSH_OK)
    ERROR("Unable to create an assh context.\n");

  /* initialize the 2 client sessions */
  if (assh_session_create(context, &fwd_session) != ASSH_OK ||
      assh_session_create(context, &rexec_session) != ASSH_OK)
    ERROR("Unable to create an sessions.\n");

  /* initializes an interactive session state machine object for the
     rexec session */
  assh_client_init_inter_session(&rexec_inter, command, NULL);

                                                        /* anchor mainloop */
  while (1)
    {
      /* run the event loop of the forwarding session */
      if (!ssh_loop_fwd())
        break;

      /* run the event loop of the rexec session */
      if (!ssh_loop_rexec())
        assh_session_disconnect(fwd_session, SSH_DISCONNECT_BY_APPLICATION, NULL);
    }
                                                        /* anchor maincleanup */
  fprintf(stderr, "Connection closed\n");

  assh_session_release(rexec_session);
  assh_session_release(fwd_session);
  assh_context_release(context);

  return 0;
}
