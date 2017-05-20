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
#include <assh/helper_fd.h>
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
#include <unistd.h>
#include <termios.h>

static assh_bool_t use_compression = 0;

static const char *hostname = "localhost";

static int port = 22;

static const char *user;

static enum assh_userauth_methods_e auth_methods =
    ASSH_USERAUTH_METHOD_PASSWORD |
    ASSH_USERAUTH_METHOD_PUBKEY |
    ASSH_USERAUTH_METHOD_KEYBOARD;

struct termios term;

static ASSH_KEX_FILTER_FCN(algo_filter)
{
  if (algo->class_ == ASSH_ALGO_COMPRESS &&
      use_compression == (algo == &assh_compress_none.algo))
    return 0;

  return (name->spec & ASSH_ALGO_ASSH) ||
         (name->spec & ASSH_ALGO_COMMON);
}

static assh_bool_t
ssh_loop(struct assh_session_s *session,
          struct assh_client_inter_session_s *inter,
          struct pollfd *p)
{
  assh_error_t err;
  time_t t = time(NULL);

  while (1)
    {
      struct assh_event_s event;

      /* Get the next event from the assh library. Any error reported
         to the assh_event_done function will end up here. */
      if (!assh_event_get(session, &event, t))
        return 0;

      switch (event.id)
        {
        case ASSH_EVENT_READ:
          if (!(p[2].revents & POLLIN))
            {
              assh_event_done(session, &event, ASSH_OK);
              return 1;
            }

          /* get ssh stream from socket */
          assh_fd_event(session, &event, p[2].fd);
          p[2].revents ^= POLLIN;
          break;

        case ASSH_EVENT_WRITE:
          if (!(p[2].revents & POLLOUT))
            {
              assh_event_done(session, &event, ASSH_OK);
              return 1;
            }

          /* write ssh stream to socket */
          assh_fd_event(session, &event, p[2].fd);
          p[2].revents ^= POLLOUT;
          break;

        case ASSH_EVENT_KEX_HOSTKEY_LOOKUP:
          /* lookup host key in openssh standard files and query user */
          assh_client_event_openssh_hk_lookup(session, hostname, &event);
          break;

        case ASSH_EVENT_KEX_DONE:
          /* register new host key as needed */
          assh_client_event_openssh_hk_add(session, hostname, &event);
          break;

        case ASSH_EVENT_USERAUTH_CLIENT_BANNER:
        case ASSH_EVENT_USERAUTH_CLIENT_USER:
        case ASSH_EVENT_USERAUTH_CLIENT_METHODS:
        case ASSH_EVENT_USERAUTH_CLIENT_PWCHANGE:
        case ASSH_EVENT_USERAUTH_CLIENT_KEYBOARD:
          /* handle user authentication events */
          assh_client_event_openssh_auth(session, user, hostname,
             &auth_methods, assh_client_openssh_user_key_default, &event);
          break;

        case ASSH_EVENT_CONNECTION_START:
          /* put terminal in raw mode */
          if (isatty(0))
            {
              struct termios t;
              t = term;
              cfmakeraw(&t);
              tcsetattr(0, 0, &t);
            }

        case ASSH_EVENT_CHANNEL_OPEN_REPLY:
        case ASSH_EVENT_REQUEST_REPLY:
        case ASSH_EVENT_CHANNEL_CLOSE:
          /* start interactive session and shell */
          assh_client_event_inter_session(session, &event, inter);
          break;

        case ASSH_EVENT_CHANNEL_DATA: {
          if (!(p[1].revents & POLLOUT))
            {
              assh_event_done(session, &event, ASSH_OK);
              return 1;
            }

          struct assh_event_channel_data_s *ev = &event.connection.channel_data;

          ssize_t r = write(p[1].fd, ev->data.data, ev->data.size);
          if (r <= 0)
            err = ASSH_ERR_IO | ASSH_ERRSV_DISCONNECT;
          else
            ev->transferred = r;

          assh_event_done(session, &event, err);
          p[1].revents ^= POLLOUT;
          break;
        }

        default:
          ASSH_DEBUG("event %u not handled\n", event.id);
          assh_event_done(session, &event, ASSH_OK);
        }
    }
}

int main(int argc, char **argv)
{
#ifdef CONFIG_ASSH_USE_GCRYPT
  if (!gcry_check_version(GCRYPT_VERSION))
    return -1;
#endif

  if (argc > 1)
    port = atoi(argv[1]);

  int sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  assert(sock >= 0);

  struct sockaddr_in sin;

  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(0x7f000001);
  sin.sin_port = htons(port);

  int r = connect(sock, (struct sockaddr*)(&sin), sizeof(sin));
  assert(r == 0);

  struct assh_context_s *context;

  if (assh_context_create(&context, ASSH_CLIENT, CONFIG_ASSH_MAX_ALGORITHMS,
                          NULL, NULL, NULL, NULL))
    abort();

  if (assh_service_register_default(context) != ASSH_OK)
    return -1;

  if (assh_algo_register_default(context, 99, 10, 0) != ASSH_OK)
    return -1;

  struct assh_session_s *session;

  if (assh_session_create(context, &session) != ASSH_OK)
    return -1;

  if (assh_session_algo_filter(session, &algo_filter))
    return -1;

  assh_error_t err;

  user = getenv("USER");
  if (!user)
    return -1;

  struct assh_client_inter_session_s inter;
  assh_client_init_inter_session(&inter, NULL, getenv("TERM"));

  if (isatty(0))
    tcgetattr(0, &term);

  struct pollfd p[3];
  p[0].fd = 0;
  p[1].fd = 1;
  p[2].fd = sock;

  do {
    p[0].events = 0;
    p[1].events = 0;

    if (inter.state == ASSH_CLIENT_INTER_ST_OPEN)
      {
        p[0].events = POLLIN;
        if (assh_channel_more_data(session))
          p[1].events = POLLOUT;
      }

    p[2].events = POLLIN;
    if (assh_transport_has_output(session))
      p[2].events |= POLLOUT;

    int timeout = assh_session_delay(session, time(NULL)) * 1000;
    ASSH_DEBUG("Timeout %i\n", timeout);

    if (poll(p, 3, timeout) > 0)
      {
        if (inter.state == ASSH_CLIENT_INTER_ST_OPEN &&
            p[0].revents)
          {
            uint8_t *buf;
            size_t s = 256;
            if (assh_channel_data_alloc(inter.channel, &buf, &s, 1) == ASSH_OK)
              {
                ssize_t r = read(p[0].fd, buf, s);
                if (r)
                  assh_channel_data_send(inter.channel, r);
              }
           }


          {
          }
      }

    /* we may have ssh stream to transfer in either size or data
       to receive from the interactive sessions channel. This is
       handled by libassh events. */
    if (p[2].revents || p[1].revents)
      if (!ssh_loop(session, &inter, p))
        break;

    /* we quit when the last error has been reported or when the
       remote side has closed the interactive session. */
  } while (inter.state != ASSH_CLIENT_INTER_ST_CLOSED);
  assh_session_release(session);
  assh_context_release(context);

  if (isatty(0))
    tcsetattr(0, 0, &term);

  return 0;
}

