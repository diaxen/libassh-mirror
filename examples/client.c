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
  This implements a toy ssh client example
  with the following features:

   - Event loop driven with fd polling for read and write.
   - Password and public key user authentication.
   - Disable some user athentication methods depending on kex safety.
   - Handle interactive session with shell or command.
   - Handle pseudo TTY allocation and pipes.
*/

#include "config.h"

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
#include <termios.h>

#define ERROR(...) do { fprintf(stderr, __VA_ARGS__); exit(1); } while (0)

static assh_bool_t use_compression = 0;

static const char *port = "22";
static const char *hostname;
static const char *user = NULL;

static assh_safety_t algo_safety = 50;
static assh_safety_t algo_min_safety = 20;
static assh_safety_t kex_warn_safety = 25;

static assh_bool_t verbose = 0;

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

/* used to index our array of struct pollfd */
enum poll_e
{
  POLL_STDIN,
  POLL_STDOUT,
  POLL_SOCKET,
};

static assh_bool_t
ssh_loop(struct assh_session_s *session,
          struct assh_client_inter_session_s *inter,
          struct pollfd *p)
{
  time_t t = time(NULL);

  /* Process all events from the assh session until we encounter one
     which involves an IO operation that may be blocking. */
  while (1)
    {
      struct assh_event_s event;

      /* Get the next event from the assh library. */
      if (!assh_event_get(session, &event, t))
        return 0;

      switch (event.id)
        {
        case ASSH_EVENT_READ:
          /* return if we are not sure that we can read some ssh
             stream from the socket without blocking */
          if (!(p[POLL_SOCKET].revents & POLLIN))
            {
              assh_event_done(session, &event, ASSH_OK);
              return 1;
            }

          /* let an helper function read ssh stream from socket */
          assh_fd_event(session, &event, p[POLL_SOCKET].fd);
          p[POLL_SOCKET].revents ^= POLLIN;
          break;

        case ASSH_EVENT_WRITE:
          /* return if we are not sure that we can write some ssh
             stream to the socket without blocking */
          if (!(p[POLL_SOCKET].revents & POLLOUT))
            {
              assh_event_done(session, &event, ASSH_OK);
              return 1;
            }

          /* let an helper function write ssh stream to socket */
          assh_fd_event(session, &event, p[POLL_SOCKET].fd);
          p[POLL_SOCKET].revents ^= POLLOUT;
          break;

        case ASSH_EVENT_ERROR:
          /* Any error reported to the assh_event_done function will
             end up here. */
          assh_client_event_print_error(session, stderr, &event);
          break;

        case ASSH_EVENT_KEX_HOSTKEY_LOOKUP:
          /* let an helper function lookup host key in openssh
             standard files and query user */
          assh_client_event_openssh_hk_lookup(session, stderr, stdin, hostname, &event);
          break;

        case ASSH_EVENT_KEX_DONE: {
          /* warn about algorithmic safety */
          struct assh_event_kex_done_s *ev = &event.kex.done;
          assh_bool_t warn = ev->safety <= kex_warn_safety;
          if (warn)
            {
              auth_methods &= ~(ASSH_USERAUTH_METHOD_PASSWORD |
                                ASSH_USERAUTH_METHOD_KEYBOARD);
              fprintf(stderr,
                      "WARNING: The algorithmic safety of the key exchange is potentially weak (%u%%).\n"
                      "The ssh connection may not be secure. Password based authentication methods\n"
                      "have been disabled. The -k option may be used to control this warning.\n\n",
                      ev->safety);
            }

          if (verbose || warn)  /* be verbose about negotiated algorithms */
            assh_client_print_kex_details(session, stderr, &event);

          /* let an helper function register new host key as needed */
          assh_client_event_openssh_hk_add(session, hostname, &event);
          break;
        }

        case ASSH_EVENT_USERAUTH_CLIENT_BANNER:
        case ASSH_EVENT_USERAUTH_CLIENT_USER:
        case ASSH_EVENT_USERAUTH_CLIENT_METHODS:
        case ASSH_EVENT_USERAUTH_CLIENT_PWCHANGE:
        case ASSH_EVENT_USERAUTH_CLIENT_KEYBOARD:
          /* let an helper function handle user authentication events */
          assh_client_event_openssh_auth(session, stderr, stdin, user, hostname,
             &auth_methods, assh_client_openssh_user_key_default, &event);
          break;

        case ASSH_EVENT_SERVICE_START:

          if (event.service.start.srv ==
              &assh_service_connection &&
              isatty(0))
            {
              /* put terminal in raw mode */
              struct termios t;
              t = term;
              cfmakeraw(&t);
              tcsetattr(0, 0, &t);
            }

        case ASSH_EVENT_CHANNEL_OPEN_REPLY:
        case ASSH_EVENT_REQUEST_REPLY:
        case ASSH_EVENT_CHANNEL_CLOSE:
          /* let an helper function start and manage an interactive
             session. */
          assh_client_event_inter_session(session, &event, inter);
          break;

        case ASSH_EVENT_CHANNEL_DATA: {
          assh_error_t err = ASSH_OK;

          /* return if we are not sure that we can write some data to
             the standard output right now */
          if (!(p[POLL_STDOUT].revents & POLLOUT))
            {
              assh_event_done(session, &event, ASSH_OK);
              return 1;
            }

          struct assh_event_channel_data_s *ev = &event.connection.channel_data;

          /* write to stdout */
          ssize_t r = write(p[POLL_STDOUT].fd, ev->data.data, ev->data.size);
          if (r < 0)
            err = ASSH_ERR_IO | ASSH_ERRSV_DISCONNECT;
          else
            ev->transferred = r;

          assh_event_done(session, &event, err);
          p[POLL_STDOUT].revents ^= POLLOUT;
          break;
        }

        default:
          ASSH_DEBUG("event %u not handled\n", event.id);
          assh_event_done(session, &event, ASSH_OK);
        }
    }
}

static void usage(const char *program, assh_bool_t opts)
{
  fprintf(stderr, "usage: %s [-h | options] [user@]host [command]\n", program);

  if (opts)
    fprintf(stderr, "List of available options:\n\n"
          "    -p port    specify the TCP port number\n"
          "    -l user    specify the user login name\n"
          "    -C         enable compression\n\n"

          "    -o val     specify how safety is favored over speed (0 to 99)\n"
          "    -m val     specify minimal safety of algorithms (0 to 99)\n"
          "    -k val     specify warn level of key exchange safety (0 to 99)\n\n"

          "    -v         be verbose\n"
          "    -h         show help\n");

  exit(1);
}

int main(int argc, char **argv)
{
  /* perform initialization of third party libraries */
  if (assh_deps_init())
    ERROR("initialization error\n");

  /* parse command line options */
  int opt;
  while (optind < argc && argv[optind][0] == '-' && /* stop on 1st non option arg */
         (opt = getopt(argc, argv, "hCl:p:o:m:k:v")) != -1)
    {
      switch (opt)
        {
        case 'C':
          use_compression = 1;
          break;
        case 'l':
          user = optarg;
          break;
        case 'p':
          port = optarg;
          break;
        case 'o':
          algo_safety = atoi(optarg);
          if (algo_safety > 99)
            usage(argv[0], 1);
          break;
        case 'm':
          algo_min_safety = atoi(optarg);
          if (algo_min_safety > 99)
            usage(argv[0], 1);
          break;
        case 'k':
          kex_warn_safety = atoi(optarg);
          if (kex_warn_safety > 99)
            usage(argv[0], 1);
          break;
        case 'v':
          verbose = 1;
          break;
        case 'h':
          usage(argv[0], 1);
          break;
        }
    }

  /* parse host name with optional user@ */
  if (optind == argc)
    usage(argv[0], 0);
  char *userhost = argv[optind];

  char *at = strchr(userhost, '@');
  if (at != NULL)
    {
      user = userhost;
      *at = 0;
      hostname = at + 1;
    }
  else
    {
      hostname = userhost;
    }

  if (user == NULL)
    user = getenv("USER");

  if (user == NULL)
    ERROR("Unspecified user name\n");

  /* resolve host name */
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

  /* concat remaining arguments as remote command */
  char *cmd = NULL;
  size_t i, cmd_len = 0;
  for (i = optind + 1; i < argc; i++)
    cmd_len += strlen(argv[i]) + 1;

  if (cmd_len)
    {
      cmd = malloc(cmd_len);
      if (!cmd)
        ERROR("remote command buffer allocation error\n");

      char *c = cmd;
      for (i = optind + 1; i < argc; i++)
        {
          size_t len = strlen(argv[i]);
          memcpy(c, argv[i], len);
          c += len;
          *c++ = ' ';
        }
      c[-1] = '\0';
    }

  /* initializes an assh context object */
  struct assh_context_s *context;

  if (assh_context_create(&context, ASSH_CLIENT,
                          NULL, NULL, NULL, NULL) != ASSH_OK ||
      assh_service_register_default(context) != ASSH_OK ||
      assh_algo_register_default(context, algo_safety, algo_min_safety, 0) != ASSH_OK)
    ERROR("Unable to create an assh context.\n");

  /* initializes an assh session object */
  struct assh_session_s *session;

  if (assh_session_create(context, &session) != ASSH_OK ||
      assh_session_algo_filter(session, &algo_filter))
    ERROR("Unable to create an assh session.\n");

  /* initializes an interactive session state machine object */
  struct assh_client_inter_session_s inter;
  assh_client_init_inter_session(&inter, cmd,
             isatty(0) ? getenv("TERM") : NULL);

  /* save terminal attributes */
  if (isatty(0))
    tcgetattr(0, &term);

  /* main IOs polling loop */
  struct pollfd p[3];
  p[POLL_STDIN].fd = 0;
  p[POLL_STDOUT].fd = 1;
  p[POLL_SOCKET].fd = sock;

  do {
    p[POLL_STDIN].events = 0;
    p[POLL_STDOUT].events = 0;

    /* poll on terminal when the interactive session is open */
    if (inter.state == ASSH_CLIENT_INTER_ST_OPEN)
      {
        p[POLL_STDIN].events = POLLIN;
        if (assh_channel_more_data(session))
          p[POLL_STDOUT].events = POLLOUT;
      }

    /* always poll on the ssh socket */
    p[POLL_SOCKET].events = POLLIN;
    if (assh_transport_has_output(session))
      p[POLL_SOCKET].events |= POLLOUT;

    /* get the appropriate ssh protocol timeout */
    int timeout = assh_session_delay(session, time(NULL)) * 1000;
    ASSH_DEBUG("Timeout %i\n", timeout);

    if (poll(p, 3, timeout) <= 0)
      continue;

    /* we may need to write data from the terminal to the
       interactive session channel */
    if (p[POLL_STDIN].revents)
      {
        assert(inter.state == ASSH_CLIENT_INTER_ST_OPEN);

        /* let the library allocate an output buffer for us */
        uint8_t *buf;
        size_t s = 256;
        if (assh_channel_data_alloc(inter.channel, &buf, &s, 1) == ASSH_OK)
          {
            /* read data from the terminal directly in the
               buffer of the outgoing packet then send it. */
            ssize_t r = read(p[POLL_STDIN].fd, buf, s);
            if (r > 0)
              assh_channel_data_send(inter.channel, r);
          }
       }

    /* we disconnect when the remote side has closed the interactive
       session. */
    if (inter.state == ASSH_CLIENT_INTER_ST_CLOSED)
      assh_session_disconnect(session, SSH_DISCONNECT_BY_APPLICATION, NULL);

    /* let our ssh event loop handle ssh stream io events, channel data
       input events and any other ssh related events. */
  } while (ssh_loop(session, &inter, p));

  /* restore terminal attributes */
  if (isatty(0))
    tcsetattr(0, 0, &term);

  /* not useful here as we are about to leave... */
  assh_session_release(session);
  assh_context_release(context);

  close(sock);

  return 0;
}

