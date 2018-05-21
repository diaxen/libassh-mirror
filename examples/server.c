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
  This implements a toy ssh server example
  with the following features:

   - Fork on new connection.
   - Event loop driven with fd polling for read and write.
   - Password and public key user authentication.
   - Handle interactive session with shell or command.
   - Handle pseudo TTY allocation and pipes.
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
#include <assh/helper_interactive.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <netinet/ip.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>

#define ERROR(...) do { fprintf(stderr, __VA_ARGS__); exit(1); } while (0)

static const char *port = "22222";

/* our interactive session state */
enum interactive_session_state_e
{
  SESSION_NONE,
  SESSION_PIPE,
  SESSION_PTY,
  SESSION_RUNNING,
  SESSION_EOF,
  SESSION_ERROR,
};

/* our interactive session context */
static enum interactive_session_state_e its_state = SESSION_NONE;
static int its_child_stderr_fd;
static int its_child_stdout_fd;
static int its_child_stdin_fd;
static int its_child_pid;
static struct assh_channel_s *its_channel;

/* iniate a new interactive session */
static int
interactive_session_init(struct assh_channel_s *ch)
{
  if (its_state != SESSION_NONE)
    return -1;

  its_state = SESSION_PIPE;
  its_channel = ch;

  return 0;
}

#ifdef CONFIG_ASSH_POSIX_OPENPT
/* allocate pty for a session */
static int
interactive_session_pty(const struct assh_inter_pty_req_s *rqi)
{
  if (its_state != SESSION_PIPE)
    return -1;

  int fd = posix_openpt(O_RDWR | O_NOCTTY);
  if (fd < 0)
    return -1;

  grantpt(fd);
  unlockpt(fd);

  its_child_stdout_fd = its_child_stdin_fd = fd;
  its_child_stderr_fd = -1;
  its_state = SESSION_PTY;

  return 0;
}
#endif

/* execute a command in a session */
static int
interactive_session_exec(const char *cmd)
{
  int child_pid;

  switch (its_state)
    {
    case SESSION_PIPE: {
      int child_stderr[2];
      int child_stdout[2];
      int child_stdin[2];

      /* no pty allocated yet, use pipes in order to
	 communicate with the child */
      pipe(child_stderr);
      pipe(child_stdout);
      pipe(child_stdin);

      its_child_stderr_fd = child_stderr[0];
      its_child_stdout_fd = child_stdout[0];
      its_child_stdin_fd = child_stdin[1];

      /* fork child process */
      child_pid = fork();
      if (child_pid < 0)
	return -1;

      if (!child_pid)
	{
	  /* bind pipes to child stdin/stdout */
	  dup2(child_stderr[1], 2);
	  close(child_stderr[0]);
	  close(child_stderr[1]);

	  dup2(child_stdout[1], 1);
	  close(child_stdout[0]);
	  close(child_stdout[1]);

	  dup2(child_stdin[0], 0);
	  close(child_stdin[0]);
	  close(child_stdin[1]);

	  /* exec requested command in child */
	  execlp("/bin/sh", "/bin/sh", "-c", cmd, NULL);
	  exit(-1);
	}

      close(child_stderr[1]);
      close(child_stdout[1]);
      close(child_stdin[0]);
      break;
    }

#ifdef CONFIG_ASSH_POSIX_OPENPT
    case SESSION_PTY:
      /* fork child process */
      child_pid = fork();
      if (child_pid < 0)
	return -1;

      if (!child_pid)
	{
	  /* bind allocated pty to child stdin/stdout */
	  const char *slave_name = ptsname(its_child_stdin_fd);
	  close(its_child_stdin_fd);
	  setsid();

	  int slave_fd = open(slave_name, O_RDWR);
	  dup2(slave_fd, 0);
	  dup2(slave_fd, 1);
	  dup2(slave_fd, 2);
	  close(slave_fd);

	  /* exec requested command in child */
	  execlp("/bin/sh", "/bin/sh", "-c", cmd, NULL);
	  exit(-1);
	}
      break;
#endif

    default:
      /* unable to execute a child in this state */
      return -1;
    }

  its_child_pid = child_pid;
  its_state = SESSION_RUNNING;

  return 0;
}

/* forward data from the command in the child process to the remote client */
static void
interactive_session_child2channel(assh_bool_t e)
{
  /* let the library allocate an output buffer for us */
  uint8_t *buf;
  size_t s = 256;
  assh_error_t err;

  if (e)
    err = assh_channel_data_alloc_ext(its_channel, 1, &buf, &s, 1);
  else
    err = assh_channel_data_alloc(its_channel, &buf, &s, 1);

  if (ASSH_ERR_ERROR(err) == ASSH_OK)
    {
      /* read data from the child directly in the
	 buffer of the outgoing packet then send it. */
      ssize_t r;
      if (e)
	r = read(its_child_stderr_fd, buf, s);
      else
	r = read(its_child_stdout_fd, buf, s);
      if (r > 0)
	assh_channel_data_send(its_channel, r);
    }
}

/* forward data from the remote client to the command in the child process */
static void
interactive_session_channel2child(struct assh_event_channel_data_s *ev,
				  assh_error_t *err)
{
  assert(its_state == SESSION_RUNNING ||
	 its_state == SESSION_EOF);

  /* return if we are not sure that we can write some data to
     the standard output right now */

  /* write to stdout */
  ssize_t r = write(its_child_stdin_fd, ev->data.data, ev->data.size);
  if (r < 0)
    *err = ASSH_ERR_IO | ASSH_ERRSV_DISCONNECT;
  else
    ev->transferred = r;
}

/* half close pipe to the command in the child process */
static void
interactive_session_eof(struct assh_event_channel_eof_s *ev)
{
  assert(its_state == SESSION_RUNNING);
  assert(ev->ch == its_channel);

  close(its_child_stdin_fd);
  its_child_stdin_fd = -1;
}

/* close pipe to the command in the child process */
static void
interactive_session_close(struct assh_event_channel_close_s *ev)
{
  assert(its_state != SESSION_NONE);
  assert(ev->ch == its_channel);

  if (its_child_stdin_fd >= 0)
    close(its_child_stdin_fd);
  its_child_stdin_fd = -1;

  close(its_child_stdout_fd);
  its_child_stdin_fd = -1;

  its_state = SESSION_NONE;
}

/* used to index our array of struct pollfd */
enum poll_e
{
  POLL_SOCKET,
  POLL_CHILD_STDIN,
  POLL_CHILD_STDOUT,
  POLL_CHILD_STDERR,
};

/* Ssh event handling, This returns 0 when terminated. This returns 1
   when not sure if an IO operation can be performed without blocking.
*/
static assh_bool_t
ssh_loop(struct assh_session_s *session,
	 struct pollfd *p)
{
  time_t t = time(NULL);

  while (1)
    {
      struct assh_event_s event;

      /* get events from the core. */
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

          /* let an helper function write ssh stream to the socket */
          assh_fd_event(session, &event, p[POLL_SOCKET].fd);
          p[POLL_SOCKET].revents ^= POLLOUT;
          break;

	case ASSH_EVENT_ERROR:
          /* Any error reported to the assh_event_done function will
             end up here. */
	  fprintf(stderr, "[%u] SSH error: %s\n", getpid(),
		  assh_error_str(event.error.code));
	  assh_event_done(session, &event, ASSH_OK);
	  break;

	case ASSH_EVENT_USERAUTH_SERVER_METHODS:
	  /* report the user authentication methods we will accept. */
	  event.userauth_server.methods.methods =
	    ASSH_USERAUTH_METHOD_PUBKEY |
	    ASSH_USERAUTH_METHOD_PASSWORD;
	  assh_event_done(session, &event, ASSH_OK);
	  break;

	case ASSH_EVENT_USERAUTH_SERVER_USERKEY:
	case ASSH_EVENT_USERAUTH_SERVER_PASSWORD:
          /* let an helper function handle user authentication from
	     system password file and user authorized_keys file. */
	  assh_server_event_openssh_auth(session, &event);
	  break;

	case ASSH_EVENT_USERAUTH_SERVER_SUCCESS: {
	  /* change user id when user authentication is over */
	  uid_t uid;
	  gid_t gid;
	  if (assh_server_event_user_id(session, &uid, &gid, &event))
	    abort();
	  setgid(gid);
	  setuid(uid);
	  break;
	}

	case ASSH_EVENT_CHANNEL_OPEN: {
	  struct assh_event_channel_open_s *ev =
	    &event.connection.channel_open;

	  /* only accept session channels */
	  if (!assh_buffer_strcmp(&ev->type, "session"))
	    if (!interactive_session_init(ev->ch))
	      ev->reply = ASSH_CONNECTION_REPLY_SUCCESS;

	  assh_event_done(session, &event, ASSH_OK);
	  break;
	}

	case ASSH_EVENT_REQUEST: {
	  struct assh_event_request_s *ev = &event.connection.request;
	  assh_error_t err = ASSH_OK;

	  /* handle some standard requests associated to our session,
	     relying on some request decoding functions. */

	  if (ev->ch)
	    {
	      /* PTY request from the remote client */
	      if (!assh_buffer_strcmp(&ev->type, "pty-req"))
		{
#ifdef CONFIG_ASSH_POSIX_OPENPT
		  struct assh_inter_pty_req_s rqi;
		  err = assh_inter_decode_pty_req(&rqi, ev->rq_data.data,
						  ev->rq_data.size);

		  if (ASSH_ERR_ERROR(err) == ASSH_OK &&
		      !interactive_session_pty(&rqi))
		    ev->reply = ASSH_CONNECTION_REPLY_SUCCESS;
#endif
		}

	      /* shell exec from the remote client */
	      else if (!assh_buffer_strcmp(&ev->type, "shell"))
		{
		  if (!interactive_session_exec("/bin/sh"))
		    ev->reply = ASSH_CONNECTION_REPLY_SUCCESS;
		}

	      /* command exec from the remote client */
	      else if (!assh_buffer_strcmp(&ev->type, "exec"))
		{
		  struct assh_inter_exec_s rqi;
		  err = assh_inter_decode_exec(&rqi, ev->rq_data.data,
					       ev->rq_data.size);

		  if (ASSH_ERR_ERROR(err) == ASSH_OK)
		    {
		      const char *cmd = assh_buffer_strdup(&rqi.command);
		      if (!interactive_session_exec(cmd))
			ev->reply = ASSH_CONNECTION_REPLY_SUCCESS;
		      free((char*)cmd);
		    }
		}

	    }

	  assh_event_done(session, &event, err);
	  break;
	}

	case ASSH_EVENT_CHANNEL_DATA: {
          struct assh_event_channel_data_s *ev = &event.connection.channel_data;
	  assh_error_t err = ASSH_OK;

	  switch (its_state)
	    {
	    case SESSION_RUNNING:
	    case SESSION_EOF:
	      /* return if we are not sure that we can write data
		 to the child process without blocking */
	      if (!(p[POLL_CHILD_STDIN].revents & POLLOUT))
		{
		  assh_event_done(session, &event, ASSH_OK);
		  return 1;
		}

	      /* forward session data from the remote client to our child process */
	      interactive_session_channel2child(ev, &err);
	      p[POLL_CHILD_STDIN].revents ^= POLLOUT;
	      break;

	    default:
	      /* dicard channel data if session is not started */
	      ev->transferred = ev->data.size;
	      break;
	    }

	  assh_event_done(session, &event, err);

	  break;
	}

	case ASSH_EVENT_CHANNEL_EOF: {
	  struct assh_event_channel_eof_s *ev = &event.connection.channel_eof;

	  /* handle session EOF */
	  interactive_session_eof(ev);
	  assh_event_done(session, &event, ASSH_OK);

	  break;
	}

	case ASSH_EVENT_CHANNEL_CLOSE: {
	  struct assh_event_channel_close_s *ev = &event.connection.channel_close;

	  /* handle session close */
	  interactive_session_close(ev);
	  assh_event_done(session, &event, ASSH_OK);
	  break;
	}

	default:
	  assh_event_done(session, &event, ASSH_OK);
	}
    }
}

static ASSH_KEX_FILTER_FCN(algo_filter)
{
  return (name->spec & ASSH_ALGO_ASSH) ||
         (name->spec & ASSH_ALGO_COMMON);
}

static int
server_connected(struct assh_context_s *context,
		 int conn, const struct sockaddr_in *con_addr)
{
  /* init a session for the incoming connection */
  struct assh_session_s *session;
  if (assh_session_create(context, &session) != ASSH_OK)
    goto err;

  if (assh_session_algo_filter(session, &algo_filter))
    goto err_session;

  struct pollfd p[4];
  p[POLL_SOCKET].fd = conn;               /* ssh socket */

  do {
    uint_fast8_t poll_count = 1;

    /* always poll on the ssh socket */
    p[POLL_SOCKET].events = POLLIN;
    if (assh_transport_has_output(session))
      p[POLL_SOCKET].events |= POLLOUT;

    p[POLL_CHILD_STDERR].revents = 0;
    p[POLL_CHILD_STDOUT].revents = 0;
    p[POLL_CHILD_STDIN].revents = 0;

    /* poll on child i/o if an interactive session is running */
    switch (its_state)
      {
      case SESSION_RUNNING:
	if (its_child_stderr_fd >= 0)
	  {
	    poll_count++;
	    p[POLL_CHILD_STDERR].fd = its_child_stderr_fd;
	    p[POLL_CHILD_STDERR].events = POLLIN;
	  }

	poll_count++;
	p[POLL_CHILD_STDOUT].fd = its_child_stdout_fd;
	p[POLL_CHILD_STDOUT].events = POLLIN;

      case SESSION_EOF:
	poll_count++;
	p[POLL_CHILD_STDIN].fd = its_child_stdin_fd;
	p[POLL_CHILD_STDIN].events =
	  assh_channel_more_data(session) ? POLLOUT : 0;
	break;

      default:
	break;
      }

    /* get the appropriate ssh protocol timeout */
    int timeout = assh_session_delay(session, time(NULL)) * 1000;
    ASSH_DEBUG("Timeout %i\n", timeout);

    if (poll(p, poll_count, timeout) <= 0)
      continue;

    switch (its_state)
      {
      case SESSION_RUNNING:
      case SESSION_EOF:
	if (p[POLL_CHILD_STDOUT].revents & POLLIN)
	  {
	    /* forward stdout of child to the remote client */
	    interactive_session_child2channel(0);
	  }
	else if (p[POLL_CHILD_STDERR].revents & POLLIN)
	  {
	    /* forward stderr of child to the remote client */
	    interactive_session_child2channel(1);
	  }
	else if ((p[POLL_CHILD_STDOUT].revents |
		  p[POLL_CHILD_STDERR].revents) & (POLLERR | POLLHUP))
	  {
	    /* send EOF if the child wont send more data */
	    its_state = SESSION_EOF;
	    assh_channel_eof(its_channel);
	  }
	else if (its_state == SESSION_EOF &&
		 (p[POLL_CHILD_STDIN].revents & (POLLERR | POLLHUP)))
	  {
	    /* close session channel on child io hup/error */
	    its_state = SESSION_ERROR;
	    assh_channel_close(its_channel);
	  }

      default:
	break;
      }

    /* let our ssh event loop handle ssh stream io events, channel data
       input events and any other ssh related events. */
  } while (ssh_loop(session, p));

  fprintf(stderr, "[%u] SSH cleanup\n", getpid());

 err_session:
  assh_session_release(session);
 err:
  close(conn);

  return 0;
}

static void usage(const char *program, assh_bool_t opts)
{
  fprintf(stderr, "usage: %s [-h | options]\n", program);

  if (opts)
    fprintf(stderr, "List of available options:\n\n"
          "    -p port    specify the TCP port number\n"

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
  while ((opt = getopt(argc, argv, "hp:")) != -1)
    {
      switch (opt)
        {
        case 'p':
          port = optarg;
          break;
        case 'h':
          usage(argv[0], 1);
          break;
	}
    }

  /* create listening socket */
  int sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0)
    ERROR("Unable to create socket: %s\n", strerror(errno));

  int tmp = 1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(tmp));

  struct sockaddr_in addr =
    {
      .sin_port = htons(atoi(port)),
      .sin_family = AF_INET,
    };

  if (bind(sock, (struct sockaddr*)&addr, sizeof (struct sockaddr_in)) < 0)
    ERROR("Unable to bind: %s\n", strerror(errno));

  if (listen(sock, 8) < 0)
    ERROR("Unable to listen: %s\n", strerror(errno));

  /* init a server context */
  struct assh_context_s *context;

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
  signal(SIGCHLD, SIG_IGN);

  while (1)
    {
      /* handle incoming connections */
      struct sockaddr_in con_addr;
      socklen_t addr_size = sizeof(con_addr);

      int conn = accept(sock, (struct sockaddr*)&con_addr, &addr_size);

      if (conn < 0)
	break;

      /* handle incoming connection in a child process */
      if (fork())
	{
	  close(conn);
	}
      else
	{
	  close(sock);
	  exit(server_connected(context, conn, &con_addr));
	}
    }

  assh_context_release(context);

  return 0;
}

