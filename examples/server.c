/*

  libassh - asynchronous ssh2 client/server library.

  Copyright (C) 2013-2020 Alexandre Becoulet <alexandre.becoulet@free.fr>

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
   - Mux interactive sessions on a single connection.
   - Handle sessions with shell or command.
   - Handle pseudo TTY allocation and pipes.

   A detailed description of the code is provided in the libassh manual.

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

#include <assh/helper_key.h>
#include <assh/helper_server.h>
#include <assh/helper_io.h>
#include <assh/helper_interactive.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#ifdef CONFIG_ASSH_POSIX_SETGROUPS
# include <grp.h>
#endif

#define ERROR(...) do { fprintf(stderr, __VA_ARGS__); exit(1); } while (0)

static const char *port = "22222";
                                                        /* anchor fsm */
/* our interactive session state */
enum interactive_session_state_e
{
  ITS_PIPE,                 /* use pipe() to redirect child IOs in its_exec */
  ITS_PTY,                  /* use a pty to redirect child IOs in its_exec */
  ITS_OPEN,                 /* channel is open and child is running */
  ITS_HALF_NO_SEND,         /* channel half closed, sending is not allowed */
  ITS_HALF_NO_RECV,         /* channel half closed, receiving is not possible */
  ITS_CLOSED,               /* channel is closed */
};
                                                        /* anchor state */
/* our interactive session context */
struct its_s
{
  enum interactive_session_state_e state;

  struct assh_channel_s *channel;

  int child_pid;
  int child_stderr_fd;
  int child_stdout_fd;
  int child_stdin_fd;
  int poll_index;
};
                                                        /* anchor itstable */
#define MAX_ITS_COUNT 10
#define MAX_POLL_ENTRIES (/* socket */ 1 + /* childs IOs */ MAX_ITS_COUNT * 3)

static struct its_s *its_table[MAX_ITS_COUNT];
static size_t its_table_count = 0;
                                                        /* anchor itsapiopen */
static struct its_s *
its_open(struct assh_channel_s *ch);
                                                        /* anchor itsapipty */
static int
its_pty(struct its_s *its);
                                                        /* anchor itsapiexec */
static int
its_exec(struct its_s *its,
	 const char *cmd);
                                                        /* anchor itsapipoll */
static void
its_poll_setup(struct its_s *its,
	       struct assh_session_s *session,
	       struct pollfd p[], int *poll_i);
                                                        /* anchor itsapidata */
static void
its_child2channel(struct its_s *its,
		  const struct pollfd p[]);
                                                        /* anchor itsapidata2 */
static assh_bool_t
its_channel2child(struct its_s *its, struct pollfd *p,
		  struct assh_event_channel_data_s *ev,
		  assh_status_t *err);
                                                        /* anchor itsapiclose */
static void
its_eof(struct its_s *its,
	struct assh_event_channel_eof_s *ev);

static void
its_close(struct its_s *its,
	  struct assh_event_channel_close_s *ev);

                                                        /* anchor itscode */
/* iniate a new interactive session */
static struct its_s *
its_open(struct assh_channel_s *ch)
{
  if (its_table_count >= MAX_ITS_COUNT)
    return NULL;

  struct its_s *its = malloc(sizeof(*its));

  if (its != NULL)
    {
      its->state = ITS_PIPE;
      its->channel = ch;
      its->poll_index = -1;
      its_table[its_table_count++] = its;

      printf("[%u] Interactive session %p open\n",
	      getpid(), its);
    }

  return its;
}

#ifdef HAVE_POSIX_OPENPT
/* allocate pty for a session */
static int
its_pty(struct its_s *its)
{
  if (its->state != ITS_PIPE)
    return -1;

  int fd = posix_openpt(O_RDWR | O_NOCTTY);
  if (fd < 0)
    return -1;

  grantpt(fd);
  unlockpt(fd);

  its->child_stdout_fd = its->child_stdin_fd = fd;
  its->child_stderr_fd = -1;
  its->state = ITS_PTY;

  return 0;
}
#endif

/* execute a command in a session */
static int
its_exec(struct its_s *its,
			 const char *cmd)
{
  int child_pid;

  switch (its->state)
    {
    case ITS_PIPE: {

      /* no pty allocated yet, use pipes in order to
	 communicate with the child */
      int child_stderr[2];
      if (pipe(child_stderr))
	return -1;

      int child_stdout[2];
      if (pipe(child_stdout))
	goto pipe_out_err;

      int child_stdin[2];
      if (pipe(child_stdin))
	goto pipe_in_err;

      its->child_stderr_fd = child_stderr[0];
      its->child_stdout_fd = child_stdout[0];
      its->child_stdin_fd = child_stdin[1];

      /* fork child process */
      child_pid = fork();
      if (child_pid < 0)
	goto fork_err;

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

     fork_err:
      close(child_stdin[0]);
      close(child_stdin[1]);
     pipe_in_err:
      close(child_stdout[0]);
      close(child_stdout[1]);
     pipe_out_err:
      close(child_stderr[0]);
      close(child_stderr[1]);
      return -1;
    }

#ifdef HAVE_POSIX_OPENPT
    case ITS_PTY:
      /* fork child process */
      child_pid = fork();
      if (child_pid < 0)
	return -1;

      if (!child_pid)
	{
	  /* bind allocated pty to child stdin/stdout */
	  const char *slave_name = ptsname(its->child_stdin_fd);
	  close(its->child_stdin_fd);
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

  its->child_pid = child_pid;
  its->state = ITS_OPEN;

  return 0;
}

/* used to index our array of struct pollfd */
enum poll_e
{
  POLL_CHILD_STDIN,
  POLL_CHILD_STDOUT,
  POLL_CHILD_STDERR,
};

static void
its_poll_setup(struct its_s *its,
			       struct assh_session_s *session,
			       struct pollfd p[], int *poll_i)
{
  int i = *poll_i;
  its->poll_index = i;

  if (its->state == ITS_OPEN ||
      its->state == ITS_HALF_NO_SEND)
    {
      /* poll for writting to child stdin if we have some incoming
	 data from the channel. */
      p[i + POLL_CHILD_STDIN].fd = its->child_stdin_fd;

      if (its->channel == assh_channel_more_data(session))
	p[i + POLL_CHILD_STDIN].events = POLLOUT;
      else
	p[i + POLL_CHILD_STDIN].events = 0;

      (*poll_i)++;
    }

  if (its->state == ITS_OPEN ||
      its->state == ITS_HALF_NO_RECV)
    {
      /* poll for reading from the channel. */
      p[i + POLL_CHILD_STDOUT].fd = its->child_stdout_fd;
      p[i + POLL_CHILD_STDOUT].events = POLLIN;
      (*poll_i)++;

      if (its->child_stderr_fd >= 0)
	{
	  p[i + POLL_CHILD_STDERR].fd = its->child_stderr_fd;
	  p[i + POLL_CHILD_STDERR].events = POLLIN;
	  (*poll_i)++;
	}
    }
}

static void
its_child2channel(struct its_s *its,
				  const struct pollfd p[])
{
  int i = its->poll_index;
  uint8_t *buf;

  if (its->state == ITS_OPEN ||
      its->state == ITS_HALF_NO_RECV)
    {
      int revents = p[i + POLL_CHILD_STDOUT].revents;

      /* forward stdout of the child to the remote client */
      if (revents & POLLIN)
	{
	  size_t s = 256;

	  if (!assh_channel_data_alloc(its->channel, &buf, &s, 1))
	    {
	      /* read data from the child directly in the
		 buffer of the outgoing packet then send it. */
	      ssize_t r = read(its->child_stdout_fd, buf, s);
	      if (r > 0)
		assh_channel_data_send(its->channel, r);
	    }
	}

      /* do the same for the stderr pipe */
      if (its->child_stderr_fd >= 0)
	{
	  revents |= p[i + POLL_CHILD_STDERR].revents;

	  if (p[i + POLL_CHILD_STDERR].revents & POLLIN)
	    {
	      size_t s = 256;

	      if (!assh_channel_data_alloc_ext(its->channel,
					       1, &buf, &s, 1))
		{
		  ssize_t r = read(its->child_stderr_fd, buf, s);
		  if (r > 0)
		    assh_channel_data_send(its->channel, r);
		}
	    }
	}

      /* report channel EOF when unable to read from the child */
      if (revents & (POLLERR | POLLHUP))
	{
	  assh_channel_eof(its->channel);

	  if (its->state == ITS_OPEN)
	    its->state = ITS_HALF_NO_SEND;
	  else
	    its->state = ITS_CLOSED;
	}
    }

  if (its->state == ITS_OPEN ||
      its->state == ITS_HALF_NO_SEND)
    {
      if (p[i + POLL_CHILD_STDIN].revents & (POLLERR | POLLHUP))
	{
	  /* close the channel on broken pipe */
	  its->state = ITS_CLOSED;
	  assh_channel_close(its->channel);
	}
    }
}

/* forward data from the remote client to the command in the child process */
static assh_bool_t
its_channel2child(struct its_s *its, struct pollfd *p,
				  struct assh_event_channel_data_s *ev,
				  assh_status_t *err)
{
  int i = its->poll_index;
  ssize_t r;

  *err = ASSH_OK;

  switch (its->state)
    {
    case ITS_OPEN:
    case ITS_HALF_NO_SEND:

      /* break the loop if we are not sure that we can write some data
	 to the standard output right now */
      if (i < 0 || !(p[i + POLL_CHILD_STDIN].revents & POLLOUT))
	return 1;

      /* forward session data from the remote client to our child process */
      r = write(its->child_stdin_fd, ev->data.data, ev->data.size);
      if (r < 0)
	*err = ASSH_ERR_IO;
      else
	ev->transferred = r;

      p[i + POLL_CHILD_STDIN].revents &= ~POLLOUT;
      break;

    default:
      /* dicard channel data if the child is not able to sink data. */
      ev->transferred = ev->data.size;
      break;
    }

  return 0;
}

/* half close pipe to the command in the child process */
static void
its_eof(struct its_s *its,
			struct assh_event_channel_eof_s *ev)
{
  assert(ev->ch == its->channel);

  switch (its->state)
    {
    case ITS_OPEN:
      its->state = ITS_HALF_NO_RECV;
      break;
    case ITS_HALF_NO_SEND:
      its->state = ITS_CLOSED;
      break;
    default:
      abort();
    }

  printf("[%u] Interactive session %p eof\n",
	  getpid(), its);

  close(its->child_stdin_fd);
  its->child_stdin_fd = -1;
}

/* close pipe to the command in the child process */
static void
its_close(struct its_s *its,
			  struct assh_event_channel_close_s *ev)
{
  assert(ev->ch == its->channel);

  if (its->child_stdin_fd >= 0)
    close(its->child_stdin_fd);

  if (its->child_stderr_fd >= 0)
    close(its->child_stderr_fd);

  close(its->child_stdout_fd);

  /* remove from table, replace by last entry */
  int i;
  for (i = 0; its_table[i] != its; i++)
    ;
  its_table[i] = its_table[--its_table_count];

  printf("[%u] Interactive session %p closed\n",
	  getpid(), its);

  free(its);
}

/* Ssh event handling, This returns 0 when terminated. This returns 1
   when not sure that an IO operation can be performed without blocking. */
                                                        /* anchor evloop */
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
                                                        /* anchor evnetio */
        case ASSH_EVENT_READ:
          /* return if we are not sure that we can read some ssh
             stream from the socket without blocking */
          if (!(p[0].revents & POLLIN))
            {
              assh_event_done(session, &event, ASSH_OK);
              return 1;
            }

          /* let an helper function read ssh stream from socket */
          asshh_fd_event(session, &event, p[0].fd);
          p[0].revents &= ~POLLIN;
          break;

        case ASSH_EVENT_WRITE:
          /* return if we are not sure that we can write some ssh
             stream to the socket without blocking */
          if (!(p[0].revents & POLLOUT))
            {
              assh_event_done(session, &event, ASSH_OK);
              return 1;
            }

          /* let an helper function write ssh stream to the socket */
          asshh_fd_event(session, &event, p[0].fd);
          p[0].revents &= ~POLLOUT;
          break;
                                                        /* anchor everror */
	case ASSH_EVENT_SESSION_ERROR:
          /* Any error reported to the assh_event_done function will
             end up here. */
	  printf("[%u] SSH error: %s\n", getpid(),
		  assh_error_str(event.session.error.code));
	  assh_event_done(session, &event, ASSH_OK);
	  break;
                                                        /* anchor evauthmet */
	case ASSH_EVENT_USERAUTH_SERVER_METHODS:
	  /* wait 3 seconds after a failed password attempt */
	  if (event.userauth_server.methods.failed &
	      ASSH_USERAUTH_METHOD_PASSWORD)
	    sleep(3);

	  /* report the user authentication methods we accept. */
	  event.userauth_server.methods.methods =
	    ASSH_USERAUTH_METHOD_PUBKEY |
	    ASSH_USERAUTH_METHOD_PASSWORD;
	  assh_event_done(session, &event, ASSH_OK);
	  break;

                                                        /* anchor evauth */
	case ASSH_EVENT_USERAUTH_SERVER_USERKEY:
	case ASSH_EVENT_USERAUTH_SERVER_PASSWORD:
          /* let an helper function handle user authentication from
	     system password file and user authorized_keys file. */
	  asshh_server_event_auth(session, &event);
	  break;

	case ASSH_EVENT_USERAUTH_SERVER_SUCCESS: {
	  /* change the process user id when user authentication is over */
	  uid_t uid;
	  gid_t gid;
	  if (asshh_server_event_user_id(session, &uid, &gid, &event) ||
#ifdef CONFIG_ASSH_POSIX_SETGROUPS
	      setgroups(0, NULL) ||
#endif
	      setgid(gid) ||
	      setuid(uid))
	    abort();
	  break;
	}
                                                        /* anchor evchopen */
	case ASSH_EVENT_CHANNEL_OPEN: {
	  struct assh_event_channel_open_s *ev =
	    &event.connection.channel_open;

	  /* only accept session channels */
	  if (!assh_buffer_strcmp(&ev->type, "session"))
	    {
	      struct its_s *its = its_open(ev->ch);
	      if (its != NULL)
		{
		  assh_channel_set_pv(ev->ch, its);
		  ev->reply = ASSH_CONNECTION_REPLY_SUCCESS;
		}
	    }

	  assh_event_done(session, &event, ASSH_OK);
	  break;
	}
                                                        /* anchor evrq */
	case ASSH_EVENT_REQUEST: {
	  struct assh_event_request_s *ev =
	    &event.connection.request;
	  assh_status_t err = ASSH_OK;

	  /* handle some standard requests associated to our session,
	     relying on request decoding helper functions. */
	  if (ev->ch != NULL)
	    {
	      struct its_s *its = assh_channel_pv(ev->ch);
                                                        /* anchor evrqpty */
	      /* PTY request from the remote client */
	      if (!assh_buffer_strcmp(&ev->type, "pty-req"))
		{
#ifdef HAVE_POSIX_OPENPT
		  struct asshh_inter_pty_req_s rqi;
		  err = asshh_inter_decode_pty_req(&rqi, ev->rq_data.data,
						  ev->rq_data.size);

		  if (!err && !its_pty(its))
		    ev->reply = ASSH_CONNECTION_REPLY_SUCCESS;
#endif
		}
                                                        /* anchor evrqshell */
	      /* shell exec from the remote client */
	      else if (!assh_buffer_strcmp(&ev->type, "shell"))
		{
		  if (!its_exec(its, "/bin/sh"))
		    ev->reply = ASSH_CONNECTION_REPLY_SUCCESS;
		}
                                                        /* anchor evrqexec */
	      /* command exec from the remote client */
	      else if (!assh_buffer_strcmp(&ev->type, "exec"))
		{
		  struct asshh_inter_exec_s rqi;
		  err = asshh_inter_decode_exec(&rqi, ev->rq_data.data,
					       ev->rq_data.size);

		  if (!err)
		    {
		      /* we need a null terminated string */
		      char *cmd = assh_buffer_strdup(&rqi.command);
		      if (cmd && !its_exec(its, cmd))
			ev->reply = ASSH_CONNECTION_REPLY_SUCCESS;
		      free(cmd);
		    }
		}
                                                        /* anchor evrqdone */
	    }

	  assh_event_done(session, &event, err);
	  break;
	}
                                                        /* anchor eveof */
	case ASSH_EVENT_CHANNEL_EOF: {
	  struct assh_event_channel_eof_s *ev =
	    &event.connection.channel_eof;
	  struct its_s *its = assh_channel_pv(ev->ch);

	  /* handle session EOF */
	  its_eof(its, ev);
	  assh_event_done(session, &event, ASSH_OK);

	  break;
	}
                                                        /* anchor evclose */
	case ASSH_EVENT_CHANNEL_CLOSE: {
	  struct assh_event_channel_close_s *ev =
	    &event.connection.channel_close;
	  struct its_s *its = assh_channel_pv(ev->ch);

	  /* handle session close */
	  its_close(its, ev);
	  assh_event_done(session, &event, ASSH_OK);
	  break;
	}
                                                        /* anchor evdata */
	case ASSH_EVENT_CHANNEL_DATA: {
          struct assh_event_channel_data_s *ev =
	    &event.connection.channel_data;
	  struct its_s *its = assh_channel_pv(ev->ch);
	  assh_status_t err;

	  assh_bool_t wait = its_channel2child(its, p, ev, &err);
	  assh_event_done(session, &event, err);

	  if (wait)
	    return 1;
	  break;
	}
                                                        /* anchor evother */
	default:
	  assh_event_done(session, &event, ASSH_OK);
	}
    }
}
                                                        /* anchor algofilter */
static ASSH_KEX_FILTER_FCN(algo_filter)
{
  return (name->spec & ASSH_ALGO_ASSH) ||
         (name->spec & ASSH_ALGO_COMMON);
}
                                                        /* anchor connected */
static int
server_connected(struct assh_context_s *context,
		 int conn, const struct sockaddr_in *con_addr)
{
  printf("[%u] Client connected\n", getpid());

  /* init a session for the incoming connection */
  struct assh_session_s *session;

  if (assh_session_create(context, &session) ||
      assh_session_algo_filter(session, &algo_filter))
    ERROR("Unable to create assh session.\n");
                                                        /* anchor pollloop */
  struct pollfd p[MAX_POLL_ENTRIES];

  do {
    /* always poll on the ssh socket */
    p[0].fd = conn;
    p[0].events = POLLIN;
    if (assh_transport_has_output(session))
      p[0].events |= POLLOUT;

    /* also register file descriptors related to child processes */
    unsigned i;
    int poll_i = 1;
    for (i = 0; i < its_table_count; i++)
      its_poll_setup(its_table[i], session, p, &poll_i);
                                                        /* anchor poll */
    /* get the appropriate ssh protocol timeout */
    assh_time_t timeout = assh_session_delay(session, time(NULL)) * 1000;

    if (poll(p, poll_i, timeout) <= 0)
      continue;

                                                        /* anchor chi2cha */
    /* read from childs and transmit over ssh */
    for (i = 0; i < its_table_count; i++)
      its_child2channel(its_table[i], p);

                                                        /* anchor loopcall */
    /* let our ssh event loop handle ssh stream io events, channel data
       input events and any other ssh related events. */
  } while (ssh_loop(session, p));

  printf("[%u] Client disconnected\n", getpid());

  assh_session_release(session);
  close(conn);

  return 0;
}
                                                        /* anchor usage */
static void usage(const char *program, assh_bool_t opts)
{
  printf("usage: %s [-h | options]\n", program);

  if (opts)
    printf("List of available options:\n\n"
          "    -p port    specify the TCP port number\n"

          "    -h         show help\n");

  exit(1);
}
                                                        /* anchor main */
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
			  NULL, NULL, NULL, NULL) ||
      assh_service_register_default(context) ||
      assh_algo_register_default(context, ASSH_SAFETY_WEAK))
    ERROR("Unable to create an assh context.\n");

  /* load or create host key(s) */
  if (asshh_server_load_hk(context)
#ifdef CONFIG_ASSH_KEY_CREATE
      && asshh_key_create(context, assh_context_keys(context),
			  0, "ssh-ed25519", ASSH_ALGO_SIGN)
      && asshh_key_create(context, assh_context_keys(context),
			  0, "ssh-rsa", ASSH_ALGO_SIGN)
#endif
      )
    ERROR("Unable to load or create host key.\n");

  signal(SIGPIPE, SIG_IGN);
  signal(SIGCHLD, SIG_IGN);

  printf("Listening on port %s\n", port);

                                                        /* anchor mainloop */
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
	  server_connected(context, conn, &con_addr);
	  break;
	}
    }
                                                        /* anchor maincleanup */
  assh_context_release(context);

  return 0;
}
