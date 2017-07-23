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
#include <assh/assh_userauth_server.h>
#include <assh/assh_connection.h>
#include <assh/assh_kex.h>
#include <assh/assh_event.h>
#include <assh/assh_algo.h>
#include <assh/assh_packet.h>

#include <assh/helper_fd.h>
#include <assh/helper_key.h>
#include <assh/helper_interactive.h>

#include <assh/key_rsa.h>
#include <assh/key_dsa.h>
#include <assh/key_eddsa.h>
#include <assh/key_ecdsa.h>

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

static ASSH_KEX_FILTER_FCN(algo_filter)
{
  return (name->spec & ASSH_ALGO_ASSH) ||
         (name->spec & ASSH_ALGO_COMMON);
}

int main()
{
#ifdef CONFIG_ASSH_USE_GCRYPT
  if (!gcry_check_version(GCRYPT_VERSION))
    return -1;
  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
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

  /** init a server context */
  struct assh_context_s *context;

  if (assh_context_create(&context, ASSH_SERVER, CONFIG_ASSH_MAX_ALGORITHMS,
			  NULL, NULL, NULL, NULL))
    abort();

  /** register authentication and connection services */
  if (assh_service_register_default(context) != ASSH_OK)
    return -1;

  /** register algorithms */
  if (assh_algo_register_default(context, 99, 10, 0) != ASSH_OK)
    return -1;

  /** load host key */
  if (assh_load_hostkey_filename(context, &assh_key_dsa, ASSH_ALGO_SIGN, "dsa_host_key",
				 ASSH_KEY_FMT_PV_PEM, 0) != ASSH_OK)
    fprintf(stderr, "unable to load dsa key\n");

  if (assh_load_hostkey_filename(context, &assh_key_rsa, ASSH_ALGO_SIGN, "rsa_host_key",
				 ASSH_KEY_FMT_PV_PEM, 0) != ASSH_OK)
    fprintf(stderr, "unable to load rsa key\n");

  if (assh_load_hostkey_filename(context, &assh_key_ed25519, ASSH_ALGO_SIGN, "ed25519_host_key",
				 ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 0) != ASSH_OK)
    fprintf(stderr, "unable to load ed25519 key\n");

  if (assh_load_hostkey_filename(context, &assh_key_eddsa_e382, ASSH_ALGO_SIGN, "e382_host_key",
				 ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 0) != ASSH_OK)
    fprintf(stderr, "unable to load eddsa e382 key\n");

  if (assh_load_hostkey_filename(context, &assh_key_eddsa_e521, ASSH_ALGO_SIGN, "e521_host_key",
				 ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 0) != ASSH_OK)
    fprintf(stderr, "unable to load eddsa e521 key\n");

  if (assh_load_hostkey_filename(context, &assh_key_ecdsa_nistp, ASSH_ALGO_SIGN, "ecdsa_host_key",
				 ASSH_KEY_FMT_PV_PEM, 0) != ASSH_OK)
    fprintf(stderr, "unable to load ecdsa key\n");

  signal(SIGPIPE, SIG_IGN);

  while (1)
    {
      struct sockaddr_in con_addr;
      socklen_t addr_size = sizeof(con_addr);

      int conn = accept(sock, (struct sockaddr*)&con_addr, &addr_size);

      /** init a session for the incoming connection */
      struct assh_session_s *session;
      if (assh_session_create(context, &session) != ASSH_OK)
	return -1;

      if (assh_session_algo_filter(session, &algo_filter))
	return -1;

      time_t t = time(0);
      fprintf(stderr, "============== %s\n", ctime(&t));

      struct assh_event_s event;

      /** get events from the core. */
      while (assh_event_get(session, &event, time(NULL)))
	{
	  switch (event.id)
	    {
	    case ASSH_EVENT_READ:
	    case ASSH_EVENT_WRITE:
	      assh_fd_event(session, &event, conn);
	      break;

	    case ASSH_EVENT_ERROR:
	      fprintf(stderr, "SSH error: %s\n",
		      assh_error_str(event.error.code));
	      assh_event_done(session, &event, ASSH_OK);
	      break;

	    case ASSH_EVENT_KEX_DONE: {
	      fprintf(stderr, "kex safety factor: %u\n", event.kex.done.safety);
	      break;
	    }

	    case ASSH_EVENT_USERAUTH_SERVER_METHODS: {
	      struct assh_event_userauth_server_methods_s *ev =
		&event.userauth_server.methods;

	      assh_buffer_strset(&ev->banner, "welcome!");

	      assh_event_done(session, &event, ASSH_OK);
	      break;
	    }

	    case ASSH_EVENT_USERAUTH_SERVER_USERKEY: {
	      struct assh_event_userauth_server_userkey_s *ev =
		&event.userauth_server.userkey;

#warning validate key ? keys should be validated once when added to the list

	      /* XXX check that user public key is in the list of
		 user authorized keys. */
	      ev->found = 1;

	      assh_event_done(session, &event, ASSH_OK);
	      break;
	    }

	    case ASSH_EVENT_USERAUTH_SERVER_PASSWORD: {
	      struct assh_event_userauth_server_password_s *ev =
		&event.userauth_server.password;

	      /* XXX check that user/password pair matches. */
	      ev->result = ASSH_SERVER_PWSTATUS_SUCCESS;

	      assh_event_done(session, &event, ASSH_OK);
	      break;
	    }

	    case ASSH_EVENT_USERAUTH_SERVER_HOSTBASED: {
	      struct assh_event_userauth_server_hostbased_s *ev =
		&event.userauth_server.hostbased;

	      /* XXX check that host public key is in the list of
		 user authorized keys. */
	      ev->found = 1;

	      assh_event_done(session, &event, ASSH_OK);
	      break;
	    }

	    case ASSH_EVENT_CHANNEL_OPEN: {
	      struct assh_event_channel_open_s *ev =
		&event.connection.channel_open;

	      if (!assh_buffer_strcmp(&ev->type, "session"))
		  ev->reply = ASSH_CONNECTION_REPLY_SUCCESS;

	      assh_event_done(session, &event, ASSH_OK);
	      break;
	    }

	    case ASSH_EVENT_REQUEST: {
	      struct assh_event_request_s *ev = &event.connection.request;
	      assh_error_t err = ASSH_OK;

	      if (ev->ch)
		{
		  if (!assh_buffer_strcmp(&ev->type, "shell"))
		    {
		      ev->reply = ASSH_CONNECTION_REPLY_SUCCESS;
		    }
		  else if (!assh_buffer_strcmp(&ev->type, "pty-req"))
		    {
		      struct assh_inter_pty_req_s rqi;
		      err = assh_inter_decode_pty_req(&rqi, ev->rq_data.data, ev->rq_data.size);
		      if (!err)
			{
			  ev->reply = ASSH_CONNECTION_REPLY_SUCCESS;
			}
		    }
		}

	      assh_event_done(session, &event, err);
	      break;
	    }

	    case ASSH_EVENT_CHANNEL_DATA: {
	      struct assh_event_channel_data_s *ev = &event.connection.channel_data;

	      uint8_t *data;
	      size_t size = ev->data.size;

	      /* allocate output data packet */
	      assh_error_t perr = assh_channel_data_alloc(ev->ch, &data, &size, size);

	      if (perr == ASSH_OK)  /* copy input data to output buffer */
		memcpy(data, ev->data.data, size);

	      ev->transferred = size;

	      /* acknowledge input data event before sending */
	      assh_event_done(session, &event, ASSH_OK);

	      if (perr == ASSH_OK)  /* send output data */
		assh_channel_data_send(ev->ch, size);
	      break;
	    }

	    default:
	      printf("Don't know how to handle event %u\n", event.id);
	      assh_event_done(session, &event, ASSH_OK);
	    }
	}

      assh_session_release(session);
      break;
    }

  assh_context_release(context);

  return 0;
}

