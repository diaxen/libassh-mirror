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
#include <assh/assh_userauth_client.h>
#include <assh/assh_compress.h>
#include <assh/assh_connection.h>
#include <assh/helper_key.h>
#include <assh/helper_interactive.h>
#include <assh/assh_kex.h>
#include <assh/helper_fd.h>
#include <assh/assh_event.h>
#include <assh/assh_algo.h>
#include <assh/key_rsa.h>
#include <assh/key_dsa.h>

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

assh_bool_t use_compression = 0;

static ASSH_KEX_FILTER_FCN(algo_filter)
{
  if (algo->class_ == ASSH_ALGO_COMPRESS &&
      use_compression == (algo == &assh_compress_none.algo))
    return 0;

  return (name->spec & ASSH_ALGO_ASSH) ||
         (name->spec & ASSH_ALGO_COMMON);
}

int main(int argc, char **argv)
{
#ifdef CONFIG_ASSH_USE_GCRYPT
  if (!gcry_check_version(GCRYPT_VERSION))
    return -1;
#endif

  int port = 22;

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

  assh_bool_t auth_keys_done = 0;
  assh_safety_t safety = 0;

  struct assh_channel_s *session_ch;
  struct assh_request_s *request;

  while (1)
    {
      struct assh_event_s event;

      err = assh_event_get(session, &event, time(NULL));
      if (ASSH_ERR_ERROR(err) != ASSH_OK)
        {
          fprintf(stderr, "assh error %x sv %x in main loop (errno=%i)\n",
                  (unsigned)ASSH_ERR_ERROR(err),
                  (unsigned)ASSH_ERR_SEVERITY(err), errno);
          if (ASSH_ERR_ERROR(err) == ASSH_ERR_CLOSED)
            goto err_;
          continue;
        }

      switch (event.id)
        {
        case ASSH_EVENT_READ:
        case ASSH_EVENT_WRITE:
          err = assh_fd_event(session, &event, sock);
          break;

        case ASSH_EVENT_KEX_HOSTKEY_LOOKUP: {
          struct assh_event_kex_hostkey_lookup_s *ev =
            &event.kex.hostkey_lookup;

          /* XXX the key validity may be checked before adding
             the key to the list of known hosts. */
          if (assh_key_validate(context, ev->key))
            break;

          event.kex.hostkey_lookup.accept = 1;
          break;
        }

        case ASSH_EVENT_KEX_DONE: {
          struct assh_event_kex_done_s *ev = &event.kex.done;

          safety = ev->safety;

          fprintf(stderr, "kex safety factor: %u\n", safety);
          break;
        }

        case ASSH_EVENT_USERAUTH_CLIENT_USER: {
          struct assh_event_userauth_client_user_s *ev =
            &event.userauth_client.user;

          assh_buffer_strset(&ev->username, "test");

          break;
        }

        case ASSH_EVENT_USERAUTH_CLIENT_METHODS: {
          struct assh_event_userauth_client_methods_s *ev =
            &event.userauth_client.methods;

          if ((ev->methods & ASSH_USERAUTH_METHOD_PUBKEY)
              && !(auth_keys_done & 1))
            {
              auth_keys_done |= 1;
              ev->select = ASSH_USERAUTH_METHOD_PUBKEY;

              if (assh_load_key_filename(context, &ev->keys,
                                         &assh_key_dsa, ASSH_ALGO_SIGN, "dsa_user_key",
                                         ASSH_KEY_FMT_PV_PEM, NULL, 0) != ASSH_OK)
                fprintf(stderr, "unable to load user dsa key\n");

              if (assh_load_key_filename(context, &ev->keys,
                                         &assh_key_rsa, ASSH_ALGO_SIGN, "rsa_user_key",
                                         ASSH_KEY_FMT_PV_PEM, NULL, 0) != ASSH_OK)
                fprintf(stderr, "unable to load user rsa key\n");
            }

          else if ((ev->methods & ASSH_USERAUTH_METHOD_HOSTBASED)
              && !(auth_keys_done & 2))
            {
              auth_keys_done |= 2;
              ev->select = ASSH_USERAUTH_METHOD_HOSTBASED;

              if (assh_load_key_filename(context, &ev->keys,
                                         &assh_key_rsa, ASSH_ALGO_SIGN, "ssh_host_rsa_key",
                                         ASSH_KEY_FMT_PV_PEM, NULL, 0) != ASSH_OK)
                fprintf(stderr, "unable to load host rsa key\n");

              assh_buffer_strset(&ev->host_name, "localhost");
              assh_buffer_strset(&ev->host_username, "test");
            }

          else if ((ev->methods & ASSH_USERAUTH_METHOD_PASSWORD)
              && safety > 25)
            {
              ev->select = ASSH_USERAUTH_METHOD_PASSWORD;
              fprintf(stderr, "password input\n");
              assh_buffer_strset(&ev->password, "test");
            }
          break;
        }

        case ASSH_EVENT_USERAUTH_CLIENT_BANNER: {
          struct assh_event_userauth_client_banner_s *ev =
            &event.userauth_client.banner;

          /* XXX terminal control chars should be filtered */
          fwrite(ev->text.str, ev->text.len, 1, stderr);
          break;
        }

        case ASSH_EVENT_USERAUTH_CLIENT_SUCCESS:
          fprintf(stderr, "userauth success\n");
          break;

        case ASSH_EVENT_CONNECTION_START: {
          /* may send channel related requests from this point */
          err = assh_channel_open(session, "session", 7, NULL, 0, &session_ch);
          break;
        }

        case ASSH_EVENT_CHANNEL_OPEN_REPLY: {
          struct assh_event_channel_open_reply_s *ev =
            &event.connection.channel_open_reply;
          assert(ev->ch == session_ch);

          if (ev->reply != ASSH_CONNECTION_REPLY_SUCCESS)
            {
              fprintf(stderr, "unable to open session channel\n");
              err = ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT;
            }
          else
            {
              assh_event_done(session, &event, ASSH_OK);
              struct assh_inter_pty_req_s i;
              assh_inter_init_pty_req(&i, getenv("TERM"), 0, 0, 0, 0, NULL);
              assh_inter_send_pty_req(session, session_ch, &request, &i);
            }
          break;
        }

        case ASSH_EVENT_REQUEST_REPLY: {
          struct assh_event_request_reply_s *ev =
            &event.connection.request_reply;
          assert(ev->ch == session_ch);
          assert(ev->rq == request);
          if (ev->reply != ASSH_CONNECTION_REPLY_SUCCESS)
            {
              fprintf(stderr, "unable to get a pty\n");
              err = ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT;
            }
          else
            {
              assh_event_done(session, &event, ASSH_OK);
              assh_inter_send_shell(session, session_ch, NULL);
            }
          break;
        }

        default:
          printf("Don't know how to handle event %u\n", event.id);
        }

      assh_event_done(session, &event, err);
    }

 err_:
  assh_session_release(session);
  assh_context_release(context);
  return 0;
}

