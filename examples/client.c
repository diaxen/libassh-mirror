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
#include <assh/helper_key.h>
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

static ASSH_KEX_FILTER_FCN(algo_filter)
{
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

  if (assh_algo_register_default(context, 99, 10) != ASSH_OK)
    return -1;

  struct assh_session_s *session;

  if (assh_session_create(context, &session) != ASSH_OK)
    return -1;

  if (assh_session_algo_filter(session, &algo_filter))
    return -1;

  assh_error_t err;

  struct assh_event_hndl_table_s ev_table;
  assh_event_table_init(&ev_table);

  struct assh_fd_context_s fd_ctx;
  assh_fd_events_register(&ev_table, &fd_ctx, sock);

  assh_bool_t auth_keys_done = 0;

  while (1)
    {
      struct assh_event_s event;

      err = assh_event_table_run(session, &ev_table, &event);
      if (ASSH_ERR_ERROR(err) != ASSH_OK)
        {
          fprintf(stderr, "assh error %x sv %x in main loop (errno=%i)\n",
                  ASSH_ERR_ERROR(err), ASSH_ERR_SEVERITY(err), errno);
          if (ASSH_ERR_ERROR(err) == ASSH_ERR_CLOSED)
            goto err_;
          continue;
        }

      switch (event.id)
        {
        case ASSH_EVENT_KEX_HOSTKEY_LOOKUP: {
          /* XXX the key validity may be checked before adding
             the key to the list of known hosts. */
          if (assh_key_validate(context, event.kex.hostkey_lookup.key))
            break;

          event.kex.hostkey_lookup.accept = 1;
          break;
        }

        case ASSH_EVENT_USERAUTH_CLIENT_USER: {
          event.userauth_client.user.username.str = "test";
          event.userauth_client.user.username.len = 4;
          break;
        }

        case ASSH_EVENT_USERAUTH_CLIENT_METHODS: {
          if (event.userauth_client.methods.use_pub_key && !auth_keys_done)
            {
              auth_keys_done = 1;

              if (assh_load_key_filename(context, &event.userauth_client.methods.pub_keys,
                                         &assh_key_dsa, ASSH_ALGO_SIGN, "dsa_user_key",
                                         ASSH_KEY_FMT_PV_PEM, NULL) != ASSH_OK)
                fprintf(stderr, "unable to load user dsa key\n");

              if (assh_load_key_filename(context, &event.userauth_client.methods.pub_keys,
                                         &assh_key_rsa, ASSH_ALGO_SIGN, "rsa_user_key",
                                         ASSH_KEY_FMT_PV_PEM, NULL) != ASSH_OK)
                fprintf(stderr, "unable to load user rsa key\n");
            }

          if (event.userauth_client.methods.use_password &&
              assh_session_safety(session) > 25)
            {
              fprintf(stderr, "password input\n");
              event.userauth_client.methods.password.str = "test";
              event.userauth_client.methods.password.len = 4;
            }
          break;
        }

        default:
          printf("Don't know how to handle event %u\n", event.id);
        }

      err = assh_event_done(session, &event, ASSH_OK);
      if (err != ASSH_OK)
        fprintf(stderr, "assh error %x in main loop (errno=%i)\n", err, errno);
    }

 err_:
  assh_session_release(session);
  assh_context_release(context);
  return 0;
}

