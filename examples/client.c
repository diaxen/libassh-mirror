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
#include <assh/srv_userauth_client.h>
#include <assh/helper_fd.h>
#include <assh/helper_key.h>
#include <assh/assh_kex.h>
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

  struct assh_context_s context;
  assh_context_init(&context, ASSH_CLIENT);

  if (assh_service_register_default(&context) != ASSH_OK)
    return -1;

  if (assh_algo_register_default(&context, 99, 10) != ASSH_OK)
    return -1;

  struct assh_session_s session;
  if (assh_session_init(&context, &session) != ASSH_OK)
    return -1;

  int rnd_fd = open("/dev/urandom", O_RDONLY);
  assert(rnd_fd >= 0);

  assh_error_t err;

  fprintf(stderr, "assh loop\n");
  while (1)
    {
      struct assh_event_s event;

      err = assh_fd_event_get(&session, sock, rnd_fd, &event);
      if (ASSH_ERR_ERROR(err) != ASSH_OK)
        {
          fprintf(stderr, "assh error %i in main loop (errno=%i)\n", err, errno);

          if (ASSH_ERR_ERROR(err) == ASSH_ERR_DISCONNECTED)
            return err;
          continue;
        }

      switch (event.id)
        {
        case ASSH_EVENT_KEX_HOSTKEY_LOOKUP: {
          /* XXX the key validity may be checked before adding
             the key to the list of known hosts. */
          assh_bool_t valid;
          if (assh_key_validate(&context, event.kex.hostkey_lookup.key,
                                &valid) || !valid)
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
          if (event.userauth_client.methods.pub_keys)
            assh_load_key_filename(&context, &event.userauth_client.methods.pub_keys,
                                   "ssh-dss", "/home/test/.ssh/id_dsa", ASSH_KEY_FMT_PV_RFC2440_PEM_ASN1);

#if 0
          if (event.userauth_client.methods.password)
            event.userauth_client_methods.password = "test";
#endif
          break;
        }

        default:
          printf("Don't know how to handle event %u\n", event.id);
        }

      err = assh_event_done(&session, &event);
      if (ASSH_ERR_ERROR(err) != ASSH_OK)
        fprintf(stderr, "assh error %i in main loop (errno=%i)\n", err, errno);
    }

  assh_session_cleanup(&session);
  assh_context_cleanup(&context);
  return 0;
}

