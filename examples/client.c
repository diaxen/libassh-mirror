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
#include <assh/assh_prng.h>
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

  if (assh_service_register_default(&context))
    return -1;

  if (assh_algo_register_default(&context) != ASSH_OK)
    return -1;

  if (assh_context_prng(&context, &assh_prng_xswap) != ASSH_OK)
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
      if (err != ASSH_OK)
        goto err;

      switch (event.id)
        {
#if 0
        case ASSH_EVENT_HOSTKEY_LOOKUP:
          event.hostkey_lookup.accept = 1;
          break;

        case ASSH_EVENT_USER_NAME: {
          event.user_name.username = "guest";
          break;
        }

        case ASSH_EVENT_USER_PRIVKEY_LOOKUP: {
          if (assh_load_key_filename(&context, &event.user_privkey_lookup.key,
                                     event.user_privkey_lookup.key.algo, "user_key",
                                     ASSH_KEY_FMT_PV_RFC2440_PEM_ASN1))
            event.user_privkey_lookup.key = NULL;
          break;
        }

        case ASSH_EVENT_USER_PASSWORD_INPUT: {
          event.user_password_input.password = "anonymous";
          break;          
        }
#endif
        default:
          assert(!"Don't know how to handle this event");
        }

      err = assh_event_done(&session, &event);
      if (err != ASSH_OK)
        goto err;
    }

  assh_session_cleanup(&session);
  assh_context_cleanup(&context);
  return 0;

 err:
  fprintf(stderr, "assh error %i in main loop (errno=%i)\n", err, errno);
  return err;
}

