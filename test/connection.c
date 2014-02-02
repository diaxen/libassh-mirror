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
#include <assh/assh_kex.h>
#include <assh/assh_cipher.h>
#include <assh/assh_sign.h>
#include <assh/assh_mac.h>
#include <assh/assh_prng.h>
#include <assh/srv_connection.h>
#include <assh/assh_event.h>

#include <errno.h>

#ifdef CONFIG_ASSH_USE_GCRYPT
# include <gcrypt.h>
#endif

int main()
{
#ifdef CONFIG_ASSH_USE_GCRYPT
  if (!gcry_check_version(GCRYPT_VERSION))
    return -1;
#endif

  struct assh_context_s context[2];
  assh_context_init(&context[0], ASSH_SERVER);
  assh_context_init(&context[1], ASSH_CLIENT);

  if (assh_service_register_va(&context[1], &assh_service_connection, NULL))
    return -1;
  if (assh_service_register_va(&context[0], &assh_service_connection, NULL))
    return -1;

  if (assh_algo_register_va(&context[0], 0, 0, &assh_kex_none, &assh_sign_dss,
			    &assh_cipher_none, &assh_hmac_sha1, NULL) != ASSH_OK)
    return -1;
  if (assh_algo_register_va(&context[1], 0, 0, &assh_kex_none, &assh_sign_dss,
			    &assh_cipher_none, &assh_hmac_sha1, NULL) != ASSH_OK)
    return -1;

  struct assh_session_s session[2];
  if (assh_session_init(&context[0], &session[0]) != ASSH_OK)
    return -1;
  if (assh_session_init(&context[1], &session[1]) != ASSH_OK)
    return -1;

  while (1)
    {
      unsigned int i;

      for (i = 0; i < 2; i++)
	{
	  struct assh_event_s event;

	  assh_error_t err = assh_event_get(&session[i], &event);
	  if (err != ASSH_OK)
	    return -1;

	  switch (event.id)
	    {
	    case ASSH_EVENT_CHANNEL_OPEN:
	      event.connection.channel_open.reply = ASSH_CONNECTION_REPLY_SUCCESS;
	      break;

	    default:
	      printf("Don't know how to handle event %u (context %u)\n", event.id, i);
	      return -1;
	    }
	  
	  err = assh_event_done(&session[i], &event);
	  if (ASSH_ERR_ERROR(err) != ASSH_OK)
	    {
	      fprintf(stderr, "assh error %i in main loop (errno=%i) (context %u)\n", err, errno, i);
	      return -1;
	    }
	}
    }

  return 0;
}

