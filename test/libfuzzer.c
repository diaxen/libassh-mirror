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

#include "config.h"

#undef CONFIG_ASSH_ABI_WARN

#include <assh/assh_session.h>
#include <assh/assh_context.h>
#include <assh/assh_service.h>
#include <assh/assh_userauth_server.h>
#include <assh/assh_connection.h>
#include <assh/assh_kex.h>
#include <assh/assh_cipher.h>
#include <assh/assh_sign.h>
#include <assh/assh_mac.h>
#include <assh/assh_prng.h>
#include <assh/assh_compress.h>
#include <assh/assh_event.h>
#include <assh/assh_algo.h>
#include <assh/assh_packet.h>
#include <assh/key_eddsa.h>

#include <assh/helper_key.h>
#include <assh/helper_server.h>
#include <assh/helper_io.h>

#include "prng_dummy.h"

#define ERROR(...) do { fprintf(stderr, __VA_ARGS__); exit(1); } while (0)

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  if (assh_deps_init())
    ERROR("initialization error\n");

  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
  prng_seed = 1;

  static const struct assh_algo_s *algos[] = {
    &assh_kex_none.algo, &assh_sign_none.algo,
    &assh_cipher_none.algo, &assh_hmac_none.algo, &assh_compress_none.algo,
    NULL
  };

  if (!Size)
    return 0;

  const uint8_t *flags = Data;
  Data += 1;
  Size -= 1;

  struct assh_context_s context;

  if (assh_context_init(&context, flags[0] & 1 ? ASSH_SERVER : ASSH_CLIENT,
			  NULL, NULL, &assh_prng_dummy, &context_prng_seed) != ASSH_OK ||
      assh_service_register_default(&context) != ASSH_OK ||
      assh_algo_register_static(&context, algos) != ASSH_OK)
    ERROR("Unable to create an assh context.\n");

  if (assh_key_create(&context, assh_context_keys(&context),
		      255, &assh_key_none, ASSH_ALGO_SIGN))
    ERROR("Unable to create host key.\n");

  struct assh_session_s session;

  if (assh_session_init(&context, &session) != ASSH_OK)
    ERROR("Unable to create an assh session.\n");

  struct assh_event_s event;

  while (assh_event_get(&session, &event, time(NULL)))
    {
      switch (event.id)
	{
	case ASSH_EVENT_READ: {
	  struct assh_event_transport_read_s *te = &event.transport.read;

	  if (Size == 0)
	    {
	      assh_event_done(&session, &event, ASSH_ERR_IO);
	    }
	  else
	    {
	      size_t s = ASSH_MIN(Size, te->buf.size);
	      memcpy(te->buf.data, Data, s);
	      te->transferred = s;
	      Data += s;
	      Size -= s;
	      assh_event_done(&session, &event, ASSH_OK);
	    }
	  break;
	}

	case ASSH_EVENT_WRITE: {
	  struct assh_event_transport_write_s *te = &event.transport.write;
	  /* discard output */
          te->transferred = te->buf.size;
	  assh_event_done(&session, &event, ASSH_OK);
	  break;
	}

	case ASSH_EVENT_CHANNEL_OPEN: {
	  struct assh_event_channel_open_s *ev =
	    &event.connection.channel_open;

	  if (assh_prng_rand() & 1)
	    ev->reply = ASSH_CONNECTION_REPLY_SUCCESS;

	  assh_event_done(&session, &event, ASSH_OK);
	  break;
	}

	case ASSH_EVENT_REQUEST: {
	  struct assh_event_request_s *ev = &event.connection.request;

	  if (assh_prng_rand() & 1)
	    ev->reply = ASSH_CONNECTION_REPLY_SUCCESS;

	  assh_event_done(&session, &event, ASSH_OK);
	  break;
	}

	case ASSH_EVENT_CHANNEL_DATA: {
	  struct assh_event_channel_data_s *ev = &event.connection.channel_data;

	  ev->transferred = ev->data.size;
	  assh_event_done(&session, &event, ASSH_OK);
	  break;
	}

	default:
	  assh_event_done(&session, &event, ASSH_OK);
	  break;
	}
    }

  assh_session_cleanup(&session);
  assh_context_cleanup(&context);

  return 0;
}

#ifdef TESTINPUT
int main(int argc, char **argv)
{
  LLVMFuzzerInitialize(0, 0);

  if (argc < 2)
    return 1;

  FILE *f = fopen(argv[1], "rb");
  if (!f)
    return 1;

  fseek(f, 0, SEEK_END);
  size_t size = ftell(f);
  fseek(f, 0, SEEK_SET);

  uint8_t *buf = alloca(size);
  fread(buf, size, 1, f);

  return LLVMFuzzerTestOneInput(buf, size);
}
#endif
