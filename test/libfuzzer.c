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

#include "config.h"

#undef CONFIG_ASSH_ABI_WARN

#include <assh/assh_session.h>
#include <assh/assh_context.h>
#include <assh/assh_service.h>
#include <assh/assh_userauth_server.h>
#include <assh/assh_userauth_client.h>
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

#include <assh/helper_key.h>
#include <assh/helper_server.h>
#include <assh/helper_io.h>

#include "prng_weak.h"
#include "keys.h"

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

  if (Size < 3)
    return 0;

  const uint8_t *flags = Data;
  Data += 3;
  Size -= 3;

  struct assh_context_s context;

  if (assh_context_init(&context, flags[0] & 1 ? ASSH_SERVER : ASSH_CLIENT,
			  NULL, NULL, &assh_prng_dummy, NULL) != ASSH_OK ||
      assh_service_register_default(&context) != ASSH_OK ||
      assh_algo_register_va(&context, 0, 0, 0, &assh_kex_none.algo_wk.algo,
			    &assh_sign_none.algo_wk.algo,
			    &assh_mac_none.algo, &assh_cipher_none.algo,
			    &assh_compress_none.algo, NULL) ||
      assh_algo_register_default(&context, 0, 0, 0))
    ERROR("Unable to create an assh context.\n");

  struct assh_key_s *key_none;

  if (assh_key_create(&context, &key_none,
		      255, &assh_key_none, ASSH_ALGO_SIGN))
    ERROR("Unable to create host key.\n");

  assh_key_refinc(key_none);
  assh_key_insert(assh_context_keys(&context), key_none);

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
	      size_t s = assh_min_uint(Size, te->buf.size);
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

	case ASSH_EVENT_KEX_HOSTKEY_LOOKUP:
	  event.kex.hostkey_lookup.accept = !(flags[0] & 2);
	  assh_event_done(&session, &event, ASSH_OK);
	  break;

	  /*******************************************************/

        case ASSH_EVENT_USERAUTH_CLIENT_METHODS: {
	  int f = (flags[0] & 0x70) >> 4;
	  while (!event.userauth_client.methods.select)
	    {
	      switch (f & 7)
		{
		case 0:
		  if (!(event.userauth_client.methods.methods &
			ASSH_USERAUTH_METHOD_NONE))
		    break;
		  event.userauth_client.methods.select = ASSH_USERAUTH_METHOD_NONE;
		  break;

		case 1:
		case 2:
		  if (!(event.userauth_client.methods.methods &
			ASSH_USERAUTH_METHOD_PASSWORD))
		    break;
		  event.userauth_client.methods.select = ASSH_USERAUTH_METHOD_PASSWORD;
		  assh_buffer_strset(&event.userauth_client.methods.password, "test");
		  break;

		case 3:
		  if (!(event.userauth_client.methods.methods &
			ASSH_USERAUTH_METHOD_KEYBOARD))
		    break;
		  event.userauth_client.methods.select = ASSH_USERAUTH_METHOD_KEYBOARD;
		  assh_buffer_strset(&event.userauth_client.methods.keyboard_sub, "method");
		  break;

		case 4:
		case 5:
		  if (!(event.userauth_client.methods.methods
			& ASSH_USERAUTH_METHOD_PUBKEY))
		    break;
		  event.userauth_client.methods.select = ASSH_USERAUTH_METHOD_PUBKEY;

		  assh_key_refinc(key_none);
		  assh_key_insert(&event.userauth_client.methods.keys, key_none);
		  break;

		case 6:
		case 7:
		  if (!(event.userauth_client.methods.methods
			& ASSH_USERAUTH_METHOD_HOSTBASED))
		    break;
		  event.userauth_client.methods.select = ASSH_USERAUTH_METHOD_HOSTBASED;

		  assh_buffer_strset(&event.userauth_client.methods.host_name, "localhost");
		  assh_buffer_strset(&event.userauth_client.methods.host_username, "test");

		  assh_key_refinc(key_none);
		  assh_key_insert(&event.userauth_client.methods.keys, key_none);
		  break;
		}
	      f++;
	    }
	  assh_event_done(&session, &event, ASSH_OK);
          break;
	}

	case ASSH_EVENT_USERAUTH_CLIENT_SIGN: {
	  struct assh_event_userauth_client_sign_s *e =
	    &event.userauth_client.sign;

	  if (assh_sign_generate(&context, e->algo, key_none,
				 1, &e->auth_data, e->sign.data, &e->sign.len))
	    abort();

	  assh_event_done(&session, &event, ASSH_OK);
	  break;
	}

	case ASSH_EVENT_USERAUTH_CLIENT_PWCHANGE:
	  assh_buffer_strset(&event.userauth_client.pwchange.old_password, "oldpass");
	  assh_buffer_strset(&event.userauth_client.pwchange.new_password, "newpass");
	  assh_event_done(&session, &event, ASSH_OK);
	  break;

        case ASSH_EVENT_USERAUTH_CLIENT_KEYBOARD:
          for (unsigned i = 0; i < event.userauth_client.keyboard.count; i++)
	    assh_buffer_strset(&event.userauth_client.keyboard.responses[i], "resp");
	  assh_event_done(&session, &event, ASSH_OK);
	  break;

	  /*******************************************************/

	case ASSH_EVENT_USERAUTH_SERVER_METHODS:
	  event.userauth_server.methods.methods =
	    flags[1] & ASSH_USERAUTH_METHOD_SERVER_IMPLEMENTED;
	  assh_event_done(&session, &event, ASSH_OK);
	  break;

	case ASSH_EVENT_USERAUTH_SERVER_USERKEY:
	  event.userauth_server.userkey.found = !(flags[0] & 4);
	  assh_event_done(&session, &event, ASSH_OK);
	  break;

	case ASSH_EVENT_USERAUTH_SERVER_KBINFO: {
	  assh_buffer_strset(&event.userauth_server.kbinfo.name, "nametest");
	  assh_buffer_strset(&event.userauth_server.kbinfo.instruction, "insttest");
	  static const struct assh_cbuffer_s p[] = {
	    { .str = "AAAA", .len = 4 },
	    { .str = "BBBB", .len = 4 },
	  };
	  event.userauth_server.kbinfo.count = flags[0] & 8 ? 1 : 2;
	  event.userauth_server.kbinfo.prompts = p;
	  assh_event_done(&session, &event, ASSH_OK);
	  break;
	}

	case ASSH_EVENT_USERAUTH_SERVER_KBRESPONSE:
	  switch ((flags[0] & 0x30) >> 4)
	    {
	    case 0:
	      break;
	    case 1:
	      event.userauth_server.kbresponse.result = ASSH_SERVER_KBSTATUS_FAILURE;
	      break;
	    case 2:
	      event.userauth_server.kbresponse.result = ASSH_SERVER_KBSTATUS_SUCCESS;
	      break;
	    case 3:
	      event.userauth_server.kbresponse.result = ASSH_SERVER_KBSTATUS_CONTINUE;
	      break;
	    }
	  assh_event_done(&session, &event, ASSH_OK);
	  break;

	case ASSH_EVENT_USERAUTH_SERVER_PASSWORD:
	  switch ((flags[0] & 0xc0) >> 6)
	    {
	    case 0:
	      break;
	    case 1:
	      event.userauth_server.password.result = ASSH_SERVER_PWSTATUS_FAILURE;
	      break;
	    case 2:
	      event.userauth_server.password.result = ASSH_SERVER_PWSTATUS_SUCCESS;
	      break;
	    case 3:
	      event.userauth_server.password.result = ASSH_SERVER_PWSTATUS_CHANGE;
	      break;
	    }
	  assh_event_done(&session, &event, ASSH_OK);
	  break;

	case ASSH_EVENT_USERAUTH_SERVER_HOSTBASED:
	  event.userauth_server.hostbased.found = !(flags[2] & 1);
	  assh_event_done(&session, &event, ASSH_OK);
	  break;

	case ASSH_EVENT_USERAUTH_SERVER_SUCCESS:
	  if (flags[2] & 2)
	    event.userauth_server.success.methods = ASSH_USERAUTH_METHOD_SERVER_IMPLEMENTED;
	  assh_event_done(&session, &event, ASSH_OK);
	  break;

	  /*******************************************************/

	case ASSH_EVENT_CHANNEL_OPEN: {
	  struct assh_event_channel_open_s *ev =
	    &event.connection.channel_open;

	  if (flags[0] & 4)
	    ev->reply = ASSH_CONNECTION_REPLY_SUCCESS;

	  assh_event_done(&session, &event, ASSH_OK);
	  break;
	}

	case ASSH_EVENT_REQUEST: {
	  struct assh_event_request_s *ev =
	    &event.connection.request;

	  if (assh_prng_rand() & 1)
	    ev->reply = ASSH_CONNECTION_REPLY_SUCCESS;

	  assh_event_done(&session, &event, ASSH_OK);
	  break;
	}

	case ASSH_EVENT_CHANNEL_DATA: {
	  struct assh_event_channel_data_s *ev =
	    &event.connection.channel_data;

	  ev->transferred = ev->data.size;
	  assh_event_done(&session, &event, ASSH_OK);
	  break;
	}

	default:
	  assh_event_done(&session, &event, ASSH_OK);
	  break;
	}
    }

  assh_key_drop(&context, &key_none);

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
