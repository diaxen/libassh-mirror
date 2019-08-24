/*

  libassh - asynchronous ssh2 client/server library.

  Copyright (C) 2016 Alexandre Becoulet <alexandre.becoulet@free.fr>

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
#include <assh/assh_compress.h>
#include <assh/helper_key.h>
#include <assh/assh_connection.h>
#include <assh/assh_userauth_client.h>
#include <assh/assh_userauth_server.h>
#include <assh/assh_event.h>
#include <assh/key_rsa.h>
#include <assh/key_dsa.h>
#include <assh/key_eddsa.h>
#include <assh/key_ecdsa.h>

#include <getopt.h>

#include "fifo.h"
#include "prng_weak.h"
#include "leaks_check.h"
#include "test.h"
#include "cipher_fuzz.h"

static struct fifo_s fifo[2];
static struct assh_context_s context[2];
static struct assh_session_s session[2];

struct test_key_s
{
  struct assh_key_s *key_s, *key_c, *key_cpub;
  uint8_t *blob;
  size_t blob_len;
};

#define TEST_KEYS_COUNT 6
static struct test_key_s keys[TEST_KEYS_COUNT];

struct {
  const struct assh_key_algo_s *algo;
  size_t bits;
} keys_algo[TEST_KEYS_COUNT] = {
  { &assh_key_rsa, 1024 },
  { &assh_key_dsa, 1024 },
  { &assh_key_ed25519, 255 },
  { &assh_key_eddsa_e521, 521 },
  { &assh_key_ecdsa_nistp, 256 },
  { &assh_key_ecdsa_nistp, 521 },
};

#define TEST_PASS_COUNT 5
static const char * pass[TEST_PASS_COUNT] = {
  "foo",
  "bar",
  "0123456789",
  "testpassword",
  "verylongpasswordverylongpassword",
};

static unsigned long auth_done_count = 0;
static unsigned long auth_stall_count = 0;
static unsigned long auth_server_pubkey_found_count = 0;
static unsigned long auth_server_pubkey_wrong_count = 0;
static unsigned long auth_server_password_ok_count = 0;
static unsigned long auth_server_password_change_count = 0;
static unsigned long auth_server_password_wrong_count = 0;
static unsigned long auth_server_password_new_count = 0;
static unsigned long auth_server_keyboard_info_count = 0;
static unsigned long auth_server_keyboard_success_count = 0;
static unsigned long auth_server_keyboard_failure_count = 0;
static unsigned long auth_server_keyboard_continue_count = 0;
static unsigned long auth_server_methods_count = 0;
static unsigned long auth_server_failure_count = 0;
static unsigned long auth_server_partial_success_count = 0;
static unsigned long auth_server_success_count = 0;
static unsigned long auth_server_err_count = 0;
static unsigned long auth_client_none_count = 0;
static unsigned long auth_client_pubkey_count = 0;
static unsigned long auth_client_hostbased_count = 0;
static unsigned long auth_client_int_sign_count = 0;
static unsigned long auth_client_ext_sign_count = 0;
static unsigned long auth_client_password_count = 0;
static unsigned long auth_client_password_change_count = 0;
static unsigned long auth_client_password_skip_change_count = 0;
static unsigned long auth_client_keyboard_count = 0;
static unsigned long auth_client_keyboard_resp_count = 0;
static unsigned long auth_client_partial_success_count = 0;
static unsigned long auth_client_success_count = 0;
static unsigned long auth_client_err_count = 0;

/* use some of the available keys */
static assh_bool_t use_keys(struct assh_key_s **k)
{
  uint_fast8_t i;
  assh_bool_t done = 0;

  for (i = 0; i < TEST_KEYS_COUNT; i++)
    switch (assh_prng_rand() & 3)
      {
      case 0:
      case 1:
	break;
      case 2:
	if (keys[i].key_c->ref_count > 1)
	  break;
	done = 1;
	assh_key_refinc(keys[i].key_c);
	assh_key_insert(k, keys[i].key_c);
	auth_client_int_sign_count++;
	break;
      case 3:
	if (keys[i].key_cpub->ref_count > 1)
	  break;
	done = 1;
	assh_key_refinc(keys[i].key_cpub);
	assh_key_insert(k, keys[i].key_cpub);
	auth_client_ext_sign_count++;
	break;
      }

  return done;
}

static int test()
{
  uint_fast8_t i;
  uint_fast8_t done = 0;
  uint_fast8_t stall = 0;
  size_t alloc_size_init = alloc_size;

  ASSH_DEBUG("%u allocated before sessions\n", alloc_size_init);

  for (i = 0; i < 2; i++)
    {
      if (assh_session_init(&context[i], &session[i]) != ASSH_OK)
	TEST_FAIL("");

      fifo_init(&fifo[i]);
    }

  const char *username = NULL;
  const char *password = NULL;
  const char *new_password = NULL;

  while (1)
    {
      struct assh_event_s event;

      /****************************************************/
      ASSH_DEBUG("=== server %u ===\n", stall);
      if (!assh_event_get(&session[0], &event, 0))
	TEST_FAIL("session terminated");

      switch (event.id)
	{
	  /* exchange ssh stream with the client using a in memory
	     fifo and detect protocol stall */
	case ASSH_EVENT_READ:
	  if (fifo_rw_event(fifo, &event, 0))
	    stall++;
	  break;

	case ASSH_EVENT_WRITE:
	  stall++;
	  if (!fifo_rw_event(fifo, &event, 0))
	    stall = 0;
	  break;

	case ASSH_EVENT_SESSION_ERROR:
	  auth_server_err_count++;
	  if (packet_fuzz || alloc_fuzz)
	    goto done;
	  TEST_FAIL("error event");

	case ASSH_EVENT_KEX_DONE:
	  assert(!session[0].tr_user_auth_done);
	  assert(!session[0].user_auth_done);
	  break;

	case ASSH_EVENT_USERAUTH_SERVER_METHODS:
	  event.userauth_server.methods.banner.size = 4 - assh_prng_rand() % 5;
	  event.userauth_server.methods.banner.str = "test";

	  do {
	    /* randomly choose some initial allowed methods */
	    event.userauth_server.methods.methods =
	      assh_prng_rand() & ASSH_USERAUTH_METHOD_SERVER_IMPLEMENTED;
	  } while (!event.userauth_server.methods.methods);

	  /* unlimited retries */
	  event.userauth_server.methods.retries = 254;

	  if (event.userauth_server.methods.failed)
	    auth_server_failure_count++;
	  auth_server_methods_count++;

	  break;

	case ASSH_EVENT_USERAUTH_SERVER_NONE:
	  break;

	case ASSH_EVENT_USERAUTH_SERVER_USERKEY: {
	  stall = 0;
	  assh_bool_t found = assh_prng_rand() & 1;
	  /* randomly report userkey found */
	  event.userauth_server.userkey.found = found;
	  if (found)
	    auth_server_pubkey_found_count++;
	  else
	    auth_server_pubkey_wrong_count++;
	  if (!packet_fuzz)
	    {
	      if (assh_buffer_strcmp(&event.userauth_server.userkey.username, username))
		TEST_FAIL("");

	      uint_fast8_t i;
	      for (i = 0; i < TEST_KEYS_COUNT; i++)
		if (assh_key_cmp(&context[0], event.userauth_server.userkey.pub_key,
				 keys[i].key_s, 1))
		  break;
	      if (i == TEST_KEYS_COUNT)
		TEST_FAIL("");
	    }
	  break;
	}

	case ASSH_EVENT_USERAUTH_SERVER_KBINFO: {
	  assh_buffer_strset(&event.userauth_server.kbinfo.name,
			     "nametest" + assh_prng_rand() % 8);
	  assh_buffer_strset(&event.userauth_server.kbinfo.instruction,
			     "insttest" + assh_prng_rand() % 8);
	  static const struct assh_cbuffer_s p[] = {
	    { .str = "password: ", .len = 10 },
	    { .str = "token: ", .len = 7 },
	    { .str = "foo: ", .len = 5 },
	    { .str = "bar: ", .len = 5 },
	  };
	  event.userauth_server.kbinfo.count = assh_prng_rand() % 4;
	  event.userauth_server.kbinfo.prompts = p;
	  auth_server_keyboard_info_count++;
	  break;
	}

	case ASSH_EVENT_USERAUTH_SERVER_KBRESPONSE: {
	  switch (assh_prng_rand() % 8)
	    {
	    case 0:
	      break;
	    case 1:
	    case 2:
	      auth_server_keyboard_failure_count++;
	      event.userauth_server.kbresponse.result = ASSH_SERVER_KBSTATUS_FAILURE;
	      break;
	    case 3:
	    case 4:
	    case 5:
	      auth_server_keyboard_success_count++;
	      event.userauth_server.kbresponse.result = ASSH_SERVER_KBSTATUS_SUCCESS;
	      break;
	    case 6:
	    case 7:
	      auth_server_keyboard_continue_count++;
	      event.userauth_server.kbresponse.result = ASSH_SERVER_KBSTATUS_CONTINUE;
	      break;
	    }
	  break;
	}

	case ASSH_EVENT_USERAUTH_SERVER_PASSWORD:
	  stall = 0;
	  /* randomly report password success */
	  if (!packet_fuzz)
	    {
	      if (assh_buffer_strcmp(&event.userauth_server.password.username, username) ||
		  assh_buffer_strcmp(&event.userauth_server.password.password, password))
		TEST_FAIL("user %s password %s\n", username, password);
	      if ((event.userauth_server.password.new_password.len == 0) !=
		  (new_password == NULL) || (new_password &&
		     assh_buffer_strcmp(&event.userauth_server.password.new_password, new_password)))
		TEST_FAIL("user %s new_password %s\n", username, new_password);
	    }

	  if (event.userauth_server.password.new_password.len)
	    auth_server_password_new_count++;

	  switch (assh_prng_rand() % 8)
	    {
	    case 0:
	      break;
	    case 1:
	    case 2:
	      auth_server_password_wrong_count++;
	      event.userauth_server.password.result = ASSH_SERVER_PWSTATUS_FAILURE;
	      break;
	    case 3:
	    case 4:
	    case 5:
	      auth_server_password_ok_count++;
	      event.userauth_server.password.result = ASSH_SERVER_PWSTATUS_SUCCESS;
	      break;
	    case 6:
	      assh_buffer_strset(&event.userauth_server.password.change_prompt,
				 "expired" + assh_prng_rand() % 7);
	      assh_buffer_strset(&event.userauth_server.password.change_lang,
				 "en" + assh_prng_rand() % 2);
	    case 7:
	      auth_server_password_change_count++;
	      event.userauth_server.password.result = ASSH_SERVER_PWSTATUS_CHANGE;
	      break;
	    }
	  break;

	case ASSH_EVENT_USERAUTH_SERVER_HOSTBASED:
	  event.userauth_server.hostbased.found = assh_prng_rand() & 1;
	  break;

	case ASSH_EVENT_USERAUTH_SERVER_SUCCESS:
	  ASSH_DEBUG("=> success %u %u\n",
		     event.userauth_server.success.method,
		     event.userauth_server.success.sign_safety);

	  /* randomly request multi factors authentication */
	  event.userauth_server.success.methods =
	    assh_prng_rand() & ASSH_USERAUTH_METHOD_SERVER_IMPLEMENTED;

	  if (event.userauth_server.success.methods)
	    auth_server_partial_success_count++;
	  else
	    auth_server_success_count++;

	  break;

	case ASSH_EVENT_SERVICE_START:
	  stall = 0;
	  if (event.service.start.srv == &assh_service_connection)
	    done |= 1;
	  break;

	default:
	  ASSH_DEBUG("server: don't know how to handle event %u\n", event.id);
	  break;
	}

      assh_event_done(&session[0], &event, ASSH_OK);

      /****************************************************/
      ASSH_DEBUG("=== client %u ===\n", stall);
      if (!assh_event_get(&session[1], &event, 0))
	TEST_FAIL("session terminated");

      switch (event.id)
	{
	  /* exchange ssh stream with the server using a in memory
	     fifo and detect protocol stall */
	case ASSH_EVENT_READ:
	  if (fifo_rw_event(fifo, &event, 1))
	    stall++;
	  break;

	case ASSH_EVENT_WRITE:
	  if (!fifo_rw_event(fifo, &event, 1))
	    stall = 0;
	  break;

	case ASSH_EVENT_SESSION_ERROR:
	  auth_client_err_count++;
	  if (packet_fuzz || alloc_fuzz)
	    goto done;
	  TEST_FAIL("error event");

	case ASSH_EVENT_KEX_DONE:
	  assert(!session[1].tr_user_auth_done);
	  assert(!session[1].user_auth_done);
	  break;

        case ASSH_EVENT_USERAUTH_CLIENT_USER:
	  /* use a username of random len */
	  username = "testtest" + assh_prng_rand() % 4;
          assh_buffer_strset(&event.userauth_client.user.username, username);
          break;

        case ASSH_EVENT_USERAUTH_CLIENT_METHODS: {
	  stall = 0;
	  new_password = NULL;
	  if (event.userauth_client.methods.partial_success)
	    auth_client_partial_success_count++;
	  /* randomly try available authentication methods */
	  while (!event.userauth_client.methods.select)
	    {
	      switch (assh_prng_rand() % 8)
		{
		case 0:
		  if (!(event.userauth_client.methods.methods &
			ASSH_USERAUTH_METHOD_NONE))
		    break;
		  event.userauth_client.methods.select = ASSH_USERAUTH_METHOD_NONE;
		  auth_client_none_count++;
		  break;

		case 1:
		case 2:
		  if (!(event.userauth_client.methods.methods &
			ASSH_USERAUTH_METHOD_PASSWORD))
		    break;
		  /* randomly pick a password */
		  i = assh_prng_rand() % TEST_PASS_COUNT;
		  password = pass[i];
		  assh_buffer_strset(&event.userauth_client.methods.password, password);
		  event.userauth_client.methods.select = ASSH_USERAUTH_METHOD_PASSWORD;
		  auth_client_password_count++;
		  break;

		case 3:
		  if (!(event.userauth_client.methods.methods &
			ASSH_USERAUTH_METHOD_KEYBOARD))
		    break;
		  event.userauth_client.methods.select = ASSH_USERAUTH_METHOD_KEYBOARD;
		  assh_buffer_strset(&event.userauth_client.methods.keyboard_sub,
				     "method" + assh_prng_rand() % 6);
		  auth_client_keyboard_count++;
		  break;

		case 4:
		case 5:
		case 6:
		  if (!(event.userauth_client.methods.methods
			& ASSH_USERAUTH_METHOD_PUBKEY))
		    break;
		  event.userauth_client.methods.select = ASSH_USERAUTH_METHOD_PUBKEY;

		  if (!use_keys(&event.userauth_client.methods.keys))
		    event.userauth_client.methods.select = 0;
		  else
		    auth_client_pubkey_count++;
		  break;

		case 7:
		  if (!(event.userauth_client.methods.methods
			& ASSH_USERAUTH_METHOD_HOSTBASED))
		    break;
		  event.userauth_client.methods.select = ASSH_USERAUTH_METHOD_HOSTBASED;
		  assh_buffer_strset(&event.userauth_client.methods.host_name,
				     "localhost" + assh_prng_rand() % 9);
		  assh_buffer_strset(&event.userauth_client.methods.host_username,
				     "test" + assh_prng_rand() % 4);

		  if (!use_keys(&event.userauth_client.methods.keys))
		    event.userauth_client.methods.select = 0;
		  else
		    auth_client_hostbased_count++;
		  break;
		}
	    }
          break;
	}

	case ASSH_EVENT_USERAUTH_CLIENT_SIGN: {
	  struct assh_event_userauth_client_sign_s *e = &event.userauth_client.sign;
	  for (i = 0; i < TEST_KEYS_COUNT; i++)
	    if (keys[i].key_cpub == e->pub_key)
	      {
		if (assh_sign_generate(&context[1], e->algo, keys[i].key_c,
				       1, &e->auth_data, e->sign.data, &e->sign.len)
		    && !alloc_fuzz)
		  TEST_FAIL("sign");
		break;
	      }
	  break;
	}

	case ASSH_EVENT_USERAUTH_CLIENT_PWCHANGE: {
	  if (assh_prng_rand() & 1)
	    {
	      auth_client_password_skip_change_count++;
	      break;
	    }
	  i = assh_prng_rand() % TEST_PASS_COUNT;
	  password = pass[i];
	  assh_buffer_strset(&event.userauth_client.pwchange.old_password,
			     password);
	  new_password = pass[(i + 1) % TEST_PASS_COUNT];
	  assh_buffer_strset(&event.userauth_client.pwchange.new_password,
			     new_password);
	  auth_client_password_change_count++;
	  break;
	}

        case ASSH_EVENT_USERAUTH_CLIENT_KEYBOARD: {
          uint_fast8_t i;
          for (i = 0; i < event.userauth_client.keyboard.count; i++)
            {
              assh_buffer_strset(&event.userauth_client.keyboard.responses[i],
				 "azertyui" + assh_prng_rand() % 8);
	      auth_client_keyboard_resp_count++;
            }
	  break;
	}

	case ASSH_EVENT_USERAUTH_CLIENT_SUCCESS:
	  auth_client_success_count++;
	  break;

	case ASSH_EVENT_SERVICE_START:
	  if (event.service.start.srv == &assh_service_connection)
	    done |= 2;
	  break;

	default:
	  ASSH_DEBUG("client: don't know how to handle event %u\n", event.id);
	  break;
	}

      assh_event_done(&session[1], &event, ASSH_OK);

      if (done == 3)
	{
	  /* client and server have both
	     completed the authentication process */
	  auth_done_count++;
	  break;
	}

      if (stall >= 100)
	{
	  /* packet exchange is stalled, hopefully due to a fuzzing error */
	  auth_stall_count++;
	  ASSH_DEBUG("=== stall ===");
	  if (!packet_fuzz)
	    TEST_FAIL("stalled");
	  break;
	}
    }

 done:
  ASSH_DEBUG("=== done ===\n");

  /* unlimited retries should lead to authentication completion when
     no error is introduced */
  assert(packet_fuzz || alloc_fuzz ||
	 (session[0].user_auth_done && session[1].user_auth_done));

  if (!packet_fuzz && !alloc_fuzz && alloc_size == alloc_size_init)
    TEST_FAIL("leak checking not working\n");

  for (i = 0; i < 2; i++)
    assh_session_cleanup(&session[i]);

  assh_packet_collect(&context[0]);
  assh_packet_collect(&context[1]);

  if (alloc_size != alloc_size_init)
    TEST_FAIL("memory leak detected, %zu bytes allocated\n", alloc_size);

  return 0;
}

static void usage()
{
  fprintf(stderr, "usage: userauth [options]\n");

  fprintf(stderr,
	  "Options:\n\n"

	  "    -h         show help\n"
	  "    -t         run non-fuzzing tests\n"
	  "    -a         run memory allocator fuzzing tests\n"
	  "    -p         run packet corruption fuzzing tests\n"
	  "    -f         run more fuzzing tests\n"
	  "    -c count   set number of test passes (default 100)\n"
	  "    -s seed    set initial seed (default: time(0))\n"
	  );
}

int main(int argc, char **argv)
{
  if (assh_deps_init())
    return -1;

  enum action_e {
    ACTION_NOFUZZING = 1,
    ACTION_PACKET_FUZZ = 2,
    ACTION_ALLOC_FUZZ = 4,
    ACTION_ALL_FUZZ = 8
  };

  enum action_e action = 0;
  unsigned int count = 100;
  unsigned int seed = time(0);
  int opt;

  while ((opt = getopt(argc, argv, "tpafhs:c:")) != -1)
    {
      switch (opt)
	{
	case 't':
	  action |= ACTION_NOFUZZING;
	  break;
	case 'p':
	  action |= ACTION_PACKET_FUZZ;
	  break;
	case 'a':
	  action |= ACTION_ALLOC_FUZZ;
	  break;
	case 'f':
	  action |= ACTION_ALL_FUZZ;
	  break;
	case 's':
	  seed = atoi(optarg);
	  break;
	case 'c':
	  count = atoi(optarg);
	  break;
	case 'h':
	  usage();
	default:
	  return 1;
	}
    }

  if (!action)
    action = ACTION_NOFUZZING;

  static const struct assh_algo_s *algos[] = {
    &assh_kex_none.algo, &assh_sign_none.algo,
    &assh_sign_rsa_sha1.algo, &assh_sign_dsa1024.algo, &assh_sign_ed25519.algo,
    &assh_sign_eddsa_e521.algo, &assh_sign_nistp256.algo, &assh_sign_nistp521.algo,
    &assh_cipher_fuzz.algo, &assh_hmac_none.algo, &assh_compress_none.algo, NULL
  };

  uint_fast8_t i;
  /* init server context */
  if (assh_context_init(&context[0], ASSH_SERVER,
			assh_leaks_allocator, NULL, &assh_prng_weak, NULL) ||
      assh_service_register_va(&context[0], &assh_service_userauth_server,
			       &assh_service_connection, NULL) ||
      assh_algo_register_static(&context[0], algos))
    TEST_FAIL("");

  /* create host key */
  if (assh_key_create(&context[0], &context[0].keys, 0, &assh_key_none,
		      ASSH_ALGO_SIGN) != ASSH_OK)
    TEST_FAIL("");

  /* init client context */
  if (assh_context_init(&context[1], ASSH_CLIENT,
			assh_leaks_allocator, NULL, &assh_prng_weak, NULL) ||
      assh_service_register_va(&context[1], &assh_service_userauth_client,
			       &assh_service_connection, NULL) ||
      assh_algo_register_static(&context[1], algos))
    TEST_FAIL("");

  /* create some user authentication keys */
  for (i = 0; i < TEST_KEYS_COUNT; i++)
    {
      struct test_key_s *k = &keys[i];
      k->key_s = k->key_c = NULL;
      ASSH_DEBUG("create key %u\n", i);

      if (assh_key_create(&context[1], &k->key_c, keys_algo[i].bits,
			  keys_algo[i].algo, ASSH_ALGO_SIGN))
	TEST_FAIL("");

      if (assh_key_output(&context[1], k->key_c, NULL, &k->blob_len,
			  ASSH_KEY_FMT_PUB_RFC4253))
	TEST_FAIL("");

      k->blob = malloc(k->blob_len);
      if (k->blob == NULL)
	TEST_FAIL("");

      if (assh_key_output(&context[1], k->key_c, k->blob, &k->blob_len,
			  ASSH_KEY_FMT_PUB_RFC4253))
	TEST_FAIL("");

      const uint8_t *b = k->blob;
      if (assh_key_load(&context[0], &k->key_s, keys_algo[i].algo, ASSH_ALGO_SIGN,
			ASSH_KEY_FMT_PUB_RFC4253, &b, k->blob_len))
	TEST_FAIL("");

      b = k->blob;
      if (assh_key_load(&context[1], &k->key_cpub, keys_algo[i].algo, ASSH_ALGO_SIGN,
			ASSH_KEY_FMT_PUB_RFC4253, &b, k->blob_len))
	TEST_FAIL("");
    }

  if (alloc_size == 0)
    TEST_FAIL("leak checking not working\n");

  unsigned int k, l;

  /* run some ssh sessions */
  for (l = k = 0; k < count; k++)
    {
      assh_prng_seed(seed + k);

      /* run a session */
      if (action & ACTION_NOFUZZING)
	{
	  alloc_fuzz = 0;
	  packet_fuzz = 0;
	  putc('t', stderr);
	  l++;
	  if (test())
	    return 1;
	}

      /* run a session with some packet error */
      if (action & ACTION_PACKET_FUZZ)
	{
	  alloc_fuzz = 0;
	  packet_fuzz = 10 + assh_prng_rand() % 1024;
	  putc('p', stderr);
	  l++;
	  test();
	}

      /* run a session with some allocation fails */
      if (action & ACTION_ALLOC_FUZZ)
	{
	  alloc_fuzz = 4 + assh_prng_rand() % 32;
	  packet_fuzz = 0;
	  putc('a', stderr);
	  l++;
	  test();
	}

      if (action & ACTION_ALL_FUZZ)
	{
	  alloc_fuzz = 4 + assh_prng_rand() % 32;
	  packet_fuzz = 10 + assh_prng_rand() % 1024;
	  putc('A', stderr);
	  l++;
	  test();
	}

      if (l > 40)
	{
	  fprintf(stderr, " seed=%u\n", seed + k);
	  l = 0;
	}
    }

  if (l)
    fputc('\n', stderr);

  /* release user keys */
  for (i = 0; i < TEST_KEYS_COUNT; i++)
    {
      struct test_key_s *k = &keys[i];
      assh_key_drop(&context[0], &k->key_s);
      assh_key_drop(&context[1], &k->key_c);
      assh_key_drop(&context[1], &k->key_cpub);
    }

  /* release contexts */
  for (i = 0; i < 2; i++)
    assh_context_cleanup(&context[i]);

  if (alloc_size != 0)
    TEST_FAIL("memory leak detected, %zu bytes allocated\n", alloc_size);

  fprintf(stderr, "\nSummary:\n"
	  "  %8lu authentication completion count\n"
	  "  %8lu server public key found count\n"
	  "  %8lu server public key wrong count\n"
	  "  %8lu server password ok count\n"
	  "  %8lu server password change count\n"
	  "  %8lu server password wrong count\n"
	  "  %8lu server password new count\n"
	  "  %8lu server keyboard info count\n"
	  "  %8lu server keyboard success count\n"
	  "  %8lu server keyboard failure count\n"
	  "  %8lu server keyboard continue count\n"
	  "  %8lu server get methods count\n"
	  "  %8lu server failure count\n"
	  "  %8lu server partial success count\n"
	  "  %8lu server success count\n"
	  "  %8lu client none count\n"
	  "  %8lu client pubkey count\n"
	  "  %8lu client hostbased count\n"
	  "  %8lu client internal signature count\n"
	  "  %8lu client external signature count\n"
	  "  %8lu client password count\n"
	  "  %8lu client password change count\n"
	  "  %8lu client password skip change count\n"
	  "  %8lu client keyboard count\n"
	  "  %8lu client keyboard response count\n"
	  "  %8lu client partial success count\n"
	  "  %8lu client success count\n"
	  ,
	  auth_done_count,
	  auth_server_pubkey_found_count,
	  auth_server_pubkey_wrong_count,
	  auth_server_password_ok_count,
	  auth_server_password_change_count,
	  auth_server_password_wrong_count,
	  auth_server_password_new_count,
	  auth_server_keyboard_info_count,
	  auth_server_keyboard_success_count,
	  auth_server_keyboard_failure_count,
	  auth_server_keyboard_continue_count,
	  auth_server_methods_count,
	  auth_server_failure_count,
	  auth_server_partial_success_count,
	  auth_server_success_count,
	  auth_client_none_count,
	  auth_client_pubkey_count,
	  auth_client_hostbased_count,
	  auth_client_int_sign_count,
	  auth_client_ext_sign_count,
	  auth_client_password_count,
	  auth_client_password_change_count,
	  auth_client_password_skip_change_count,
	  auth_client_keyboard_count,
	  auth_client_keyboard_resp_count,
	  auth_client_partial_success_count,
	  auth_client_success_count
	  );

  if (action & (ACTION_PACKET_FUZZ | ACTION_ALLOC_FUZZ | ACTION_ALL_FUZZ))
    fprintf(stderr,
	    "\nFuzzing:\n"
	    "  %8lu memory allocation fails\n"
	    "  %8lu packet bit errors\n"
	    "  %8lu protocol stall count\n"
	    "  %8lu server session error count\n"
	    "  %8lu client session error count\n"
	    ,
	    alloc_fuzz_fails,
	    packet_fuzz_bits,
	    auth_stall_count,
	    auth_server_err_count,
	    auth_client_err_count
	    );

  return 0;
}

