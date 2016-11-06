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

#include "fifo.h"
#include "prng_weak.h"
#include "leaks_check.h"
#include "test.h"
#include "cipher_fuzz.h"

#ifdef CONFIG_ASSH_USE_GCRYPT
# include <gcrypt.h>
#endif

static struct fifo_s fifo[2];
static struct assh_context_s context[2];
static struct assh_session_s session[2];

struct test_key_s
{
  struct assh_key_s *key_s, *key_c;
  uint8_t *blob;
  size_t blob_len;
};

#define TEST_KEYS_COUNT 6
static struct test_key_s keys[TEST_KEYS_COUNT];

struct {
  const struct assh_key_ops_s *algo;
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
static unsigned long auth_server_partial_success_count = 0;
static unsigned long auth_server_success_count = 0;
static unsigned long auth_server_err_count = 0;
static unsigned long auth_server_err_ev_count = 0;
static unsigned long auth_client_pubkey_count = 0;
static unsigned long auth_client_password_count = 0;
static unsigned long auth_client_password_change_count = 0;
static unsigned long auth_client_password_skip_change_count = 0;
static unsigned long auth_client_partial_success_count = 0;
static unsigned long auth_client_success_count = 0;
static unsigned long auth_client_err_count = 0;
static unsigned long auth_client_err_ev_count = 0;

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
      assh_error_t err;
      struct assh_event_s event;

      /****************************************************/
      ASSH_DEBUG("=== server %u ===\n", stall);
      err = assh_event_get(&session[0], &event);
      if (ASSH_ERR_ERROR(err) != ASSH_OK)
	{
	  auth_server_err_count++;
	  if (packet_fuzz || alloc_fuzz)
	    break;
	  TEST_FAIL("");
	}

      switch (event.id)
	{
	  /* exchange ssh stream with the client using a in memory
	     fifo and detect protocol stall */
	case ASSH_EVENT_READ:
	  if (fifo_rw_event(fifo, &event, 0))
	    stall++;
	  break;

	case ASSH_EVENT_WRITE:
	  if (!fifo_rw_event(fifo, &event, 0))
	    stall = 0;
	  break;

	case ASSH_EVENT_KEX_DONE:
	  assert(!session[0].auth_done);
	  break;

	case ASSH_EVENT_USERAUTH_SERVER_METHODS:
	  event.userauth_server.methods.banner.size = 4 - rand() % 5;
	  event.userauth_server.methods.banner.str = "test";

	  do {
	    /* randomly choose some initial allowed methods */
	    event.userauth_server.methods.methods =
	      rand() & ASSH_USERAUTH_METHOD_IMPLEMENTED;
	  } while (!event.userauth_server.methods.methods);

	  /* unlimited retries */
	  event.userauth_server.methods.retries = 0;
	  break;

	case ASSH_EVENT_USERAUTH_SERVER_USERKEY: {
	  stall = 0;
	  assh_bool_t found = rand() & 1;
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

	  switch (rand() % 8)
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
	      assh_buffer_strcpy(&event.userauth_server.password.change_prompt,
				 "expired" + rand() % 7);
	      assh_buffer_strcpy(&event.userauth_server.password.change_lang,
				 "en" + rand() % 2);
	    case 7:
	      auth_server_password_change_count++;
	      event.userauth_server.password.result = ASSH_SERVER_PWSTATUS_CHANGE;
	      break;
	    }
	  break;

	case ASSH_EVENT_USERAUTH_SERVER_SUCCESS:
	  ASSH_DEBUG("=> success %u %u\n",
		     event.userauth_server.success.method,
		     event.userauth_server.success.sign_safety);

	  /* randomly request multi factors authentication */
	  event.userauth_server.success.methods =
	    rand() & ASSH_USERAUTH_METHOD_IMPLEMENTED;

	  if (event.userauth_server.success.methods)
	    auth_server_partial_success_count++;
	  else
	    auth_server_success_count++;

	  break;

	case ASSH_EVENT_CONNECTION_START:
	  stall = 0;
	  done |= 1;
	  break;

	default:
	  printf("server: don't know how to handle event %u\n", event.id);
	  break;
	}

      err = assh_event_done(&session[0], &event, ASSH_OK);
      if (ASSH_ERR_ERROR(err) != ASSH_OK)
	{
	  auth_server_err_ev_count++;
	  if (packet_fuzz || alloc_fuzz)
	    break;
	  TEST_FAIL("");
	}

      /****************************************************/
      ASSH_DEBUG("=== client %u ===\n", stall);
      err = assh_event_get(&session[1], &event);
      if (ASSH_ERR_ERROR(err) != ASSH_OK)
	{
	  auth_client_err_count++;
	  if (packet_fuzz || alloc_fuzz)
	    break;
	  TEST_FAIL("");
	}

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

	case ASSH_EVENT_KEX_DONE:
	  assert(!session[1].auth_done);
	  break;

        case ASSH_EVENT_USERAUTH_CLIENT_USER:
	  /* use a username of random len */
	  username = "testtest" + rand() % 4;
          assh_buffer_strcpy(&event.userauth_client.user.username, username);
          break;

        case ASSH_EVENT_USERAUTH_CLIENT_METHODS: {
	  stall = 0;
	  new_password = NULL;
	  if (event.userauth_client.methods.partial_success)
	    auth_client_partial_success_count++;
	  /* randomly try available authentication methods */
	  while (!event.userauth_client.methods.select)
	    {
	      if ((event.userauth_client.methods.methods &
		   ASSH_USERAUTH_METHOD_PASSWORD) && (rand() & 1))
		{
		  /* randomly pick a password */
		  i = rand() % TEST_PASS_COUNT;
		  password = pass[i];
		  assh_buffer_strcpy(&event.userauth_client.methods.password, password);
		  event.userauth_client.methods.select = ASSH_USERAUTH_METHOD_PASSWORD;
		  auth_client_password_count++;
		}
	      else if (event.userauth_client.methods.methods
		  & ASSH_USERAUTH_METHOD_PUBKEY)
		{
		  /* use some of the available keys */
		  for (i = 0; i < TEST_KEYS_COUNT; i++)
		    if (rand() & 1)
		      {
			assh_key_refinc(keys[i].key_c);
			assh_key_insert(&event.userauth_client.methods.pub_keys, keys[i].key_c);
			event.userauth_client.methods.select = ASSH_USERAUTH_METHOD_PUBKEY;
			auth_client_pubkey_count++;
		      }
		}
	    }
          break;
	}

	case ASSH_EVENT_USERAUTH_CLIENT_PWCHANGE: {
	  if (rand() & 1)
	    {
	      auth_client_password_skip_change_count++;
	      break;
	    }
	  i = rand() % TEST_PASS_COUNT;
	  password = pass[i];
	  assh_buffer_strcpy(&event.userauth_client.pwchange.old_password,
			     password);
	  new_password = pass[(i + 1) % TEST_PASS_COUNT];
	  assh_buffer_strcpy(&event.userauth_client.pwchange.new_password,
			     new_password);
	  auth_client_password_change_count++;
	  break;
	}

	default:
	  ASSH_DEBUG("client: don't know how to handle event %u\n", event.id);
	  break;

	case ASSH_EVENT_USERAUTH_CLIENT_SUCCESS:
	  auth_client_success_count++;
	  break;

	case ASSH_EVENT_CONNECTION_START:
	  done |= 2;
	}

      err = assh_event_done(&session[1], &event, ASSH_OK);
      if (ASSH_ERR_ERROR(err) != ASSH_OK)
	{
	  auth_client_err_ev_count++;
	  if (packet_fuzz || alloc_fuzz)
	    break;
	  TEST_FAIL("");
	}

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

  ASSH_DEBUG("=== done ===\n");

  /* unlimited retries should lead to authentication completion when
     no error is introduced */
  assert(packet_fuzz || alloc_fuzz ||
	 (session[0].auth_done && session[1].auth_done));

  if (!packet_fuzz && !alloc_fuzz && alloc_size == alloc_size_init)
    TEST_FAIL("leak checking not working\n");

  for (i = 0; i < 2; i++)
    assh_session_cleanup(&session[i]);

#ifndef CONFIG_ASSH_PACKET_POOL
  if (alloc_size != alloc_size_init)
    TEST_FAIL("memory leak detected, %zu bytes allocated\n", alloc_size);
#endif

  return 0;
}

int main(int argc, char **argv)
{
#ifdef CONFIG_ASSH_USE_GCRYPT
  if (!gcry_check_version(GCRYPT_VERSION))
    TEST_FAIL("");
#endif
  unsigned int count = argc > 1 ? atoi(argv[1]) : 1000;
  unsigned int action = argc > 2 ? atoi(argv[2]) : 7;
  unsigned int seed = argc > 3 ? atoi(argv[3]) : time(0);

  uint_fast8_t i;
  /* init server context */
  if (assh_context_init(&context[0], ASSH_SERVER,
			assh_leaks_allocator, NULL, &assh_prng_weak, NULL) ||
      assh_service_register_va(&context[0], &assh_service_userauth_server,
			       &assh_service_connection, NULL))
    TEST_FAIL("");

  /* create host key */
  if (assh_key_create(&context[0], &context[0].keys, 0, &assh_key_none,
		      ASSH_ALGO_SIGN) != ASSH_OK)
    TEST_FAIL("");

  /* init client context */
  if (assh_context_init(&context[1], ASSH_CLIENT,
			assh_leaks_allocator, NULL, &assh_prng_weak, NULL) ||
      assh_service_register_va(&context[1], &assh_service_userauth_client,
			       &assh_service_connection, NULL))
    TEST_FAIL("");

  /* register some algorithms */
  for (i = 0; i < 2; i++)
    {
      if (assh_algo_register_va(&context[i], 0, 0, 0, &assh_kex_none, &assh_sign_none,
				&assh_cipher_fuzz, &assh_hmac_none, &assh_compress_none,
				&assh_sign_rsa_sha1, &assh_sign_dsa, &assh_sign_ed25519,
				&assh_sign_eddsa_e521, &assh_sign_nistp256, &assh_sign_nistp521,
				NULL))
	TEST_FAIL("");
    }

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
    }

  if (alloc_size == 0)
    TEST_FAIL("leak checking not working\n");

  unsigned int k;

  /* run some ssh sessions */
  for (k = 0; k < count; )
    {
      srand(seed + k);

      /* run a session */
      if (action & 1)
	{
	  alloc_fuzz = 0;
	  packet_fuzz = 0;
	  putc('r', stderr);
	  if (test())
	    return 1;
	}

      /* run a session with some packet error */
      if (action & 2)
	{
	  alloc_fuzz = 0;
	  packet_fuzz = 10 + rand() % 1024;
	  putc('f', stderr);
	  test();
	}

      /* run a session with some allocation fails */
      if (action & 4)
	{
	  alloc_fuzz = 4 + rand() % 32;
	  packet_fuzz = 0;
	  putc('a', stderr);
	  test();
	}

      if (++k % 32 == 0)
	fprintf(stderr, " seed=%u\n", seed + k);
    }

  /* release user keys */
  for (i = 0; i < TEST_KEYS_COUNT; i++)
    {
      struct test_key_s *k = &keys[i];
      assh_key_drop(&context[0], &k->key_s);
      assh_key_drop(&context[1], &k->key_c);
    }

  /* release contexts */
  for (i = 0; i < 2; i++)
    assh_context_cleanup(&context[i]);

  if (alloc_size != 0)
    TEST_FAIL("memory leak detected, %zu bytes allocated\n", alloc_size);

  fprintf(stderr, "Summary:\n"
	  "  %8lu authentication completion count\n"
	  "  %8lu protocol stall count\n"
	  "  %8lu server public key found count\n"
	  "  %8lu server public key wrong count\n"
	  "  %8lu server password ok count\n"
	  "  %8lu server password change count\n"
	  "  %8lu server password wrong count\n"
	  "  %8lu server password new count\n"
	  "  %8lu server partial success count\n"
	  "  %8lu server success count\n"
	  "  %8lu server fuzz error count\n"
	  "  %8lu server fuzz event error count\n"
	  "  %8lu client password count\n"
	  "  %8lu client password change count\n"
	  "  %8lu client password skip change count\n"
	  "  %8lu client partial success count\n"
	  "  %8lu client success count\n"
	  "  %8lu client fuzz error count\n"
	  "  %8lu client fuzz event error count\n"
	  "  %8lu fuzz packet bit errors\n"
	  "  %8lu fuzz memory allocation fails\n"
	  ,
	  auth_done_count,
	  auth_stall_count,
	  auth_server_pubkey_found_count,
	  auth_server_pubkey_wrong_count,
	  auth_server_password_ok_count,
	  auth_server_password_change_count,
	  auth_server_password_wrong_count,
	  auth_server_password_new_count,
	  auth_server_partial_success_count,
	  auth_server_success_count,
	  auth_server_err_count,
	  auth_server_err_ev_count,
	  auth_client_password_count,
	  auth_client_password_change_count,
	  auth_client_password_skip_change_count,
	  auth_client_partial_success_count,
	  auth_client_success_count,
	  auth_client_err_count,
	  auth_client_err_ev_count,
	  packet_fuzz_bits,
	  alloc_fuzz_fails
	  );

  return 0;
}

