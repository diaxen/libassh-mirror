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

/*
  This tests the ssh connection layer by performing random channel and
  request operations. This test injects packet bits errors and memory
  allocation failure.
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
#include <assh/assh_transport.h>
#include <assh/assh_connection.h>
#include <assh/assh_event.h>
#include <assh/helper_key.h>

#include "prng_weak.h"
#include "fifo.h"
#include "leaks_check.h"
#include "test.h"
#include "cipher_fuzz.h"

#include <errno.h>

#ifdef CONFIG_ASSH_USE_GCRYPT
# include <gcrypt.h>
#endif

#define RQ_FIFO_SIZE 32
#define CH_MAP_SIZE 32

enum ch_status_e
{
  CH_POSTONED = 1,
  CH_WAIT     = 2,
  CH_OPEN     = 3,
  CH_EOF      = 4,
  CH_CLOSE    = 5,
};

#define RQ_POSTPONED_SIZE (RQ_FIFO_SIZE * (CH_MAP_SIZE + 1)) 

struct assh_channel_s *ch_map[2][CH_MAP_SIZE];
struct assh_request_s *rq_postponed[2][RQ_POSTPONED_SIZE];

struct fifo_s fifo[2];
struct assh_context_s context[2];
struct assh_session_s session[2];

unsigned int seed = 0;

unsigned long rq_send_count = 0;
unsigned long rq_reply_success = 0;
unsigned long rq_reply_failed = 0;
unsigned long rq_event_count = 0;
unsigned long rq_event_success_count = 0;
unsigned long rq_event_failed_count = 0;
unsigned long rq_event_closed_count = 0;
unsigned long rq_postpone_count = 0;
unsigned long ch_open_count = 0;
unsigned long ch_event_open_count = 0;
unsigned long ch_open_reply_success_count = 0;
unsigned long ch_open_reply_failed_count = 0;
unsigned long ch_postpone_count = 0;
unsigned long ch_close_count = 0;
unsigned long ch_event_close_count = 0;
unsigned long ch_eof_count = 0;
unsigned long ch_event_eof_count = 0;
unsigned long ch_data_send = 0;
unsigned long ch_data_recv = 0;
unsigned long ch_data_window = 0;
unsigned long ev_err_count = 0;
unsigned long disconnect_count = 0;
unsigned long rekex_count = 0;

static void get_data(size_t *size, const uint8_t **data)
{
  static const uint8_t r[] = "1a2q3w4z5s6x7e8d9c0r1f2v3t4g5b6y7h8n9u0j1k2i3l4m5p6o";
  *size = rand() % sizeof(r);
  *data = r + rand() % (sizeof(r) - *size);
}

void test(int (*fend)(int, int), int n, int evrate, unsigned alloc_f)
{
  assh_error_t err;
  unsigned int i, j;
  assh_bool_t started[2] = {};
  assh_bool_t kex_done = 0;

  /********************* intiailization */

  ASSH_DEBUG("==============================================================\n");

  alloc_fuzz = 0;
  if (assh_context_init(&context[0], ASSH_SERVER,
			assh_leaks_allocator, NULL, NULL, NULL) ||
      assh_context_init(&context[1], ASSH_CLIENT,
			assh_leaks_allocator, NULL, NULL, NULL))
    TEST_FAIL("init");

  for (i = 0; i < 2; i++)
    {
      fifo_init(&fifo[i]);

      if (assh_service_register_va(&context[i], &assh_service_connection, NULL))
	TEST_FAIL("init");

      if (assh_algo_register_va(&context[i], 0, 0, 0, &assh_kex_none, &assh_sign_none,
				&assh_cipher_fuzz, &assh_cipher_none, &assh_hmac_none,
				&assh_compress_none, NULL) != ASSH_OK)
	TEST_FAIL("init");

      if (assh_session_init(&context[i], &session[i]) != ASSH_OK)
	TEST_FAIL("init");
      assh_cipher_fuzz_initreg(&context[i], &session[i]);

      session[i].user_auth_done = 1;
      if (assh_kex_set_threshold(&session[i], 1 + rand() % 16384))
	TEST_FAIL("init");

      for (j = 0; j < RQ_POSTPONED_SIZE; j++)
	rq_postponed[i][j] = NULL;

      for (j = 0; j < CH_MAP_SIZE; j++)
	ch_map[i][j] = NULL;
    }

  if (assh_key_create(&context[0], &context[0].keys, 0, &assh_key_none, ASSH_ALGO_SIGN) != ASSH_OK)
    TEST_FAIL("init");

  /********************* sessions test loop */

  uint_fast32_t stall[2] = { 0, 0 };

  for (j = 0; (session[0].tr_st != ASSH_TR_CLOSED &&
	       session[1].tr_st != ASSH_TR_CLOSED) && fend(j, n); j++)
    {
      /* alternate between the two sessions */
      for (i = 0; i < 2; i++)
	{
	  struct assh_event_s event;

	  ASSH_DEBUG("=== context %u %u ===\n", i, stall[i]);

	  /********************* generate request and channel open... */

	  if (started[i])
	    switch (rand() % 8)
	      {
	      case 0:
	      case 1: {    	/***** send a new request *****/
		assh_bool_t want_reply = rand() % 2;
		unsigned int k = rand() % CH_MAP_SIZE;
		struct assh_channel_s *ch = ch_map[i][k];
		struct assh_request_s *rq;

		if (!ch)
		  goto globl_rq;
		switch (assh_channel_status(ch))
		  {
		    size_t data_len;
		    const uint8_t *data;
		  case ASSH_CHANNEL_ST_OPEN:
		  case ASSH_CHANNEL_ST_EOF_SENT:
		  case ASSH_CHANNEL_ST_EOF_RECEIVED:
		  globl_rq:
		    get_data(&data_len, &data);
		    err = assh_request(&session[i], ch, (const char *)data, data_len,
				       data, data_len,
				       want_reply ? &rq : NULL);
		    if (err == ASSH_NO_DATA)
		      break;
		    if (err > ASSH_NO_DATA)
		      {
			if (alloc_f)
			  break;
			TEST_FAIL("(ctx %u seed %u) assh_request()\n", i, seed);
		      }
		    ASSH_DEBUG("assh_request %p\n", rq);
		    rq_send_count++;
		  default:
		    break;
		  }
		break;
	      }

	      case 2:
	      case 3: {		/***** reply to postponed request *****/
		unsigned int n;
		struct assh_request_s *rq;

		/* look for postponed requests */
		for (n = 0; n < RQ_POSTPONED_SIZE; n++)
		  if ((rq = rq_postponed[i][n]))
		    break;
		if (rq == NULL)
		  break;

		struct assh_channel_s *ch = assh_request_channel(rq);
		if (ch && assh_channel_pvi(ch) == CH_CLOSE)
		  break;

		rq_postponed[i][n] = NULL;

		switch (rand() % 2)
		  {
		  case 0: {
		    size_t data_len = 0;
		    const uint8_t *data;
		    if (!ch)
		      get_data(&data_len, &data);
		    assh_error_t er = assh_request_success_reply(rq, data, data_len);
		    if (er > ASSH_NO_DATA)
		      {
			if (alloc_f)
			  break;
			TEST_FAIL("(ctx %u seed %u) assh_request_reply(ASSH_CONNECTION_REPLY_SUCCESS)\n", i, seed);
		      }
		    ASSH_DEBUG("assh_request_success_reply %p\n", rq);
		    rq_reply_success++;
		    break;
		  }
		  case 1: {
		    assh_error_t er = assh_request_failed_reply(rq);
		    if (er > ASSH_NO_DATA)
		      {
			if (alloc_f)
			  break;
			TEST_FAIL("(ctx %u seed %u) assh_request_reply(ASSH_CONNECTION_REPLY_FAILED)\n", i, seed);
		      }
		    ASSH_DEBUG("assh_request_failed_reply %p\n", rq);
		    rq_reply_failed++;
		    break;
		  }
		  }
		break;
	      }

	      case 4: {    	/***** channel actions *****/
		unsigned int k = rand() % CH_MAP_SIZE;
		struct assh_channel_s *ch = ch_map[i][k];

		if (ch == NULL) /**** channel is closed, try to open ****/
		  {
		    size_t data_len;
		    const uint8_t *data;
		    get_data(&data_len, &data);
		    err = assh_channel_open2(&session[i], (const char *)data, data_len,
					     data, data_len,
					     rand() % 31 + 1, rand() % 128,
					     &ch);
		    if (err == ASSH_NO_DATA)
		      break;
		    if (err > ASSH_NO_DATA)
		      {
			if (alloc_f)
			  break;
			TEST_FAIL("(ctx %u seed %u) assh_channel_open2()\n", i, seed);
		      }

		    ASSH_DEBUG("assh_channel_open2 %p\n", ch);

		    ch_open_count++;
		    ch_map[i][k] = ch;
		    assh_channel_set_pvi(ch, CH_WAIT);
		  }
		else
		  {
		    if (assh_channel_pvi(ch) == CH_CLOSE)
		      break;
		    if (assh_channel_pvi(ch) == CH_POSTONED) /* postponned */
		      {
			switch (rand() % 2)
			  {
			    size_t data_len;
			    const uint8_t *data;
			  case 0:
			    get_data(&data_len, &data);
			    if (assh_channel_open_success_reply2(ch,
					rand() % 31 + 1, rand() % 128,
								 data, data_len))
			      {
				if (alloc_f)
				  break;
				TEST_FAIL("(ctx %u seed %u) assh_channel_open_success_reply2()\n", i, seed);
			      }
			    ASSH_DEBUG("assh_channel_open_success_reply2 %p\n", ch);
			    ch_open_reply_success_count++;
			    assh_channel_set_pvi(ch, CH_OPEN);
			    break;
			  case 1:
			    if (assh_channel_open_failed_reply(ch, rand() % 4 + 1))
			      {
				if (alloc_f)
				  break;
				TEST_FAIL("(ctx %u seed %u) assh_channel_open_failed_reply()\n", i, seed);
			      }
			    ASSH_DEBUG("assh_channel_open_failed_reply %p\n", ch);
			    ch_map[i][k] = NULL;
			    ch_open_reply_failed_count++;
			    break;
			  }
		      }
		    else
		      {
			switch (rand() % 4)
			  {
			  case 0: {	/**** may close ****/
			    if (assh_channel_status(ch) == ASSH_CHANNEL_ST_OPEN_SENT)
			      break;
			    ch_close_count++;

			    if (assh_channel_close(ch))
			      {
				if (alloc_f)
				  break;
				TEST_FAIL("(ctx %u seed %u) assh_channel_close()\n", i, seed);
			      }

			    ASSH_DEBUG("assh_channel_close %p\n", ch);

			    assh_channel_set_pvi(ch, CH_CLOSE);
			    break;
			  }
			  case 1: {	/**** may send eof ****/
			    if (assh_channel_pvi(ch) != CH_OPEN)
			      break;
			    if (assh_channel_pvi(ch) == CH_EOF)
			      break;
			    assh_channel_set_pvi(ch, CH_EOF);
			    ch_eof_count++;

			    if (assh_channel_eof(ch))
			      {
				if (alloc_f)
				  break;
				TEST_FAIL("(ctx %u seed %u) assh_channel_eof()\n", i, seed);
			      }

			    ASSH_DEBUG("assh_channel_eof %p\n", ch);
			    break;
			  }
			  case 2: /*** send channel data ***/
			  case 3: {
			    if (assh_channel_pvi(ch) != CH_OPEN)
			      break;
			    uint8_t *d;
			    size_t m = rand() % 64 + 1;
			    size_t s = s % m + 1;
			    assh_error_t er = assh_channel_data_alloc(ch, &d, &s, m);
			    if (er > ASSH_NO_DATA)
			      {
				if (alloc_f)
				  break;
				TEST_FAIL("(ctx %u seed %u) assh_channel_data_alloc()\n", i, seed);
			      }
			    if (er == ASSH_OK && s > 0)
			      {
				memset(d, rand(), s);
				if (assh_channel_data_send(ch, s))
				  TEST_FAIL("(ctx %u seed %u) assh_channel_data_send()\n", i, seed);
				ch_data_send++;
			      }
			  }
			  }
		      }
		  }

	      }
	      default:
		break;
	      }

	  /********************* handle events */

	  if (!assh_event_get(&session[i], &event, 0))
	    {
	      continue;
	    }

	  assh_error_t everr = ASSH_OK;

	  if (evrate && !(rand() % evrate))
	    {
	      ev_err_count++;
	      everr = (rand() % 32 + 0x100);
	      everr |= ((1 << (12 + rand() % 3))
			& (ASSH_ERRSV_DISCONNECT | ASSH_ERRSV_FIN));
	    }

	  ASSH_DEBUG("event %u err %u\n", event.id, everr);
	  switch (event.id)
	    {
	    case ASSH_EVENT_REQUEST: {        /***** incoming request *****/
	      struct assh_event_request_s *e = &event.connection.request;
	      rq_event_count++;

	      if (everr)
		goto rq_fail;

	      switch (rand() % 3)
		{
		case 1:
		rq_fail:
		  e->reply = ASSH_CONNECTION_REPLY_FAILED;
		  rq_reply_failed++;
		  break;
		case 2:
		  if (e->rq)
		    {
		      unsigned int n;
		      for (n = 0; n < RQ_POSTPONED_SIZE; n++)
			{
			  if (rq_postponed[i][n] == NULL)
			    {
			      rq_postponed[i][n] = e->rq;
			      e->reply = ASSH_CONNECTION_REPLY_POSTPONED;
			      rq_postpone_count++;
			      goto rq_ev_done;
			    }
			}
		    }
		case 0:
		  e->reply = ASSH_CONNECTION_REPLY_SUCCESS;
		  if (e->rq && !assh_request_channel(e->rq))
		    get_data(&e->rsp_data.size, &e->rsp_data.data);
		  rq_reply_success++;
		rq_ev_done:
		  break;
		}

	      ASSH_DEBUG("ASSH_EVENT_REQUEST %p %u\n", e->rq, e->reply);
	      break;
	    }

	    case ASSH_EVENT_REQUEST_ABORT: {
	      struct assh_event_request_abort_s *e = &event.connection.request_abort;
	      ASSH_DEBUG("ASSH_EVENT_REQUEST_ABORT %p\n", e->rq);

	      unsigned int n;
	      for (n = 0; n < RQ_POSTPONED_SIZE; n++)
		if (e->rq == rq_postponed[i][n])
		  rq_postponed[i][n] = NULL;

	      break;
	    }

	    case ASSH_EVENT_REQUEST_REPLY: {      /***** request reply *****/
	      struct assh_event_request_reply_s *e = &event.connection.request_reply;
	      ASSH_DEBUG("ASSH_EVENT_REQUEST_REPLY %p\n", e->rq);

	      for (n = 0; n < RQ_POSTPONED_SIZE; n++)
		assert(rq_postponed[i][n] != e->rq);

	      switch (e->reply)
		{
		case ASSH_CONNECTION_REPLY_SUCCESS:
		  if (!started[i])
		    TEST_FAIL("(ctx %u seed %u) ASSH_CONNECTION_REPLY_SUCCESS while not started\n", i, seed);

		  rq_event_success_count++;
		  break;

		case ASSH_CONNECTION_REPLY_FAILED:
		  if (!started[i])
		    TEST_FAIL("(ctx %u seed %u) ASSH_CONNECTION_REPLY_FAILED while not started\n", i, seed);

		  rq_event_failed_count++;
		  break;

		case ASSH_CONNECTION_REPLY_CLOSED:
		  rq_event_closed_count++;
		  break;

		default:
		  TEST_FAIL("(ctx %u seed %u) request_reply.reply\n", n, seed);
		}

	      break;
	    }

	    case ASSH_EVENT_CHANNEL_OPEN: {      /***** channel open event *****/
	      struct assh_event_channel_open_s *e = &event.connection.channel_open;

	      if (!started[i])
		TEST_FAIL("(ctx %u seed %u) ASSH_EVENT_CHANNEL_OPEN while not started\n", i, seed);

	      ch_event_open_count++;

	      if (everr)
		goto ch_fail;

	      for (n = 0; n < CH_MAP_SIZE; n++)
		{
		  if (ch_map[i][n] == NULL)
		    {
		      switch (rand() % 3)
			{
			case 0:
			  ch_map[i][n] = e->ch;
			  e->reply = ASSH_CONNECTION_REPLY_SUCCESS;
			  assh_channel_set_pvi(e->ch, CH_OPEN);
			  ch_open_reply_success_count++;
			  break;
			case 2:
			  e->reply = ASSH_CONNECTION_REPLY_POSTPONED;
			  ch_map[i][n] = e->ch;
			  assh_channel_set_pvi(e->ch, CH_POSTONED);
			  ch_postpone_count++;
			  break;
			case 1:
			ch_fail:
			  e->reply = ASSH_CONNECTION_REPLY_FAILED;
			  ch_open_reply_failed_count++;
			  break;
			}
		      break;
		    }
		}

	      ASSH_DEBUG("ASSH_EVENT_CHANNEL_OPEN %p %u\n", e->ch, e->reply);
	      break;
	    }

	    case ASSH_EVENT_CHANNEL_OPEN_REPLY: {      /***** open reply event *****/
	      struct assh_event_channel_open_reply_s *e = &event.connection.channel_open_reply;
	      ASSH_DEBUG("ASSH_EVENT_CHANNEL_OPEN_REPLY %p\n", e->ch);

	      if (e->reply == ASSH_CONNECTION_REPLY_FAILED)
		{
		  for (n = 0; n < CH_MAP_SIZE; n++)
		    if (ch_map[i][n] == e->ch)
		      ch_map[i][n] = NULL;
		}
	      else
		{
		  assh_channel_set_pvi(e->ch, CH_OPEN);
		}

	      break;
	    }

	    case ASSH_EVENT_CHANNEL_CLOSE: {      /***** close event *****/
	      struct assh_event_channel_close_s *e = &event.connection.channel_close;
	      ASSH_DEBUG("ASSH_EVENT_CHANNEL_CLOSE %p\n", e->ch);

	      ch_event_close_count++;

	      for (n = 0; n < CH_MAP_SIZE; n++)
		if (ch_map[i][n] == e->ch)
		  ch_map[i][n] = NULL;

	      break;
	    }

	    case ASSH_EVENT_CHANNEL_DATA: {
	      struct assh_event_channel_data_s *e = &event.connection.channel_data;
	      e->transferred = rand() % (e->data.size + 1);
	      ASSH_DEBUG("ASSH_EVENT_CHANNEL_DATA %p\n", e->ch);
	      ch_data_recv++;
	      break;
	    }

	    case ASSH_EVENT_CHANNEL_WINDOW: {
	      ch_data_window++;
	      break;
	    }

	    case ASSH_EVENT_CHANNEL_EOF: {      /***** eof event *****/
	      struct assh_event_channel_close_s *e = &event.connection.channel_close;
	      (void)e;
	      ASSH_DEBUG("ASSH_EVENT_CHANNEL_EOF %p\n", e->ch);

	      ch_event_eof_count++;
	      break;
	    }

	    case ASSH_EVENT_ERROR: {
	      everr = ASSH_OK;
	      if (ASSH_ERR_SEVERITY(event.error.code))
		started[i] = 0;
	      break;
	    }

	    case ASSH_EVENT_KEX_HOSTKEY_LOOKUP:
	      everr = ASSH_OK;
	      event.kex.hostkey_lookup.accept = 1;
	      break;

	    case ASSH_EVENT_KEX_DONE:
	      everr = ASSH_OK;
	      if (kex_done)
		rekex_count++;
	      kex_done = 1;
	      break;

	    case ASSH_EVENT_READ:
	      everr = ASSH_OK;
	      if (fifo_rw_event(fifo, &event, i))
		stall[i]++;
	      break;

	    case ASSH_EVENT_WRITE:
	      everr = ASSH_OK;
	      stall[i]++;
	      if (!fifo_rw_event(fifo, &event, i))
		stall[i] = 0;
	      break;

	    case ASSH_EVENT_SERVICE_START:
	      everr = ASSH_OK;
	      if (event.service.start.srv == &assh_service_connection)
		{
		  alloc_fuzz = alloc_f;
		  started[i]++;
		}
	      break;

	    default:
	      TEST_FAIL("(ctx %u seed %u) Don't know how to handle event %u\n", i, seed, event.id);
	    }

	  assh_event_done(&session[i], &event, everr);

	  if (stall[i] >= 10000)
	    {
	      if (evrate || packet_fuzz || alloc_fuzz)
		goto done;
	      TEST_FAIL("stalled\n");
	    }
	  continue;
	}
    }

  /********************* cleanup and memory leak checking */

 done:
  if (alloc_size == 0)
    TEST_FAIL("leak checking not working\n");

  for (i = 0; i < 2; i++)
    {
      assh_session_cleanup(&session[i]);
      assh_context_cleanup(&context[i]);
    }

  if (alloc_size != 0)
    TEST_FAIL("memory leak detected, %zu bytes allocated\n", alloc_size);
}

static int end_disconnect(int j, int n)
{
  if (rand() % 5000)
    {
      assh_session_disconnect(&session[0], rand() % 15 + 1,
			      "dummy error message" + rand() % 8);
      disconnect_count++;
    }
  if (rand() % 5000)
    {
      assh_session_disconnect(&session[1], rand() % 15 + 1,
			      "dummy error message" + rand() % 8);
      disconnect_count++;
    }
  return 0;
}

static int end_wait_error(int j, int n)
{
  return 1;
}

static int end_early_cleanup(int j, int n)
{
  return rand() % 10000;
}

int main(int argc, char **argv)
{
#ifdef CONFIG_ASSH_USE_GCRYPT
  if (!gcry_check_version(GCRYPT_VERSION))
    TEST_FAIL("init");
  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
#endif

  unsigned int count = argc > 1 ? atoi(argv[1]) : 200;
  unsigned int action = argc > 2 ? atoi(argv[2]) : 31;
  unsigned int k;

  seed = argc > 3 ? atoi(argv[3]) : time(0);

  for (k = 0; k < count; )
    {
      srand(seed);
      packet_fuzz = 0;

      if (action & 1)
	{
	  putc('e', stderr);
	  test(&end_early_cleanup, 10000, 0, 0);
	}

      if (action & 2)
	{
	  putc('d', stderr);
	  test(&end_disconnect, 1000000, 0, 0);
	}

      if (action & 4)
	{
	  packet_fuzz = 10 + rand() % 1024;
	  putc('f', stderr);
	  test(&end_wait_error, 10000, 0, 0);
	}

      if (action & 8)
	{
	  packet_fuzz = 0;
	  putc('a', stderr);
	  test(&end_wait_error, 10000, 0, 4 + rand() % 32);
	}

      if (action & 16)
	{
	  putc('v', stderr);
	  packet_fuzz = 10 + rand() % 1024;
	  test(&end_wait_error, 10000,
		   rand() % 256 + 16,
		   rand() % 128 + 16);
	}

      seed++;

      if (++k % 12 == 0)
	fprintf(stderr, " seed=%u\n", seed);
    }

  if (k % 16)
    fputc('\n', stderr);

  fprintf(stderr, "Summary:\n"
	  "  %8lu request calls\n"
	  "  %8lu request replies (success)\n"
	  "  %8lu request replies (failed)\n"
	  "  %8lu request received events\n"
	  "  %8lu request reply events (success)\n"
	  "  %8lu request reply events (failed)\n"
	  "  %8lu request reply events (closed)\n"
	  "  %8lu request postponed\n"
	  "  %8lu channel open calls\n"
	  "  %8lu channel open events\n"
	  "  %8lu channel open reply (success)\n"
	  "  %8lu channel open reply (failed)\n"
	  "  %8lu channel open postponed\n"
	  "  %8lu channel close calls\n"
	  "  %8lu channel close events\n"
	  "  %8lu channel eof calls\n"
	  "  %8lu channel eof events\n"
	  "  %8lu channel data send\n"
	  "  %8lu channel data receive\n"
	  "  %8lu channel window\n"
	  "  %8lu rekex\n"
	  "  %8lu event error\n"
	  "  %8lu disconnect\n"
	  "  %8lu fuzz packet bit errors\n"
	  "  %8lu fuzz memory allocation fails\n"
	  ,
	  rq_send_count, rq_reply_success, rq_reply_failed,
	  rq_event_count, rq_event_success_count,
	  rq_event_failed_count, rq_event_closed_count, rq_postpone_count,
	  ch_open_count, ch_event_open_count,
	  ch_open_reply_success_count,
	  ch_open_reply_failed_count, ch_postpone_count,
	  ch_close_count, ch_event_close_count,
	  ch_eof_count, ch_event_eof_count,
	  ch_data_send, ch_data_recv, ch_data_window, rekex_count, ev_err_count,
	  disconnect_count, packet_fuzz_bits, alloc_fuzz_fails
	  );

  return 0;
}

