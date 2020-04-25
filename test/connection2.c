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
#include <assh/assh_userauth.h>
#include <assh/helper_key.h>

#include "fifo.h"
#include "test.h"

#include <getopt.h>
#include <errno.h>

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
unsigned long ch_event_open_reply_success_count = 0;
unsigned long ch_event_open_reply_failed_count = 0;
unsigned long ch_open_reply_success_count = 0;
unsigned long ch_open_reply_failed_count = 0;
unsigned long ch_postpone_count = 0;
unsigned long ch_open_success_reply_call_count = 0;
unsigned long ch_open_failed_reply_call_count = 0;
unsigned long ch_close_count = 0;
unsigned long ch_event_abort_count = 0;
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
  *size = test_prng_rand() % sizeof(r);
  *data = r + test_prng_rand() % (sizeof(r) - *size);
}

void test(int (*fend)(int, int), int cnt, int evrate,
	  unsigned alloc_f, assh_bool_t disco)
{
  assh_status_t err;
  unsigned int i, j;
  assh_bool_t started[2] = {};
  assh_bool_t kex_done = 0;

  /********************* intiailization */

  ASSH_DEBUG("==============================================================\n");

  static const struct assh_algo_s *algos[] = {
    &assh_kex_none.algo_wk.algo, &assh_sign_none.algo_wk.algo,
    &test_cipher_fuzz.algo, &assh_mac_none.algo, &assh_compress_none.algo,
    NULL
  };

  test_alloc_fuzz = 0;
  if (assh_context_init(&context[0], ASSH_SERVER,
			test_leaks_allocator, NULL,
			&test_prng_dummy, NULL) ||
      assh_algo_register_static(&context[0], algos) ||
      assh_context_init(&context[1], ASSH_CLIENT,
			test_leaks_allocator, NULL,
			&test_prng_dummy, NULL) ||
      assh_algo_register_static(&context[1], algos))
    TEST_FAIL("init");

  for (i = 0; i < 2; i++)
    {
      fifo_init(&fifo[i]);

      if (assh_service_register_va(&context[i], &assh_service_connection, NULL))
	TEST_FAIL("init");

      if (assh_session_init(&context[i], &session[i]) != ASSH_OK)
	TEST_FAIL("init");
      test_cipher_fuzz_initreg(&context[i], &session[i]);

      assh_userauth_done(&session[i]);
      if (assh_kex_set_threshold(&session[i], 1 + test_prng_rand() % 16384))
	TEST_FAIL("init");

      for (j = 0; j < RQ_POSTPONED_SIZE; j++)
	rq_postponed[i][j] = NULL;

      for (j = 0; j < CH_MAP_SIZE; j++)
	ch_map[i][j] = NULL;
    }

  if (assh_key_load(&context[0], &context[0].keys, &assh_key_none, ASSH_ALGO_SIGN,
		    ASSH_KEY_FMT_PUB_RFC4253, NULL, 0) != ASSH_OK)
    TEST_FAIL("init");

  /********************* sessions test loop */

  uint_fast32_t stall[2] = { 0, 0 };

  for (j = 0; (session[0].tr_st != ASSH_TR_CLOSED &&
	       session[1].tr_st != ASSH_TR_CLOSED) && fend(j, cnt); j++)
    {
      /* alternate between the two sessions */
      for (i = 0; i < 2; i++)
	{
	  struct assh_event_s event;

	  ASSH_DEBUG("=== context %u %u ===\n", i, stall[i]);

	  /********************* generate request and channel open... */

	  if (started[i])
	    switch (test_prng_rand() % 8)
	      {
	      case 0:
	      case 1: {    	/***** send a new request *****/
		assh_bool_t want_reply = test_prng_rand() % 2;
		unsigned int k = test_prng_rand() % CH_MAP_SIZE;
		struct assh_channel_s *ch = ch_map[i][k];
		struct assh_request_s *rq;

		if (!ch)
		  goto globl_rq;

		switch (assh_channel_pvi(ch))
		  {
		    size_t data_len;
		    const uint8_t *data;
		  case CH_OPEN:
		  case CH_EOF:
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

		switch (test_prng_rand() % 2)
		  {
		  case 0: {
		    size_t data_len = 0;
		    const uint8_t *data = NULL;
		    if (!ch)
		      get_data(&data_len, &data);
		    assh_status_t er = assh_request_success_reply(rq, data, data_len);
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
		    assh_status_t er = assh_request_failed_reply(rq);
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
		unsigned int k = test_prng_rand() % CH_MAP_SIZE;
		struct assh_channel_s *ch = ch_map[i][k];

		if (ch == NULL) /**** channel is closed, try to open ****/
		  {
		    size_t data_len;
		    const uint8_t *data;
		    get_data(&data_len, &data);
		    err = assh_channel_open(&session[i], (const char *)data, data_len,
					     data, data_len,
					     test_prng_rand() % 31 + 1, test_prng_rand() % 128,
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
		    switch (assh_channel_pvi(ch))
		      {
		      case CH_WAIT:
		      case CH_CLOSE:
			break;

		      case CH_POSTONED: /* postponned */
			switch (test_prng_rand() % 2)
			  {
			    size_t data_len;
			    const uint8_t *data;
			  case 0:
			    get_data(&data_len, &data);
			    err = assh_channel_open_success_reply2(ch,
					test_prng_rand() % 31 + 1, test_prng_rand() % 128,
								   data, data_len);
			    if (err == ASSH_NO_DATA)
			      break;
			    if (err > ASSH_NO_DATA)
			      {
				if (alloc_f)
				  break;
				TEST_FAIL("(ctx %u seed %u) assh_channel_open_success_reply2()\n", i, seed);
			      }
			    ASSH_DEBUG("assh_channel_open_success_reply2 %p\n", ch);
			    ch_open_success_reply_call_count++;
			    assh_channel_set_pvi(ch, CH_OPEN);
			    break;
			  case 1:
			    err = assh_channel_open_failed_reply(ch, test_prng_rand() % 4 + 1);
			    if (err == ASSH_NO_DATA)
			      break;
			    if (err > ASSH_NO_DATA)
			      {
				if (alloc_f)
				  break;
				TEST_FAIL("(ctx %u seed %u) assh_channel_open_failed_reply()\n", i, seed);
			      }
			    ASSH_DEBUG("assh_channel_open_failed_reply %p\n", ch);
			    ch_map[i][k] = NULL;
			    ch_open_failed_reply_call_count++;
			    break;
			  }
			break;

		      case CH_OPEN:
			switch (test_prng_rand() % 8)
			  {
			  case 0:
			    goto try_close;
			  case 1: {	/**** may send eof ****/
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
			  case 3:
			  case 4:
			  case 5: {
			    uint8_t *d;
			    size_t m = test_prng_rand() % 64;
			    size_t s = test_prng_rand() % (m + 1);
			    assh_status_t er = assh_channel_data_alloc(ch, &d, &s, m);
			    if (er > ASSH_NO_DATA)
			      {
				if (alloc_f)
				  break;
				TEST_FAIL("(ctx %u seed %u) assh_channel_data_alloc()\n", i, seed);
			      }
			    if (er == ASSH_OK && s > 0)
			      {
				memset(d, test_prng_rand(), s);
				if (assh_channel_data_send(ch, s))
				  TEST_FAIL("(ctx %u seed %u) assh_channel_data_send()\n", i, seed);
				ch_data_send++;
			      }
			    break;
			  }
			  }
			break;

		      case CH_EOF:
			if (test_prng_rand() % 4)
			  break;
		      try_close:
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
		  }

	      }
	      default:
		break;
	      }

	  /********************* handle events */

	  if (!assh_event_get(&session[i], &event, 0))
	    continue;

	  assh_status_t everr = ASSH_OK;

	  if (evrate && !(test_prng_rand() % evrate))
	    {
	      ev_err_count++;
	      everr = (test_prng_rand() % 32 + 0x100);
	      if (ASSH_STATUS(everr) == ASSH_ERR_PROTOCOL && !test_packet_fuzz)
		everr = ASSH_OK;
	    }

	  ASSH_DEBUG("event %u err %u\n", event.id, everr);
	  switch (event.id)
	    {
	    case ASSH_EVENT_REQUEST: {        /***** incoming request *****/
	      struct assh_event_request_s *e = &event.connection.request;
	      rq_event_count++;

	      if (everr)
		goto rq_fail;

	      switch (test_prng_rand() % 3)
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

	    case ASSH_EVENT_REQUEST_SUCCESS: {      /***** request reply *****/
	      struct assh_event_request_success_s *e
		= &event.connection.request_success;
	      ASSH_DEBUG("ASSH_EVENT_REQUEST_SUCCESS %p\n", e->rq);

	      unsigned n;
	      for (n = 0; n < RQ_POSTPONED_SIZE; n++)
		assert(rq_postponed[i][n] != e->rq);

	      rq_event_success_count++;
	      break;
	    }

	    case ASSH_EVENT_REQUEST_FAILURE: {      /***** request reply *****/
	      struct assh_event_request_failure_s *e
		= &event.connection.request_failure;
	      ASSH_DEBUG("ASSH_EVENT_REQUEST_FAILURE %p\n", e->rq);

	      unsigned n;
	      for (n = 0; n < RQ_POSTPONED_SIZE; n++)
		assert(rq_postponed[i][n] != e->rq);

	      switch (e->reason)
		{
		case ASSH_REQUEST_FAILED:
		  rq_event_failed_count++;
		  break;

		case ASSH_REQUEST_SESSION_DISCONNECTED:
		  rq_event_closed_count++;
		  break;
		}

	      break;
	    }

	    case ASSH_EVENT_CHANNEL_OPEN: {      /***** channel open event *****/
	      struct assh_event_channel_open_s *e = &event.connection.channel_open;

	      if (everr)
		goto ch_fail;

	      unsigned n;
	      for (n = 0; n < CH_MAP_SIZE; n++)
		{
		  if (ch_map[i][n] == NULL)
		    {
		      switch (test_prng_rand() % 3)
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

	    case ASSH_EVENT_CHANNEL_CONFIRMATION: {      /***** open reply event *****/
	      struct assh_event_channel_confirmation_s *e
		= &event.connection.channel_confirmation;
	      ASSH_DEBUG("ASSH_EVENT_CHANNEL_CONFIRMATION %p\n", e->ch);

	      if (assh_channel_pvi(e->ch) != CH_WAIT)
		TEST_FAIL("(ctx %u seed %u) channel_open reply success\n", i, seed);

	      assh_channel_set_pvi(e->ch, CH_OPEN);
	      ch_event_open_reply_success_count++;

	      break;
	    }

	    case ASSH_EVENT_CHANNEL_FAILURE: {      /***** open reply event *****/
	      struct assh_event_channel_failure_s *e
		= &event.connection.channel_failure;
	      ASSH_DEBUG("ASSH_EVENT_CHANNEL_FAILURE %p\n", e->ch);

	      if (assh_channel_pvi(e->ch) != CH_WAIT)
		TEST_FAIL("(ctx %u seed %u) channel_open reply\n", i, seed);

	      unsigned n;
	      for (n = 0; n < CH_MAP_SIZE; n++)
		if (ch_map[i][n] == e->ch)
		  ch_map[i][n] = NULL;
	      ch_event_open_reply_failed_count++;

	      break;
	    }

	    case ASSH_EVENT_CHANNEL_ABORT: {
	      struct assh_event_channel_abort_s *e = &event.connection.channel_abort;
	      ASSH_DEBUG("ASSH_EVENT_CHANNEL_ABORT %p\n", e->ch);

	      if (assh_channel_pvi(e->ch) != CH_POSTONED)
		TEST_FAIL("(ctx %u seed %u) channel_abort\n", i, seed);

	      ch_event_abort_count++;

	      unsigned n;
	      for (n = 0; n < CH_MAP_SIZE; n++)
		if (ch_map[i][n] == e->ch)
		  ch_map[i][n] = NULL;

	      break;
	    }

	    case ASSH_EVENT_CHANNEL_CLOSE: {      /***** close event *****/
	      struct assh_event_channel_close_s *e = &event.connection.channel_close;
	      ASSH_DEBUG("ASSH_EVENT_CHANNEL_CLOSE %p\n", e->ch);

	      if (assh_channel_pvi(e->ch) != CH_OPEN &&
		  assh_channel_pvi(e->ch) != CH_EOF &&
		  assh_channel_pvi(e->ch) != CH_CLOSE)
		TEST_FAIL("(ctx %u seed %u) channel_close\n", i, seed);

	      ch_event_close_count++;

	      unsigned n;
	      for (n = 0; n < CH_MAP_SIZE; n++)
		if (ch_map[i][n] == e->ch)
		  ch_map[i][n] = NULL;

	      break;
	    }

	    case ASSH_EVENT_CHANNEL_DATA: {
	      struct assh_event_channel_data_s *e = &event.connection.channel_data;
	      e->transferred = test_prng_rand() % (e->data.size + 1);
	      ASSH_DEBUG("ASSH_EVENT_CHANNEL_DATA %p\n", e->ch);
	      if (!ASSH_SUCCESS(assh_channel_window_adjust(e->ch, e->transferred)) && !test_alloc_fuzz)
		TEST_FAIL("assh_channel_window_adjust");
	      ch_data_recv++;
	      break;
	    }

	    case ASSH_EVENT_CHANNEL_WINDOW: {
	      ch_data_window++;
	      break;
	    }

	    case ASSH_EVENT_CHANNEL_EOF: {      /***** eof event *****/
	      struct assh_event_channel_eof_s *e = &event.connection.channel_eof;
	      (void)e;
	      ASSH_DEBUG("ASSH_EVENT_CHANNEL_EOF %p\n", e->ch);

	      ch_event_eof_count++;
	      break;
	    }

	    case ASSH_EVENT_DISCONNECT: {
	      if (!disco && !evrate && !test_packet_fuzz && !test_alloc_fuzz)
		TEST_FAIL("unexpected disconnection %x : %.*s\n",
			  event.transport.disconnect.reason,
			  (int)event.transport.disconnect.desc.len,
			  event.transport.disconnect.desc.str);
	      break;
	    }

	    case ASSH_EVENT_SESSION_ERROR: {
	      everr = ASSH_OK;
	      err = event.session.error.code;
	      if (ASSH_SEVERITY(err))
		started[i] = 0;
	      if (session[i^1].tr_st >= ASSH_TR_DISCONNECT &&
		  (ASSH_STATUS(err) == ASSH_ERR_IO))
		break;
	      if (!evrate && !test_packet_fuzz && !test_alloc_fuzz)
		TEST_FAIL("(ctx %u seed %u) unexpected error event 0x%lx\n", i, seed, err);
	      if (ASSH_STATUS(err) == ASSH_ERR_PROTOCOL && !test_packet_fuzz)
		TEST_FAIL("(ctx %u seed %u) unexpected protocol error\n", i, seed);
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
	      if (session[i ^ 1].tr_st >= ASSH_TR_DISCONNECT)
		{
		  everr = ASSH_ERR_IO;
		}
	      else
		{
		  everr = ASSH_OK;
		  stall[i]++;
		  if (!fifo_rw_event(fifo, &event, i))
		    stall[i] = 0;
		}
	      break;

	    case ASSH_EVENT_SERVICE_START:
	      everr = ASSH_OK;
	      if (event.service.start.srv == &assh_service_connection)
		{
		  test_alloc_fuzz = alloc_f;
		  started[i]++;
		}
	      break;

	    default:
	      ASSH_DEBUG("(ctx %u seed %u) Don't know how to handle event %u\n", i, seed, event.id);
	    }

	  assh_event_done(&session[i], &event, everr);

	  if (stall[i] >= 10000)
	    {
	      if (evrate || test_packet_fuzz || test_alloc_fuzz)
		goto done;
	      TEST_FAIL("(ctx %u seed %u) stalled\n", i, seed);
	    }
	  continue;
	}
    }

  /********************* cleanup and memory leak checking */

 done:
  if (test_alloc_size == 0)
    TEST_FAIL("leak checking not working\n");

  for (i = 0; i < 2; i++)
    {
      assh_session_cleanup(&session[i]);
      assh_context_cleanup(&context[i]);
    }

  if (test_alloc_size != 0)
    TEST_FAIL("memory leak detected, %zu bytes allocated\n", test_alloc_size);
}

static int end_disconnect(int j, int n)
{
  if (test_prng_rand() % 8192 == 0)
    {
      assh_session_disconnect(&session[0], test_prng_rand() % 15 + 1,
		      (const char*)"dummy error message" + test_prng_rand() % 8);
      disconnect_count++;
    }
  if (test_prng_rand() % 8192 == 0)
    {
      assh_session_disconnect(&session[1], test_prng_rand() % 15 + 1,
		      (const char*)"dummy error message" + test_prng_rand() % 8);
      disconnect_count++;
    }
  return 1;
}

static int end_wait_error(int j, int n)
{
  return 1;
}

static int end_early_cleanup(int j, int n)
{
  return test_prng_rand() % 10000;
}

static void usage()
{
  printf("usage: connection2 [options]\n");

  printf(	  "Options:\n\n"

	  "    -h         show help\n"
	  "    -e         test pass with early end\n"
	  "    -d         test pass with disconnect\n"
	  "    -f         test pass with packet fuzzing\n"
	  "    -a         test pass with allocator fuzzing\n"
	  "    -v         test pass with event errors and fuzzing\n"
	  "    -c count   set number of test passes (default 100)\n"
	  "    -s seed    set initial seed (default: time(0))\n"
	  );
}

int main(int argc, char **argv)
{
  setvbuf(stdout, NULL, _IONBF, 0);

  if (assh_deps_init())
    return -1;

  enum action_e {
    ACTION_EARLY_END = 1,
    ACTION_DISCONNECT = 2,
    ACTION_PACKET_FUZZ = 4,
    ACTION_ALLOC_FUZZ = 8,
    ACTION_ALL_FUZZ = 16,
  };

  enum action_e action = 0;
  unsigned int count = 100;
  unsigned int seed = time(0);
  int opt;

  while ((opt = getopt(argc, argv, "edfavhs:c:")) != -1)
    {
      switch (opt)
	{
	case 'e':
	  action |= ACTION_EARLY_END;
	  break;
	case 'd':
	  action |= ACTION_DISCONNECT;
	  break;
	case 'f':
	  action |= ACTION_PACKET_FUZZ;
	  break;
	case 'a':
	  action |= ACTION_ALLOC_FUZZ;
	  break;
	case 'v':
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
    action = ACTION_EARLY_END | ACTION_DISCONNECT;

  unsigned k, l;

  for (l = k = 0; k < count; k++)
    {
      test_prng_set_seed(seed);
      test_packet_fuzz = 0;

      if (action & ACTION_EARLY_END)
	{
	  putc('e', stdout);
	  l++;
	  test(&end_early_cleanup, 10000, 0, 0, 0);
	}

      if (action & ACTION_DISCONNECT)
	{
	  putc('d', stdout);
	  l++;
	  test(&end_disconnect, 1000000, 0, 0, 1);
	}

      if (action & ACTION_PACKET_FUZZ)
	{
	  test_packet_fuzz = 10 + test_prng_rand() % 1024;
	  putc('f', stdout);
	  l++;
	  test(&end_wait_error, 10000, 0, 0, 0);
	}

      if (action & ACTION_ALLOC_FUZZ)
	{
	  test_packet_fuzz = 0;
	  putc('a', stdout);
	  l++;
	  test(&end_wait_error, 10000, 0, 4 + test_prng_rand() % 32, 0);
	}

      if (action & ACTION_ALL_FUZZ)
	{
	  putc('v', stdout);
	  l++;
	  test_packet_fuzz = 10 + test_prng_rand() % 1024;
	  test(&end_disconnect, 10000,
	       test_prng_rand() % 256 + 16,
	       test_prng_rand() % 128 + 16, 1);
	}

      seed++;

      if (l > 40)
	{
	  printf(" seed=%u\n", seed);
	  l = 0;
	}
    }

  if (l)
    putchar('\n');

  printf("\nSummary:\n"
	  "  %8lu request calls\n"
	  "  %8lu request replies (success)\n"
	  "  %8lu request replies (failed)\n"
	  "  %8lu request received events\n"
	  "  %8lu request reply events (success)\n"
	  "  %8lu request reply events (failed)\n"
	  "  %8lu request reply events (closed)\n"
	  "  %8lu request postponed\n"
	  "  %8lu channel open calls\n"
	  "  %8lu channel open reply event (success)\n"
	  "  %8lu channel open reply event (failed)\n"
	  "  %8lu channel open events (success)\n"
	  "  %8lu channel open events (failed)\n"
	  "  %8lu channel open events postponed\n"
	  "  %8lu channel open reply call (success)\n"
	  "  %8lu channel open reply call (failed)\n"
	  "  %8lu channel close calls\n"
	  "  %8lu channel close events\n"
	  "  %8lu channel abort events\n"
	  "  %8lu channel eof calls\n"
	  "  %8lu channel eof events\n"
	  "  %8lu channel data send\n"
	  "  %8lu channel data receive\n"
	  "  %8lu channel window\n"
	  "  %8lu rekex\n"
	  "  %8lu disconnect\n"
	  ,
	  rq_send_count, rq_reply_success, rq_reply_failed,
	  rq_event_count, rq_event_success_count,
	  rq_event_failed_count, rq_event_closed_count, rq_postpone_count,
	  ch_open_count, ch_event_open_reply_success_count, ch_event_open_reply_failed_count,
	  ch_open_reply_success_count, ch_open_reply_failed_count, ch_postpone_count,
	  ch_open_success_reply_call_count, ch_open_failed_reply_call_count,
	  ch_close_count, ch_event_close_count, ch_event_abort_count,
	  ch_eof_count, ch_event_eof_count,
	  ch_data_send, ch_data_recv, ch_data_window, rekex_count,
	  disconnect_count
	  );

  if (action & (ACTION_PACKET_FUZZ | ACTION_ALLOC_FUZZ | ACTION_ALL_FUZZ))
    printf("\nFuzzing:\n"
	    "  %8lu fuzz packet bit errors\n"
	    "  %8lu fuzz memory allocation fails\n"
	    "  %8lu event error\n"
	    ,
	    test_packet_fuzz_bits, test_alloc_fuzz_fails, ev_err_count
	    );

  puts("\nTest passed");
  return 0;
}

