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
  request operations. This test keeps track of client and server
  operations using unified channel and request states and check
  consistency of operation on both sides.
*/

#define ASSH_PV
#define ASSH_ABI_UNSAFE  /* do not warn */

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

struct ch_map_entry_s;

enum rq_status_e
{
  RQ_RELEASED  = 0,
  RQ_SENT      = 1,
  RQ_SUCCESS   = 2,
  RQ_FAIL      = 3,
  RQ_POSTPONED = 4,
  RQ_NOREPLY   = 5,
  RQ_ERROR     = 6,
};

struct rq_fifo_entry_s
{
  struct ch_map_entry_s *che;
  struct assh_request_s *srq;	/* sender request */
  struct assh_request_s *rrq;	/* receiver request */
  unsigned int          type_len;
  char                  type[10];
  unsigned int          data_len;
  uint8_t               rq_data[32];
  uint8_t               rsp_data[32];
  enum rq_status_e      status:8;
};

struct rq_fifo_s
{
  int first;
  int first_r;
  int count;
  struct rq_fifo_entry_s entry[RQ_FIFO_SIZE];
};

static void rq_fifo_init(struct rq_fifo_s *f)
{
  f->first = 0;
  f->first_r = 0;
  f->count = 0;	  
}

enum ch_status_e
{
  CH_CLOSED    = 0,
  CH_REQUESTED = 1,
  CH_SUCCESS   = 2,
  CH_FAIL      = 3,
  CH_POSTPONED = 4,
  CH_OPEN      = 5,
  CH_HALFCLOSED = 6,
};

struct ch_map_entry_s
{
  struct assh_channel_s *ch[2];
  struct rq_fifo_s      rq_fifo[2];
  unsigned int          type_len;
  char                  type[10];
  unsigned int          data_len;
  uint8_t               data[32];
  enum ch_status_e      status:8;
  int                   initiator:8;
  int                   close_sent:3;
  int                   eof_sent:3;
};

struct ch_map_entry_s ch_map[CH_MAP_SIZE];
unsigned int ch_refs;
unsigned int rq_refs_in;
unsigned int rq_refs_out;

#define ch_report(che) \
  ASSH_DEBUG("%u:CHANNEL %p: s=%u status=%u ch0=%p ch1=%p\n", \
	     __LINE__, che, i, che->status, che->ch[0], che->ch[1])

#define RQ_POSTPONED_SIZE (RQ_FIFO_SIZE * (CH_MAP_SIZE + 1)) 
struct rq_fifo_entry_s *rq_postponed[RQ_POSTPONED_SIZE];

struct fifo_s fifo[2];
struct assh_context_s context[2];
struct assh_session_s session[2];
struct rq_fifo_s global_rq_fifo[2];

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
unsigned long ev_err_count = 0;
unsigned long rekex_count = 0;

static void pop_request(struct rq_fifo_s *lrqf)
{
  struct rq_fifo_entry_s *rqe;
  /* pop request as well as subsequent
     requests with no reply  */
  do {
    lrqf->first++;
    lrqf->count--;
    rqe = &lrqf->entry[(lrqf->first % RQ_FIFO_SIZE)];
  } while (lrqf->count > 0 && (rqe->status == RQ_NOREPLY));
}

void test(int (*fend)(int, int), int n, int evrate)
{
  assh_status_t err;
  unsigned int i, j;
  assh_bool_t started[2] = {};
  assh_bool_t closed[2] = {};
  assh_bool_t kex_done = 0;

  /********************* intiailization */

  ASSH_DEBUG("==============================================================\n");

  static const struct assh_algo_s *algos[] = {
    &assh_kex_none.algo_wk.algo, &assh_sign_none.algo_wk.algo,
    &assh_cipher_none.algo, &assh_mac_none.algo, &assh_compress_none.algo,
    NULL
  };

  if (assh_context_init(&context[0], ASSH_SERVER,
			test_leaks_allocator, NULL,
			&test_prng_dummy, NULL) ||
      assh_algo_register_static(&context[0], algos) ||
      assh_context_init(&context[1], ASSH_CLIENT,
			test_leaks_allocator, NULL,
			&test_prng_dummy, NULL) ||
      assh_algo_register_static(&context[1], algos))
    TEST_FAIL("init");

  ch_refs = rq_refs_in = rq_refs_out = 0;

  for (j = 0; j < CH_MAP_SIZE; j++)
    {
      for (i = 0; i < 2; i++)
	{
	  ch_map[j].ch[i] = NULL;
	  rq_fifo_init(&ch_map[j].rq_fifo[i]);
	}
      ch_map[j].status = CH_CLOSED;
    }

  for (i = 0; i < 2; i++)
    {
      fifo_init(&fifo[i]);

      rq_fifo_init(&global_rq_fifo[i]);

      if (assh_service_register_va(&context[i], &assh_service_connection, NULL))
	TEST_FAIL("init");

      if (assh_session_init(&context[i], &session[i]) != ASSH_OK)
	TEST_FAIL("init");

      assh_session_userauth_done(&session[i]);
      if (assh_kex_set_threshold(&session[i], 1 + test_prng_rand() % 4096))
	TEST_FAIL("init");
    }

  for (i = 0; i < RQ_POSTPONED_SIZE; i++)
    rq_postponed[i] = NULL;

  if (assh_key_load(&context[0], &context[0].keys, &assh_key_none, ASSH_ALGO_SIGN,
		    ASSH_KEY_FMT_PV_PEM_ASN1, NULL, 0) != ASSH_OK)
    TEST_FAIL("init");

  /********************* sessions test loop */

  //  ASSH_DEBUG("----\n");
  uint_fast32_t stall[2] = { 0, 0 };

  for (j = 0; fend(j, n); j++)
    {
      /* alternate between the two sessions */
      for (i = 0; i < 2; i++)
	{
	  struct assh_event_s event;

	  ASSH_DEBUG("=== context %u ===\n", i);

	  /********************* generate request and channel open... */

	  if (started[i])
	    switch (test_prng_rand() % 10)
	      {
	      case 0:
	      case 1: {    	/***** send a new request *****/
		unsigned int k = test_prng_rand() % CH_MAP_SIZE;
		struct ch_map_entry_s *che = &ch_map[k];
		struct assh_channel_s *ch = NULL;
		struct rq_fifo_s *lrqf = &global_rq_fifo[i];
		if (che->status == CH_OPEN && che->ch[i] && !(che->close_sent & (1 << i)))
		  {
		    lrqf = &che->rq_fifo[i];
		    ch = che->ch[i];
		  }

		if (lrqf->count >= RQ_FIFO_SIZE || j > n)
		  break;

		struct rq_fifo_entry_s *rqe = &lrqf->entry[(lrqf->first + lrqf->count++) % RQ_FIFO_SIZE];
		assh_bool_t want_reply = test_prng_rand() % 2;

		rqe->che = ch ? che : NULL;

		rqe->type_len = test_prng_rand() % (sizeof(rqe->type) - 1) + 1;
		memset(rqe->type, 'a' + test_prng_rand() % 26, rqe->type_len);

		rqe->data_len = test_prng_rand() % sizeof(rqe->rq_data);
		memset(rqe->rq_data, test_prng_rand(), rqe->data_len);

		rqe->status = RQ_SENT;
		rqe->srq = NULL;
		err = assh_request(&session[i], ch, rqe->type, rqe->type_len,
				   rqe->data_len || test_prng_rand() % 2 ? rqe->rq_data : NULL, rqe->data_len,
				   want_reply ? &rqe->srq : NULL);
		if (err == ASSH_NO_DATA)
		  break;
		if (err > ASSH_NO_DATA)
		  TEST_FAIL("(ctx %u seed %u) assh_request failed 0x%lx\n", i, seed, err);
		ASSH_DEBUG("assh_request %p\n", &rqe->srq);
		if (want_reply)
		  rq_refs_out++;
		rq_send_count++;
		if (want_reply)
		  assh_request_set_pv(rqe->srq, rqe);
		rqe->rrq = NULL;
		break;
	      }

	      case 2:
	      case 3: {		/***** reply to postponed request *****/
		struct rq_fifo_entry_s *rqe;
		unsigned int n, l = test_prng_rand() % RQ_POSTPONED_SIZE;

		/* look for postponed requests in the fifo */
		for (n = 0; n < RQ_POSTPONED_SIZE; n++)
		  {
		    if ((rqe = rq_postponed[(n+l) % RQ_POSTPONED_SIZE]) &&
			rqe->status == RQ_POSTPONED)
		      break;
		  }
		if (n == RQ_POSTPONED_SIZE)
		  break;
		rqe->data_len = 0;

		if (rqe->che)
		  {
		    if (assh_request_channel(rqe->rrq) != rqe->che->ch[i])
		      break;
		    if (rqe->che->close_sent & (1 << i))
		      break;
		  }

		switch (test_prng_rand() % 2)
		  {
		  case 0: {
		    if (rqe->che == NULL)
		      {
			rqe->data_len = test_prng_rand() % sizeof(rqe->rsp_data);
			memset(rqe->rsp_data, test_prng_rand(), rqe->data_len);
		      }

		    assh_status_t er = assh_request_success_reply(rqe->rrq, rqe->rsp_data, rqe->data_len);
		    if (er > ASSH_NO_DATA)
		      TEST_FAIL("(ctx %u seed %u) assh_request_reply(ASSH_CONNECTION_REPLY_SUCCESS)\n", i, seed);
		    ASSH_DEBUG("assh_request_success_reply %p\n", rqe->rrq);
		    rq_refs_in--;
		    rq_reply_success++;
		    rqe->status = RQ_SUCCESS;
		    break;
		  }
		  case 1: {
		    assh_status_t er = assh_request_failed_reply(rqe->rrq);
		    if (er > ASSH_NO_DATA)
		      TEST_FAIL("(ctx %u seed %u) assh_request_reply(ASSH_CONNECTION_REPLY_FAILED)\n", i, seed);
		    ASSH_DEBUG("assh_request_failed_reply %p\n", rqe->rrq);
		    rq_refs_in--;
		    rq_reply_failed++;
		    rqe->status = RQ_FAIL;
		    break;
		  }
		  }
		break;
	      }

	      case 4: {    	/***** channel actions *****/
		unsigned int k = test_prng_rand() % CH_MAP_SIZE;
		struct ch_map_entry_s *che = &ch_map[k];

		switch (che->status)
		  {
		  case CH_CLOSED: { /**** channel is closed, try to open ****/
		    if (j > n)
		      break;
		    che->type_len = test_prng_rand() % (sizeof(che->type) - 1) + 1;
		    memset(che->type, 'a' + test_prng_rand() % 26, che->type_len);
		    che->type[0] = k;

		    che->data_len = test_prng_rand() % sizeof(che->data);
		    memset(che->data, test_prng_rand(), che->data_len);

		    err = assh_channel_open(&session[i], che->type, che->type_len,
					   che->data, che->data_len,
					   test_prng_rand() % 31 + 1, test_prng_rand() % 128,
					     &che->ch[i]);
		    if (err == ASSH_NO_DATA)
		      break;
		    if (err > ASSH_NO_DATA)
		      TEST_FAIL("(ctx %u seed %u) assh_channel_open2 failed 0x%lx\n", i, seed, err);

		    ASSH_DEBUG("assh_channel_open2 %p\n", &che->ch[i]);
		    assh_channel_set_pv(che->ch[i], che);
		    che->initiator = i;
		    che->status = CH_REQUESTED;
		    ch_refs++;
		    che->close_sent = 0;
		    che->eof_sent = 0;
		    rq_fifo_init(&che->rq_fifo[0]);
		    rq_fifo_init(&che->rq_fifo[1]);
		    ch_open_count++;
		    ch_report(che);
		    break;
		  }

		  case CH_POSTPONED: { /**** reply to postponed open ****/
		    if (che->initiator == i)
		      break;
		    switch (test_prng_rand() % 2)
		      {
		      case 0:
			che->data_len = test_prng_rand() % sizeof(che->data);
			memset(che->data, test_prng_rand(), che->data_len);
			err = assh_channel_open_success_reply2(che->ch[i],
							       test_prng_rand() % 31 + 1, test_prng_rand() % 128,
							       che->data, che->data_len);
			if (err)
			  TEST_FAIL("(ctx %u seed %u) assh_channel_open_success_reply failed 0x%lx\n", i, seed, err);
			ASSH_DEBUG("assh_channel_open_success_reply2 %p\n", che->ch[i]);
			che->status = CH_SUCCESS;
			ch_report(che);
			ch_open_reply_success_count++;
			break;
		      case 1:
			err = assh_channel_open_failed_reply(che->ch[i], test_prng_rand() % 4 + 1);
			if (err)
			  TEST_FAIL("(ctx %u seed %u) assh_channel_open_failed_reply failed 0x%lx\n", i, seed, err);
			ASSH_DEBUG("assh_channel_open_failed_reply %p\n", che->ch[i]);
			che->status = CH_FAIL;
			ch_report(che);
			ch_refs--;
			ch_open_reply_failed_count++;
			break;
		      }
		    break;
		  }
		  case CH_OPEN: { /**** channel is open ****/

		    switch (test_prng_rand() % 2)
		      {
		      case 0: {	/**** may close ****/
			if (che->ch[i] == NULL)
			  break;
			ch_close_count++;
			if (che->close_sent & (1 << i))
			  break;
			che->close_sent |= 1 << i;
			err = assh_channel_close(che->ch[i]);
			if (err)
			  TEST_FAIL("(ctx %u seed %u) assh_channel_close failed 0x%lx\n", i, seed, err);
			ASSH_DEBUG("assh_channel_close %p\n", che->ch[i]);

			break;
		      }
		      case 1: {	/**** may send eof ****/
			if (che->ch[i] == NULL)
			  break;
			if ((che->eof_sent | che->close_sent) & (1 << i))
			  break;
			ch_eof_count++;
			che->eof_sent |= 1 << i;
			err = assh_channel_eof(che->ch[i]);
			if (err)
			  TEST_FAIL("(ctx %u seed %u) assh_channel_eof failed 0x%lx\n", i, seed, err);
			ASSH_DEBUG("assh_channel_eof %p\n", che->ch[i]);
			break;
		      }
		      }
		    break;
		  }
		  default:
		    break;
		  }
		break;
	      }

	      }

	  /********************* handle events */

	  if (!assh_event_get(&session[i], &event, 0))
	    {
	      closed[i] = 1;

	      if (closed[0] && closed[1])
		{
		  if (ch_refs)
		    TEST_FAIL("(ctx %u seed %u) not all channels are closed\n", i, seed);
		  if (rq_refs_in)
		    TEST_FAIL("(ctx %u seed %u) incoming requests are pending\n", i, seed);
		  if (rq_refs_out)
		    TEST_FAIL("(ctx %u seed %u) outgoing requests are pending\n", i, seed);
		  goto done;
		}

	      continue;
	    }

	  assh_status_t everr = ASSH_OK;

	  if (evrate && !(test_prng_rand() % evrate))
	    {
	      ev_err_count++;
	      everr = (test_prng_rand() % 32 + 0x100);
	      if (ASSH_STATUS(everr) == ASSH_ERR_PROTOCOL)
		everr = ASSH_OK;
	    }

	  switch (event.id)
	    {
	    case ASSH_EVENT_SESSION_ERROR: {
	      err = event.session.error.code;
	      if (!evrate)
		TEST_FAIL("(ctx %u seed %u) unexpected error event 0x%lx\n", i, seed, err);
	      if (ASSH_STATUS(err) == ASSH_ERR_PROTOCOL)
		TEST_FAIL("(ctx %u seed %u) unexpected protocol error\n", i, seed);
	      started[i] = 0;
	      break;
	    }

	    case ASSH_EVENT_REQUEST: {        /***** incoming request *****/
	      struct assh_event_request_s *e = &event.connection.request;
	      struct rq_fifo_s *rrqf = &global_rq_fifo[i^1];
	      if (e->ch != NULL)
		{
		  struct ch_map_entry_s *che = assh_channel_pv(e->ch);
		  rrqf = &che->rq_fifo[i^1];
		}
	      struct rq_fifo_entry_s *rqe = &rrqf->entry[(rrqf->first_r++ % RQ_FIFO_SIZE)];

	      rqe->rrq = e->rq;

	      if (!started[i] && !evrate)
		TEST_FAIL("(ctx %u seed %u) ASSH_EVENT_REQUEST while not started\n", i, seed);

	      if (started[i^1])
		{
		  if (rrqf->count == 0)
		    TEST_FAIL("(ctx %u seed %u) rrqf->count is zero\n", i, seed);

		  if (rqe->status != RQ_SENT)
		    TEST_FAIL("(ctx %u seed %u) request status %u, (1 expected)\n",
			      i, seed, rqe->status);

		  if (rqe->type_len != e->type.len)
		    {
		      ASSH_DEBUG_HEXDUMP("rq", rqe->type, rqe->type_len);
		      ASSH_DEBUG_HEXDUMP("ev", e->type.str, e->type.len);
		      TEST_FAIL("(ctx %u seed %u) request.type_len: rq:%u ev:%zu\n",
				i, seed, rqe->type_len, e->type.len);
		    }

		  if (e->type.len && memcmp(rqe->type, e->type.str, e->type.len))
		    {
		      ASSH_DEBUG_HEXDUMP("rq", rqe->type, rqe->type_len);
		      ASSH_DEBUG_HEXDUMP("ev", e->type.str, e->type.len);
		      TEST_FAIL("(ctx %u seed %u) request.type\n", i, seed);
		    }

		  if (rqe->data_len != e->rq_data.size)
		    TEST_FAIL("(ctx %u seed %u) request.data_len: rq:%u ev:%zu\n",
			      i, seed, rqe->data_len, e->rq_data.size);

		  if (e->rq_data.size && memcmp(rqe->rq_data, e->rq_data.data, e->rq_data.size))
		    {
		      ASSH_DEBUG_HEXDUMP("rq", rqe->rq_data, rqe->data_len);
		      ASSH_DEBUG_HEXDUMP("ev", e->rq_data.data, e->rq_data.size);
		      TEST_FAIL("(ctx %u seed %u) request.data\n", i, seed);
		    }

		  if (!rqe->rrq != !rqe->srq)
		    TEST_FAIL("(ctx %u seed %u) request.rq\n", i, seed);
		}

	      rq_event_count++;

	      if (e->rq == NULL)
		{
		  /* We can only pop request with no reply if it's first in
		     the fifo. It will be poped later in the other case. */
		  if (rrqf->first_r == rrqf->first + 1)
		    {
		      rrqf->first++;
		      rrqf->count--;
		      goto ev_request_done;
		    }
		  rqe->status = RQ_NOREPLY;
		  goto ev_request_done;
		}

	      assh_request_set_pv(e->rq, rqe);
	      e->rsp_data.data = NULL;
	      rqe->data_len = e->rsp_data.size = 0;

	      if (everr)
		goto rq_fail;

	      switch (test_prng_rand() % 3)
		{
		case 0:
		  e->reply = ASSH_CONNECTION_REPLY_SUCCESS;
		  if (e->ch == NULL)
		    {
		      rqe->data_len = test_prng_rand() % sizeof(rqe->rsp_data);
		      memset(rqe->rsp_data, test_prng_rand(), rqe->data_len);
		      e->rsp_data.data = rqe->rsp_data;
		      e->rsp_data.size = rqe->data_len;
		    }
		  rqe->status = RQ_SUCCESS;
		  rq_reply_success++;
		  break;
		case 1:
		rq_fail:
		  e->reply = ASSH_CONNECTION_REPLY_FAILED;
		  rqe->status = RQ_FAIL;
		  rq_reply_failed++;
		  break;
		case 2: {
		  unsigned int n;
		  e->reply = ASSH_CONNECTION_REPLY_POSTPONED;
		  rqe->status = RQ_POSTPONED;
		  rq_postpone_count++;
		  for (n = 0; n < RQ_POSTPONED_SIZE; n++)
		    if (rq_postponed[n] == NULL)
		      break;
		  TEST_ASSERT(n < RQ_POSTPONED_SIZE);
		  rq_postponed[n] = rqe;
		  rq_refs_in++;
		  break;
		}
		}

	    ev_request_done:
	      ASSH_DEBUG("ASSH_EVENT_REQUEST %p:%p %u\n", e->rq, rqe, e->reply);
	      break;
	    }

	    case ASSH_EVENT_REQUEST_ABORT: {        /***** incoming request *****/
	      struct assh_event_request_abort_s *e = &event.connection.request_abort;
	      ASSH_DEBUG("ASSH_EVENT_REQUEST_ABORT %p\n", e->rq);
	      struct rq_fifo_entry_s *rqe = assh_request_pv(e->rq);
	      rq_refs_in--;

	      unsigned int n;
	      for (n = 0; n < RQ_POSTPONED_SIZE; n++)
		if (rq_postponed[n] == rqe)
		  {
		    rq_postponed[n] = NULL;
		    rqe->status = RQ_ERROR;
		    break;
		  }
	      if (n == RQ_POSTPONED_SIZE)
		TEST_FAIL("(ctx %u seed %u) unknown postponed request\n", i, seed);
	      break;
	    }

	    case ASSH_EVENT_REQUEST_SUCCESS: {
	      struct assh_event_request_success_s *e
		= &event.connection.request_success;
	      struct rq_fifo_s *lrqf = &global_rq_fifo[i];
	      struct ch_map_entry_s *che = NULL;

	      rq_refs_out--;
	      if (e->ch != NULL)
		{
		  che = assh_channel_pv(e->ch);
		  lrqf = &che->rq_fifo[i];
		}
	      struct rq_fifo_entry_s *rqe;

	      rqe = &lrqf->entry[lrqf->first % RQ_FIFO_SIZE];
	      ASSH_DEBUG("ASSH_EVENT_REQUEST_SUCCESS %p:%p\n", e->rq, rqe);

	      TEST_ASSERT(e->rq == rqe->srq);

	      if (lrqf->count <= 0)
		TEST_FAIL("(ctx %u seed %u) request count %u %p, (> 0 expected) %u\n",
			     i, seed, lrqf->count, &lrqf->count, rqe->status);

	      if (!started[i] && !evrate)
		TEST_FAIL("(ctx %u seed %u) ASSH_CONNECTION_REPLY_SUCCESS while not started\n", i, seed);

	      if (started[i^1])
		{
		  if (rqe->status != RQ_SUCCESS)
		    TEST_FAIL("(ctx %u seed %u) request status %u, (2 expected)\n",
			      i, seed, rqe->status);

		  if (rqe->data_len != e->rsp_data.size)
		    TEST_FAIL("(ctx %u seed %u) request_reply.rsp_data.size: rq:%u ev:%zu\n",
			      i, seed, rqe->data_len, e->rsp_data.size);

		  if (e->rsp_data.size && memcmp(rqe->rsp_data, e->rsp_data.data, e->rsp_data.size))
		    {
		      ASSH_DEBUG_HEXDUMP("rq", rqe->rsp_data, rqe->data_len);
		      ASSH_DEBUG_HEXDUMP("ev", e->rsp_data.data, e->rsp_data.size);
		      TEST_FAIL("(ctx %u seed %u) request_reply.rsp_data.data\n", i, seed);
		    }
		}
	      rq_event_success_count++;

	      rqe->status = RQ_RELEASED;

	      ASSH_DEBUG("ASSH_EVENT_REQUEST_SUCESS %p status %u\n", e->rq, rqe->status);

	      pop_request(lrqf);
	      break;
	    }

	    case ASSH_EVENT_REQUEST_FAILURE: {      /***** request reply *****/
	      struct assh_event_request_failure_s *e
		= &event.connection.request_failure;
	      struct rq_fifo_s *lrqf = &global_rq_fifo[i];
	      struct ch_map_entry_s *che = NULL;

	      rq_refs_out--;
	      if (e->ch != NULL)
		{
		  che = assh_channel_pv(e->ch);
		  lrqf = &che->rq_fifo[i];
		}
	      struct rq_fifo_entry_s *rqe;

	      while (1)
		{
		  rqe = &lrqf->entry[lrqf->first % RQ_FIFO_SIZE];
		  // rqe = assh_request_pv(e->rq);
		  if (e->reason == ASSH_REQUEST_FAILED || rqe->srq != NULL)
		    break;
		  lrqf->first++;
		  lrqf->count--;
		}

	      ASSH_DEBUG("ASSH_EVENT_REQUEST_FAILURE %p:%p\n", e->rq, rqe);

	      TEST_ASSERT(e->rq == rqe->srq);

	      if (lrqf->count <= 0)
		TEST_FAIL("(ctx %u seed %u) request count %u %p, (> 0 expected) %u\n",
			     i, seed, lrqf->count, &lrqf->count, rqe->status);

	      switch (e->reason)
		{
		case ASSH_REQUEST_FAILED:
		  if (!started[i] && !evrate)
		    TEST_FAIL("(ctx %u seed %u) ASSH_CONNECTION_REPLY_FAILED while not started\n", i, seed);

		  if (started[i^1])
		    {
		      if (rqe->status != RQ_FAIL)
			TEST_FAIL("(ctx %u seed %u) request status %u, (3 expected)\n",
			      i, seed, rqe->status);
		    }
		  rq_event_failed_count++;
		  break;

		case ASSH_REQUEST_SESSION_DISCONNECTED:
		  rq_event_closed_count++;
		  break;

		default:
		  TEST_FAIL("(ctx %u seed %u) request_reply.reply\n", seed, rqe->status);
		}

	      rqe->status = RQ_RELEASED;

	      ASSH_DEBUG("ASSH_EVENT_REQUEST_FAILURE %p status %u\n", e->rq, rqe->status);

	      pop_request(lrqf);
	      break;
	    }

	    case ASSH_EVENT_CHANNEL_OPEN: {      /***** channel open event *****/
	      struct assh_event_channel_open_s *e = &event.connection.channel_open;
	      unsigned int k = e->type.str[0];
	      struct ch_map_entry_s *che = &ch_map[k];

	      if (!started[i] && !evrate)
		TEST_FAIL("(ctx %u seed %u) ASSH_EVENT_CHANNEL_OPEN while not started\n", i, seed);

	      if (k >= CH_MAP_SIZE)
		TEST_FAIL("(ctx %u seed %u) CH_MAP_SIZE\n", i, seed);

	      if (started[i^1])
		{
		  if (che->status != CH_REQUESTED)
		    TEST_FAIL("(ctx %u seed %u) channel_open status %u\n", i, seed, che->status);

		  if (che->ch[i] != NULL || che->ch[i^1] == NULL)
		    TEST_FAIL("(ctx %u seed %u) channel_open ptr\n", i, seed);

		  if (che->type_len != e->type.len)
		    TEST_FAIL("(ctx %u seed %u) channel_open.type_len: ch:%u ev:%zu\n",
			      i, seed, che->type_len, e->type.len);

		  if (e->type.len && memcmp(che->type, e->type.str, e->type.len))
		    {
		      ASSH_DEBUG_HEXDUMP("ch", che->type, che->type_len);
		      ASSH_DEBUG_HEXDUMP("ev", e->type.str, e->type.len);
		      TEST_FAIL("(ctx %u seed %u) channel_open.type\n", i, seed);
		    }

		  if (che->data_len != e->rq_data.size)
		    TEST_FAIL("(ctx %u seed %u) channel_open.data_len: ch:%u ev:%zu\n",
			      i, seed, che->data_len, e->rq_data.size);

		  if (e->rq_data.size && memcmp(che->data, e->rq_data.data, e->rq_data.size))
		    {
		      ASSH_DEBUG_HEXDUMP("ch", che->data, che->data_len);
		      ASSH_DEBUG_HEXDUMP("ev", e->rq_data.data, e->rq_data.size);
		      TEST_FAIL("(ctx %u seed %u) channel_open.data\n", i, seed);
		    }
		}

	      ch_event_open_count++;

	      if (everr)
		goto ch_fail;

	      switch (test_prng_rand() % 3)
		{
		case 0:
		  e->reply = ASSH_CONNECTION_REPLY_SUCCESS;
		  che->ch[i] = e->ch;
		  assh_channel_set_pv(e->ch, che);
		  che->status = CH_SUCCESS;
		  ch_refs++;
		  ch_open_reply_success_count++;

		  che->data_len = test_prng_rand() % sizeof(che->data);
		  memset(che->data, test_prng_rand(), che->data_len);
		  e->rsp_data.data = che->data;
		  e->rsp_data.size = che->data_len;
		  ch_report(che);
		  break;
		case 1:
		ch_fail:
		  e->reply = ASSH_CONNECTION_REPLY_FAILED;
		  che->ch[i] = NULL;
		  che->status = CH_FAIL;
		  ch_open_reply_failed_count++;
		  ch_report(che);
		  break;
		case 2:
		  e->reply = ASSH_CONNECTION_REPLY_POSTPONED;
		  che->ch[i] = e->ch;
		  assh_channel_set_pv(e->ch, che);
		  che->status = CH_POSTPONED;
		  ch_refs++;
		  ch_postpone_count++;
		  ch_report(che);
		  break;
		}

	      ASSH_DEBUG("ASSH_EVENT_CHANNEL_OPEN %p %u\n", e->ch, e->reply);
	      break;
	    }

	    case ASSH_EVENT_CHANNEL_CONFIRMATION: {      /***** open reply event *****/
	      struct assh_event_channel_confirmation_s *e
		= &event.connection.channel_confirmation;
	      ASSH_DEBUG("ASSH_EVENT_CHANNEL_CONFIRMATION %p\n", e->ch);
	      struct ch_map_entry_s *che = assh_channel_pv(e->ch);

	      if (che->status == CH_FAIL)
		TEST_FAIL("(ctx %u seed %u) channel_open_reply.reply == FAIL\n", i, seed);

	      che->status = CH_OPEN;
	      ch_report(che);

	      if (started[i^1])
		{
		  if (che->data_len != e->rsp_data.size)
		    TEST_FAIL("(ctx %u seed %u) channel_open_reply.data_len: ch:%u ev:%zu\n",
			      i, seed, che->data_len, e->rsp_data.size);

		  if (e->rsp_data.size && memcmp(che->data, e->rsp_data.data, e->rsp_data.size))
		    {
		      ASSH_DEBUG_HEXDUMP("ch", che->data, che->data_len);
		      ASSH_DEBUG_HEXDUMP("ev", e->rsp_data.data, e->rsp_data.size);
		      TEST_FAIL("(ctx %u seed %u) channel_open_reply.data\n", i, seed);
		    }
		}
	      break;
	    }

	    case ASSH_EVENT_CHANNEL_FAILURE: {      /***** open reply event *****/
	      struct assh_event_channel_failure_s *e
		= &event.connection.channel_failure;
	      ASSH_DEBUG("ASSH_EVENT_CHANNEL_FAILURE %p\n", e->ch);
	      struct ch_map_entry_s *che = assh_channel_pv(e->ch);

	      if (che->status != CH_FAIL)
		{
		  if (started[i])
		    TEST_FAIL("(ctx %u seed %u) ASSH_EVENT_CHANNEL_OPEN_REPLY while started\n", i, seed);
		  che->ch[i] = NULL;
		}
	      else
		{
		  che->ch[0] = che->ch[1] = NULL;
		  che->status = CH_CLOSED;
		}
	      ch_refs--;
	      ch_report(che);

	      break;
	    }

	    case ASSH_EVENT_CHANNEL_ABORT:
	    case ASSH_EVENT_CHANNEL_CLOSE: {      /***** close event *****/
	      struct assh_event_channel_close_s *e = &event.connection.channel_close;
	      ASSH_DEBUG("ASSH_EVENT_CHANNEL_CLOSE %p\n", e->ch);
	      struct ch_map_entry_s *che = assh_channel_pv(e->ch);

	      ch_report(che);
	      ch_event_close_count++;
	      if (che->ch[i] == NULL)
		TEST_FAIL("(ctx %u seed %u) channel_close %p status=%u\n", i, seed, che, che->status);

	      if (che->status == CH_CLOSED)
		TEST_FAIL("(ctx %u seed %u) channel %p already closed\n", i, seed, che);

	      ch_refs--;
	      che->ch[i] = NULL;
	      che->status = (che->status == CH_HALFCLOSED) ? CH_CLOSED : CH_HALFCLOSED;

	      if (che->status == CH_CLOSED && (che->ch[0] != NULL || che->ch[1] != NULL))
		TEST_FAIL("(ctx %u seed %u) channel %p not NULL\n", i, seed, che);

	      break;
	    }

	    case ASSH_EVENT_CHANNEL_EOF: {      /***** eof event *****/
	      struct assh_event_channel_eof_s *e = &event.connection.channel_eof;
	      ASSH_DEBUG("ASSH_EVENT_CHANNEL_EOF %p\n", e->ch);
	      struct ch_map_entry_s *che = assh_channel_pv(e->ch);

	      if (!started[i] && !evrate)
		TEST_FAIL("(ctx %u seed %u) ASSH_EVENT_CHANNEL_EOF while not started\n", i, seed);

	      ch_event_eof_count++;
	      if (started[i^1])
		{
		  if (che->ch[i] == NULL)
		    TEST_FAIL("(ctx %u seed %u) channel_eof\n", i, seed);

		  if ((che->eof_sent & (2 >> i)) == 0)
		    TEST_FAIL("(ctx %u seed %u) channel_eof sent\n", i, seed);
		}
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
		started[i]++;
	      break;

	    default:
	      TEST_FAIL("(ctx %u seed %u) Don't know how to handle event %u\n", i, seed, event.id);
	    }

	  assh_event_done(&session[i], &event, everr);

	  if (stall[i] >= 100000)
	    {
	      if (evrate)
		goto done;
	      TEST_FAIL("stalled\n");
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

static int end_wait_error(int j, int n)
{
  return 1;
}

static int end_no_more_requests(int j, int n)
{
  return (j < n ||
	  global_rq_fifo[0].count > 0 ||
	  global_rq_fifo[1].count > 0 ||
	  ch_refs > 0);

  /* TODO check alloc counts when there is no more reuqests/channels */
}

static int end_early_cleanup(int j, int n)
{
  return (/* global_rq_fifo[0].count < RQ_FIFO_SIZE / 2 ||
	  global_rq_fifo[1].count < RQ_FIFO_SIZE / 2 ||
	  ch_refs < CH_MAP_SIZE / 2 ||*/
	  test_prng_rand() % 1000);
}

static void usage()
{
  printf("usage: connection [options]\n");

  printf(	  "Options:\n\n"

	  "    -h         show help\n"
	  "    -r         pass end when there is no more request/channel\n"
	  "    -e         paas end at random time\n"
	  "    -w         pass end when there is an error\n"
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
    ACTION_NO_MORE_RQ = 1,
    ACTION_EARLY_END = 2,
    ACTION_WAIT_ERROR = 4
  };

  enum action_e action = 0;
  unsigned int count = 100;
  unsigned int seed = time(0);
  int opt;

  while ((opt = getopt(argc, argv, "rewhs:c:")) != -1)
    {
      switch (opt)
	{
	case 'r':
	  action |= ACTION_NO_MORE_RQ;
	  break;
	case 'e':
	  action |= ACTION_EARLY_END;
	  break;
	case 'w':
	  action |= ACTION_WAIT_ERROR;
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
    action = ACTION_NO_MORE_RQ | ACTION_EARLY_END | ACTION_WAIT_ERROR;

  unsigned int k, l;

  for (l = k = 0; k < count; k++)
    {
      test_prng_set_seed(seed);

      if (action & ACTION_NO_MORE_RQ)
	{
	  putc('r', stdout);
	  l++;
	  test(&end_no_more_requests, 10000, 0);
	}

      if (action & ACTION_EARLY_END)
	{
	  putc('e', stdout);
	  l++;
	  test(&end_early_cleanup, 10000, 0);
	}

      if (action & ACTION_WAIT_ERROR)
	{
	  putc('w', stdout);
	  l++;
	  test(&end_wait_error, 10000, test_prng_rand() % 256 + 16);
	}

      seed++;

      if (l > 40)
	{
	  printf(" seed=%u\n", seed + k);
	  l = 0;
	}
    }

  if (l)
    putchar('\n');

  printf("Summary:\n"
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
	  "  %8lu rekex\n"
	  "  %8lu event error\n"
	  ,
	  rq_send_count, rq_reply_success, rq_reply_failed,
	  rq_event_count, rq_event_success_count,
	  rq_event_failed_count, rq_event_closed_count, rq_postpone_count,
	  ch_open_count, ch_event_open_count,
	  ch_open_reply_success_count,
	  ch_open_reply_failed_count, ch_postpone_count,
	  ch_close_count, ch_event_close_count,
	  ch_eof_count, ch_event_eof_count, rekex_count, ev_err_count
	  );

  puts("\nTest passed");
  return 0;
}

