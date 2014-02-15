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
#include <assh/assh_compress.h>
#include <assh/assh_transport.h>
#include <assh/srv_connection.h>
#include <assh/assh_event.h>

#include "fifo.h"
#include "leaks_check.h"

#include <errno.h>

#ifdef CONFIG_ASSH_USE_GCRYPT
# include <gcrypt.h>
#endif

#define RQ_FIFO_SIZE 32
#define CH_MAP_SIZE 32

struct rq_fifo_entry_s
{
  struct assh_channel_s *ch;
  struct assh_request_s *srq;	/* sender request */
  struct assh_request_s *rrq;	/* receiver request */
  unsigned int          type_len;
  char                  type[10];
  unsigned int          data_len;
  uint8_t               rq_data[32];
  uint8_t               rsp_data[32];
  int                   status:8;
};

struct rq_fifo_s
{
  unsigned int first;
  unsigned int first_r;
  unsigned int count;
  struct rq_fifo_entry_s entry[RQ_FIFO_SIZE];
};

struct ch_map_entry_s
{
  struct assh_channel_s *ch[2];
  struct rq_fifo_s      rq_fifo[2];
  unsigned int          type_len;
  char                  type[10];
  unsigned int          data_len;
  uint8_t               data[32];
  int                   status:8;
  int                   initiator:8;
};

struct ch_map_entry_s ch_map[CH_MAP_SIZE];
unsigned int ch_refs;

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
unsigned long rq_postpone_count = 0;
unsigned long ch_open_count = 0;
unsigned long ch_event_open_count = 0;
unsigned long ch_open_reply_success_count = 0;
unsigned long ch_open_reply_failed_count = 0;
unsigned long ch_postpone_count = 0;
unsigned long ch_close_count = 0;
unsigned long ch_event_close_count = 0;

int test(int (*fend)(int, int), int n)
{
  assh_error_t err;
  unsigned int i, j;
  assh_bool_t started[2] = {};

  /********************* intiailization */

  assh_context_init(&context[0], ASSH_SERVER);
  assh_context_init(&context[1], ASSH_CLIENT);

  ch_refs = 0;
  for (j = 0; j < CH_MAP_SIZE; j++)
    {
      for (i = 0; i < 2; i++)
	{
	  ch_map[j].ch[i] = NULL;
	  ch_map[j].rq_fifo[i].first = 0;
	  ch_map[j].rq_fifo[i].first_r = 0;
	  ch_map[j].rq_fifo[i].count = 0;	  
	}
      ch_map[j].status = 0;
    }

  for (i = 0; i < 2; i++)
    {
      fifo_init(&fifo[i]);

      global_rq_fifo[i].first = 0;
      global_rq_fifo[i].first_r = 0;
      global_rq_fifo[i].count = 0;

      assh_context_allocator(&context[i], assh_leaks_allocator, NULL);

      if (assh_service_register_va(&context[i], &assh_service_connection, NULL))
	return -1;

#if 0
      if (assh_algo_register_default(&context[i], 99, 10) != ASSH_OK)
	return -1;
#else
      if (assh_algo_register_va(&context[i], 0, 0, &assh_kex_none, &assh_sign_none,
				&assh_cipher_none, &assh_hmac_none, &assh_compress_none, NULL) != ASSH_OK)
	return -1;
#endif

      if (assh_session_init(&context[i], &session[i]) != ASSH_OK)
	return -1;
    }

  if (assh_load_hostkey_filename(&context[0], "none@libassh.org", "/dev/null",
				 ASSH_KEY_FMT_PV_PEM_ASN1) != ASSH_OK)
    return -1;

  /********************* sessions test loop */

  //  ASSH_DEBUG("----\n");

  for (j = 0; fend(j, n); j++)
    {
      srand(seed);

      /* alternate between the two sessions */
      for (i = 0; i < 2; i++)
	{
	  struct assh_event_s event;

	  //	  ASSH_DEBUG("=== context %u ===\n", i);

	  struct rq_fifo_s *lrqf = &global_rq_fifo[i];
	  struct rq_fifo_s *rrqf = &global_rq_fifo[i^1];

	  /********************* generate request and channel open... */

	  if (started[i])
	    switch (rand() % 5)
	      {
	      case 0: {    	/***** send a new request *****/
		if (lrqf->count >= RQ_FIFO_SIZE || j > n)
		  break;

		struct rq_fifo_entry_s *rqe = &lrqf->entry[(lrqf->first + lrqf->count++) % RQ_FIFO_SIZE];
		assh_bool_t want_reply = rand() % 2;

		rqe->type_len = rand() % (sizeof(rqe->type) - 1) + 1;
		memset(rqe->type, 'a' + rand() % 26, rqe->type_len);

		rqe->data_len = rand() % sizeof(rqe->rq_data);
		memset(rqe->rq_data, rand(), rqe->data_len);

		rqe->status = 1;
		err = assh_request(&session[i], NULL, rqe->type, rqe->type_len,
				   rqe->data_len || rand() % 2 ? rqe->rq_data : NULL, rqe->data_len,
				   want_reply, &rqe->srq);
		rq_send_count++;
		rqe->rrq = NULL;
		if (err)
		  return 3;
		break;
	      }

	      case 1: {		/***** reply to postponed request *****/
		struct rq_fifo_entry_s *rqe;
		unsigned int l;

		/* look for postponed requests in the fifo */
		for (l = 0; l < rrqf->count; l++)
		  {
		    rqe = &rrqf->entry[((rrqf->first + l) % RQ_FIFO_SIZE)];
		    if (rqe->status == 4)
		      break;
		  }
		if (l == rrqf->count)
		  break;

		switch (rand() % 2)
		  {
		  case 0:
		    rqe->data_len = rand() % sizeof(rqe->rsp_data);
		    memset(rqe->rsp_data, rand(), rqe->data_len);
		    if (assh_request_success_reply(rqe->rrq, rqe->rsp_data, rqe->data_len))
		    {
		      ASSH_DEBUG("FAIL (ctx %u seed %u) assh_request_reply(ASSH_CONNECTION_REPLY_SUCCESS)\n", i, seed);
		      return 1;
		    }
		    rq_reply_success++;
		    rqe->status = 2;
		    break;
		  case 1:
		    if (assh_request_failed_reply(rqe->rrq))
		      {
			ASSH_DEBUG("FAIL (ctx %u seed %u) assh_request_reply(ASSH_CONNECTION_REPLY_FAILED)\n", i, seed);
			return 1;
		      }
		    rq_reply_failed++;
		    rqe->status = 3;
		    break;
		  }
		break;
	      }

	      case 2: {    	/***** channel actions *****/
		unsigned int k = rand() % CH_MAP_SIZE;
		struct ch_map_entry_s *che = &ch_map[k];

		switch (che->status)
		  {
		  case 0: { /**** channel is closed, try to open ****/
		    if (j > n)
		      break;
		    che->type_len = rand() % (sizeof(che->type) - 1) + 1;
		    memset(che->type, 'a' + rand() % 26, che->type_len);
		    che->type[0] = k;

		    che->data_len = rand() % sizeof(che->data);
		    memset(che->data, rand(), che->data_len);

		    if (assh_channel_open(&session[i], che->type, che->type_len,
					  che->data, che->data_len,
					  rand() % 31 + 1, rand() % 32,
					  &che->ch[i]))
		      return 1;

		    assh_channel_set_pv(che->ch[i], che);
		    che->initiator = i;
		    che->status = 1;
		    ch_open_count++;
		    break;
		  }

		  case 4: { /**** reply to postponed open ****/
		    if (che->initiator == i)
		      break;
		    switch (rand() % 2)
		      {
		      case 0:
			che->data_len = rand() % sizeof(che->data);
			memset(che->data, rand(), che->data_len);
			if (assh_channel_open_success_reply(che->ch[i],
					  rand() % 32, rand() % 31 + 1,
							    che->data, che->data_len))
			  return 1;
			che->status = 2;
			ch_open_reply_success_count++;
			break;
		      case 1:
			if (assh_channel_open_failed_reply(che->ch[i], rand() % 4 + 1))
			  return 1;
			che->status = 3;
			ch_open_reply_failed_count++;
			break;
		      }
		    break;
		  }
		  case 5: { /**** channel is open, may close ****/
		    if (che->ch[i] == NULL)
		      break;
		    ch_close_count++;
		    if (assh_channel_close(che->ch[i]))
		      return 1;
		  }
		  }
	      }

	      }

	  /********************* handle events */

	  err = assh_event_get(&session[i], &event);
	  if (err != ASSH_OK)
	    return 1;

	  switch (event.id)
	    {
	    case ASSH_EVENT_REQUEST: {        /***** incoming request *****/
	      struct assh_event_request_s *e = &event.connection.request;
	      struct rq_fifo_entry_s *rqe = &rrqf->entry[(rrqf->first_r++ % RQ_FIFO_SIZE)];

	      rqe->rrq = e->rq;

	      if (rrqf->count == 0)
		{
		  ASSH_DEBUG("FAIL (ctx %u seed %u) rrqf->count is zero\n", i, seed);
		  return 1;
		}

	      if (rqe->status != 1)
		{
		  ASSH_DEBUG("FAIL (ctx %u seed %u) request status %u, (0 expected)\n",
			     i, seed, rqe->status);
		  return 1;
		}

	      if (rqe->type_len != e->type.len)
		{
		  ASSH_DEBUG("FAIL (ctx %u seed %u) request.type_len: rq:%u ev:%zu\n",
			     i, seed, rqe->type_len, e->type.len);
		  return 1;
		}

	      if (e->type.len && memcmp(rqe->type, e->type.str, e->type.len))
		{
		  ASSH_DEBUG("FAIL (ctx %u seed %u) request.type\n", i, seed);
		  assh_hexdump("rq", rqe->type, rqe->type_len);
		  assh_hexdump("ev", e->type.str, e->type.len);
		  return 1;
		}

	      if (rqe->data_len != e->rq_data.size)
		{
		  ASSH_DEBUG("FAIL (ctx %u seed %u) request.data_len: rq:%u ev:%zu\n",
			     i, seed, rqe->data_len, e->rq_data.size);
		  return 1;
		}

	      if (e->rq_data.size && memcmp(rqe->rq_data, e->rq_data.data, e->rq_data.size))
		{
		  ASSH_DEBUG("FAIL (ctx %u seed %u) request.data\n", i, seed);
		  assh_hexdump("rq", rqe->rq_data, rqe->data_len);
		  assh_hexdump("ev", e->rq_data.data, e->rq_data.size);
		  return 1;
		}

	      if (!rqe->rrq != !rqe->srq)
		{
		  ASSH_DEBUG("FAIL (ctx %u seed %u) request.rq\n", i, seed);
		  return 1;
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
		    }
		  rqe->status = 5;
		  break;
		}

	      switch (rand() % 3)
		{
		case 0:
		  e->reply = ASSH_CONNECTION_REPLY_SUCCESS;
		  rqe->data_len = rand() % sizeof(rqe->rsp_data);
		  memset(rqe->rsp_data, rand(), rqe->data_len);
		  e->rsp_data.data = rqe->rsp_data;
		  e->rsp_data.size = rqe->data_len;
		  rqe->status = 2;
		  rq_reply_success++;
		  break;
		case 1:
		  e->reply = ASSH_CONNECTION_REPLY_FAILED;
		  rqe->status = 3;
		  rq_reply_failed++;
		  break;
		case 2:
		  e->reply = ASSH_CONNECTION_REPLY_POSTPONED;
		  rqe->status = 4;
		  rq_postpone_count++;
		  break;
		}

	      break;
	    }

	    case ASSH_EVENT_REQUEST_REPLY: {      /***** request reply *****/
	      struct assh_event_request_reply_s *e = &event.connection.request_reply;
	      struct rq_fifo_entry_s *rqe = &lrqf->entry[(lrqf->first % RQ_FIFO_SIZE)];

	      assert(e->rq == rqe->srq);
	      assert(lrqf->count > 0);

	      switch (e->reply)
		{
		case ASSH_CONNECTION_REPLY_SUCCESS:
		  if (rqe->status != 2)
		    {
		      ASSH_DEBUG("FAIL (ctx %u seed %u) request status %u, (2 expected)\n",
				 i, seed, rqe->status);
		      return 1;
		    }

		  if (rqe->data_len != e->rsp_data.size)
		    {
		      ASSH_DEBUG("FAIL (ctx %u seed %u) request_reply.rsp_data.size: rq:%u ev:%zu\n",
				 i, seed, rqe->data_len, e->rsp_data.size);
		      return 4;
		    }

		  if (e->rsp_data.size && memcmp(rqe->rsp_data, e->rsp_data.data, e->rsp_data.size))
		    {
		      ASSH_DEBUG("FAIL (ctx %u seed %u) request_reply.rsp_data.data\n", i, seed);
		      assh_hexdump("rq", rqe->rsp_data, rqe->data_len);
		      assh_hexdump("ev", e->rsp_data.data, e->rsp_data.size);
		      return 4;
		    }
		  rq_event_success_count++;
		  break;

		case ASSH_CONNECTION_REPLY_FAILED:
		  if (rqe->status != 3)
		    {
		      ASSH_DEBUG("FAIL (ctx %u seed %u) request status %u, (3 expected)\n",
				 i, seed, rqe->status);
		      return 1;
		    }
		  rq_event_failed_count++;
		  break;

		default:
		  ASSH_DEBUG("FAIL (ctx %u seed %u) request_reply.reply\n", seed, rqe->status);
		  return 1;
		}
	      rqe->status = 0;

	      /* pop request as well as subsequent
		 requests with no reply  */
	      do {
		lrqf->first++;
		lrqf->count--;
		rqe = &lrqf->entry[(lrqf->first % RQ_FIFO_SIZE)];
	      } while (lrqf->count > 0 && rqe->status == 5);

	      break;
	    }

	    case ASSH_EVENT_CHANNEL_OPEN: {      /***** channel open event *****/
	      struct assh_event_channel_open_s *e = &event.connection.channel_open;
	      unsigned int k = e->type.str[0];
	      struct ch_map_entry_s *che = &ch_map[k];

	      if (k >= CH_MAP_SIZE)
		{
		  ASSH_DEBUG("FAIL (ctx %u seed %u) CH_MAP_SIZE\n", i, seed);
		  return 1;
		}

	      if (che->status != 1)
		{
		  ASSH_DEBUG("FAIL (ctx %u seed %u) channel_open status %u\n", i, seed, che->status);
		  return 1;
		}

	      if (che->ch[i] != NULL || che->ch[i^1] == NULL)
		{
		  ASSH_DEBUG("FAIL (ctx %u seed %u) channel_open ptr\n", i, seed);
		  return 1;
		}

	      if (che->type_len != e->type.len)
		{
		  ASSH_DEBUG("FAIL (ctx %u seed %u) channel_open.type_len: ch:%u ev:%zu\n",
			     i, seed, che->type_len, e->type.len);
		  return 1;
		}

	      if (e->type.len && memcmp(che->type, e->type.str, e->type.len))
		{
		  ASSH_DEBUG("FAIL (ctx %u seed %u) channel_open.type\n", i, seed);
		  assh_hexdump("ch", che->type, che->type_len);
		  assh_hexdump("ev", e->type.str, e->type.len);
		  return 1;
		}

	      if (che->data_len != e->rq_data.size)
		{
		  ASSH_DEBUG("FAIL (ctx %u seed %u) channel_open.data_len: ch:%u ev:%zu\n",
			     i, seed, che->data_len, e->rq_data.size);
		  return 1;
		}

	      if (e->rq_data.size && memcmp(che->data, e->rq_data.data, e->rq_data.size))
		{
		  ASSH_DEBUG("FAIL (ctx %u seed %u) channel_open.data\n", i, seed);
		  assh_hexdump("ch", che->data, che->data_len);
		  assh_hexdump("ev", e->rq_data.data, e->rq_data.size);
		  return 1;
		}

	      ch_event_open_count++;

	      switch (rand() % 3)
		{
		case 0:
		  e->reply = ASSH_CONNECTION_REPLY_SUCCESS;
		  che->ch[i] = e->ch;
		  assh_channel_set_pv(e->ch, che);
		  che->status = 2;
		  ch_open_reply_success_count++;

		  che->data_len = rand() % sizeof(che->data);
		  memset(che->data, rand(), che->data_len);
		  e->rsp_data.data = che->data;
		  e->rsp_data.size = che->data_len;
		  break;
		case 1:
		  e->reply = ASSH_CONNECTION_REPLY_FAILED;
		  che->ch[i] = NULL;
		  che->status = 3;
		  ch_open_reply_failed_count++;
		  break;
		case 2:
		  e->reply = ASSH_CONNECTION_REPLY_POSTPONED;
		  che->ch[i] = e->ch;
		  assh_channel_set_pv(e->ch, che);
		  che->status = 4;
		  ch_postpone_count++;
		  break;
		}
	      break;
	    }

	    case ASSH_EVENT_CHANNEL_OPEN_REPLY: {      /***** open reply event *****/
	      struct assh_event_channel_open_reply_s *e = &event.connection.channel_open_reply;
	      struct ch_map_entry_s *che = assh_channel_get_pv(e->ch);
	      switch (che->status)
		{
		case 2:
		  che->status = 5;
		  ch_refs++;

		  if (che->data_len != e->rsp_data.size)
		    {
		      ASSH_DEBUG("FAIL (ctx %u seed %u) channel_open_reply.data_len: ch:%u ev:%zu\n",
				 i, seed, che->data_len, e->rsp_data.size);
		      return 1;
		    }

		  if (e->rsp_data.size && memcmp(che->data, e->rsp_data.data, e->rsp_data.size))
		    {
		      ASSH_DEBUG("FAIL (ctx %u seed %u) channel_open_reply.data\n", i, seed);
		      assh_hexdump("ch", che->data, che->data_len);
		      assh_hexdump("ev", e->rsp_data.data, e->rsp_data.size);
		      return 1;
		    }

		  break;
		case 3:
		  che->ch[0] = che->ch[1] = NULL;
		  che->status = 0;
		  break;
		default:
		  ASSH_DEBUG("FAIL (ctx %u seed %u) channel_open_reply status\n", i, seed);
		  return 1;
		}

	      break;
	    }

	    case ASSH_EVENT_CHANNEL_CLOSE: {      /***** close event *****/
	      struct assh_event_channel_close_s *e = &event.connection.channel_close;
	      struct ch_map_entry_s *che = assh_channel_get_pv(e->ch);

	      ch_event_close_count++;
	      if (che->ch[i] == NULL)
		{
		  ASSH_DEBUG("FAIL (ctx %u seed %u) channel_close\n",
			     i, seed, che->status);
		  return 1;
		}

	      che->ch[i] = NULL;
	      if (che->ch[0] == NULL && che->ch[1] == NULL)
		{
		  ch_refs--;
		  che->status = 0;
		}
	      break;
	    }

	    case ASSH_EVENT_KEX_HOSTKEY_LOOKUP:
	      event.kex.hostkey_lookup.accept = 1;
	      break;

	    case ASSH_EVENT_READ: {
	      struct assh_event_transport_read_s *te = &event.transport.read;
	      te->transferred = fifo_read(&fifo[i], te->buf.data,
					  te->buf.size % (rand() % FIFO_BUF_SIZE + 1));
	      break;
	    }

	    case ASSH_EVENT_WRITE: {
	      struct assh_event_transport_write_s *te = &event.transport.write;
	      te->transferred = fifo_write(&fifo[i ^ 1], te->buf.data,
					   te->buf.size % (rand() % FIFO_BUF_SIZE + 1));
	      break;
	    }

	    case ASSH_EVENT_CONNECTION_START:
	      started[i]++;
	      break;

	    default:
	      printf("Don't know how to handle event %u (context %u)\n", event.id, i);
	      return 21;
	    }
	  
	  err = assh_event_done(&session[i], &event);
	  if (ASSH_ERR_ERROR(err) != ASSH_OK)
	    {
	      fprintf(stderr, "assh error %i in main loop (errno=%i) (context %u)\n", err, errno, i);
	      return -1;
	    }
	}

      seed++;
    }

  /********************* cleanup and memory leak checking */

  if (alloc_size == 0)
    {
      ASSH_DEBUG("leak checking not working\n");
      return 1;
    }

  for (i = 0; i < 2; i++)
    {
      assh_session_cleanup(&session[i]);
      assh_context_cleanup(&context[i]);
    }

  if (alloc_size != 0)
    {
      ASSH_DEBUG("memory leak detected, %zu bytes allocated\n", alloc_size);
      return 1;
    }

  return 0;
}

static int end_no_more_requests(int j, int n)
{
  return (j < n ||
	  global_rq_fifo[0].count > 0 ||
	  global_rq_fifo[1].count > 0 ||
	  ch_refs > 0);
}

static int end_early_cleanup(int j, int n)
{
  return (global_rq_fifo[0].count < RQ_FIFO_SIZE / 2 ||
	  global_rq_fifo[1].count < RQ_FIFO_SIZE / 2 ||
	  ch_refs < CH_MAP_SIZE / 2,
	  rand() % 100);
}

int main(int argc, char **argv)
{
#ifdef CONFIG_ASSH_USE_GCRYPT
  if (!gcry_check_version(GCRYPT_VERSION))
    return -1;
#endif

  unsigned int count = argc > 1 ? atoi(argv[1]) : 1000;
  unsigned int k;

  for (k = 0; k < count; k++)
    {
      putc('r', stderr);
      if (test(&end_no_more_requests, 1000))
	return 1;

      putc('e', stderr);
      if (test(&end_early_cleanup, 10000))
	return 1;
    }

  fprintf(stderr, "Summary:\n"
	  "  %8lu requests\n"
	  "  %8lu request replies (success)\n"
	  "  %8lu request replies (failed)\n"
	  "  %8lu request received events\n"
	  "  %8lu request reply events (success)\n"
	  "  %8lu request reply events (failed)\n"
	  "  %8lu request postponed\n"
	  "  %8lu channel open requests\n"
	  "  %8lu channel open events\n"
	  "  %8lu channel open reply (success)\n"
	  "  %8lu channel open reply (failed)\n"
	  "  %8lu channel open postponed\n"
	  "  %8lu channel close requests\n"
	  "  %8lu channel close events\n"
	  ,
	  rq_send_count, rq_reply_success, rq_reply_failed,
	  rq_event_count, rq_event_success_count,
	  rq_event_failed_count, rq_postpone_count,
	  ch_open_count, ch_event_open_count,
	  ch_open_reply_success_count,
	  ch_open_reply_failed_count, ch_postpone_count,
	  ch_close_count, ch_event_close_count
	  );


  return 0;
}

