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

#define ASSH_EV_CONST /* write access to event const fields */

#include <assh/assh_transport.h>

#include <assh/assh_context.h>
#include <assh/assh_session.h>
#include <assh/assh_packet.h>
#include <assh/assh_queue.h>
#include <assh/assh_service.h>
#include <assh/assh_cipher.h>
#include <assh/assh_mac.h>
#include <assh/assh_kex.h>
#include <assh/assh_event.h>
#include <assh/assh_prng.h>
#include <assh/assh_compress.h>

#include <assert.h>
#include <string.h>
#include <stdlib.h>

ASSH_EVENT_SIZE_SASSERT(transport);

void assh_transport_push(struct assh_session_s *s,
			 struct assh_packet_s *p)
{
  struct assh_queue_s *q = &s->out_queue;

  /* sending of service packets is postponed during kex */
  assh_bool_t kex_msg = p->head.msg <= SSH_MSG_KEXSPEC_LAST &&
    p->head.msg != SSH_MSG_SERVICE_REQUEST &&
    p->head.msg != SSH_MSG_SERVICE_ACCEPT;

  switch (s->tr_st)
    {
    case ASSH_TR_IDENT:
    case ASSH_TR_KEX_INIT:
    case ASSH_TR_KEX_WAIT:
    case ASSH_TR_KEX_SKIP:
    case ASSH_TR_KEX_RUNNING:
    case ASSH_TR_NEWKEY:
    case ASSH_TR_SERVICE_KEX:
      if (!kex_msg)
	q = &s->alt_queue;

    case ASSH_TR_SERVICE:
    case ASSH_TR_DISCONNECT:
      assh_queue_push_back(q, &p->entry);
      break;

    case ASSH_TR_FIN:
    case ASSH_TR_CLOSED:
      assh_packet_release(p);
      break;
    }
}

static ASSH_EVENT_DONE_FCN(assh_event_read_done)
{
  assh_error_t err;
  struct assh_kex_keys_s *k = s->cur_keys_in;
  uint_fast8_t hsize = k->cipher->head_size;

  size_t rd_size = e->transport.read.transferred;
  assert(rd_size <= e->transport.read.buf.size);
  s->stream_in_size += rd_size;
  s->time = e->transport.read.time;

  switch (s->stream_in_st)
    {
    /* process ident text lines */
    case ASSH_TR_IN_IDENT_DONE: {
      uint_fast16_t i;

      /* look for End of Line */
      for (i = s->stream_in_size - rd_size; i < s->stream_in_size; i++)
	if (s->ident_str[i] == '\n')
	  {
	    s->stream_in_size -= i + 1;

	    /* test line prefix */
	    if (i >= 7 && !strncmp((char*)s->ident_str, "SSH-", 4))
	      {
		ASSH_CHK_RET(strncmp((char*)s->ident_str + 4, "2.0", 3) &&
			     strncmp((char*)s->ident_str + 4, "1.9", 3),
			     ASSH_ERR_BAD_VERSION | ASSH_ERRSV_FIN);

		/* copy remaining unused bytes to packet header buffer */
		memcpy(s->stream_in_stub.data, s->ident_str + i + 1, s->stream_in_size);

		/* ajust and keep ident string length */
		if (s->ident_str[i - 1] == '\r')
		  i--;
		s->ident_len = i;

		assh_transport_state(s, ASSH_TR_KEX_INIT);

		/* we might still have enough bytes to start packet decode */
		if (s->stream_in_size >= hsize)
		  goto head_done;

		s->stream_in_st = ASSH_TR_IN_HEAD;
		return ASSH_OK;
	      }

	    /* discard this line */
	    memmove(s->ident_str, s->ident_str + i + 1, s->stream_in_size);
	    i = 0;
	  }

      ASSH_CHK_RET(s->stream_in_size >= sizeof(s->ident_str),
		   ASSH_ERR_INPUT_OVERFLOW | ASSH_ERRSV_FIN);

      s->stream_in_st = ASSH_TR_IN_IDENT;
      return ASSH_OK;
    }

    /* decipher packet head, compute packet length and allocate packet */
    case ASSH_TR_IN_HEAD_DONE: {

      if (s->stream_in_size < hsize)
	{
	  /* not enough header data yet to decipher the 1st block */
	  s->stream_in_st = ASSH_TR_IN_HEAD;
	  return ASSH_OK;
	}
      head_done:

      /* decipher head */
      if (!k->mac->etm)
	ASSH_ERR_RET(k->cipher->f_process(k->cipher_ctx,
		       s->stream_in_stub.data, hsize,
		       ASSH_CIPHER_PCK_HEAD, s->in_seq) | ASSH_ERRSV_DISCONNECT);

      /* check length */
      size_t len = assh_load_u32(s->stream_in_stub.head.pck_len);

      ASSH_CHK_RET(len - ASSH_PACKET_MIN_PADDING - 1 > ASSH_PACKET_MAX_PAYLOAD,
		   ASSH_ERR_INPUT_OVERFLOW | ASSH_ERRSV_DISCONNECT);

      /* allocate actual packet and copy header */
      size_t mac_len = k->mac->mac_size + k->cipher->auth_size;
      size_t buffer_size = /* pck_len field */ 4 + len + mac_len;

      struct assh_packet_s *p;
      ASSH_ERR_RET(assh_packet_alloc_raw(s->ctx, buffer_size, &p)
		   | ASSH_ERRSV_DISCONNECT);

      memcpy(p->data, s->stream_in_stub.data, s->stream_in_size);
      p->data_size = buffer_size;
      s->stream_in_pck = p;
    }

    /* decipher remaining packet data, check MAC and accept packet */
    case ASSH_TR_IN_PAYLOAD_DONE: {
      struct assh_packet_s *p = s->stream_in_pck;

      if (s->stream_in_size < p->data_size)
	{
	  /* not enough data for the whole packet yet */
	  s->stream_in_st = ASSH_TR_IN_PAYLOAD;
	  return ASSH_OK;
	}

      uint32_t seq = s->in_seq;
      uint8_t *data = p->data;
      size_t data_size = p->data_size;
      size_t mac_len = k->mac->mac_size + k->cipher->auth_size;

      if (k->cipher->auth_size)	/* Authenticated cipher */
	{
	  ASSH_ERR_RET(k->cipher->f_process(k->cipher_ctx, data,
				       data_size, ASSH_CIPHER_PCK_TAIL, seq)
		       | ASSH_ERRSV_DISCONNECT);
	}
      else if (k->mac->etm)	/* Encrypt then Mac */
	{
	  ASSH_ERR_RET(k->mac->f_check(k->mac_ctx, seq, data,
				       data_size - mac_len,
				       data + data_size - mac_len)
		       | ASSH_ERRSV_DISCONNECT);

	  ASSH_ERR_RET(k->cipher->f_process(k->cipher_ctx, data + 4,
				  data_size - mac_len - 4, ASSH_CIPHER_PCK_TAIL, seq)
		       | ASSH_ERRSV_DISCONNECT);
	}
      else			/* Mac and Encrypt */
	{
	  ASSH_ERR_RET(k->cipher->f_process(k->cipher_ctx, data + hsize,
				  data_size - hsize - mac_len, ASSH_CIPHER_PCK_TAIL, seq)
		       | ASSH_ERRSV_DISCONNECT);

	  ASSH_ERR_RET(k->mac->f_check(k->mac_ctx, seq, data,
				       data_size - mac_len,
				       data + data_size - mac_len)
		       | ASSH_ERRSV_DISCONNECT);
	}

      /* check and adjust packet data size */
      size_t len = assh_load_u32(p->head.pck_len);
      uint8_t pad_len = p->head.pad_len;

      ASSH_CHK_RET(pad_len < 4,
		   ASSH_ERR_INPUT_OVERFLOW | ASSH_ERRSV_DISCONNECT);

      ASSH_CHK_RET(len < /* pad_len field */ 1 + /* msg field */ 1 + pad_len,
		   ASSH_ERR_INPUT_OVERFLOW | ASSH_ERRSV_DISCONNECT);

      ASSH_CHK_RET(len - pad_len - 1 > ASSH_PACKET_MAX_PAYLOAD,
		   ASSH_ERR_INPUT_OVERFLOW | ASSH_ERRSV_DISCONNECT);

      p->data_size = data_size - mac_len - pad_len;

      /* push completed incoming packet for dispatch */
      p->seq = seq;
      assert(s->in_pck == NULL);

      /* decompress payload */
      struct assh_packet_s *p_ = p;
      ASSH_ERR_RET(k->cmp->f_process(s->ctx, k->cmp_ctx, &p, s->auth_done)
		   | ASSH_ERRSV_FIN);

      if (p_ != p)
	assh_packet_release(p_);

#ifdef CONFIG_ASSH_DEBUG_PROTOCOL
      ASSH_DEBUG("incoming packet: session=%p tr_st=%i, size=%zu, msg=%u\n",
		 s, s->tr_st, data_size, p->head.msg);
      assh_hexdump("in packet", data, data_size);
#endif

#ifdef CONFIG_ASSH_CLIENT
      s->auth_done |= s->ctx->type == ASSH_CLIENT &&
	p->head.msg == SSH_MSG_USERAUTH_SUCCESS;
#endif

      s->kex_bytes += data_size;
      s->in_pck = p;
      /* reinit input state */

      s->in_seq++;
      s->stream_in_pck = NULL;
      s->stream_in_st = ASSH_TR_IN_HEAD;
      s->stream_in_size = 0;
      return ASSH_OK;
    }

    default:
      ASSH_ERR_RET(ASSH_ERR_STATE | ASSH_ERRSV_FATAL);
    }

  return ASSH_OK;
}

assh_error_t assh_transport_read(struct assh_session_s *s,
				 struct assh_event_s *e)
{
  assh_error_t err;
  struct assh_kex_keys_s *k = s->cur_keys_in;
  uint8_t **data = &e->transport.read.buf.data;
  size_t *size = &e->transport.read.buf.size;
  e->transport.read.time = 0;
  e->transport.read.delay = s->time < s->deadline ?
    ASSH_MIN(3600, s->deadline - s->time) : 1;

  switch (s->stream_in_st)
    {
    /* read stream into ident buffer */
    case ASSH_TR_IN_IDENT:
      *data = s->ident_str + s->stream_in_size;
      s->stream_in_st = ASSH_TR_IN_IDENT_DONE;
      *size = ASSH_MIN(8, sizeof(s->ident_str) - s->stream_in_size);
      break;

    /* read stream into packet head buffer */
    case ASSH_TR_IN_HEAD: {
      *data = s->stream_in_stub.data + s->stream_in_size;
      s->stream_in_st = ASSH_TR_IN_HEAD_DONE;
      *size = k->cipher->head_size - s->stream_in_size;
      break;
    }

    /* read stream into actual packet buffer */
    case ASSH_TR_IN_PAYLOAD: {
      struct assh_packet_s *p = s->stream_in_pck;
      *data = p->data + s->stream_in_size;
      *size = p->data_size - s->stream_in_size;
      s->stream_in_st = ASSH_TR_IN_PAYLOAD_DONE;
      assert(s->in_pck == NULL);
      break;
    }

    default:
      ASSH_ERR_RET(ASSH_ERR_STATE | ASSH_ERRSV_FATAL);
    }

  e->id = ASSH_EVENT_READ;
  e->f_done = &assh_event_read_done;
  e->transport.read.transferred = 0;
  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_event_write_done)
{
  assh_error_t err;

  size_t wr_size = e->transport.write.transferred;
  assert(wr_size <= e->transport.write.buf.size);
  s->stream_out_size += wr_size;
  s->time = e->transport.write.time;

  switch (s->stream_out_st)
    {
    /* check if sending of ident string has completed */
    case ASSH_TR_OUT_IDENT_DONE:
      if (s->deadline == 0)
	s->deadline = s->time + ASSH_TIMEOUT_IDENT;
      s->stream_out_st = s->stream_out_size >= sizeof(ASSH_IDENT) - 1
	? ASSH_TR_OUT_PACKETS : ASSH_TR_OUT_IDENT_PAUSE;
      return ASSH_OK;

    /* check if sending of packet has completed */
    case ASSH_TR_OUT_PACKETS_DONE: {
      assert(!assh_queue_isempty(&s->out_queue));

      struct assh_queue_entry_s *e = assh_queue_front(&s->out_queue);
      struct assh_packet_s *p = (void*)e;

      if (s->stream_out_size < p->data_size)
	{
	  /* packet partially sent, need to report one more write
	     event later. Yield to the input state machine for now. */
	  s->stream_out_st = ASSH_TR_OUT_PACKETS_PAUSE;
	  return ASSH_OK;
	}

      p->seq = s->out_seq++;
      p->sent = 1;

      /* pop and release packet */
      assh_queue_remove(e);
      assh_packet_release(p);

      s->stream_out_st = ASSH_TR_OUT_PACKETS;
      return ASSH_OK;
    }

    default:
      ASSH_ERR_RET(ASSH_ERR_STATE | ASSH_ERRSV_FATAL);
    }

  return ASSH_OK;
}

assh_error_t assh_transport_write(struct assh_session_s *s,
				  struct assh_event_s *e)
{
  assh_error_t err;
  uint8_t **data = &e->transport.write.buf.data;
  size_t *size = &e->transport.write.buf.size;
  e->transport.write.time = 0;
  e->transport.write.delay = s->time < s->deadline ?
    ASSH_MIN(3600, s->deadline - s->time) : 1;

  switch (s->stream_out_st)
    {
    /* the write stream buffer is the constant ident string */
    case ASSH_TR_OUT_IDENT: {
      *data = (uint8_t*)ASSH_IDENT + s->stream_out_size;
      *size = sizeof(ASSH_IDENT) - 1 - s->stream_out_size;
      s->stream_out_st = ASSH_TR_OUT_IDENT_DONE;
      if (s->deadline == 0)
	e->transport.write.delay = ASSH_TIMEOUT_IDENT;
      break;
    }

    /* the last ident buffer write was incomplete, yield to input */
    case ASSH_TR_OUT_IDENT_PAUSE:
      s->stream_out_st = ASSH_TR_OUT_IDENT;
      return ASSH_OK;

    /* the next output packet must be enciphered before write */
    case ASSH_TR_OUT_PACKETS: {

      /* nothing to output, yield to input */
      if (assh_queue_isempty(&s->out_queue))
	return ASSH_OK;

      struct assh_queue_s *q = &s->out_queue;
      struct assh_packet_s *p = (void*)assh_queue_front(q);

      struct assh_kex_keys_s *k = s->cur_keys_out;

      assh_bool_t newkey = p->head.msg == SSH_MSG_NEWKEYS;
      assh_bool_t auth = p->head.msg == SSH_MSG_USERAUTH_SUCCESS;

#ifdef CONFIG_ASSH_DEBUG_PROTOCOL
      ASSH_DEBUG("outgoing packet: session=%p tr_st=%i, size=%zu, msg=%u\n",
		 s, s->tr_st, p->data_size, p->head.msg);
      assh_hexdump("out packet", p->data, p->data_size);
#endif

      struct assh_packet_s *p_ = p;
      /* compress payload */
      ASSH_ERR_RET(k->cmp->f_process(s->ctx, k->cmp_ctx, &p, s->auth_done)
		   | ASSH_ERRSV_FIN);

      if (p_ != p)
	{
	  assh_queue_remove(&p_->entry);
	  assh_packet_release(p_);
	  assh_queue_push_front(q, &p->entry);
	}

      /* compute various length and payload pointer values */
      uint_fast8_t align = ASSH_MAX(k->cipher->block_size, 8);
      size_t mac_len = k->mac->mac_size + k->cipher->auth_size;

      size_t cipher_len = p->data_size;
      if (k->mac->etm || k->cipher->auth_size)
	cipher_len -= 4;

      size_t pad_len;
      switch (p->padding)
	{
	case ASSH_PADDING_MIN:
	  /* use minimal padding */
	  pad_len = align - cipher_len % align;
	  if (pad_len < 4)
	    pad_len += align;
	  break;
	case ASSH_PADDING_MAX:
	  pad_len = ASSH_MIN(255, p->alloc_size - p->data_size - mac_len);
	  pad_len -= (pad_len + cipher_len) % align;
	  break;
	default:
	  ASSH_UNREACHABLE();
	}

      assert(pad_len >= 4 && pad_len <= 255);

      p->data_size += pad_len + mac_len;
      assert(p->data_size <= p->alloc_size);

      assh_store_u32(p->head.pck_len, p->data_size - 4 - mac_len);
      p->head.pad_len = pad_len;
      uint8_t *mac_ptr = p->data + p->data_size - mac_len;
      uint8_t *pad = mac_ptr - pad_len;

      if (pad_len > 0)
	ASSH_ERR_RET(assh_prng_get(s->ctx, pad, pad_len, ASSH_PRNG_QUALITY_PADDING)
		     | ASSH_ERRSV_FIN);

      uint32_t seq = s->out_seq;

      if (k->cipher->auth_size)	/* Authenticated cipher */
	{
	  assert(k->cipher->auth_size != 0);
	  ASSH_ERR_RET(k->cipher->f_process(k->cipher_ctx, p->data,
			    p->data_size, ASSH_CIPHER_PCK_TAIL, seq)
		       | ASSH_ERRSV_FIN);
	}
      else if (k->mac->etm)	/* Encrypt then Mac */
	{
	  ASSH_ERR_RET(k->cipher->f_process(k->cipher_ctx, p->data + 4,
			    p->data_size - mac_len - 4, ASSH_CIPHER_PCK_TAIL, seq)
		       | ASSH_ERRSV_FIN);

	  ASSH_ERR_RET(k->mac->f_compute(k->mac_ctx, seq, p->data,
			 p->data_size - mac_len, mac_ptr)
		       | ASSH_ERRSV_FIN);
	}
      else			/* Mac and Encrypt */
	{
	  ASSH_ERR_RET(k->mac->f_compute(k->mac_ctx, seq, p->data,
			 p->data_size - mac_len, mac_ptr) | ASSH_ERRSV_FIN);

	  ASSH_ERR_RET(k->cipher->f_process(k->cipher_ctx, p->data,
			    p->data_size - mac_len, ASSH_CIPHER_PCK_TAIL, seq)
		       | ASSH_ERRSV_FIN);
	}

      s->stream_out_st = ASSH_TR_OUT_PACKETS_DONE;
      s->auth_done |= auth;

      if (newkey)
	{
	  /* release the old output cipher/mac context and install the new one */
	  assert(s->new_keys_out != NULL);
	  assh_kex_keys_cleanup(s, s->cur_keys_out);
	  s->cur_keys_out = s->new_keys_out;
	  s->new_keys_out = NULL;
	}

      s->kex_bytes += p->data_size;

      /* reinit output state */
      s->stream_out_size = 0;
      *data = p->data;
      *size = p->data_size;
      break;
    }

    /* the write stream buffer is an already enciphered output packet */
    case ASSH_TR_OUT_PACKETS_ENCIPHERED: {

      assert(!assh_queue_isempty(&s->out_queue));
      struct assh_packet_s *p = (void*)assh_queue_front(&s->out_queue);

      *data = p->data + s->stream_out_size;
      *size = p->data_size - s->stream_out_size;
      s->stream_out_st = ASSH_TR_OUT_PACKETS_DONE;
      break;
    }

    /* the last packet buffer write was incomplete, yield to input */
    case ASSH_TR_OUT_PACKETS_PAUSE:
      s->stream_out_st = ASSH_TR_OUT_PACKETS_ENCIPHERED;
      return ASSH_OK;

    default:
      ASSH_ERR_RET(ASSH_ERR_STATE | ASSH_ERRSV_FATAL);
    }

  /* a buffer is available for output, return a write event */
  e->id = ASSH_EVENT_WRITE;
  e->f_done = &assh_event_write_done;
  e->transport.write.transferred = 0;
  return ASSH_OK;
}

assh_error_t assh_transport_unimp(struct assh_session_s *s,
				  struct assh_packet_s *pin)
{
  assh_error_t err;
  struct assh_packet_s *p;

  if (pin->head.msg != SSH_MSG_UNIMPLEMENTED)
    {
      ASSH_ERR_RET(assh_packet_alloc(s->ctx, SSH_MSG_UNIMPLEMENTED, 4, &p));
      ASSH_ASSERT(assh_packet_add_u32(p, pin->seq));
      assh_transport_push(s, p);
    }

  return ASSH_OK;
}

assh_error_t assh_transport_dispatch(struct assh_session_s *s,
				     struct assh_event_s *e)
{
  assh_error_t err = ASSH_OK;
  enum assh_ssh_msg_e msg = SSH_MSG_INVALID;
  struct assh_packet_s *p = s->tr_st < ASSH_TR_DISCONNECT ? s->in_pck : NULL;

  if (p != NULL)
    {
      msg = p->head.msg;

      /* handle transport layer generic messages */
      switch (msg)
	{
	case SSH_MSG_INVALID:
	  ASSH_ERR_RET(ASSH_ERR_PROTOCOL | ASSH_ERRSV_FIN);

	case SSH_MSG_DISCONNECT:
	  ASSH_ERR_RET(ASSH_ERR_DISCONNECTED | ASSH_ERRSV_FIN);

	case SSH_MSG_DEBUG:
	case SSH_MSG_IGNORE:
	  goto done;

	case SSH_MSG_UNIMPLEMENTED: {
	  uint8_t *seqp = p->head.end;
	  ASSH_ERR_RET(assh_packet_check_array(p, seqp, 4, NULL)
		       | ASSH_ERRSV_DISCONNECT);
	  p->seq = assh_load_u32(seqp);

#ifdef CONFIG_ASSH_DEBUG_PROTOCOL
	  ASSH_DEBUG("SSH_MSG_UNIMPLEMENTED: seq=%u\n", p->seq);
#endif
	  break;
	}

	default:
	  if (msg > SSH_MSG_TRGENERIC_LAST)
	    {
	    case SSH_MSG_SERVICE_REQUEST:
	    case SSH_MSG_SERVICE_ACCEPT:
	      break;
	    }
	  ASSH_ERR_RET(assh_transport_unimp(s, p));
	  goto done;
	}
    }

  /* transport protocol state machine */
  switch (s->tr_st)
    {
    case ASSH_TR_IDENT:
      return ASSH_OK;

    /* send first kex init packet during session init */
    case ASSH_TR_KEX_INIT:
      ASSH_ERR_RET(assh_kex_send_init(s) | ASSH_ERRSV_DISCONNECT);
      assh_transport_state(s, ASSH_TR_KEX_WAIT);

    /* wait for initial kex init packet during session init */
    case ASSH_TR_KEX_WAIT:
      if (msg == SSH_MSG_INVALID)
	break;
      ASSH_CHK_RET(msg != SSH_MSG_KEXINIT, ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);
    kex_init:
      s->deadline = s->time + ASSH_TIMEOUT_KEX;
      ASSH_ERR_RET(assh_kex_got_init(s, p) | ASSH_ERRSV_DISCONNECT);

      p = NULL;
      msg = SSH_MSG_INVALID;

    /* key exchange algorithm is running (session init or rekeying) */
    case ASSH_TR_KEX_RUNNING:
      switch (msg)
	{
	case SSH_MSG_KEXINIT:
	case SSH_MSG_NEWKEYS:
	case SSH_MSG_SERVICE_REQUEST:
	case SSH_MSG_SERVICE_ACCEPT:
	  ASSH_ERR_RET(ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);

	default:
	  ASSH_CHK_RET(msg >= SSH_MSG_SERVICE_FIRST,
		       ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);
	  if (msg >= SSH_MSG_KEXSPEC_FIRST)
	    {
	    case SSH_MSG_INVALID:
	    case SSH_MSG_UNIMPLEMENTED:
	      ASSH_ERR_RET(s->kex->f_process(s, p, e) | ASSH_ERRSV_DISCONNECT);
	      break;
	    }
	  ASSH_ERR_RET(assh_transport_unimp(s, p));
	}
      break;

    /* the first kex init packet must be ignored */
    case ASSH_TR_KEX_SKIP:
      if (msg != SSH_MSG_INVALID)
	{
	  ASSH_CHK_RET(msg < SSH_MSG_KEXSPEC_FIRST ||
		       msg > SSH_MSG_KEXSPEC_LAST,
		       ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);
	  assh_transport_state(s, ASSH_TR_KEX_RUNNING);
	}
      break;

      /* kex exchange is over, NEWKEYS packet expected */
    case ASSH_TR_NEWKEY:
      if (msg == SSH_MSG_INVALID)
	break;
      ASSH_CHK_RET(msg != SSH_MSG_NEWKEYS, ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);

      /* release the old input cipher/mac context and install the new one */
      assert(s->new_keys_in != NULL);
      assh_kex_keys_cleanup(s, s->cur_keys_in);
      s->cur_keys_in = s->new_keys_in;
      s->new_keys_in = NULL;

      /* move postponed service packets to output queue */
      assh_queue_concat(&s->out_queue, &s->alt_queue);

      /* switch to service running state */
      p = NULL;
      msg = SSH_MSG_INVALID;

      assh_transport_state(s, ASSH_TR_SERVICE);
      e->id = ASSH_EVENT_KEX_DONE;
      e->f_done = NULL;
      e->kex.done.safety = ASSH_MIN(s->cur_keys_in->safety,
        s->new_keys_out != NULL ? s->new_keys_out->safety
			        : s->cur_keys_out->safety);
      break;

    /* key re-exchange initiated, run service */
    case ASSH_TR_SERVICE_KEX:
      if (msg == SSH_MSG_KEXINIT)
	goto kex_init;

    /* handle service related packet, run service */
    case ASSH_TR_SERVICE:
      switch (msg)
	{
        /* received a rekeying request, reply and switch to ASSH_TR_KEX_RUNNING */
	case SSH_MSG_KEXINIT:
	  ASSH_CHK_RET(s->new_keys_out != NULL, ASSH_ERR_PROTOCOL | ASSH_ERRSV_FIN);
	  ASSH_ERR_RET(assh_kex_send_init(s) | ASSH_ERRSV_DISCONNECT);
	  goto kex_init;

	/* handle a service request packet */
	case SSH_MSG_SERVICE_REQUEST:
#ifdef CONFIG_ASSH_SERVER
	  if (s->ctx->type == ASSH_SERVER)
	    ASSH_ERR_RET(assh_service_got_request(s, p) | ASSH_ERRSV_DISCONNECT);
	  else
#endif
	    ASSH_ERR_RET(ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);
	  p = NULL;
	  break;

	/* handle a service accept packet */
        case SSH_MSG_SERVICE_ACCEPT:
#ifdef CONFIG_ASSH_CLIENT
	  if (s->ctx->type == ASSH_CLIENT)
	    ASSH_ERR_RET(assh_service_got_accept(s, p) | ASSH_ERRSV_DISCONNECT);
	  else
#endif
	    ASSH_ERR_RET(ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);
	  p = NULL;
	  break;

	/* dispatch packet to service */
        default:
	  ASSH_CHK_RET(msg >= SSH_MSG_ALGONEG_FIRST &&
		       msg <= SSH_MSG_KEXSPEC_LAST,
		       ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT);
	case SSH_MSG_INVALID:
	  break;
	}

    case ASSH_TR_FIN:

      /* run the service loop */
      err = assh_service_loop(s, p, e);

      if (err == ASSH_NO_DATA)
	return ASSH_OK;	/* do not consume the input packet */

    case ASSH_TR_DISCONNECT:
      break;

    case ASSH_TR_CLOSED:
      ASSH_ERR_RET(ASSH_ERR_STATE | ASSH_ERRSV_FATAL);
    }

 done:
  assh_packet_release(s->in_pck);
  s->in_pck = NULL;
  ASSH_ERR_RET(err | ASSH_ERRSV_DISCONNECT);
  return ASSH_OK;
}

