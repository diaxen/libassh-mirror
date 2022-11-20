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

#define ASSH_PV
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

#include <string.h>
#include <stdlib.h>

ASSH_EVENT_SIZE_SASSERT(transport);

void assh_transport_push(struct assh_session_s *s,
			 struct assh_packet_s *p)
{
  struct assh_queue_s *q = &s->out_queue;

  if (s->stream_out_st == ASSH_TR_OUT_CLOSED)
    {
      assh_packet_release(p);
      return;
    }

  /* sending of service packets is postponed during kex */
  assh_bool_t kex_msg = p->head.msg <= SSH_MSG_KEXSPEC_LAST &&
    p->head.msg != SSH_MSG_SERVICE_REQUEST &&
    p->head.msg != SSH_MSG_SERVICE_ACCEPT &&
    p->head.msg != SSH_MSG_IGNORE;

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
      s->queue_out_size += p->data_size;
      assh_queue_push_back(q, &p->entry);
      break;

    case ASSH_TR_INIT:
    case ASSH_TR_CLOSED:
      ASSH_UNREACHABLE();
    }
}

assh_status_t
assh_transport_input_done(struct assh_session_s *s,
			  size_t rd_size)
{
  assh_status_t err;
  struct assh_kex_keys_s *k = s->cur_keys_in;
  const struct assh_algo_mac_s *ma = k->mac_algo;
  const struct assh_algo_cipher_s *ca = k->cipher_algo;
  uint_fast8_t hsize = ca->head_size;

  s->stream_in_size += rd_size;

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
		ASSH_RET_IF_TRUE(strncmp((char*)s->ident_str + 4, "2.0", 3) &&
			     strncmp((char*)s->ident_str + 4, "1.9", 3),
			     ASSH_ERR_BAD_VERSION | ASSH_ERRSV_DISCONNECT);

		/* copy remaining unused bytes to packet header buffer */
		memcpy(s->stream_in_stub.data, s->ident_str + i + 1, s->stream_in_size);

		/* ajust and keep ident string length */
		if (s->ident_str[i - 1] == '\r')
		  i--;
		s->ident_len = i;
#ifdef CONFIG_ASSH_DEBUG_PROTOCOL
		ASSH_DEBUG_HEXDUMP("remote ident", s->ident_str, s->ident_len);
#endif
		ASSH_SET_STATE(s, tr_st, ASSH_TR_KEX_INIT);

		/* we might still have enough bytes to start packet decode */
		goto head_done;
	      }

	    /* discard this line */
	    memmove(s->ident_str, s->ident_str + i + 1, s->stream_in_size);
	    i = 0;
	  }

      ASSH_RET_IF_TRUE(s->stream_in_size >= sizeof(s->ident_str),
		   ASSH_ERR_INPUT_OVERFLOW | ASSH_ERRSV_DISCONNECT);

      ASSH_SET_STATE(s, stream_in_st, ASSH_TR_IN_IDENT);
      return ASSH_NO_DATA;
    }

    /* decipher packet head, compute packet length and allocate packet */
    case ASSH_TR_IN_HEAD_DONE: {
      head_done:

      if (s->stream_in_size < hsize)
	{
	  /* not enough header data yet to decipher the 1st block */
	  ASSH_SET_STATE(s, stream_in_st, ASSH_TR_IN_HEAD);
	  return ASSH_NO_DATA;
	}

      /* decipher head */
      if (!ma->etm)
	ASSH_RET_ON_ERR(ca->f_process(k->cipher_ctx,
		       s->stream_in_stub.data, hsize,
		       ASSH_CIPHER_PCK_HEAD, s->in_seq) | ASSH_ERRSV_DISCONNECT);

      /* check length */
      size_t len = assh_load_u32(s->stream_in_stub.head.pck_len);

      ASSH_RET_IF_TRUE(len < 1 + ASSH_PACKET_MIN_PADDING,
		   ASSH_ERR_INPUT_OVERFLOW | ASSH_ERRSV_DISCONNECT);

      ASSH_RET_IF_TRUE(len > 1 + CONFIG_ASSH_MAX_PAYLOAD + ASSH_PACKET_MAX_PADDING,
		   ASSH_ERR_INPUT_OVERFLOW | ASSH_ERRSV_DISCONNECT);

      /* allocate actual packet and copy header */
      size_t mac_len = ma->mac_size + ca->auth_size;
      size_t buffer_size = /* pck_len field */ 4 + len;

      ASSH_RET_IF_TRUE(buffer_size < ca->block_size,
      		       ASSH_ERR_INPUT_OVERFLOW | ASSH_ERRSV_DISCONNECT);

      buffer_size += mac_len;

      ASSH_RET_IF_TRUE(buffer_size < s->stream_in_size,
		   ASSH_ERR_INPUT_OVERFLOW | ASSH_ERRSV_DISCONNECT);

      struct assh_packet_s *p;
      ASSH_RET_ON_ERR(assh_packet_alloc_raw(s->ctx, buffer_size, &p)
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
	  ASSH_SET_STATE(s, stream_in_st, ASSH_TR_IN_PAYLOAD);
	  return ASSH_NO_DATA;
	}

      uint32_t seq = s->in_seq;
      uint8_t *data = p->data;
      size_t data_size = p->data_size;

      size_t mac_len = ma->mac_size + ca->auth_size;

      if (ca->auth_size)	/* Authenticated cipher */
	{
	  ASSH_RET_IF_TRUE(data_size < 4 + ca->block_size + mac_len,
			   ASSH_ERR_INPUT_OVERFLOW | ASSH_ERRSV_DISCONNECT);

	  ASSH_RET_IF_TRUE((data_size - 4 - mac_len) & (ca->block_size - 1),
			   ASSH_ERR_INPUT_OVERFLOW | ASSH_ERRSV_DISCONNECT);

	  ASSH_RET_ON_ERR(ca->f_process(k->cipher_ctx, data,
				       data_size, ASSH_CIPHER_PCK_TAIL, seq)
		       | ASSH_ERRSV_DISCONNECT);
	}
      else if (ma->etm)	/* Encrypt then Mac */
	{
	  ASSH_RET_IF_TRUE(data_size < 4 + ca->block_size + mac_len,
			   ASSH_ERR_INPUT_OVERFLOW | ASSH_ERRSV_DISCONNECT);

	  ASSH_RET_IF_TRUE((data_size - 4 - mac_len) & (ca->block_size - 1),
			   ASSH_ERR_INPUT_OVERFLOW | ASSH_ERRSV_DISCONNECT);

	  ASSH_RET_ON_ERR(ma->f_process(k->mac_ctx, data,
					    data_size - mac_len,
					    data + data_size - mac_len, seq)
		       | ASSH_ERRSV_DISCONNECT);

	  ASSH_RET_ON_ERR(ca->f_process(k->cipher_ctx, data + 4,
				  data_size - mac_len - 4, ASSH_CIPHER_PCK_TAIL, seq)
		       | ASSH_ERRSV_DISCONNECT);
	}
      else if (data_size > hsize + mac_len)	/* Mac and Encrypt */
	{
	  ASSH_RET_IF_TRUE((data_size - mac_len) & (ca->block_size - 1),
			   ASSH_ERR_INPUT_OVERFLOW | ASSH_ERRSV_DISCONNECT);

	  ASSH_RET_ON_ERR(ca->f_process(k->cipher_ctx, data + hsize,
				  data_size - hsize - mac_len, ASSH_CIPHER_PCK_TAIL, seq)
		       | ASSH_ERRSV_DISCONNECT);

	  ASSH_RET_ON_ERR(ma->f_process(k->mac_ctx, data,
					    data_size - mac_len,
					    data + data_size - mac_len, seq)
		       | ASSH_ERRSV_DISCONNECT);
	}

      /* check and adjust packet data size */
      size_t len = assh_load_u32(p->head.pck_len);
      uint8_t pad_len = p->head.pad_len;

      ASSH_RET_IF_TRUE(pad_len < 4,
		   ASSH_ERR_INPUT_OVERFLOW | ASSH_ERRSV_DISCONNECT);

      ASSH_RET_IF_TRUE(len < /* pad_len field */ 1 + /* msg field */ 1 + pad_len,
		   ASSH_ERR_INPUT_OVERFLOW | ASSH_ERRSV_DISCONNECT);

      ASSH_RET_IF_TRUE(len - pad_len - 1 > CONFIG_ASSH_MAX_PAYLOAD,
		   ASSH_ERR_INPUT_OVERFLOW | ASSH_ERRSV_DISCONNECT);

      p->data_size = data_size - mac_len - pad_len;

      /* push completed incoming packet for dispatch */
      p->seq = seq;
      assert(s->in_pck == NULL);

      /* decompress payload */
      struct assh_packet_s *p_ = p;
      ASSH_RET_ON_ERR(k->cmp_algo->f_process(s->ctx, k->cmp_ctx, &p, s->tr_user_auth_done)
		   | ASSH_ERRSV_DISCONNECT);

      if (p_ != p)
	assh_packet_release(p_);

#ifdef CONFIG_ASSH_DEBUG_PROTOCOL
      ASSH_DEBUG("incoming packet: session=%p tr_st=%i, size=%zu, msg=%u\n",
		 s, s->tr_st, data_size, p->head.msg);
      ASSH_DEBUG_HEXDUMP("in packet", data, data_size);
#endif

#ifdef CONFIG_ASSH_CLIENT
      s->tr_user_auth_done |= s->ctx->type == ASSH_CLIENT &&
	p->head.msg == SSH_MSG_USERAUTH_SUCCESS;
#endif

      s->kex_bytes += data_size;
      s->in_pck = p;
      /* reinit input state */

      s->in_seq++;
      s->stream_in_pck = NULL;
      ASSH_SET_STATE(s, stream_in_st, ASSH_TR_IN_HEAD);
      s->stream_in_size = 0;
      return ASSH_OK;
    }

    default:
      ASSH_UNREACHABLE();
    }
}

assh_status_t
assh_transport_input_buffer(struct assh_session_s *s,
			    uint8_t **data, size_t *size)
{
  struct assh_kex_keys_s *k = s->cur_keys_in;

  if (s->tr_st >= ASSH_TR_DISCONNECT)
    ASSH_SET_STATE(s, stream_in_st, ASSH_TR_IN_CLOSED);

  switch (s->stream_in_st)
    {
    /* read stream into ident buffer */
    case ASSH_TR_IN_IDENT:
      *data = s->ident_str + s->stream_in_size;
      ASSH_SET_STATE(s, stream_in_st, ASSH_TR_IN_IDENT_DONE);
      /* any indent residue must fit in stream_in_stub and
	 must not span more than one binary packet. */
      *size = assh_min_uint(ASSH_MIN_BLOCK_SIZE,
			    sizeof(s->ident_str) - s->stream_in_size);
      return ASSH_OK;

    /* read stream into packet head buffer */
    case ASSH_TR_IN_HEAD: {
      *data = s->stream_in_stub.data + s->stream_in_size;
      ASSH_SET_STATE(s, stream_in_st, ASSH_TR_IN_HEAD_DONE);
      *size = k->cipher_algo->head_size - s->stream_in_size;
      return ASSH_OK;
    }

    /* read stream into actual packet buffer */
    case ASSH_TR_IN_PAYLOAD: {
      if (s->in_pck != NULL)
	return ASSH_NO_DATA;

      struct assh_packet_s *p = s->stream_in_pck;
      *data = p->data + s->stream_in_size;
      *size = p->data_size - s->stream_in_size;
      ASSH_SET_STATE(s, stream_in_st, ASSH_TR_IN_PAYLOAD_DONE);
      return ASSH_OK;
    }

    default:
      return ASSH_NO_DATA;
    }
}

void
assh_transport_output_done(struct assh_session_s *s,
			   size_t wr_size, assh_bool_t yield)
{
  size_t ss = s->stream_out_size += wr_size;

  switch (s->stream_out_st)
    {
    /* check if sending of ident string has completed */
    case ASSH_TR_OUT_IDENT_DONE:
      if (ss >= sizeof(ASSH_IDENT) - 1)
	ASSH_SET_STATE(s, stream_out_st, ASSH_TR_OUT_PACKETS);
      else if (yield)
	ASSH_SET_STATE(s, stream_out_st, ASSH_TR_OUT_IDENT_PAUSE);

      return;

    /* check if sending of packet has completed */
    case ASSH_TR_OUT_PACKETS_DONE: {
      assert(!assh_queue_isempty(&s->out_queue));

      struct assh_queue_entry_s *e = assh_queue_front(&s->out_queue);
      struct assh_packet_s *p = (void*)e;

      if (ss < p->data_size)
	{
	  /* packet partially sent, need to report one more write
	     event later. Yield to the input state machine for now. */
	  if (yield)
	    ASSH_SET_STATE(s, stream_out_st, ASSH_TR_OUT_PACKETS_PAUSE);
	  return;
	}

      p->seq = s->out_seq++;
      p->sent = 1;

      if (p->last)
	ASSH_SET_STATE(s, stream_out_st, ASSH_TR_OUT_CLOSED);
      else
	ASSH_SET_STATE(s, stream_out_st, ASSH_TR_OUT_PACKETS);

      /* pop and release packet */
      assh_queue_remove(e);
      s->queue_out_size -= p->data_size;
      assh_packet_release(p);

      return;
    }

    default:
      ASSH_UNREACHABLE();
    }
}

assh_status_t
assh_transport_output_buffer(struct assh_session_s *s,
			     uint8_t const ** const data,
			     size_t *size)
{
  assh_status_t err;

  switch (s->stream_out_st)
    {
    /* the last ident buffer write was incomplete, yield to input */
    case ASSH_TR_OUT_IDENT_PAUSE:
      if (s->stream_in_st != ASSH_TR_IN_CLOSED &&
	  s->tr_st < ASSH_TR_DISCONNECT)
	ASSH_SET_STATE(s, stream_out_st, ASSH_TR_OUT_IDENT);

      return ASSH_NO_DATA;

    /* the write stream buffer is the constant ident string */
    case ASSH_TR_OUT_IDENT: {
      if (s->stream_in_st == ASSH_TR_IN_CLOSED ||
	  s->tr_st >= ASSH_TR_DISCONNECT)
	return ASSH_NO_DATA;

      *data = (uint8_t*)ASSH_IDENT + s->stream_out_size;
      *size = sizeof(ASSH_IDENT) - 1 - s->stream_out_size;
      ASSH_SET_STATE(s, stream_out_st, ASSH_TR_OUT_IDENT_DONE);

      return ASSH_OK;
    }

    /* the next output packet must be enciphered before write */
    case ASSH_TR_OUT_PACKETS: {

      struct assh_queue_s *q = &s->out_queue;
      struct assh_packet_s *p;
      uint8_t msg;

      while (1)
	{
	  /* nothing to output, yield to input */
	  if (assh_queue_isempty(q))
	    return ASSH_NO_DATA;

	  p = (void*)assh_queue_front(q);
	  msg = p->head.msg;
	  p->last = (msg == SSH_MSG_DISCONNECT);

	  /* discard any packets other than SSH_MSG_DISCONNECT */
	  if (s->tr_st < ASSH_TR_DISCONNECT || p->last)
	    break;

	  assh_queue_remove(&p->entry);
	  s->queue_out_size -= p->data_size;
	  assh_packet_release(p);
	}

      struct assh_kex_keys_s *k = s->cur_keys_out;
      const struct assh_algo_mac_s *ma = k->mac_algo;
      const struct assh_algo_cipher_s *ca = k->cipher_algo;

#ifdef CONFIG_ASSH_DEBUG_PROTOCOL
      ASSH_DEBUG("outgoing packet: session=%p tr_st=%i, size=%zu, msg=%u\n",
		 s, s->tr_st, p->data_size, p->head.msg);
      ASSH_DEBUG_HEXDUMP("out packet", p->data, p->data_size);
#endif

      struct assh_packet_s *p_ = p;
      size_t os = s->queue_out_size - p->data_size;

      /* compress payload */
      err = k->cmp_algo->f_process(s->ctx, k->cmp_ctx, &p, s->tr_user_auth_done);

      switch (err)
	{
	case ASSH_OK:
	  if (p_ != p)
	    {
	      assh_queue_remove(&p_->entry);
	      assh_packet_release(p_);
	      assh_queue_push_front(q, &p->entry);
	    }
	case ASSH_NO_DATA:
	  break;

	default:
	  s->queue_out_size = os + p->data_size;
	  ASSH_RETURN(err | ASSH_ERRSV_DISCONNECT);
	}

      /* compute various length and payload pointer values */
      uint_fast8_t align = assh_max_uint(ca->block_size, 8);
      size_t mac_len = ma->mac_size + ca->auth_size;

      size_t cipher_len = p->data_size;
      if (ma->etm || ca->auth_size)
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
	  pad_len = assh_min_uint(255, p->alloc_size - p->data_size - mac_len);
	  pad_len -= (pad_len + cipher_len) % align;
	  break;
	default:
	  ASSH_UNREACHABLE();
	}

      assert(pad_len >= 4 && pad_len <= 255);

      p->data_size += pad_len + mac_len;
      assert(p->data_size <= p->alloc_size);

      s->queue_out_size = os + p->data_size;

      assh_store_u32(p->head.pck_len, p->data_size - 4 - mac_len);
      p->head.pad_len = pad_len;
      uint8_t *mac_ptr = p->data + p->data_size - mac_len;
      uint8_t *pad = mac_ptr - pad_len;

      if (pad_len > 0)
	ASSH_RET_ON_ERR(assh_prng_get(s->ctx, pad, pad_len, ASSH_PRNG_QUALITY_PADDING)
		     | ASSH_ERRSV_DISCONNECT);

      uint32_t seq = s->out_seq;

      if (ca->auth_size)	/* Authenticated cipher */
	{
	  assert(ca->auth_size != 0);
	  ASSH_RET_ON_ERR(ca->f_process(k->cipher_ctx, p->data,
			    p->data_size, ASSH_CIPHER_PCK_TAIL, seq)
		       | ASSH_ERRSV_DISCONNECT);
	}
      else if (ma->etm)	/* Encrypt then Mac */
	{
	  ASSH_RET_ON_ERR(ca->f_process(k->cipher_ctx, p->data + 4,
			    p->data_size - mac_len - 4, ASSH_CIPHER_PCK_TAIL, seq)
		       | ASSH_ERRSV_DISCONNECT);

	  ASSH_RET_ON_ERR(ma->f_process(k->mac_ctx, p->data,
			 p->data_size - mac_len, mac_ptr, seq)
		       | ASSH_ERRSV_DISCONNECT);
	}
      else			/* Mac and Encrypt */
	{
	  ASSH_RET_ON_ERR(ma->f_process(k->mac_ctx, p->data,
			 p->data_size - mac_len, mac_ptr, seq)
			  | ASSH_ERRSV_DISCONNECT);

	  ASSH_RET_ON_ERR(ca->f_process(k->cipher_ctx, p->data,
			    p->data_size - mac_len, ASSH_CIPHER_PCK_TAIL, seq)
		       | ASSH_ERRSV_DISCONNECT);
	}

      ASSH_SET_STATE(s, stream_out_st, ASSH_TR_OUT_PACKETS_DONE);
      s->tr_user_auth_done |= msg == SSH_MSG_USERAUTH_SUCCESS;

      if (msg == SSH_MSG_NEWKEYS)
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
      return ASSH_OK;
    }

    /* the last packet buffer write was incomplete, yield to input */
    case ASSH_TR_OUT_PACKETS_PAUSE:
      if (s->stream_in_st != ASSH_TR_IN_CLOSED &&
	  s->tr_st < ASSH_TR_DISCONNECT)
	{
	  ASSH_SET_STATE(s, stream_out_st, ASSH_TR_OUT_PACKETS_ENCIPHERED);
	  return ASSH_NO_DATA;
	}

    /* the write stream buffer is an already enciphered output packet */
    case ASSH_TR_OUT_PACKETS_ENCIPHERED: {

      assert(!assh_queue_isempty(&s->out_queue));
      struct assh_packet_s *p = (void*)assh_queue_front(&s->out_queue);

      *data = p->data + s->stream_out_size;
      *size = p->data_size - s->stream_out_size;
      ASSH_SET_STATE(s, stream_out_st, ASSH_TR_OUT_PACKETS_DONE);
      return ASSH_OK;
    }

    default:
      return ASSH_NO_DATA;
    }
}

assh_bool_t
assh_transport_has_output(struct assh_session_s *s)
{
  switch (s->stream_out_st)
    {
    case ASSH_TR_OUT_IDENT:
    case ASSH_TR_OUT_IDENT_PAUSE:
      return 1;

    case ASSH_TR_OUT_PACKETS:
      return !assh_queue_isempty(&s->out_queue);

    case ASSH_TR_OUT_PACKETS_PAUSE:
    case ASSH_TR_OUT_PACKETS_ENCIPHERED:
      return 1;

    default:
      return 0;
    }
}

static ASSH_EVENT_DONE_FCN(assh_transport_pkt_event_done)
{
  assh_packet_release(s->in_pck);
  s->in_pck = NULL;
  return ASSH_OK;
}

static assh_status_t
assh_transport_got_disconnect(struct assh_session_s *s,
			      struct assh_event_s *e,
			      struct assh_packet_s *p)
{
  assh_status_t err;
  struct assh_event_transport_disconnect_s *ev
    = &e->transport.disconnect;

  const uint8_t *reason = p->head.end;
  const uint8_t *desc, *lang;

  ASSH_RET_ON_ERR(assh_packet_check_array(p, reason, 4, &desc));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, desc, &lang));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, lang, NULL));

  ev->reason = assh_load_u32(reason);
  ev->desc.data = desc + 4;
  ev->desc.len = assh_load_u32(desc);
  ev->lang.data = lang + 4;
  ev->lang.len = assh_load_u32(lang);

  e->id = ASSH_EVENT_DISCONNECT;
  e->f_done = &assh_transport_pkt_event_done;

  return ASSH_OK;
}

static assh_status_t
assh_transport_got_debug(struct assh_session_s *s,
			 struct assh_event_s *e,
			 struct assh_packet_s *p)
{
  assh_status_t err;
  struct assh_event_transport_debug_s *ev
    = &e->transport.debug;

  const uint8_t *display = p->head.end;
  const uint8_t *msg, *lang;

  ASSH_RET_ON_ERR(assh_packet_check_array(p, display, 1, &msg));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, msg, &lang));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, lang, NULL));

  ev->display = *display;
  ev->msg.data = msg + 4;
  ev->msg.len = assh_load_u32(msg);
  ev->lang.data = lang + 4;
  ev->lang.len = assh_load_u32(lang);

  e->id = ASSH_EVENT_DEBUG;
  e->f_done = &assh_transport_pkt_event_done;

  return ASSH_OK;
}

assh_status_t
assh_transport_debug(struct assh_session_s *s,
		     assh_bool_t display, const char *msg,
		     const char *lang)
{
  assh_status_t err;
  struct assh_packet_s *pout;

  size_t msg_len = strlen(msg);
  size_t lang_len = strlen(lang);

  ASSH_RET_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_DEBUG,
      1 + 4 + msg_len + 4 + lang_len, &pout) | ASSH_ERRSV_CONTINUE);

  uint8_t *tmp;
  ASSH_ASSERT(assh_packet_add_array(pout, 1, &tmp));
  *tmp = display;
  ASSH_ASSERT(assh_packet_add_string(pout, msg_len, &tmp));
  memcpy(tmp, msg, msg_len);
  ASSH_ASSERT(assh_packet_add_string(pout, lang_len, &tmp));
  memcpy(tmp, lang, lang_len);

  assh_transport_push(s, pout);

  return ASSH_OK;
}

assh_status_t assh_transport_unimp(struct assh_session_s *s,
				  struct assh_packet_s *pin)
{
  assh_status_t err;
  struct assh_packet_s *p;

  if (pin->head.msg != SSH_MSG_UNIMPLEMENTED)
    {
      ASSH_RET_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_UNIMPLEMENTED, 4, &p));
      ASSH_ASSERT(assh_packet_add_u32(p, pin->seq));
      assh_transport_push(s, p);
    }

  return ASSH_OK;
}

assh_status_t assh_transport_dispatch(struct assh_session_s *s,
				     struct assh_event_s *e)
{
  assh_status_t err = ASSH_OK;
  enum assh_ssh_msg_e msg = SSH_MSG_INVALID;
  struct assh_packet_s *p = s->in_pck;

  /* test if a key re-exchange should have occured at this point */
  ASSH_JMP_IF_TRUE(s->kex_bytes > ASSH_REKEX_THRESHOLD + CONFIG_ASSH_MAX_PAYLOAD * 16,
		   ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT, done);

  /* check protocol timeout */
  ASSH_JMP_IF_TRUE(s->tr_st > ASSH_TR_INIT &&
		   s->tr_st < ASSH_TR_DISCONNECT &&
		   s->tr_deadline <= s->time,
		   ASSH_ERR_TIMEOUT | ASSH_ERRSV_DISCONNECT, done);

  if (p != NULL)
    {
      msg = p->head.msg;

      /* handle transport layer generic messages */
      switch (msg)
	{
	case SSH_MSG_INVALID:
	  ASSH_JMP_ON_ERR(ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT, done);

	case SSH_MSG_DISCONNECT:
	  ASSH_SET_STATE(s, stream_in_st, ASSH_TR_IN_CLOSED);
	  ASSH_SET_STATE(s, stream_out_st, ASSH_TR_OUT_CLOSED);
	  ASSH_SET_STATE(s, tr_st, ASSH_TR_DISCONNECT);
	  ASSH_JMP_ON_ERR(assh_transport_got_disconnect(s, e, p)
			  | ASSH_ERRSV_DISCONNECT, done);
	  return ASSH_OK;

	case SSH_MSG_DEBUG:
	  ASSH_JMP_ON_ERR(assh_transport_got_debug(s, e, p)
			  | ASSH_ERRSV_DISCONNECT, done);
	  return ASSH_OK;

	case SSH_MSG_IGNORE:
	  goto done;

	case SSH_MSG_UNIMPLEMENTED: {
	  uint8_t *seqp = p->head.end;
	  ASSH_JMP_ON_ERR(assh_packet_check_array(p, seqp, 4, NULL)
			  | ASSH_ERRSV_DISCONNECT, done);
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
	  ASSH_JMP_ON_ERR(assh_transport_unimp(s, p)
			  | ASSH_ERRSV_DISCONNECT, done);
	  goto done;
	}
    }

  /* transport protocol state machine */
  switch (s->tr_st)
    {
    case ASSH_TR_INIT:
      /* set next transport timeout */
      s->tr_deadline = s->time + s->ctx->timeout_transport + 1;
      ASSH_SET_STATE(s, tr_st, ASSH_TR_IDENT);

    case ASSH_TR_IDENT:
      return ASSH_OK;

    /* send first kex init packet during session init */
    case ASSH_TR_KEX_INIT:
      ASSH_JMP_ON_ERR(assh_kex_send_init(s) | ASSH_ERRSV_DISCONNECT, done);
      ASSH_SET_STATE(s, tr_st, ASSH_TR_KEX_WAIT);

    /* wait for initial kex init packet during session init */
    case ASSH_TR_KEX_WAIT:
      if (msg == SSH_MSG_INVALID)
	break;
      ASSH_JMP_IF_TRUE(msg != SSH_MSG_KEXINIT,
		       ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT, done);
    kex_init:

#if defined(CONFIG_ASSH_SERVER) && defined (CONFIG_ASSH_NO_REKEX_BEFORE_AUTH)
      /* server does not allow multiple key exchanges before user
	 authentication. */
      ASSH_JMP_IF_TRUE(
# ifdef CONFIG_ASSH_CLIENT
		   s->ctx->type == ASSH_SERVER &&
# endif
		   s->kex_done && !s->user_auth_done,
		   ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT, done);
#endif

      /* set next transport timeout */
      s->tr_deadline = s->time + s->ctx->timeout_kex + 1;
      ASSH_JMP_ON_ERR(assh_kex_got_init(s, p) | ASSH_ERRSV_DISCONNECT, done);

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
	  ASSH_JMP_ON_ERR(ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT, done);

	default:
	  ASSH_JMP_IF_TRUE(msg >= SSH_MSG_SERVICE_FIRST,
			   ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT, done);
	  if (msg >= SSH_MSG_KEXSPEC_FIRST)
	    {
	    case SSH_MSG_INVALID:
	    case SSH_MSG_UNIMPLEMENTED:
	      ASSH_JMP_ON_ERR(s->kex_algo->f_process(s, p, e)
			      | ASSH_ERRSV_DISCONNECT, done);
	      break;
	    }
	  ASSH_JMP_ON_ERR(assh_transport_unimp(s, p)
			  | ASSH_ERRSV_DISCONNECT, done);
	}
      break;

    /* the first kex init packet must be ignored */
    case ASSH_TR_KEX_SKIP:
      if (msg != SSH_MSG_INVALID)
	{
	  ASSH_JMP_IF_TRUE(msg < SSH_MSG_KEXSPEC_FIRST ||
			   msg > SSH_MSG_KEXSPEC_LAST,
			   ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT, done);
	  ASSH_SET_STATE(s, tr_st, ASSH_TR_KEX_RUNNING);
	}
      break;

      /* kex exchange is over, NEWKEYS packet expected */
    case ASSH_TR_NEWKEY:
      if (msg == SSH_MSG_INVALID)
	break;
      ASSH_JMP_IF_TRUE(msg != SSH_MSG_NEWKEYS,
		       ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT, done);

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
      s->rekex_deadline = s->time + s->ctx->timeout_rekex + 1;

      /* set next transport timeout */
      if (s->srv_st == ASSH_SRV_RUNNING)
	s->tr_deadline = s->rekex_deadline + s->ctx->timeout_kex;
      else
	/* service start timeout */
	s->tr_deadline = s->time + s->ctx->timeout_transport + 1;

      ASSH_SET_STATE(s, tr_st, ASSH_TR_SERVICE);
      s->kex_bytes = 0;
      assh_kex_done(s, e);
      break;

    /* key re-exchange initiated, run service */
    case ASSH_TR_SERVICE_KEX:
      if (msg == SSH_MSG_KEXINIT)
	goto kex_init;

    /* handle service related packet, run service */
    case ASSH_TR_SERVICE:
      if (msg == SSH_MSG_KEXINIT)
	{
	  /* received a rekeying request, reply and switch to ASSH_TR_KEX_RUNNING */
	  ASSH_JMP_IF_TRUE(s->new_keys_out != NULL,
			   ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT, done);
	  ASSH_JMP_ON_ERR(assh_kex_send_init(s)
			  | ASSH_ERRSV_DISCONNECT, done);
	  goto kex_init;
	}

      if ((s->time > s->rekex_deadline ||
	   s->kex_bytes > s->kex_max_bytes) &&
	  s->tr_st == ASSH_TR_SERVICE)
        {
          /* initiate key re-exchange as needed */
          ASSH_JMP_ON_ERR(assh_kex_send_init(s)
			  | ASSH_ERRSV_DISCONNECT, done);
          ASSH_SET_STATE(s, tr_st, ASSH_TR_SERVICE_KEX);
        }

      /* dispatch packet to service */
      ASSH_JMP_IF_TRUE(msg >= SSH_MSG_ALGONEG_FIRST &&
		       msg <= SSH_MSG_KEXSPEC_LAST,
		       ASSH_ERR_PROTOCOL | ASSH_ERRSV_DISCONNECT, done);

    case ASSH_TR_DISCONNECT:

      /* run the service loop */
      err = assh_service_loop(s, p, e);

      if (ASSH_STATUS(err) == ASSH_NO_DATA)
	return ASSH_OK;	/* do not consume the input packet */

      break;

    case ASSH_TR_CLOSED:
      ASSH_UNREACHABLE();
    }

 done:
  assh_packet_release(s->in_pck);
  s->in_pck = NULL;
  ASSH_RETURN(err);
}

assh_status_t
assh_transport_overhead(struct assh_session_s *s,
			size_t *payload_size, size_t *packet_size)
{
  assh_status_t err;

  struct assh_kex_keys_s *k = s->cur_keys_out;
  const struct assh_algo_mac_s *ma = k->mac_algo;
  const struct assh_algo_cipher_s *ca = k->cipher_algo;

  uint_fast8_t align = assh_max_uint(ca->block_size, 8);
  int_fast32_t mac_len = ma->mac_size + ca->auth_size;

  if (*packet_size)
    {
      int_fast32_t head_len = ASSH_PACKET_HEADLEN;
      int_fast32_t cipher_len = *packet_size - mac_len;

      if (ma->etm || ca->auth_size)
	{
	  /* length field not enciphered with the payload */
	  cipher_len -= 4;
	  head_len -= 4;
	}

      ASSH_RET_IF_TRUE(cipher_len < (int_fast32_t)ca->block_size,
		       ASSH_ERR_OUTPUT_OVERFLOW);

      cipher_len -= cipher_len % align + /* minimal padding */ 4;

      ASSH_RET_IF_TRUE(cipher_len <= head_len,
		       ASSH_ERR_OUTPUT_OVERFLOW);

      *payload_size = cipher_len - head_len;

      return ASSH_OK;
    }
  else if (*payload_size)
    {
      uint_fast32_t head_len = 0;
      uint_fast32_t cipher_len = ASSH_PACKET_HEADLEN + *payload_size;

      if (ma->etm || ca->auth_size)
	{
	  /* length field not enciphered with the payload */
	  cipher_len -= 4;
	  head_len = 4;
	}

      size_t pad_len = align - cipher_len % align;
      if (pad_len < 4)
	pad_len += align;
      cipher_len += pad_len;

      *packet_size = head_len + cipher_len + mac_len;

      return ASSH_OK;
    }

  ASSH_RETURN(ASSH_ERR_BAD_ARG);
}

size_t
assh_transport_output_size(struct assh_session_s *s)
{
  return s->queue_out_size;
}
