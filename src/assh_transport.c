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

#include <assh/assh_transport.h>

#include <assh/assh_context.h>
#include <assh/assh_session.h>
#include <assh/assh_event.h>
#include <assh/assh_packet.h>
#include <assh/assh_queue.h>
#include <assh/assh_service.h>
#include <assh/assh_cipher.h>
#include <assh/assh_mac.h>
#include <assh/assh_kex.h>

#include <assert.h>
#include <string.h>
#include <stdlib.h>

ASSH_EVENT_SIZE_SASSERT(transport);

void assh_transport_push(struct assh_session_s *s,
			 struct assh_packet_s *p)
{
  struct assh_queue_s *q = &s->out_queue;

  switch (s->tr_st)
    {
    case ASSH_TR_KEX_INIT:
    case ASSH_TR_KEX_WAIT:
    case ASSH_TR_KEX_WAIT_REPLY:
    case ASSH_TR_KEX_RUNNING:
    case ASSH_TR_NEWKEY:
      /* service packets are postponed during kex */
      if (p->head.msg >= 50)
	q = &s->alt_queue;

    case ASSH_TR_SERVICE:
    case ASSH_TR_ENDING:
      assh_queue_push_front(q, &p->entry);
      break;

    case ASSH_TR_FLUSHING:
    case ASSH_TR_DISCONNECTED:
      assh_packet_release(p);
      break;
    }
}

static ASSH_EVENT_DONE_FCN(assh_event_read_done)
{
  assh_error_t err;
  struct assh_kex_keys_s *k = s->cur_keys_in;
  unsigned int bsize = k == NULL ? 16 : ASSH_MAX(k->cipher->block_size, 16);

  size_t rd_size = e->transport.read.transferred;
  assert(rd_size <= e->transport.read.buf.size);
  s->stream_in_size += rd_size;

  switch (s->stream_in_st)
    {
    /* process hello text lines */
    case ASSH_TR_IN_HELLO_DONE: {
      unsigned int i;

      /* look for End of Line */
      for (i = s->stream_in_size - rd_size; i < s->stream_in_size; i++)
	if (s->hello_str[i] == '\n')
	  {
	    s->stream_in_size -= i + 1;

	    /* test line prefix */
	    if (i >= 7 && !strncmp((char*)s->hello_str, "SSH-", 4))
	      {
		ASSH_ERR_RET(strncmp((char*)s->hello_str + 4, "2.0", 3) ? ASSH_ERR_BAD_VERSION : 0);

		/* copy remaining unused bytes to packet header buffer */
		memmove(s->stream_in_pck_head, s->hello_str + i + 1, s->stream_in_size);

		/* ajust and keep hello string length */
		if (s->hello_str[i - 1] == '\r')
		  i--;
		s->hello_len = i;

		s->stream_in_st = ASSH_TR_IN_HEAD;
		return ASSH_OK;
	      }

	    /* discard this line */
	    memmove(s->hello_str, s->hello_str + i + 1, s->stream_in_size);
	    i = 0;
	  }

      ASSH_ERR_RET(s->stream_in_size >= sizeof(s->hello_str) ? ASSH_ERR_PACKET_SIZE : 0);

      s->stream_in_st = ASSH_TR_IN_HELLO;
      return ASSH_OK;
    }

    /* decipher packet head, compute packet length and allocate packet */
    case ASSH_TR_IN_HEAD_DONE: {

      if (s->stream_in_size < bsize)
	{
	  /* not enough header data yet to decipher the 1st block */
	  s->stream_in_st = ASSH_TR_IN_HEAD;
	  return ASSH_OK;
	}

      /* decipher */
      if (k != NULL)
	ASSH_ERR_RET(k->cipher->f_process(k->cipher_ctx, k->iv,
					  s->stream_in_pck_head, bsize));

      /* compute various length values */
      size_t len = assh_load_u32(s->stream_in_pck_head);
      uint8_t pad_len = s->stream_in_pck_head[4];
      unsigned int align = k == NULL ? 8 : ASSH_MAX(k->cipher->block_size, 8);

      ASSH_ERR_RET(len > ASSH_MAX_PCK_LEN - 4 || len < 12 ? ASSH_ERR_PACKET_SIZE : 0);

      len += 4;
      ASSH_ERR_RET(len % align || pad_len < 4 ? ASSH_ERR_BAD_DATA : 0);

      if (k != NULL)
	len += k->mac->mac_size;

      /* allocate actual packet and copy header */
      struct assh_packet_s *p;
      ASSH_ERR_RET(assh_packet_alloc2(s->ctx, 0, len - 6, &p));
      memcpy(p->data, s->stream_in_pck_head, s->stream_in_size);
      p->data_size = len;
      s->stream_in_pck = p;

      if (len > s->stream_in_size)
	{
	  s->stream_in_st = ASSH_TR_IN_PAYLOAD;
	  return ASSH_OK;
	}
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

      if (k != NULL)
	{
	  size_t mac_len = k->mac->mac_size;
	  uint8_t mac[mac_len];

	  /* decipher */
	  ASSH_ERR_RET(k->cipher->f_process(
              k->cipher_ctx, k->iv, p->data + bsize,
	      p->data_size - bsize - mac_len));

	  /* compute and compare MAC */
	  ASSH_ERR_RET(k->mac->f_compute(k->mac_ctx, s->in_seq, p->data,
					 p->data_size - mac_len, mac));

	  ASSH_ERR_RET(assh_memcmp(mac, p->data + p->data_size - mac_len, mac_len)
		       ? ASSH_ERR_CODE(ASSH_ERR_MAC, SSH_DISCONNECT_MAC_ERROR) : 0);

#warning FIXME decompress
	}

      /* push completed incoming packet for dispatch */
      assert(s->in_pck == NULL);
      s->in_pck = p;

      /* reinit input state */
      s->in_seq++;
      s->stream_in_pck = NULL;
      s->stream_in_st = ASSH_TR_IN_HEAD;
      s->stream_in_size = 0;
      return ASSH_OK;
    }

    default:
      ASSH_ERR_RET(ASSH_ERR_STATE);
    }
}

assh_error_t assh_event_read(struct assh_session_s *s,
			     struct assh_event_s *e)
{
  assh_error_t err;
  struct assh_kex_keys_s *k = s->cur_keys_in;
  void **data = (void**)&e->transport.read.buf.data;
  size_t *size = (size_t*)&e->transport.read.buf.size;

  e->id = ASSH_EVENT_READ;
  e->f_done = &assh_event_read_done;
  e->transport.read.transferred = 0;

  switch (s->stream_in_st)
    {
    /* read stream into hello buffer */
    case ASSH_TR_IN_HELLO:
      *data = s->hello_str + s->stream_in_size;
      *size = ASSH_MIN(16, sizeof(s->hello_str) - s->stream_in_size);
      s->stream_in_st = ASSH_TR_IN_HELLO_DONE;
      return ASSH_OK;


    /* read stream into packet head buffer */
    case ASSH_TR_IN_HEAD: {
      unsigned int bsize = k == NULL ? 16 : ASSH_MAX(k->cipher->block_size, 16);
      *data = s->stream_in_pck_head + s->stream_in_size;
      *size = bsize - s->stream_in_size;
      s->stream_in_st = ASSH_TR_IN_HEAD_DONE;
      return ASSH_OK;
    }

    /* read stream into actual packet buffer */
    case ASSH_TR_IN_PAYLOAD: {
      struct assh_packet_s *p = s->stream_in_pck;
      *data = p->data + s->stream_in_size;
      *size = p->data_size - s->stream_in_size;
      s->stream_in_st = ASSH_TR_IN_PAYLOAD_DONE;
      assert(s->in_pck == NULL);
      return ASSH_OK;
    }

    default:
      return ASSH_ERR_STATE;
    }
}

static ASSH_EVENT_DONE_FCN(assh_event_write_done)
{
  assh_error_t err;

  size_t wr_size = e->transport.write.transferred;
  assert(wr_size <= e->transport.write.buf.size);
  s->stream_out_size += wr_size;

  switch (s->stream_out_st)
    {
    /* check if sending of hello string has completed */
    case ASSH_TR_OUT_HELLO_DONE:
      s->stream_out_st = s->stream_out_size >= sizeof(ASSH_HELLO) - 1
	? ASSH_TR_OUT_PACKETS : ASSH_TR_OUT_HELLO;
      return ASSH_OK;

    /* check if sending of packet has completed */
    case ASSH_TR_OUT_PACKETS_DONE: {
      assert(s->out_queue.count > 0);

      struct assh_queue_entry_s *e = assh_queue_back(&s->out_queue);
      struct assh_packet_s *p = (void*)e;

      if (s->stream_out_size < p->data_size)
	{
	  /* packet partially sent, need to return one more write event */
	  s->stream_out_st = ASSH_TR_OUT_PACKETS_ENCIPHERED;
	  return ASSH_OK;
	}

      /* pop and release packet */
      assh_queue_remove(&s->out_queue, e);
      assh_packet_release(p);

      s->stream_out_st = ASSH_TR_OUT_PACKETS;
      return ASSH_OK;
    }

    default:
      ASSH_ERR_RET(ASSH_ERR_STATE);
    }
}

assh_error_t assh_event_write(struct assh_session_s *s,
			      struct assh_event_s *e)
{
  assh_error_t err;
  const void **data = (const void **)&e->transport.write.buf.data;
  size_t *size = (size_t*)&e->transport.write.buf.size;

  e->id = ASSH_EVENT_WRITE;
  e->f_done = &assh_event_write_done;
  e->transport.write.transferred = 0;

  switch (s->stream_out_st)
    {
    /* write stream buffer is constant hello string */
    case ASSH_TR_OUT_HELLO: {
      *data = ASSH_HELLO + s->stream_out_size;
      *size = sizeof(ASSH_HELLO) - 1 - s->stream_out_size;
      s->stream_out_st = ASSH_TR_OUT_HELLO_DONE;
      return ASSH_OK;
    }

    /* write stream buffer is not yet enciphered packet */
    case ASSH_TR_OUT_PACKETS: {
      if (s->out_queue.count == 0)
	return ASSH_NO_DATA;

      struct assh_packet_s *p = (void*)assh_queue_back(&s->out_queue);

#ifdef CONFIG_ASSH_DEBUG_PROTOCOL
      ASSH_DEBUG("outgoing packet: tr_st=%i, size=%zu, msg=%u\n",
		 s->tr_st, p->data_size, p->head.msg);
      assh_hexdump("out packet", p->data, p->data_size);
#endif

      /* compute various length and payload pointer values */
      struct assh_kex_keys_s *k = s->cur_keys_out;
      unsigned int align = 8;
      size_t mac_len = 0;

      if (k != NULL)
	{
	  align = ASSH_MAX(k->cipher->block_size, 8);
	  mac_len = k->mac->mac_size;
	}

      size_t pad_len = align - p->data_size % align;
      if (pad_len < 4)
	pad_len += align;

      assert(pad_len >= 4 && pad_len < 255);

      p->data_size += pad_len + mac_len;
      ASSH_ERR_RET(p->data_size > p->alloc_size ? ASSH_ERR_PACKET_SIZE : 0);

      assh_store_u32(p->data, p->data_size - 4 - mac_len);
      p->head.pad_len = pad_len;
      uint8_t *mac_ptr = p->data + p->data_size - mac_len;
      uint8_t *pad = mac_ptr - pad_len;

      if (pad_len > 0)
	memset(pad, 42, pad_len);

      switch (p->head.msg)
	{
	case SSH_MSG_NEWKEYS:
	  /* use new output key from now */
	  assh_kex_keys_cleanup(s, s->cur_keys_out);
	  s->cur_keys_out = s->new_keys_out;
	  s->new_keys_out = NULL;
	  break;
	}

#warning FIXME compress

      /* compute MAC and encipher packet */
      if (k != NULL)
	{
	  ASSH_ERR_RET(k->mac->f_compute(k->mac_ctx, s->out_seq, p->data,
					 p->data_size - mac_len, mac_ptr));
	  ASSH_ERR_RET(k->cipher->f_process(k->cipher_ctx, k->iv, p->data,
					    p->data_size - mac_len));
	}

      s->out_seq++;

      /* reinit output state */
      s->stream_out_size = 0;
      *data = p->data;
      *size = p->data_size;
      s->stream_out_st = ASSH_TR_OUT_PACKETS_DONE;
      return ASSH_OK;
    }

    /* write stream buffer is already enciphered packet */
    case ASSH_TR_OUT_PACKETS_ENCIPHERED: {

      assert(s->out_queue.count != 0);
      struct assh_packet_s *p = (void*)assh_queue_back(&s->out_queue);

      *data = p->data + s->stream_out_size;
      *size = p->data_size - s->stream_out_size;
      s->stream_out_st = ASSH_TR_OUT_PACKETS_DONE;
      return ASSH_OK;
    }

    default:
      ASSH_ERR_RET(ASSH_ERR_STATE);
    }
}

assh_error_t assh_transport_disconnect(struct assh_session_s *s, uint32_t code)
{
  assh_error_t err;
  struct assh_packet_s *pout;

  ASSH_ERR_RET(assh_packet_alloc(s->ctx, SSH_MSG_DISCONNECT, 12, &pout));

  uint8_t *reason;
  ASSH_ASSERT(assh_packet_add_bytes(pout, 4, &reason)); /* reason code */
  assh_store_u32(reason, code);

  uint8_t *unused;
  ASSH_ASSERT(assh_packet_add_string(pout, 0, &unused)); /* description */
  ASSH_ASSERT(assh_packet_add_string(pout, 0, &unused)); /* language */

  assh_transport_push(s, pout);

  return ASSH_OK;
}

assh_error_t assh_transport_dispatch(struct assh_session_s *s,
				     struct assh_packet_s *p,
				     struct assh_event_s *e)
{
  assh_error_t err;
  uint8_t msg = p->head.msg;

#ifdef CONFIG_ASSH_DEBUG_PROTOCOL
  ASSH_DEBUG("incoming packet: tr_st=%i, size=%zu, msg=%u\n",
	     s->tr_st, p->data_size, msg);
  assh_hexdump("in packet", p->data, p->data_size);
#endif

  /* process always acceptable packets */
  switch (msg)
    {
    case SSH_MSG_DISCONNECT:
      s->tr_st = ASSH_TR_FLUSHING;
    case SSH_MSG_DEBUG:
    case SSH_MSG_IGNORE:
      return ASSH_OK;
    }

  /* transport state machine */
  switch (s->tr_st)
    {
#warning test rekeying
    case ASSH_TR_KEX_WAIT_REPLY:
      ASSH_ERR_RET(assh_algo_kex_send_init(s));
    case ASSH_TR_KEX_WAIT:
      ASSH_ERR_RET(msg != SSH_MSG_KEXINIT ? ASSH_ERR_PROTOCOL : 0);
      s->tr_st = ASSH_TR_KEX_RUNNING;
      ASSH_ERR_RET(assh_kex_got_init(s, p));
      return ASSH_OK;

    case ASSH_TR_KEX_RUNNING:
      /* allowed msgs are 1-4, 7-19, 20-29, 30-49 */
      ASSH_ERR_RET(msg > 49 || msg == SSH_MSG_SERVICE_REQUEST ||
		   msg == SSH_MSG_SERVICE_ACCEPT ? ASSH_ERR_PROTOCOL : 0);
      ASSH_ERR_RET(s->kex->f_process(s, p, e));
      return ASSH_OK;

    case ASSH_TR_NEWKEY:
      ASSH_ERR_RET(msg != SSH_MSG_NEWKEYS ? ASSH_ERR_PROTOCOL : 0);
      assert(s->new_keys_in != NULL);
      assh_kex_keys_cleanup(s, s->cur_keys_in);
      s->cur_keys_in = s->new_keys_in;
      s->new_keys_in = NULL;
      s->tr_st = ASSH_TR_SERVICE;
      assh_queue_concat(&s->out_queue, &s->alt_queue);
      return ASSH_OK;

    case ASSH_TR_SERVICE:
      break;

    case ASSH_TR_KEX_INIT:
    case ASSH_TR_FLUSHING:
    case ASSH_TR_ENDING:
    case ASSH_TR_DISCONNECTED:
      assert(!"possible");
    }

  /* not in KEX state, process other incoming packets */
  switch (msg)
    {
    case SSH_MSG_KEXINIT:
      ASSH_ERR_RET(s->new_keys_out != NULL ? ASSH_ERR_PROTOCOL : 0);
      ASSH_ERR_RET(assh_algo_kex_send_init(s));
      ASSH_ERR_RET(assh_kex_got_init(s, p));
#warning do not allow KEX when st > ASSH_TR_SERVICE
      s->tr_st = ASSH_TR_KEX_RUNNING;
      return ASSH_OK;

    case SSH_MSG_SERVICE_REQUEST:
#ifdef CONFIG_ASSH_SERVER
      if (s->ctx->type == ASSH_SERVER)
	{
	  ASSH_ERR_RET(assh_service_got_request(s, p));
	  return ASSH_OK;
	}
#endif
      ASSH_ERR_RET(ASSH_ERR_PROTOCOL);

    case SSH_MSG_SERVICE_ACCEPT:
#ifdef CONFIG_ASSH_CLIENT
      if (s->ctx->type == ASSH_CLIENT)
	{
	  ASSH_ERR_RET(assh_service_got_accept(s, p));
	  return ASSH_OK;
	}
#endif
      ASSH_ERR_RET(ASSH_ERR_PROTOCOL);

    default:
      ASSH_ERR_RET(s->srv == NULL ? ASSH_ERR_PROTOCOL : 0);
      ASSH_ERR_RET(s->srv->f_process(s, p, e));
      return ASSH_OK;
    }
}

