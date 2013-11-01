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

#include <assh/assh_context.h>
#include <assh/assh_transport.h>
#include <assh/assh_packet.h>
#include <assh/assh_queue.h>
#include <assh/assh_session.h>
#include <assh/assh_service.h>
#include <assh/assh_cipher.h>
#include <assh/assh_mac.h>
#include <assh/assh_kex.h>

#include <assert.h>
#include <string.h>
#include <stdlib.h>

void assh_transport_push(struct assh_session_s *s,
			 struct assh_packet_s *p)
{
  struct assh_queue_s *q = 
    (p->head.msg >= 50 && s->tr_st != ASSH_TR_SERVICE)
      ? &s->alt_queue : &s->out_queue;
  assh_queue_push_front(q, &p->entry);
}

assh_error_t assh_event_read(struct assh_session_s *s,
			     void **data, size_t *size)
{
  assh_error_t err;

  switch (s->stream_in_st)
    {
    case ASSH_TR_IN_HELLO:
      *data = s->hello_str + s->hello_len;
      *size = 1;
      s->stream_in_st = ASSH_TR_IN_HELLO_DONE;
      return ASSH_OK;

    case ASSH_TR_IN_HEAD:
      *data = &s->stream_in_pck_head;
      *size = 16;
      return ASSH_OK;

    case ASSH_TR_IN_PAYLOAD: {
      assert(s->in_pck == NULL);

      struct assh_packet_s *p;
      struct assh_kex_keys_s *k = s->cur_keys_in;
      unsigned int align = 8;

      if (k != NULL)
	{
	  ASSH_ERR_RET(k->cipher->f_process(k->cipher_ctx, k->iv, s->stream_in_pck_head,
					    sizeof(s->stream_in_pck_head)));
	  align = ASSH_MAX(k->cipher->block_size, 8);
	}

      size_t len = assh_load_u32(s->stream_in_pck_head);
      uint8_t pad_len = s->stream_in_pck_head[4];

      ASSH_ERR_RET(len > ASSH_MAX_PCK_LEN - 4 || len < 12 ? ASSH_ERR_PACKET_SIZE : 0);

      len += 4;
      ASSH_ERR_RET(len % align || pad_len < 4 ? ASSH_ERR_BAD_DATA : 0);

      size_t mac_len = k != NULL ? k->mac->mac_size : 0;
      len = len + mac_len;

      ASSH_ERR_RET(assh_packet_alloc(s, 0, len - 6, &p));

      s->stream_in_pck = p;
      memcpy(p->data, s->stream_in_pck_head, 16);
      p->data_size = len;
      *data = p->data + 16;
      *size = len - 16;
      s->stream_in_st = ASSH_TR_IN_PAYLOAD_DONE;

      return ASSH_OK;
    }

    default:
      return ASSH_ERR_STATE;
    }
}

ASSH_EVENT_DONE_FCN(assh_event_read_done)
{
  assh_error_t err;

  switch (s->stream_in_st)
    {
    case ASSH_TR_IN_HELLO_DONE: {
      static const char * ident = "SSH-2.0";
      int i = s->hello_len;
      uint8_t c = s->hello_str[i];

      if (i < 0)
	{
	  if (c == '\n')
	    s->hello_len = 0;
	}
      else if (i < 4)
	{
	  s->hello_len = (ident[i] == c) ? i + 1 : -1;
	}
      else
	{
	  s->hello_len++;
	  if (i < 7)
	    {
	      ASSH_ERR_RET(ident[i] != c ? ASSH_ERR_BAD_VERSION : 0);
	    }
	  else
	    {
	      if (c == '\n')
		{
		  s->hello_len--;
		  if (s->hello_str[i - 1] == '\r')
		    s->hello_len--;
		  s->stream_in_st = ASSH_TR_IN_HEAD;
		  return ASSH_OK;
		}
	      else
		{
		  ASSH_ERR_RET(i >= 255 ? ASSH_ERR_PACKET_SIZE : 0);
		}
	    }
	}

      s->stream_in_st = ASSH_TR_IN_HELLO;
      return ASSH_OK;
    }

    case ASSH_TR_IN_HEAD:
      s->stream_in_st = ASSH_TR_IN_PAYLOAD;
      return ASSH_OK;

    case ASSH_TR_IN_PAYLOAD_DONE: {
      struct assh_kex_keys_s *k = s->cur_keys_in;
      struct assh_packet_s *p = s->stream_in_pck;

#warning FIXME decompress

      if (k != NULL)
	{
	  size_t mac_len = k->mac->mac_size;
	  uint8_t mac[mac_len];

	  ASSH_ERR_RET(k->cipher->f_process(k->cipher_ctx, k->iv, p->data + 16,
					    p->data_size - 16 - mac_len));

	  ASSH_ERR_RET(k->mac->f_compute(k->mac_ctx, s->in_seq, p->data,
					 p->data_size - mac_len, mac));

	  ASSH_ERR_RET(memcmp(mac, p->data + p->data_size - mac_len, mac_len)
		       ? ASSH_ERR_MAC : 0);
	}

      assert(s->in_pck == NULL);
      s->in_pck = p;

      s->in_seq++;
      s->stream_in_pck = NULL;
      s->stream_in_st = ASSH_TR_IN_HEAD;
      return ASSH_OK;
    }

    default:
      ASSH_ERR_RET(ASSH_ERR_STATE);
    }
}

assh_error_t assh_event_write(struct assh_session_s *s,
			      const void **data, size_t *size)
{
  assh_error_t err;

  switch (s->stream_out_st)
    {
    case ASSH_TR_OUT_HELLO: {
      *data = ASSH_HELLO;
      *size = sizeof(ASSH_HELLO) - 1;
      s->stream_out_st = ASSH_TR_OUT_HELLO_DONE;
      return ASSH_OK;
    }

    case ASSH_TR_OUT_PACKETS: {

      if (s->out_queue.count == 0)
	return ASSH_NO_DATA;

      struct assh_queue_entry_s *q = assh_queue_back(&s->out_queue);
      struct assh_packet_s *p = (struct assh_packet_s*)q;

#ifdef CONFIG_ASSH_DEBUG_PROTOCOL
      ASSH_DEBUG("outgoing packet: tr_st=%i, size=%zu, msg=%u\n",
		 s->tr_st, p->data_size, p->head.msg);
#endif

      struct assh_kex_keys_s *k = s->cur_keys_out;
      unsigned int align = 8;

      if (k != NULL)
	align = ASSH_MAX(k->cipher->block_size, 8);

      size_t pad_len = align - p->data_size % align;
      if (pad_len < 4)
	pad_len += align;

      assert(pad_len >= 4 && pad_len < 255);

      size_t mac_len = k != NULL ? k->mac->mac_size : 0;

      p->data_size += pad_len + mac_len;
      ASSH_ERR_RET(p->data_size > p->alloc_size ? ASSH_ERR_PACKET_SIZE : 0);

      assh_store_u32(p->data, p->data_size - 4 - mac_len);
      p->head.pad_len = pad_len;
      uint8_t *mac_ptr = p->data + p->data_size - mac_len;
      uint8_t *pad = mac_ptr - pad_len;

      if (pad_len > 0)
	memset(pad, 0x2a, pad_len);

#warning FIXME compress

      if (k != NULL)
	{
	  ASSH_ERR_RET(k->mac->f_compute(k->mac_ctx, s->out_seq, p->data,
					 p->data_size - mac_len, mac_ptr));
	  ASSH_ERR_RET(k->cipher->f_process(k->cipher_ctx, k->iv, p->data,
					    p->data_size - mac_len));
	}

      switch (p->head.msg)
	{
	case SSH_MSG_NEWKEYS:
	  assh_kex_keys_cleanup(s, s->cur_keys_out);
	  s->cur_keys_out = s->new_keys_out;
	  s->new_keys_out = NULL;
	  break;
	case SSH_MSG_DISCONNECT:
	  s->tr_st = ASSH_TR_DISCONNECTED;
	  break;
	}

      s->out_seq++;
      *data = p->data;
      *size = p->data_size;
      s->stream_out_st = ASSH_TR_OUT_PACKETS_DONE;
      return ASSH_OK;
    }

    default:
      ASSH_ERR_RET(ASSH_ERR_STATE);
    }
}

ASSH_EVENT_DONE_FCN(assh_event_write_done)
{
  assh_error_t err;

  switch (s->stream_out_st)
    {
    case ASSH_TR_OUT_HELLO_DONE:
      s->stream_out_st = ASSH_TR_OUT_PACKETS;
      return ASSH_OK;

    case ASSH_TR_OUT_PACKETS_DONE: {
      assert(s->out_queue.count > 0);

      struct assh_queue_entry_s *e = assh_queue_back(&s->out_queue);
      assh_queue_remove(&s->out_queue, e);

      struct assh_packet_s *p = (struct assh_packet_s*)e;
      assh_packet_release(p);

      s->stream_out_st = ASSH_TR_OUT_PACKETS;
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

  ASSH_ERR_RET(assh_packet_alloc(s, SSH_MSG_DISCONNECT, 12, &pout));

  assh_store_u32(pout->head.end, code);
  uint8_t *unused;
  ASSH_ERR_RET(assh_packet_add_string(pout, 0, &unused)); /* description */
  ASSH_ERR_RET(assh_packet_add_string(pout, 0, &unused)); /* language */

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
#endif

  /* process always acceptable packets */
  switch (msg)
    {
    case SSH_MSG_DISCONNECT:
      s->tr_st = ASSH_TR_DISCONNECTED;
    case SSH_MSG_DEBUG:
    case SSH_MSG_IGNORE:
      return ASSH_OK;
    }

  /* transport state machine */
  switch (s->tr_st)
    {
    case ASSH_TR_KEX_INIT:
      abort();

    case ASSH_TR_KEX_WAIT_REPLY:
      ASSH_ERR_RET(assh_algo_kex_send_init(s));
    case ASSH_TR_KEX_WAIT:
      ASSH_ERR_RET(msg != SSH_MSG_KEXINIT ? ASSH_ERR_PROTOCOL : 0);
      s->tr_st = ASSH_TR_KEX_RUNNING;
      ASSH_ERR_RET(assh_kex_got_init(p));
      return ASSH_OK;

    case ASSH_TR_KEX_RUNNING:
      /* only allowed msgs are 1-4, 7-19, 20-29, 30-49 */
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

    case ASSH_TR_ERROR:
      assert(!"possible");
    }

  /* not in KEX state, process other incoming packets */
  switch (msg)
    {
    case SSH_MSG_KEXINIT:
      ASSH_ERR_RET(s->new_keys_out != NULL ? ASSH_ERR_PROTOCOL : 0);
      ASSH_ERR_RET(assh_algo_kex_send_init(s));
      ASSH_ERR_RET(assh_kex_got_init(p));
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
      ASSH_ERR_RET(ASSH_ERR_UNEXPECTED_MSG);

    case SSH_MSG_SERVICE_ACCEPT:
#ifdef CONFIG_ASSH_CLIENT
      if (s->ctx->type == ASSH_CLIENT)
	{
	  ASSH_ERR_RET(assh_service_got_accept(s, p));
	  return ASSH_OK;
	}
#endif
      ASSH_ERR_RET(ASSH_ERR_UNEXPECTED_MSG);

    default:
      ASSH_ERR_RET(s->srv == NULL ? ASSH_ERR_UNEXPECTED_MSG : 0);
      ASSH_ERR_RET(s->srv->f_process(s, p, e));
      return ASSH_OK;
    }
}

