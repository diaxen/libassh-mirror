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
#include <assh/assh_packet.h>
#include <assh/assh_kex.h>
#include <assh/assh_prng.h>
#include <assh/assh_queue.h>
#include <assh/assh_service.h>
#include <assh/assh_transport.h>
#include <assh/assh_alloc.h>
#include <assh/assh_key.h>

static ASSH_KEX_FILTER_FCN(assh_session_kex_filter)
{
  return 1;
}

assh_error_t assh_session_init(struct assh_context_s *c,
			       struct assh_session_s *s)
{
  assh_error_t err;

  ASSH_RET_IF_TRUE(c->algo_cnt == 0, ASSH_ERR_BUSY);

  s->ctx = c;

  assh_transport_state(s, ASSH_TR_IDENT);

  s->ident_len = 0;
  s->session_id_len = 0;

  s->kex = NULL;
  s->kex_init_local = NULL;
  s->kex_init_remote = NULL;
  s->kex_pv = NULL;
  s->kex_bytes = 0;
  s->kex_max_bytes = ASSH_REKEX_THRESHOLD;
  s->kex_filter = assh_session_kex_filter;
  s->kex_done = 0;

#ifdef CONFIG_ASSH_CLIENT
  s->kex_host_key = NULL;
  s->srv_index = 0;
#endif
  s->srv_st = ASSH_SRV_NONE;
  s->srv = NULL;
  s->tr_user_auth_done = 0;
  s->user_auth_done = 0;

  s->last_err = 0;
  s->time = 0;
  s->deadline = 0;

  s->stream_out_st = ASSH_TR_OUT_IDENT;
  assh_queue_init(&s->out_queue);
  assh_queue_init(&s->alt_queue);
  s->stream_out_size = 0;
  s->cur_keys_out = (struct assh_kex_keys_s *)&assh_keys_none;
  s->new_keys_out = NULL;
  s->out_seq = 0;

  s->stream_in_st = ASSH_TR_IN_IDENT;
  s->stream_in_pck = NULL;
  s->stream_in_size = 0;
  s->in_pck = NULL;
  s->cur_keys_in = (struct assh_kex_keys_s *)&assh_keys_none;
  s->new_keys_in = NULL;
  s->in_seq = 0;

  c->session_count++;

  return ASSH_OK;
}

assh_error_t assh_session_create(struct assh_context_s *c,
				 struct assh_session_s **s)
{
  assh_error_t err;
  ASSH_RET_ON_ERR(assh_alloc(c, sizeof(**s), ASSH_ALLOC_INTERNAL, (void**)s));
  ASSH_JMP_ON_ERR(assh_session_init(c, *s), err);
  return ASSH_OK;
 err:
  assh_free(c, *s);
  return err;
}

void assh_session_release(struct assh_session_s *s)
{
  assh_session_cleanup(s);
  assh_free(s->ctx, s);
}

void assh_session_cleanup(struct assh_session_s *s)
{
  if (s->kex_pv != NULL)
    s->kex->f_cleanup(s);
  assert(s->kex_pv == NULL);

  switch (s->srv_st)
    {
    case ASSH_SRV_RUNNING:
    case ASSH_SRV_INIT_EVENT:
      s->srv->f_cleanup(s);
    default:
      break;
    }

  assh_packet_release(s->kex_init_local);
  assh_packet_release(s->kex_init_remote);

  assh_packet_queue_cleanup(&s->out_queue);
  assh_packet_queue_cleanup(&s->alt_queue);

  assh_kex_keys_cleanup(s, s->cur_keys_in);
  assh_kex_keys_cleanup(s, s->cur_keys_out);
  assh_kex_keys_cleanup(s, s->new_keys_in);
  assh_kex_keys_cleanup(s, s->new_keys_out);

  assh_packet_release(s->in_pck);
  assh_packet_release(s->stream_in_pck);

#ifdef CONFIG_ASSH_CLIENT
  assh_key_drop(s->ctx, &s->kex_host_key);
#endif

  s->ctx->session_count--;
}

const char * assh_error_str(assh_error_t err)
{
  const char * str[ASSH_ERR_count - 0x100] = {
    [ASSH_ERR_IO - 0x100]
    = "IO error",
    [ASSH_ERR_MEM - 0x100]
    = "Memory allocation error",
    [ASSH_ERR_INPUT_OVERFLOW - 0x100]
    = "Input overflow",
    [ASSH_ERR_OUTPUT_OVERFLOW - 0x100]
    = "Output overflow",
    [ASSH_ERR_NUM_OVERFLOW - 0x100]
    = "Arithmetic overflow",
    [ASSH_ERR_NUM_COMPARE_FAILED - 0x100]
    = "Compare failed on big number",
    [ASSH_ERR_BAD_VERSION - 0x100]
    = "Bad protocol version",
    [ASSH_ERR_BAD_DATA - 0x100]
    = "Unexpected or corrupt data",
    [ASSH_ERR_BAD_ARG - 0x100]
    = "Invalid arguments",
    [ASSH_ERR_MAC - 0x100]
    = "Message authentication error",
    [ASSH_ERR_PROTOCOL - 0x100]
    = "Protocol error",
    [ASSH_ERR_CRYPTO - 0x100]
    = "Cryptographic operation error ",
    [ASSH_ERR_NOTSUP - 0x100]
    = "Unsupported operation or value",
    [ASSH_ERR_KEX_FAILED - 0x100]
    = "Key exchange failed",
    [ASSH_ERR_MISSING_KEY - 0x100]
    = "Key not available",
    [ASSH_ERR_MISSING_ALGO - 0x100]
    = "Algorithm not available",
    [ASSH_ERR_HOSTKEY_SIGNATURE - 0x100]
    = "Host authentication failed",
    [ASSH_ERR_SERVICE_NA - 0x100]
    = "Service not available",
    [ASSH_ERR_NO_AUTH - 0x100]
    = "No more authentication method",
    [ASSH_ERR_DISCONNECTED - 0x100]
    = "Disconnect by remote host",
    [ASSH_ERR_NO_MORE_SERVICE - 0x100]
    = "No more service",
    [ASSH_ERR_CLOSED - 0x100]
    = "Session closed",
    [ASSH_ERR_WEAK_ALGORITHM - 0x100]
    = "Weak algorithm or key",
    [ASSH_ERR_TIMEOUT - 0x100]
    = "Protocol timeout",
  };

  err = ASSH_ERR_ERROR(err);
  if (err < 0x100)
    return "Success";
  return str[err - 0x100];
}

static assh_error_t
assh_session_send_disconnect(struct assh_session_s *s,
                             enum assh_ssh_disconnect_e reason,
                             const char *desc)
{
  assh_error_t err;

  size_t sz = 0;
  if (desc != NULL)
    sz = 4 + strlen(desc);

  struct assh_packet_s *pout;
  ASSH_RET_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_DISCONNECT,
                                 3 * 4 + sz, &pout));

  ASSH_ASSERT(assh_packet_add_u32(pout, reason)); /* reason code */

  uint8_t *str;
  ASSH_ASSERT(assh_packet_add_string(pout, sz, &str)); /* description */
  if (desc != NULL)
    memcpy(str, desc, sz - 4);

  ASSH_ASSERT(assh_packet_add_string(pout, 0, NULL)); /* language */

  assh_transport_push(s, pout);

  s->deadline = s->time + 1;

  return ASSH_OK;
}

assh_error_t assh_session_error(struct assh_session_s *s, assh_error_t inerr)
{
  if (!(inerr & 0x100))
      return inerr;

  if (ASSH_ERR_SEVERITY(inerr) >= ASSH_ERR_SEVERITY(s->last_err))
    s->last_err = inerr;

  if ((inerr & ASSH_ERRSV_FATAL) || s->tr_st == ASSH_TR_CLOSED)
    {
      assh_transport_state(s, ASSH_TR_CLOSED);
      return inerr | ASSH_ERRSV_FATAL;
    }

  if ((inerr & ASSH_ERRSV_FIN) || s->tr_st == ASSH_TR_FIN ||
      ((inerr & ASSH_ERRSV_DISCONNECT) && s->tr_st == ASSH_TR_DISCONNECT))
    {
      assh_transport_state(s, ASSH_TR_FIN);
      return inerr | ASSH_ERRSV_FIN;
    }

  uint32_t reason = SSH_DISCONNECT_RESERVED;
  const char *desc = NULL;

  switch (inerr & 0xfff)
    {
    case ASSH_ERR_BAD_DATA:
    case ASSH_ERR_PROTOCOL:
#ifdef CONFIG_ASSH_VERBOSE_ERROR
      reason = SSH_DISCONNECT_PROTOCOL_ERROR;
      break;
#endif

    case ASSH_ERR_INPUT_OVERFLOW:
    case ASSH_ERR_OUTPUT_OVERFLOW:
    case ASSH_ERR_IO:
    case ASSH_ERR_BAD_VERSION:
    case ASSH_ERR_DISCONNECTED:
    case ASSH_ERR_CLOSED:
      assh_transport_state(s, ASSH_TR_FIN);
      return inerr | ASSH_ERRSV_FIN;

    case ASSH_ERR_MEM:
      reason = SSH_DISCONNECT_RESERVED;
#ifdef CONFIG_ASSH_VERBOSE_ERROR
      desc = "memory resource shortage";
#endif
      break;
    case ASSH_ERR_NUM_OVERFLOW:
      reason = SSH_DISCONNECT_RESERVED;
#ifdef CONFIG_ASSH_VERBOSE_ERROR
      desc = "numerical overflow";
#endif
      break;
    case ASSH_ERR_MAC:
#ifdef CONFIG_ASSH_VERBOSE_ERROR
      desc = "mac error";
#endif
      reason = SSH_DISCONNECT_MAC_ERROR;
      break;
    case ASSH_ERR_CRYPTO:
#ifdef CONFIG_ASSH_VERBOSE_ERROR
      desc = "crypto error";
#endif
      reason = SSH_DISCONNECT_RESERVED;
      break;
    case ASSH_ERR_NOTSUP:
      desc = "not supported";
      reason = SSH_DISCONNECT_RESERVED;
      break;
    case ASSH_ERR_KEX_FAILED:
      reason = SSH_DISCONNECT_KEY_EXCHANGE_FAILED;
      break;
    case ASSH_ERR_MISSING_KEY:
      desc = "missing key";
      reason = SSH_DISCONNECT_RESERVED;
      break;
    case ASSH_ERR_MISSING_ALGO:
      desc = "algorithm not available";
      reason = SSH_DISCONNECT_RESERVED;
      break;
    case ASSH_ERR_HOSTKEY_SIGNATURE:
      reason = SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE;
      break;
    case ASSH_ERR_SERVICE_NA:
      reason = SSH_DISCONNECT_SERVICE_NOT_AVAILABLE;
      break;
    case ASSH_ERR_NO_AUTH:
      reason = SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE;
      break;
    case ASSH_ERR_NO_MORE_SERVICE:
      reason = SSH_DISCONNECT_BY_APPLICATION;
      break;
    case ASSH_ERR_WEAK_ALGORITHM:
      desc = "weak key or algorithm parameters";
      reason = SSH_DISCONNECT_RESERVED;
      break;
    case ASSH_ERR_TIMEOUT:
      desc = "protocol timeout";
      reason = SSH_DISCONNECT_PROTOCOL_ERROR;
      break;
    }

  if (!(inerr & ASSH_ERRSV_DISCONNECT))
    return inerr;

  ASSH_DEBUG("disconnect packet reason: %u (%s)\n", reason, desc);

  assh_transport_state(s, ASSH_TR_DISCONNECT);
  assh_session_send_disconnect(s, reason, desc);

  return inerr | ASSH_ERRSV_FIN;
}

uint_fast8_t assh_session_safety(struct assh_session_s *s)
{
  return ASSH_MIN(s->cur_keys_out->safety,
                  s->cur_keys_in->safety);
}

assh_error_t
assh_session_disconnect(struct assh_session_s *s,
                        enum assh_ssh_disconnect_e reason,
                        const char *desc)
{
  assh_error_t err;

  switch (s->tr_st)
    {
    case ASSH_TR_IDENT:
      assh_transport_state(s, ASSH_TR_CLOSED);
      return ASSH_OK;

    case ASSH_TR_KEX_INIT:
    case ASSH_TR_KEX_WAIT:
    case ASSH_TR_KEX_SKIP:
    case ASSH_TR_KEX_RUNNING:
    case ASSH_TR_NEWKEY:
    case ASSH_TR_SERVICE:
    case ASSH_TR_SERVICE_KEX:
      ASSH_RET_ON_ERR(assh_session_send_disconnect(s, reason, desc));
      assh_transport_state(s, ASSH_TR_DISCONNECT);

    case ASSH_TR_DISCONNECT:
      return ASSH_OK;

    case ASSH_TR_CLOSED:
    case ASSH_TR_FIN:
      ASSH_RETURN(ASSH_ERR_CLOSED);

    default:
      ASSH_UNREACHABLE();
    }
}

assh_error_t
assh_session_disconnect_msg(struct assh_session_s *s,
                            enum assh_ssh_disconnect_e *reason,
                            struct assh_cbuffer_s *desc)
{
  assh_error_t err;
  struct assh_packet_s *p = s->in_pck;

  if (p == NULL || p->head.msg != SSH_MSG_DISCONNECT)
    return ASSH_NO_DATA;

  const uint8_t *dcode = p->head.end;
  const uint8_t *ddesc, *end;

  ASSH_RET_ON_ERR(assh_packet_check_array(p, dcode, 4, &ddesc));
  ASSH_RET_ON_ERR(assh_packet_check_string(p, ddesc, &end));

  if (reason)
    *reason = assh_load_u32(dcode);

  if (desc)
    {
      desc->data = ddesc;
      desc->size = end - ddesc;
    }

  return ASSH_OK;
}

assh_error_t
assh_session_algo_filter(struct assh_session_s *s,
                         assh_kex_filter_t *filter)
{
  assh_error_t err;

  switch (s->tr_st)
    {
    case ASSH_TR_KEX_WAIT:
    case ASSH_TR_SERVICE_KEX:
      ASSH_RETURN(ASSH_ERR_BUSY);
    default:
      s->kex_filter = filter != NULL
        ? filter : assh_session_kex_filter;
      return ASSH_OK;
    }
}

void assh_session_set_pv(struct assh_session_s *ctx,
                         void *private)
{
  ctx->user_pv = private;
}

void * assh_session_get_pv(struct assh_session_s *ctx)
{
  return ctx->user_pv;
}
