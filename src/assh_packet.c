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

#warning check packet alloc errors

#include <assh/assh_packet.h>
#include <assh/assh_bignum.h>
#include <assh/assh_queue.h>
#include <assh/assh_session.h>

#include <assert.h>
#include <string.h>

static inline int assh_packet_pool_idx(int size)
{
  int i = sizeof(int) * 8 - __builtin_clz(size) - ASSH_PCK_POOL_MIN;
  if (i < 0)
    i = 0;
  else if (i >= ASSH_PCK_POOL_SIZE)
    i = ASSH_PCK_POOL_SIZE - 1;
  return i;
}

assh_error_t
assh_packet_alloc(struct assh_session_s *s,
                  uint8_t msg, size_t size,
                  struct assh_packet_s **result)
{
  struct assh_packet_s *p, **r;
  int i = assh_packet_pool_idx(size);
  assh_error_t err;

  size += /* pck_len */ 4 + /* pad_len */ 1 + /* msg */ 1 + ASSH_MAX_MAC_LEN;
  /* get from pool */
  for (r = &s->ctx->pck_pool[i]; (p = *r) != NULL; r = &(*r)->pool_next)
    {
      if (p->alloc_size >= size)
	{
	  *r = p->pool_next;
	  break;
	}
    }

  /* fallback to alloc */
  if (p == NULL)
    {
      ASSH_ERR_RET(assh_alloc(s->ctx, sizeof(*p) + size, ASSH_ALLOC_PACKET, (void*)&p));
      p->alloc_size = size;
      p->ref_count = 1;
    }

  /* init */
  p->session = s;
  p->data_size = /* pck_len */ 4 + /* pad_len */ 1 + /* msg */ 1;
  p->head.msg = msg;

  *result = p;
  return ASSH_OK;
}

void assh_packet_release(struct assh_packet_s *p)
{
  if (p == NULL || --p->ref_count > 0)
    return;

  assert(p->ref_count == 0);

  struct assh_session_s *s = p->session;
  int i = assh_packet_pool_idx(p->alloc_size);

  p->pool_next = s->ctx->pck_pool[i];
  s->ctx->pck_pool[i] = p;

#warning Free some unused packets?
#if 0
  assh_free(s->ctx, p, ASSH_ALLOC_PACKET);
#endif
}

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_packet_dup(struct assh_packet_s *p, struct assh_packet_s **copy)
{
  assh_error_t err;

  if ((err = assh_packet_alloc(p->session, 0, p->alloc_size - 6, copy)))
    return err;
  struct assh_packet_s *r = *copy;

  memcpy(r->data, p->data, p->data_size);
  r->data_size = p->data_size;

  return ASSH_OK;
}

assh_error_t assh_packet_add_mpint(struct assh_packet_s *p,
                                   const struct assh_bignum_s *bn)
{
  assh_error_t err;

  size_t l = assh_bignum_mpint_size(bn);
  uint8_t *s;

  ASSH_ERR_RET(assh_packet_add_bytes(p, l, &s));
  ASSH_ERR_RET(assh_bignum_to_mpint(bn, s));

  p->data_size -= (l - 4) - assh_load_u32(s);
  return ASSH_OK;
}

