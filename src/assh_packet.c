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

#include <assh/assh_packet.h>
#include <assh/assh_bignum.h>
#include <assh/assh_queue.h>
#include <assh/assh_session.h>
#include <assh/assh_alloc.h>

#include <assert.h>
#include <string.h>

#ifdef CONFIG_ASSH_PACKET_POOL
/* This function returns the index of the bucket associated to a given
   packet size in the allocator pool. */
static inline struct assh_packet_pool_s *
assh_packet_pool(struct assh_context_s *c, uint32_t size)
{
  int_fast8_t i = 32 - assh_clz32(size) - ASSH_PCK_POOL_MIN;
  if (i < 0)
    i = 0;
  else if (i >= ASSH_PCK_POOL_SIZE)
    i = ASSH_PCK_POOL_SIZE - 1;
  return c->pool + i;
}
#endif

assh_error_t
assh_packet_alloc(struct assh_context_s *c,
                  uint8_t msg, size_t payload_size_m1,
                  struct assh_packet_s **result)
{
  assh_error_t err; 

  ASSH_RET_IF_TRUE(payload_size_m1 + 1 > ASSH_PACKET_MAX_PAYLOAD,
               ASSH_ERR_OUTPUT_OVERFLOW);

  struct assh_packet_s *p;
  ASSH_RET_ON_ERR(assh_packet_alloc_raw(c, ASSH_PACKET_MIN_OVERHEAD +
                 /* msg */ 1 + payload_size_m1, &p));

  p->data_size = ASSH_PACKET_HEADLEN + /* msg */ 1;
  p->head.msg = msg;
  *result = p;

  return ASSH_OK;
}

assh_error_t
assh_packet_alloc_raw(struct assh_context_s *c, size_t raw_size,
                   struct assh_packet_s **result)
{
  struct assh_packet_s *p, **r;
  assh_error_t err;

#ifdef CONFIG_ASSH_PACKET_POOL
  struct assh_packet_pool_s *pl = assh_packet_pool(c, raw_size);

  /* get from pool */
  for (r = &pl->pck; (p = *r) != NULL; r = &(*r)->pool_next)
    {
      if (p->buffer_size >= raw_size)
	{
	  *r = p->pool_next;
          pl->size -= p->buffer_size;
          pl->count--;
	  break;
	}
    }

  /* fallback to alloc */
  if (p == NULL)
#endif
    {
      ASSH_RET_ON_ERR(assh_alloc(c, sizeof(*p) - sizeof(p->head) + raw_size,
                              ASSH_ALLOC_PACKET, (void*)&p));
#ifdef CONFIG_ASSH_PACKET_POOL
      p->buffer_size = raw_size;
#endif
    }

  /* init */
  p->ref_count = 1;
  p->sent = 0;
  p->ctx = c;
  p->data_size = 0;
  p->alloc_size = raw_size;
  memset(p->data, 0, raw_size);
  p->padding = ASSH_PADDING_MIN;

  *result = p;
  return ASSH_OK;
}

void assh_packet_collect(struct assh_context_s *c)
{
#ifdef CONFIG_ASSH_PACKET_POOL
  size_t i;
  for (i = 0; i < ASSH_PCK_POOL_SIZE; i++)
    {
      struct assh_packet_s *n, *p;
      struct assh_packet_pool_s *pl = c->pool + i;

      for (p = pl->pck; p != NULL; p = n)
        {
          n = p->pool_next;
          pl->size -= p->buffer_size;
          pl->count--;
          assh_free(c, p);
        }

      assert(pl->count == 0);
      assert(pl->size == 0);
      pl->pck = NULL;
    }

  c->pck_pool_size = 0;
#endif
}

/** @internal @This returns the size of the buffer */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_packet_realloc_raw(struct assh_context_s *c,
                        struct assh_packet_s **p_,
                        size_t raw_size)
{
  struct assh_packet_s *p = *p_;

#ifdef CONFIG_ASSH_PACKET_POOL
  if (raw_size > p->buffer_size || p->ref_count > 1)
#else
  if (raw_size > p->alloc_size || p->ref_count > 1)
#endif
    return assh_packet_alloc_raw(c, raw_size, p_);

  p->alloc_size = raw_size;
  return ASSH_OK;
}

void assh_packet_release(struct assh_packet_s *p)
{
  if (p == NULL || --p->ref_count > 0)
    return;

  assert(p->ref_count == 0);

  struct assh_context_s *c = p->ctx;
#ifdef CONFIG_ASSH_PACKET_POOL
  struct assh_packet_pool_s *pl = assh_packet_pool(c, p->buffer_size);

  if (pl->size + p->buffer_size >= c->pck_pool_max_bsize ||
      c->pck_pool_size + p->buffer_size >= c->pck_pool_max_size)
    {
#endif
      assh_free(c, p);
#ifdef CONFIG_ASSH_PACKET_POOL
    }
  else
    {
      p->pool_next = pl->pck;
      pl->pck = p;
      pl->count++;
      pl->size += p->buffer_size;
    }
#endif
}

void assh_packet_queue_cleanup(struct assh_queue_s *q)
{
  while (!assh_queue_isempty(q))
    {
      struct assh_queue_entry_s *e = assh_queue_front(q);
      assh_queue_remove(e);

      struct assh_packet_s *p = (struct assh_packet_s*)e;
      assh_packet_release(p);
    }
}

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_packet_dup(struct assh_packet_s *p, struct assh_packet_s **copy)
{
  assh_error_t err;

  ASSH_RET_ON_ERR(assh_packet_alloc_raw(p->ctx, p->alloc_size, copy));
  struct assh_packet_s *r = *copy;

  memcpy(r->data, p->data, p->data_size);
  r->data_size = p->data_size;

  return ASSH_OK;
}

assh_error_t assh_packet_add_mpint(struct assh_context_s *ctx,
                                   struct assh_packet_s *p,
                                   const struct assh_bignum_s *bn)
{
  assh_error_t err;
  size_t l = assh_bignum_size_of_num(ASSH_BIGNUM_MPINT, bn);

  uint8_t *s;
  ASSH_RET_ON_ERR(assh_packet_add_array(p, l, &s));

  ASSH_RET_ON_ERR(assh_bignum_convert(ctx,
    ASSH_BIGNUM_NATIVE, ASSH_BIGNUM_MPINT, bn, s, NULL, 0));

  p->data_size -= l - assh_load_u32(s) - 4;
  return ASSH_OK;
}

assh_error_t
assh_check_asn1(const uint8_t *buffer, size_t buffer_len, const uint8_t *str,
                const uint8_t **value, const uint8_t **next, uint8_t id)
{
  assh_error_t err;

  const uint8_t *e = buffer + buffer_len;
  ASSH_RET_IF_TRUE(str < buffer || str > e - 2, ASSH_ERR_INPUT_OVERFLOW);
  ASSH_RET_IF_TRUE(id != 0 && str[0] != id, ASSH_ERR_BAD_DATA);

  str++; /* discard type identifer */
  uint_fast32_t l = *str++;
  if (l & 0x80)  /* long length form ? */
    {
      uint8_t ll = l & 0x7f;
      ASSH_RET_IF_TRUE(e - str < ll, ASSH_ERR_INPUT_OVERFLOW);
      for (l = 0; ll > 0; ll--)
        l = (l << 8) | *str++;
    }
  ASSH_RET_IF_TRUE(e - str < l, ASSH_ERR_INPUT_OVERFLOW);
  if (value != NULL)
    *value = str;
  if (next != NULL)
    *next = str + l;
  return ASSH_OK;
}

assh_error_t
assh_check_string(const uint8_t *buffer, size_t buffer_len,
                  const uint8_t *str, const uint8_t **next)
{
  assh_error_t err;

  const uint8_t *e = buffer + buffer_len;
  ASSH_RET_IF_TRUE(str < buffer || str > e - 4, ASSH_ERR_INPUT_OVERFLOW);
  size_t s = assh_load_u32(str);
  ASSH_RET_IF_TRUE(e - 4 - str < s, ASSH_ERR_INPUT_OVERFLOW);
  if (next != NULL)
    *next = str + 4 + s;
  return ASSH_OK;
}

assh_error_t
assh_check_array(const uint8_t *buffer, size_t buffer_len,
                 const uint8_t *array, size_t array_len, const uint8_t **next)
{
  assh_error_t err;

  const uint8_t *e = buffer + buffer_len;
  ASSH_RET_IF_TRUE(array < buffer || array > e, ASSH_ERR_INPUT_OVERFLOW);
  ASSH_RET_IF_TRUE(e - array < array_len, ASSH_ERR_INPUT_OVERFLOW);
  if (next != NULL)
    *next = array + array_len;
  return ASSH_OK;
}

assh_error_t
assh_packet_add_array(struct assh_packet_s *p, size_t len, uint8_t **result)
{
  assh_error_t err;

  static const size_t tail_len = ASSH_PACKET_MIN_OVERHEAD
    - ASSH_PACKET_HEADLEN - /* msg */ 1;

  ASSH_RET_IF_TRUE(p->data_size + len + tail_len >
               p->alloc_size, ASSH_ERR_OUTPUT_OVERFLOW);
  uint8_t *d = p->data + p->data_size;
  p->data_size += len;
  *result = d;
  return ASSH_OK;
}

assh_error_t
assh_packet_add_string(struct assh_packet_s *p, size_t len, uint8_t **result)
{
  assh_error_t err;

  uint8_t *d;
  ASSH_RET_ON_ERR(assh_packet_add_array(p, len + 4, &d));
  assh_store_u32(d, len);
  if (result != NULL)
    *result = d + 4;
  return ASSH_OK;
}

assh_error_t
assh_packet_enlarge_string(struct assh_packet_s *p, uint8_t *str,
                           size_t len, uint8_t **result)
{
  assh_error_t err;

  size_t olen = assh_load_u32(str - 4);
  assert(str + olen == p->data + p->data_size);
  ASSH_RET_ON_ERR(assh_packet_add_array(p, len, result));
  assh_store_u32(str - 4, olen + len);
  return ASSH_OK;
}

void
assh_packet_shrink_string(struct assh_packet_s *p, uint8_t *str,
                          size_t new_len)
{
  size_t olen = assh_load_u32(str - 4);
  assert(str + olen == p->data + p->data_size);
  assert(olen >= new_len);
  assh_store_u32(str - 4, new_len);
  p->data_size -= olen - new_len;
}

void
assh_packet_string_resized(struct assh_packet_s *p, uint8_t *str)
{
  size_t len = assh_load_u32(str - 4);
  p->data_size = str - p->data + len;
}

assh_error_t
assh_ssh_string_copy(const uint8_t *ssh_str, char *nul_str, size_t max_len)
{
  assh_error_t err;

  size_t len = assh_load_u32(ssh_str);
  assert(max_len > 0);
  ASSH_RET_IF_TRUE(len > max_len - 1, ASSH_ERR_OUTPUT_OVERFLOW);
  memcpy(nul_str, ssh_str + 4, len);
  nul_str[len] = '\0';
  return ASSH_OK;
}

void
assh_append_asn1(uint8_t **dst, uint8_t id, size_t len)
{
  uint8_t *d = *dst;
  *d++ = id;
  if (len < 0x80)
    {
      *d++ = len;
    }
  else
    {
      uint_fast8_t i = 0;
      if (len & 0xff000000)
        d[++i] = len >> 24;
      if (len & 0xffff0000)
        d[++i] = len >> 16;
      if (len & 0xffffff00)
        d[++i] = len >> 8;
      d[++i] = len;
      d[0] = 0x80 | i;
      d += i + 1;
    }
  *dst = d;
}

