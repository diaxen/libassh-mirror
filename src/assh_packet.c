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

#include <assh/assh_packet.h>
#include <assh/assh_buffer.h>
#include <assh/assh_queue.h>
#include <assh/assh_session.h>
#include <assh/assh_alloc.h>

#include <string.h>

#ifdef CONFIG_ASSH_PACKET_POOL
# ifdef CONFIG_ASSH_VALGRIND
#  include <valgrind/memcheck.h>
# endif

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

assh_status_t
assh_packet_alloc(struct assh_context_s *c,
                  uint8_t msg, size_t payload_size_m1,
                  struct assh_packet_s **result)
{
  assh_status_t err; 

  ASSH_RET_IF_TRUE(payload_size_m1 + 1 > CONFIG_ASSH_MAX_PAYLOAD,
               ASSH_ERR_OUTPUT_OVERFLOW);

  struct assh_packet_s *p;
  ASSH_RET_ON_ERR(assh_packet_alloc_raw(c, ASSH_PACKET_MIN_OVERHEAD +
                 /* msg */ 1 + payload_size_m1, &p));

  p->data_size = ASSH_PACKET_HEADLEN + /* msg */ 1;
  p->head.msg = msg;
  *result = p;

  return ASSH_OK;
}

assh_status_t
assh_packet_alloc_raw(struct assh_context_s *c, size_t raw_size,
                   struct assh_packet_s **result)
{
  struct assh_packet_s *p, **r;
  assh_status_t err;

#ifdef CONFIG_ASSH_PACKET_POOL
  struct assh_packet_pool_s *pl = assh_packet_pool(c, raw_size);

  /* get from pool */
  for (r = &pl->pck; (p = *r) != NULL; r = &(*r)->pool_next)
    {
      if (p->buffer_size >= raw_size)
	{
	  *r = p->pool_next;
          pl->size -= p->buffer_size;
          c->pck_pool_size -= p->buffer_size;
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
  p->sent = p->last = 0;
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
ASSH_WARN_UNUSED_RESULT assh_status_t
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
      c->pck_pool_size += p->buffer_size;
# ifdef CONFIG_ASSH_VALGRIND
      VALGRIND_MAKE_MEM_UNDEFINED(p->data, p->buffer_size);
# endif
    }
#endif
}

struct assh_packet_s *
assh_packet_refinc(struct assh_packet_s *p)
{
  p->ref_count++;
  return p;
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

ASSH_WARN_UNUSED_RESULT assh_status_t
assh_packet_dup(struct assh_packet_s *p, struct assh_packet_s **copy)
{
  assh_status_t err;

  ASSH_RET_ON_ERR(assh_packet_alloc_raw(p->ctx, p->alloc_size, copy));
  struct assh_packet_s *r = *copy;

  memcpy(r->data, p->data, p->data_size);
  r->data_size = p->data_size;

  return ASSH_OK;
}

assh_status_t
assh_packet_add_array(struct assh_packet_s *p, size_t len, uint8_t **result)
{
  assh_status_t err;

  static const size_t tail_len = ASSH_PACKET_MIN_OVERHEAD
    - ASSH_PACKET_HEADLEN - /* msg */ 1;

  ASSH_RET_IF_TRUE(p->data_size + len + tail_len >
               p->alloc_size, ASSH_ERR_OUTPUT_OVERFLOW);
  uint8_t *d = p->data + p->data_size;
  p->data_size += len;
  *result = d;
  return ASSH_OK;
}

assh_status_t
assh_packet_add_u32(struct assh_packet_s *p, uint32_t value)
{
  uint8_t *be;
  assh_status_t err = assh_packet_add_array(p, 4, &be);
  if (ASSH_STATUS(err) == ASSH_OK)
    assh_store_u32(be, value);
  return err;
}

assh_status_t
assh_packet_add_string(struct assh_packet_s *p, size_t len, uint8_t **result)
{
  assh_status_t err;

  uint8_t *d;
  ASSH_RET_ON_ERR(assh_packet_add_array(p, len + 4, &d));
  assh_store_u32(d, len);
  if (result != NULL)
    *result = d + 4;
  return ASSH_OK;
}

assh_status_t
assh_packet_enlarge_string(struct assh_packet_s *p, uint8_t *str,
                           size_t len, uint8_t **result)
{
  assh_status_t err;

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

assh_status_t
assh_packet_check_string(const struct assh_packet_s *p, const uint8_t *str,
                         const uint8_t **next)
{
  return assh_check_string(p->data, p->data_size, str, next);
}

assh_status_t
assh_packet_check_array(const struct assh_packet_s *p, const uint8_t *array,
                        size_t array_len, const uint8_t **next)
{
  return assh_check_array(p->data, p->data_size, array, array_len, next);
}

assh_status_t
assh_packet_check_u32(const struct assh_packet_s *p, uint32_t *u32,
		      const uint8_t *data, const uint8_t **next)
{
  assh_status_t err = assh_packet_check_array(p, data, 4, next);
  if (ASSH_STATUS(err) == ASSH_OK)
    *u32 = assh_load_u32(data);
  return err;
}
