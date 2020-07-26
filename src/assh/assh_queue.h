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

/**
   @file
   @short Linked list container
   @internal
*/

#ifndef ASSH_QUEUE_H_
#define ASSH_QUEUE_H_

#include "assh.h"

/** @internal Link list entry */
struct assh_queue_entry_s
{
  struct assh_queue_entry_s *next, *prev;
};

/** @internal Link list head */
struct assh_queue_s
{
  struct assh_queue_entry_s head;
};

/** @internal */
ASSH_PV ASSH_INLINE void
assh_queue_init(struct assh_queue_s *q)
{
  q->head.next = q->head.prev = &q->head;
}

/** @internal */
ASSH_PV ASSH_INLINE assh_bool_t
assh_queue_isempty(struct assh_queue_s *q)
{
  return q->head.next == &q->head;
}

/** @internal */
ASSH_PV ASSH_INLINE struct assh_queue_entry_s *
assh_queue_front(struct assh_queue_s *q)
{
  return q->head.next == &q->head ? NULL : q->head.next;
}

/** @internal */
ASSH_PV ASSH_INLINE struct assh_queue_entry_s *
assh_queue_back(struct assh_queue_s *q)
{
  return q->head.prev == &q->head ? NULL : q->head.prev;
}

/** @internal */
ASSH_PV ASSH_INLINE struct assh_queue_entry_s *
assh_queue_next(struct assh_queue_s *q, struct assh_queue_entry_s *e)
{
  return e->next == &q->head ? NULL : e->next;
}

/** @internal */
ASSH_PV ASSH_INLINE struct assh_queue_entry_s *
assh_queue_prev(struct assh_queue_s *q, struct assh_queue_entry_s *e)
{
  return e->prev == &q->head ? NULL : e->prev;
}

/** @internal */
ASSH_PV ASSH_INLINE void
assh_queue_remove(struct assh_queue_entry_s *e)
{
  e->prev->next = e->next;
  e->next->prev = e->prev;
}

/** @internal */
ASSH_PV ASSH_INLINE void
assh_queue_push_front(struct assh_queue_s *q,
		      struct assh_queue_entry_s *b)
{
  struct assh_queue_entry_s *a = &q->head;
  b->prev = a;
  a->next->prev = b;
  b->next = a->next;
  a->next = b;
}

/** @internal */
ASSH_PV ASSH_INLINE void
assh_queue_push_back(struct assh_queue_s *q,
		     struct assh_queue_entry_s *b)
{
  struct assh_queue_entry_s *a = &q->head;
  b->next = a;
  a->prev->next = b;
  b->prev = a->prev;
  a->prev = b;
}

/** @internal */
ASSH_PV ASSH_INLINE void
assh_queue_concat(struct assh_queue_s *q,
		  struct assh_queue_s *r)
{
  struct assh_queue_entry_s *a = &q->head;
  struct assh_queue_entry_s *b = &r->head;

  if (r->head.next == &r->head)
    return;

  b->prev->next = a;
  b->next->prev = a->prev;
  a->prev->next = b->next;
  a->prev = b->prev;

  b->next = b->prev = b;
}

#endif

