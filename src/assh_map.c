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

#include <assh/assh_map.h>

#define ASSH_MAP_W sizeof(item->id) * 8

struct assh_map_entry_s *
assh_map_insert(struct assh_map_entry_s **root,
                struct assh_map_entry_s *item)
{
  assh_map_id_t id_ = item->id;

  while (1)
    {
      struct assh_map_entry_s *e = *root;
      if (e == NULL)
        {
          item->link[0] = item->link[1] = NULL;
          *root = item;
          return NULL;
        }
      if (item->id == e->id)
        return e;
      root = &e->link[id_ & 1];
      id_ >>= 1;
    }
}

void assh_map_remove(struct assh_map_entry_s **parent,
                     struct assh_map_entry_s *item)
{
  struct assh_map_entry_s **root = parent, *e = item;

  /* get a leaf node */
  while (1)
    {
      if (e->link[0] != NULL)
        root = &e->link[0];
      else if (e->link[1] != NULL)
        root = &e->link[1];
      else
        break;
      e = *root;
    }

  *root = e->link[1];

  if (e != item)
    {
      *parent = e;
      e->link[0] = item->link[0];
      e->link[1] = item->link[1];
    }
}

struct assh_map_entry_s *
assh_map_lookup(struct assh_map_entry_s **root,
		assh_map_id_t id, struct assh_map_entry_s ***parent)
{
  struct assh_map_entry_s *e;
  assh_map_id_t id_ = id;

  while (1)
    {
      e = *root;
      if (e == NULL)
        return NULL;
      if (e->id == id)
        break;
      root = &e->link[id_ & 1];
      id_ >>= 1;
    }

  if (parent)
    *parent = root;

  return e;
}

void assh_map_iter(struct assh_map_entry_s *root, void *ctx,
		   void (*iter)(struct assh_map_entry_s *, void *))
{
  struct assh_map_entry_s *stack[sizeof(assh_map_id_t) * 8], *next, *l1;
  int i = 0;

  while (1)
    {
      for (; root != NULL; root = next)
        {
          next = root->link[0];
          l1 = root->link[1];
          if (l1 != NULL)
            stack[i++] = l1;
          iter(root, ctx);
        }
      if (i == 0)
        break;
      root = stack[--i];
    }
}

