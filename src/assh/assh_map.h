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
   @short Associative container
   @internal
*/

#ifndef ASSH_MAP_H_
#define ASSH_MAP_H_

#include "assh.h"

/** @internal Associative container key type */
typedef uint32_t assh_map_id_t;

/** @internal Associative container entry */
struct assh_map_entry_s
{
  ASSH_PV struct assh_map_entry_s *link[2];
  ASSH_PV assh_map_id_t id;
};

/* @internal @This inserts an item in the container, @tt item->id must
   be initialized. */
ASSH_PV struct assh_map_entry_s *
assh_map_insert(struct assh_map_entry_s **root,
                struct assh_map_entry_s *item);

/* @internal @This finds a node in the container. */
ASSH_PV struct assh_map_entry_s *
assh_map_lookup(struct assh_map_entry_s **root,
                assh_map_id_t id, struct assh_map_entry_s ***parent);

/* @internal @This removes an item from the container. */
ASSH_PV void
assh_map_remove(struct assh_map_entry_s **parent,
		struct assh_map_entry_s *item);

/* @internal @This finds and removes an item from the container. */
assh_status_t
assh_map_remove_id(struct assh_map_entry_s **root,
                   assh_map_id_t id);

/* @internal @This iterates over items in the container. */
ASSH_PV void
assh_map_iter(struct assh_map_entry_s *root, void *ctx,
	      void (*iter)(struct assh_map_entry_s *, void *));

#endif

