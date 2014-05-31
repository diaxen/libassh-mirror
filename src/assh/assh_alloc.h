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

#ifndef ASSH_ALLOC_H_
#define ASSH_ALLOC_H_

#include "assh_context.h"

/** This specifies the type of data to be stored in the allocated memory. */
enum assh_alloc_type_e
{
  /** General purpose allocation in non-secur memory. */
  ASSH_ALLOC_INTERNAL,
  /** Buffer allocation in secur memory which don't last longer than a
      function call. */
  ASSH_ALLOC_SCRATCH,
  /** Cryptographic allocation in secur memory. */
  ASSH_ALLOC_KEY,
  /** SSH packet allocation. Used to store enciphered and clear text
      packets. */
  ASSH_ALLOC_PACKET,
};

static inline ASSH_WARN_UNUSED_RESULT assh_error_t
assh_alloc(struct assh_context_s *c, size_t size,
	   enum assh_alloc_type_e type, void **result)
{
  *result = NULL;
  return c->f_alloc(c, result, size, type);
}

static inline ASSH_WARN_UNUSED_RESULT assh_error_t
assh_realloc(struct assh_context_s *c, void **ptr, size_t size,
	     enum assh_alloc_type_e type)
{
  return c->f_alloc(c, ptr, size, type);
}

static inline void assh_free(struct assh_context_s *c, void *ptr,
			     enum assh_alloc_type_e type)
{
  if (ptr != NULL)
    (void)c->f_alloc(c, &ptr, 0, type);
}

#ifdef CONFIG_ASSH_ALLOCA

# include <alloca.h>

# define ASSH_SCRATCH_ALLOC(context, type, name, size, sv, lbl)		\
  size_t name##_size = (size) * sizeof(type);				\
  type *name = (type*)alloca(name##_size);

# define ASSH_SCRATCH_FREE(context, name) \
  memset(name, 0, name##_size);

#else

# define ASSH_SCRATCH_ALLOC(context, type, name, size, sv, lbl)		\
  type *name;								\
  ASSH_ERR_GTO(assh_alloc(context, (size) * sizeof(type),		\
			  ASSH_ALLOC_SCRATCH, (void**)&name) | sv, lbl);

# define ASSH_SCRATCH_FREE(context, name)				\
  do { assh_free(context, name, ASSH_ALLOC_SCRATCH); } while (0)

#endif

#endif
