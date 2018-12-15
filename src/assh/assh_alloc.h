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

/**
   @file @internal
   @short Pluggable memory allocation functions used by the library
*/

#ifndef ASSH_ALLOC_H_
#define ASSH_ALLOC_H_

#include "assh_context.h"

/** @internal @This specifies the type of data to be stored in the
    allocated memory. */
enum assh_alloc_type_e
{
  ASSH_ALLOC_NONE,
  /** General purpose allocation in non-secur memory. */
  ASSH_ALLOC_INTERNAL,
  /** Buffer allocation in secur memory which don't last longer than a
      function call. */
  ASSH_ALLOC_SCRATCH,
  /** Cryptographic allocation in secur memory. */
  ASSH_ALLOC_SECUR,
  /** SSH packet allocation. Used to store enciphered and clear text
      packets. */
  ASSH_ALLOC_PACKET,
};

/** @internal @This allocates memory. */
ASSH_INLINE ASSH_WARN_UNUSED_RESULT assh_error_t
assh_alloc(struct assh_context_s *c, size_t size,
	   enum assh_alloc_type_e type, void **result)
{
  *result = NULL;
  return size != 0
    ? c->f_alloc(c->alloc_pv, result, size, type)
    : ASSH_OK;
}

/** @internal @This reallocates memory. */
ASSH_INLINE ASSH_WARN_UNUSED_RESULT assh_error_t
assh_realloc(struct assh_context_s *c, void **ptr, size_t size,
	     enum assh_alloc_type_e type)
{
  return c->f_alloc(c->alloc_pv, ptr, size, type);
}

/** @internal @This releases memory. */
ASSH_INLINE void assh_free(struct assh_context_s *c, void *ptr)
{
  if (ptr != NULL)
    (void)c->f_alloc(c->alloc_pv, &ptr, 0, ASSH_ALLOC_NONE);
}

#ifdef CONFIG_ASSH_ALLOCA

# include <alloca.h>

/** @internal @This allocates memory not used after current function
    return.

    Depending on the value of @ref #CONFIG_ASSH_ALLOCA, this macro
    either relies on the @tt alloca function or calls the @ref
    assh_alloc function using the @ref ASSH_ALLOC_SCRATCH type.

    @see #ASSH_SCRATCH_FREE.
*/
# define ASSH_SCRATCH_ALLOC(context, type, name, size, sv, lbl)		\
  size_t name##_size_ = (size) * sizeof(type);				\
  type *name = (type*)alloca(name##_size_);                              \
  if (0) goto lbl;

/** @internal @This releases memory allocated by @ref
    #ASSH_SCRATCH_ALLOC. */
# define ASSH_SCRATCH_FREE(context, name) \
  do { assh_clear(name, name##_size_); } while (0)

#else

# define ASSH_SCRATCH_ALLOC(context, type, name, size, sv, lbl)		\
  type *name;								\
  ASSH_JMP_ON_ERR(assh_alloc(context, (size) * sizeof(type),		\
			  ASSH_ALLOC_SCRATCH, (void**)&name) | sv, lbl);

# define ASSH_SCRATCH_FREE(context, name)				\
  do { assh_free(context, name); } while (0)

#endif

# ifdef CONFIG_ASSH_USE_LIBC_ALLOC
/** This allocator relies on the libc @tt realloc function. This
    allocator @b{is not} able to provide secure memory.

    It does not requires private data; @tt NULL may be passed as @tt
    alloc_pv parameter of the initialization function.
*/
ASSH_ALLOCATOR(assh_libc_allocator);
# endif

# ifdef CONFIG_ASSH_USE_GCRYPT_ALLOC
/** This allocator relies on the secur memory allocation functions
    provided by libgcrypt.

    It does not requires private data; @tt NULL may be passed as @tt
    alloc_pv parameter of the initialization function.
*/
ASSH_ALLOCATOR(assh_gcrypt_allocator);
# endif

#endif
