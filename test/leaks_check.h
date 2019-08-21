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
#include <assh/assh_alloc.h>

#include <stdlib.h>

#ifdef CONFIG_ASSH_VALGRIND
# include <valgrind/memcheck.h>
#endif

#include "prng_weak.h"

static size_t alloc_size = 0;
static uint32_t alloc_fuzz = 0;
static unsigned long alloc_fuzz_fails = 0;

#define ALLOC_ALIGN 32

static ASSH_ALLOCATOR(assh_leaks_allocator)
{
  if (*ptr == NULL)
    {
      if (alloc_fuzz && assh_prng_rand() % alloc_fuzz == 0)
	{
	  alloc_fuzz_fails++;
	  return ASSH_ERR_MEM;
	}
      size_t *bsize = malloc(ALLOC_ALIGN + size);
      if (bsize != NULL)
	{
	  *ptr = (uint8_t*)bsize + ALLOC_ALIGN;
	  *bsize = size;
	  alloc_size += size;
	  memset(*ptr, 0xa5, size);
#ifdef CONFIG_ASSH_VALGRIND
	  VALGRIND_MAKE_MEM_UNDEFINED(*ptr, size);
#endif
	  return ASSH_OK;
	}
      return ASSH_ERR_MEM;
    }
  else if (size == 0)
    {
      size_t *bsize = (void*)((uint8_t*)*ptr - ALLOC_ALIGN);
      alloc_size -= *bsize;
      memset((void*)bsize, 0x5a, *bsize);
      free((void*)bsize);
      return ASSH_OK;
    }
  else
    {
      if (alloc_fuzz && assh_prng_rand() % alloc_fuzz == 0)
	{
	  alloc_fuzz_fails++;
	  return ASSH_ERR_MEM;
	}
      size_t *bsize = (void*)((uint8_t*)*ptr - ALLOC_ALIGN);
      bsize = realloc(bsize, ALLOC_ALIGN + size);
      if (bsize != NULL)
	{
	  alloc_size -= *bsize;
	  alloc_size += size;
	  *ptr = (uint8_t*)bsize + ALLOC_ALIGN;
	  *bsize = size;
	  return ASSH_OK;
	}
      return ASSH_ERR_MEM;
    }
}

