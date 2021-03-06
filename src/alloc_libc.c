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

#include <assh/assh_alloc.h>

#include <stdlib.h>
#ifdef CONFIG_ASSH_MALLOC_USABLE_SIZE
# include <malloc.h>
#endif

#ifndef CONFIG_ASSH_USE_LIBC_ALLOC
# error
#endif

ASSH_ALLOCATOR(assh_libc_allocator)
{
  assh_status_t err;

#ifdef CONFIG_ASSH_MALLOC_USABLE_SIZE
  if (*ptr)
    {
      size_t tail = malloc_usable_size(*ptr);
      if (tail > size)
        assh_clear(*ptr + size, tail - size);
    }
#endif

  *ptr = realloc(*ptr, size);
  ASSH_RET_IF_TRUE(size != 0 && *ptr == NULL, ASSH_ERR_MEM);

  return ASSH_OK;
}
