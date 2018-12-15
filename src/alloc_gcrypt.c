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

#include <assh/assh_alloc.h>

#include <gcrypt.h>

#ifndef CONFIG_ASSH_USE_GCRYPT_ALLOC
# error
#endif

ASSH_ALLOCATOR(assh_gcrypt_allocator)
{
  assh_error_t err;

  if (size == 0)
    {
      gcry_free(*ptr);
      return ASSH_OK;
    }
  else if (*ptr == NULL)
    {
      switch (type)
	{
        case ASSH_ALLOC_NONE:
          ASSH_UNREACHABLE();
	case ASSH_ALLOC_INTERNAL:
	case ASSH_ALLOC_PACKET:
	  *ptr = gcry_malloc(size);
	  break;
	case ASSH_ALLOC_SECUR:
	case ASSH_ALLOC_SCRATCH:
	  *ptr = gcry_malloc_secure(size);
	  break;
	}
      ASSH_RET_IF_TRUE(*ptr == NULL, ASSH_ERR_MEM);
      return ASSH_OK;
    }
  else
    {
      *ptr = gcry_realloc(*ptr, size);
      ASSH_RET_IF_TRUE(*ptr == NULL, ASSH_ERR_MEM);
      return ASSH_OK;
    }

  return ASSH_OK;
}
