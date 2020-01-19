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

#include <assh/assh_alloc.h>
#include <assh/mod_openssl.h>

#ifndef CONFIG_ASSH_USE_OPENSSL_ALLOC
# error
#endif

#include <stdlib.h>
#include <openssl/crypto.h>

ASSH_ALLOCATOR(assh_openssl_allocator)
{
  assh_status_t err;

  switch (type)
    {
    case ASSH_ALLOC_NONE:
      assert(*ptr != NULL);
      if (CRYPTO_secure_allocated(*ptr))
	goto secur;

    case ASSH_ALLOC_INTERNAL:
    case ASSH_ALLOC_PACKET:
      *ptr = realloc(*ptr, size);
      ASSH_RET_IF_TRUE(size != 0 && *ptr == NULL, ASSH_ERR_MEM);
      break;

    case ASSH_ALLOC_SCRATCH:
    case ASSH_ALLOC_SECUR:
    secur:
      if (*ptr != NULL)
	{
	  if (size <= OPENSSL_secure_actual_size(*ptr))
	    {
	      if (size == 0)
		OPENSSL_secure_free(*ptr);
	    }
	  else
	    {
	      void *n = OPENSSL_secure_malloc(size);
	      ASSH_RET_IF_TRUE(n == NULL, ASSH_ERR_MEM);
	      memcpy(n, *ptr, OPENSSL_secure_actual_size(*ptr));
	      OPENSSL_secure_free(*ptr);
	      *ptr = n;
	    }
	}
      else
	{
	  void *n = OPENSSL_secure_malloc(size);
	  ASSH_RET_IF_TRUE(n == NULL, ASSH_ERR_MEM);
	  *ptr = n;
	}
      break;

    default:
      ASSH_UNREACHABLE();
    }

  return ASSH_OK;
}
