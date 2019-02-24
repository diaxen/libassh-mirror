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

#include <assh/assh.h>
#include <assh/assh_buffer.h>
#include <assh/assh_cipher.h>
#include <assh/assh_context.h>

#include "test.h"
#include "leaks_check.h"

int
main(int argc, char **argv)
{
//  if (assh_deps_init())
//    return -1;

  struct assh_context_s context;

  struct assh_buffer_s seed;
  seed.str = "aaaaaaaaaaaaaaab";
  seed.len = 16;

  if (assh_context_init(&context, ASSH_CLIENT_SERVER, assh_leaks_allocator,
			NULL, &assh_prng_xswap, &seed))
    TEST_FAIL("context init");

  for (uint_fast8_t i = 0; i < 10; i++)
    {
      size_t len = 1 + rand() % 64;
      uint8_t buf[len];
      assh_prng_get(&context, buf, len, ASSH_PRNG_QUALITY_LONGTERM_KEY);
      assh_hexdump("ltk", buf, sizeof(buf));
    }

  assh_context_cleanup(&context);

  return 0;
}
