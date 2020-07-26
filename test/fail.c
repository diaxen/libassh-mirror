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

#undef ASSH_PV  /* must not warn */

#include <assh/assh.h>
#include <assh/assh_platform.h>
#include <assh/assh_algo.h>
#include <assh/assh_alloc.h>
#include <assh/assh_bignum.h>
#include <assh/assh_cipher.h>
#include <assh/assh_compress.h>
#include <assh/assh_connection.h>
#include <assh/assh_context.h>
#include <assh/assh_hash.h>
#include <assh/assh_kex.h>
#include <assh/assh_key.h>
#include <assh/assh_mac.h>
#include <assh/assh_packet.h>
#include <assh/assh_buffer.h>
#include <assh/assh_prng.h>
#include <assh/assh_service.h>
#include <assh/assh_session.h>
#include <assh/assh_sign.h>
#include <assh/assh_transport.h>
#include <assh/assh_userauth_client.h>
#include <assh/assh_userauth_server.h>
#include <assh/assh_userauth.h>
#include <assh/helper_io.h>
#include <assh/helper_key.h>
#include <assh/helper_client.h>
#include <assh/helper_server.h>
#include <assh/helper_interactive.h>
#include <assh/helper_portfwd.h>
#include <assh/mod_builtin.h>
#include <assh/mod_gcrypt.h>
#include <assh/mod_openssl.h>
#include <assh/mod_zlib.h>
#include <assh/assh_event.h>

#include "test.h"

int main()
{
  TEST_FAIL("expected failure\n");
  return 0;
}
