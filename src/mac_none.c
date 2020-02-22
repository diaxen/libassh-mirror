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


#include <assh/assh_mac.h>

#include <string.h>

static ASSH_MAC_INIT_FCN(assh_hmac_none_init)
{
  return ASSH_OK;
}

static ASSH_MAC_CLEANUP_FCN(assh_hmac_none_cleanup)
{
}

static ASSH_MAC_PROCESS_FCN(assh_hmac_none_process)
{
  return ASSH_OK;
}

const struct assh_algo_mac_s assh_mac_none =
{
  ASSH_ALGO_BASE(MAC, "assh-builtin", 0, 99,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_ASSH,
                      "none" })
  ),
  .ctx_size = 0,
  .key_size = 0,
  .mac_size = 0,
  .f_init = assh_hmac_none_init,
  .f_process = assh_hmac_none_process,
  .f_cleanup = assh_hmac_none_cleanup,
};

