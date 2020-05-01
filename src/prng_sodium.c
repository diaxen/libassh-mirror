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

#include <assh/assh_prng.h>
#include <assh/mod_sodium.h>

#include <sodium/randombytes.h>

static ASSH_PRNG_INIT_FCN(assh_prng_sodium_init)
{
  return ASSH_OK;
}

static ASSH_PRNG_GET_FCN(assh_prng_sodium_get)
{
  randombytes_buf(rdata, rdata_len);

  return ASSH_OK;
}

static ASSH_PRNG_CLEANUP_FCN(assh_prng_sodium_cleanup)
{
}

const struct assh_prng_s assh_prng_sodium =
{
  .f_init = assh_prng_sodium_init,
  .f_get = assh_prng_sodium_get,
  .f_cleanup = assh_prng_sodium_cleanup,
};

