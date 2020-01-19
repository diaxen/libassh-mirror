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
#include <assh/mod_openssl.h>

#include <openssl/rand.h>

static ASSH_PRNG_INIT_FCN(assh_prng_openssl_init)
{
  assh_status_t err;
  ASSH_RET_IF_TRUE(!RAND_poll(), ASSH_ERR_CRYPTO);
  return ASSH_OK;
}

static ASSH_PRNG_GET_FCN(assh_prng_openssl_get)
{
  assh_status_t err;

  switch (ASSH_PRNG_QUALITY(quality))
    {
    case ASSH_PRNG_QUALITY_WEAK:
    case ASSH_PRNG_QUALITY_PUBLIC:
    case ASSH_PRNG_QUALITY_PADDING:
      ASSH_RET_IF_TRUE(!RAND_pseudo_bytes(rdata, rdata_len),
		       ASSH_ERR_CRYPTO);
      break;
    case ASSH_PRNG_QUALITY_NONCE:
    case ASSH_PRNG_QUALITY_EPHEMERAL_KEY:
    case ASSH_PRNG_QUALITY_LONGTERM_KEY:
      ASSH_RET_IF_TRUE(!RAND_bytes(rdata, rdata_len),
		       ASSH_ERR_CRYPTO);
      break;
    }

  return ASSH_OK;
}

static ASSH_PRNG_CLEANUP_FCN(assh_prng_openssl_cleanup)
{
}

const struct assh_prng_s assh_prng_openssl =
{
  .f_init = assh_prng_openssl_init,
  .f_get = assh_prng_openssl_get,
  .f_cleanup = assh_prng_openssl_cleanup,
};

