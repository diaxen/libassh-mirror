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

#include <assh/assh_prng.h>

#include "prng_weak.h"

static const struct assh_buffer_s context_prng_seed = {
  .str = "abcdefgh",
  .len = 8
};

static ASSH_PRNG_INIT_FCN(assh_prng_dummy_init)
{
  uint64_t *s = malloc(8);

  if (!s)
    return ASSH_ERR_MEM;

  c->prng_pv = s;

  if (seed->size < 8)
    return ASSH_ERR_BAD_ARG;
  *s = assh_load_u64le(seed->data);
  *s |= !*s;

  return ASSH_OK;
}

static ASSH_PRNG_GET_FCN(assh_prng_dummy_get)
{
  uint64_t *s = c->prng_pv;

  size_t i;
  for (i = 0; i < rdata_len; i++)
    rdata[i] = assh_prng_rand_seed(s);

  return ASSH_OK;
}

static ASSH_PRNG_CLEANUP_FCN(assh_prng_dummy_cleanup)
{
  free(c->prng_pv);
}

static const struct assh_prng_s assh_prng_dummy =
{
  .f_init = assh_prng_dummy_init,
  .f_get = assh_prng_dummy_get,
  .f_cleanup = assh_prng_dummy_cleanup,
};

