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

#include <assh/assh_key.h>
#include <assh/assh_context.h>
#include <assh/assh_alloc.h>

static ASSH_KEY_CLEANUP_FCN(assh_key_none_cleanup)
{
  assh_free(c, key);
}

static ASSH_KEY_OUTPUT_FCN(assh_key_none_output)
{
  assert(key->algo == &assh_key_none);

  *blob_len = 0;
  return ASSH_OK;
}

static ASSH_KEY_CMP_FCN(assh_key_none_cmp)
{
  assert(key->algo == &assh_key_none);
  return 1;
}

#ifdef CONFIG_ASSH_KEY_VALIDATE
static ASSH_KEY_VALIDATE_FCN(assh_key_none_validate)
{
  assert(key->algo == &assh_key_none);
  *result = ASSH_KEY_GOOD;
  return ASSH_OK;
}
#endif

static ASSH_KEY_LOAD_FCN(assh_key_none_load)
{
  assh_status_t err;

  ASSH_RET_ON_ERR(assh_alloc(c, sizeof(**key), ASSH_ALLOC_SECUR, (void**)key));
  struct assh_key_s *k = *key;

  k->algo = &assh_key_none;
  k->type = "none";
  k->safety = 0;

  return ASSH_OK;
}

#ifdef CONFIG_ASSH_KEY_CREATE
static ASSH_KEY_CREATE_FCN(assh_key_none_create)
{
  assh_status_t err;

  ASSH_RET_ON_ERR(assh_alloc(c, sizeof(**key), ASSH_ALLOC_SECUR, (void**)key));
  struct assh_key_s *k = *key;

  k->algo = &assh_key_none;
  k->type = "none";
  k->safety = 0;

  return ASSH_OK;
}
#endif

const struct assh_key_algo_s assh_key_none =
{
  .name = "none",
  .min_bits = 0,
  .bits = 0,
  .max_bits = 0,

  .formats = (enum assh_key_format_e[]){
    ASSH_KEY_FMT_PV_OPENSSH_V1,
    ASSH_KEY_FMT_PUB_RFC4716,
    ASSH_KEY_FMT_PUB_RFC4253,
    ASSH_KEY_FMT_PUB_OPENSSH,
    ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB,
    ASSH_KEY_FMT_PV_OPENSSH_V1_KEY,
    0,
  },

  .f_output = assh_key_none_output,
#ifdef CONFIG_ASSH_KEY_VALIDATE
  .f_validate = assh_key_none_validate,
#endif
  .f_cmp = assh_key_none_cmp,
  .f_load = assh_key_none_load,
#ifdef CONFIG_ASSH_KEY_CREATE
  .f_create = assh_key_none_create,
#endif
  .f_cleanup = assh_key_none_cleanup,
};

