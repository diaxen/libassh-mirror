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

#include <assh/assh_sign.h>
#include <assh/assh_context.h>
#include <assh/assh_alloc.h>

#include <assert.h>

static ASSH_KEY_CLEANUP_FCN(assh_sign_none_key_cleanup)
{
  assh_free(c, key, ASSH_ALLOC_KEY);
}

static ASSH_KEY_OUTPUT_FCN(assh_sign_none_key_output)
{
  assert(!strcmp(key->type, "none"));

  *blob_len = 0;
  return ASSH_OK;
}

static ASSH_KEY_CMP_FCN(assh_sign_none_key_cmp)
{
  return 1;
}

static ASSH_KEY_VALIDATE_FCN(assh_sign_none_key_validate)
{
  return ASSH_OK;
}

static ASSH_KEY_LOAD_FCN(assh_sign_none_key_load)
{
  assh_error_t err;

  ASSH_ERR_RET(assh_alloc(c, sizeof(**key), ASSH_ALLOC_KEY, (void**)key));
  struct assh_key_s *k = *key;

  k->type = "none";
  k->f_output = assh_sign_none_key_output;
  k->f_validate = assh_sign_none_key_validate;
  k->f_cmp = assh_sign_none_key_cmp;
  k->f_cleanup = assh_sign_none_key_cleanup;

  return ASSH_OK;
}

static ASSH_SIGN_GENERATE_FCN(assh_sign_none_generate)
{
  *sign_len = 0;

  return ASSH_OK;
}

static ASSH_SIGN_VERIFY_FCN(assh_sign_none_verify)
{
  return ASSH_OK;
}

struct assh_algo_sign_s assh_sign_none =
{
  .algo = {
    .name = "none@libassh.org", .class_ = ASSH_ALGO_SIGN,
    .safety = 0, .speed = 99,
  },
  .f_key_load = assh_sign_none_key_load,
  .f_generate = assh_sign_none_generate,
  .f_verify = assh_sign_none_verify,
};

