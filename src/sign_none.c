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

#include <assh/assh_sign.h>
#include <assh/assh_context.h>
#include <assh/assh_alloc.h>

static ASSH_SIGN_GENERATE_FCN(assh_sign_none_generate)
{
  *sign_len = 0;

  return ASSH_OK;
}

static ASSH_SIGN_CHECK_FCN(assh_sign_none_check)
{
  *safety = 0;

  return ASSH_OK;
}

static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_none_suitable_key)
{
  if (key == NULL)
    return c->type == ASSH_SERVER;
  return key->algo == &assh_key_none;
}

const struct assh_algo_sign_s assh_sign_none =
{
  ASSH_ALGO_BASE(SIGN, "assh-builtin", 0, 99,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_ASSH,
                      "none@libassh.org" }),
    .f_suitable_key = assh_sign_none_suitable_key,
    .key_algo = &assh_key_none,
  ),
  .f_generate = assh_sign_none_generate,
  .f_check = assh_sign_none_check,
};

