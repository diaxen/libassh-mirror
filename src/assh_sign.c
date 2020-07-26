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

#define ASSH_PV

#include <assh/assh_sign.h>

assh_status_t
assh_algo_sign_by_key(struct assh_context_s *c,
		      const struct assh_key_s *key, assh_algo_id_t *pos,
		      const struct assh_algo_sign_s **sa)
{
  assh_status_t err;
  if (key->role != ASSH_ALGO_SIGN)
    ASSH_RETURN(ASSH_ERR_MISSING_KEY);
  return assh_algo_by_key(c, key, pos,
    (const struct assh_algo_with_key_s **)sa);
}

assh_status_t
assh_sign_generate(struct assh_context_s *c, const struct assh_algo_sign_s *sa,
                   const struct assh_key_s *key, size_t data_count,
                   const struct assh_cbuffer_s data[],
                   uint8_t *sign, size_t *sign_len)
{
  assh_status_t err;
  ASSH_RET_IF_TRUE(key->algo != sa->algo_wk.key_algo, ASSH_ERR_BAD_ARG);
  ASSH_RET_IF_TRUE(sign && !key->private, ASSH_ERR_MISSING_KEY);
  return sa->f_generate(c, key, data_count, data, sign, sign_len);
}

assh_status_t
assh_sign_check(struct assh_context_s *c, const struct assh_algo_sign_s *sa,
                const struct assh_key_s *key, size_t data_count,
                const struct assh_cbuffer_s data[],
                const uint8_t *sign, size_t sign_len, assh_safety_t *safety)
{
  assh_status_t err;
  ASSH_RET_IF_TRUE(key->algo != sa->algo_wk.key_algo, ASSH_ERR_BAD_ARG);
  *safety = assh_min_uint(sa->algo_wk.algo.safety, key->safety);
  return sa->f_check(c, key, data_count, data, sign, sign_len, safety);
}

