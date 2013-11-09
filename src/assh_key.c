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
#include <assh/assh_sign.h>
#include <assh/assh_algo.h>

#include <string.h>

assh_error_t assh_key_load3(struct assh_context_s *c, struct assh_key_s **key,
                            const struct assh_algo_s *algo,
                            const uint8_t *blob, size_t blob_len,
                            enum assh_key_format_e format)
{
  assh_error_t err;
  struct assh_key_s *k;

  switch (algo->class_)
    {
    case ASSH_ALGO_SIGN:
      ASSH_ERR_RET(((struct assh_algo_sign_s*)algo)->f_key_load(c, blob, blob_len, &k, format));
      break;

    default:
      ASSH_ERR_RET(ASSH_ERR_NOTSUP);
    }

  k->algo = algo;
  k->next = *key;
  *key = k;

  return ASSH_OK;
}

assh_error_t assh_key_load2(struct assh_context_s *c, struct assh_key_s **key,
                            const char *algo_name, size_t algo_name_len,
                            const uint8_t *blob, size_t blob_len,
                            enum assh_key_format_e format)
{
  assh_error_t err;
  const struct assh_algo_s *algo;

  ASSH_ERR_RET(assh_algo_by_name(c, ASSH_ALGO_SIGN, algo_name, algo_name_len, &algo));
  ASSH_ERR_RET(assh_key_load3(c, key, algo, blob, blob_len, format));

  return ASSH_OK;
}

void assh_key_drop(struct assh_context_s *c, struct assh_key_s **head)
{
  struct assh_key_s *k = *head;
  *head = k->next;
  k->f_cleanup(c, k);
}

void assh_key_flush(struct assh_context_s *c, struct assh_key_s **head)
{
  while (*head != NULL)
    assh_key_drop(c, head);
}

