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
#include <assh/assh_packet.h>
#include <assh/assh_context.h>
#include <assh/assh_alloc.h>

#include <string.h>

static const struct assh_key_ops_s *
assh_key_algo_guess(struct assh_context_s *c,
                    enum assh_key_format_e format,
                    const uint8_t *blob, size_t blob_len,
                    enum assh_algo_class_e role)
{
  switch (format)
    {
    case ASSH_KEY_FMT_PV_OPENSSH_V1_KEY:
    case ASSH_KEY_FMT_PUB_RFC4253: {

      /* extract key type string from blob */
      const uint8_t *end;
      if (assh_check_string(blob, blob_len, blob, &end))
        return NULL;
      const char *name = (const char*)blob + 4;
      size_t name_len = end - blob - 4;

      const struct assh_algo_s *algo;

      /* try to match key ops type names */
      uint_fast16_t i;
      for (i = 0; i < c->algo_cnt; i++)
        {
          algo = c->algos[i];

          const struct assh_key_ops_s *ops = algo->key;
          if (ops == NULL || algo->class_ != role)
            continue;

          if (!strncmp(ops->type, name, name_len) &&
              !ops->type[name_len])
            return ops;
        }

      /* try to match algorithm names */
      if (!assh_algo_by_name(c, role, name, name_len, &algo, NULL) &&
          algo->key != NULL)
        return algo->key;

      return NULL;
    }
     
    default:
      return NULL;
    }
}

assh_error_t assh_key_load(struct assh_context_s *c,
                           struct assh_key_s **key,
                           const struct assh_key_ops_s *algo,
                           enum assh_algo_class_e role,
                           enum assh_key_format_e format,
                           const uint8_t **blob, size_t blob_len)
{
  assh_error_t err;

  if (algo == NULL)
    algo = assh_key_algo_guess(c, format, *blob, blob_len, role);
  ASSH_RET_IF_TRUE(algo == NULL, ASSH_ERR_MISSING_ALGO);

  struct assh_key_s *k;

  ASSH_RET_ON_ERR(algo->f_load(c, algo, blob, blob_len, &k, format));

  k->role = role;
  k->next = *key;
  k->ref_count = 1;
  k->stored = 0;
  k->comment = NULL;
  *key = k;

  return ASSH_OK;
}

#ifdef CONFIG_ASSH_KEY_CREATE
assh_error_t
assh_key_create(struct assh_context_s *c,
                struct assh_key_s **key, size_t bits,
                const struct assh_key_ops_s *algo,
                enum assh_algo_class_e role)
{
  assh_error_t err;
  struct assh_key_s *k;

  ASSH_RET_ON_ERR(algo->f_create(c, algo, bits, &k));

  k->role = role;
  k->next = *key;
  k->ref_count = 1;
  k->stored = 0;
  k->comment = NULL;
  *key = k;

  return ASSH_OK;
}
#endif

assh_error_t
assh_key_comment(struct assh_context_s *c,
                 struct assh_key_s *key,
                 const char *comment)
{
  assh_error_t err;
  assh_free(c, key->comment);
  ASSH_RETURN(assh_strdup(c, &key->comment, comment, ASSH_ALLOC_INTERNAL));
}

void assh_key_drop(struct assh_context_s *c,
                   struct assh_key_s **head)
{
  struct assh_key_s *k = *head;
  if (k != NULL)
    {
      *head = k->next;
      if (!--k->ref_count)
        {
          assh_free(c, k->comment);
          k->algo->f_cleanup(c, (struct assh_key_s *)k);
        }
    }
}

assh_error_t
assh_key_lookup(struct assh_context_s *c,
                struct assh_key_s **key,
                const struct assh_algo_s *algo)
{
  struct assh_key_s *k = c->keys;

  while (k != NULL && !assh_algo_suitable_key(c, algo, k))
    k = k->next;
  if (k == NULL)
    return ASSH_NOT_FOUND;

  if (key != NULL)
    *key = k;

  return ASSH_OK;
}

