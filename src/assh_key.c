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

#include <assh/assh_key.h>
#include <assh/assh_sign.h>
#include <assh/assh_algo.h>
#include <assh/assh_packet.h>
#include <assh/assh_context.h>
#include <assh/assh_alloc.h>

#include <string.h>

static const struct assh_key_algo_s *
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

      /* try to match key ops type names */

      uint_fast16_t i;
      for (i = 0; i < c->algo_cnt; i++)
        {
          const struct assh_algo_with_key_s *awk
	    = assh_algo_with_key(c->algos[i]);
	  if (!awk)
	    continue;

          const struct assh_key_algo_s *ops = awk->key_algo;
          if (ops == NULL || (role != ASSH_ALGO_ANY &&
			      awk->algo.class_ != role))
            continue;

          if (!assh_string_strcmp(name, name_len, ops->name))
            return ops;
        }

      /* try to match algorithm names */
      const struct assh_algo_s *algo;
      if (!assh_algo_by_name(c, role, name, name_len, &algo, NULL))
	{
          const struct assh_algo_with_key_s *awk
	    = assh_algo_with_key(algo);
          if (awk && awk->key_algo != NULL)
	    return awk->key_algo;
	}

      return NULL;
    }
     
    default:
      return NULL;
    }
}

assh_status_t assh_key_load(struct assh_context_s *c,
                           struct assh_key_s **key,
                           const struct assh_key_algo_s *algo,
                           enum assh_algo_class_e role,
                           enum assh_key_format_e format,
                           const uint8_t **blob, size_t blob_len)
{
  assh_status_t err;

  if (algo == NULL)
    algo = assh_key_algo_guess(c, format, *blob, blob_len, role);
  ASSH_RET_IF_TRUE(algo == NULL, ASSH_ERR_MISSING_ALGO);

  struct assh_key_s *k = NULL;

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
assh_status_t
assh_key_create(struct assh_context_s *c,
                struct assh_key_s **key, size_t bits,
                const struct assh_key_algo_s *algo,
                enum assh_algo_class_e role)
{
  assh_status_t err;
  struct assh_key_s *k;

  if (bits == 0)
    bits = algo->bits;

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

assh_status_t
assh_key_set_comment(struct assh_context_s *c,
                 struct assh_key_s *key,
                 const char *comment)
{
  assh_status_t err;
  assh_free(c, key->comment);
  ASSH_RETURN(assh_strdup(c, &key->comment, comment, ASSH_ALLOC_INTERNAL));
}

const char *
assh_key_get_comment(const struct assh_key_s *key)
{
  return key->comment;
}

const struct assh_key_algo_s *
assh_key_algo(const struct assh_key_s *key)
{
  return key->algo;
}

const char *
assh_key_algo_name(const struct assh_key_algo_s *kya)
{
  return kya->name;
}

const char *
assh_key_algo_implem(const struct assh_key_algo_s *kya)
{
  return kya->implem;
}

const enum assh_key_format_e *
assh_key_algo_formats(const struct assh_key_algo_s *kya)
{
  return kya->formats;
}

assh_bool_t
assh_key_private(const struct assh_key_s *key)
{
  return key->private;
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

assh_status_t
assh_key_lookup(struct assh_context_s *c,
                struct assh_key_s **key, assh_bool_t private,
                const struct assh_algo_with_key_s *awk)
{
  struct assh_key_s *k;

  for (k = c->keys; k; k = k->next)
    if ((!private || k->private) &&
	assh_algo_suitable_key(c, awk, k))
      {
	if (key != NULL)
	  *key = k;
	return ASSH_OK;
      }

  return ASSH_NOT_FOUND;
}

assh_status_t
assh_key_algo_enumerate_static(const struct assh_algo_s **atable,
			       enum assh_algo_class_e cl, size_t *count,
			       const struct assh_key_algo_s **ktable,
			       assh_bool_t dup)
{
  const struct assh_algo_s *a;
  size_t max = *count;
  size_t cnt = 0;

  while ((a = *atable++) != NULL)
    {
      if (cl != ASSH_ALGO_ANY && cl != a->class_)
	continue;

      const struct assh_algo_with_key_s *awk =
	assh_algo_with_key(a);
      if (!awk)
	continue;

      const struct assh_key_algo_s *kya = awk->key_algo;
      if (!kya)
	continue;

      uint_fast16_t j;
      for (j = 0; j < cnt; j++)
	if (dup)
	  {
	    /* discard duplicate pointers only */
	    if (ktable[j] == kya)
	      goto next;
	  }
	else if (!strcmp(ktable[j]->name, kya->name))
	  {
	    if (ktable[j]->priority < kya->priority)
	      ktable[j] = kya;
	    goto next;
	  }

      if (cnt == max)
	return ASSH_NO_DATA;

      ktable[cnt++] = kya;

    next:
      ;
    }

  *count = cnt;
  return ASSH_OK;
}

assh_status_t
assh_key_algo_enumerate_implems(struct assh_context_s *c,
				enum assh_algo_class_e cl, size_t *count,
				const struct assh_key_algo_s **table)
{
  assh_status_t err;
  ASSH_RETURN(assh_key_algo_enumerate_static(c->algos, cl, count, table, 1));
}

assh_status_t
assh_key_algo_enumerate_names(struct assh_context_s *c,
			      enum assh_algo_class_e cl, size_t *count,
			      const struct assh_key_algo_s **table)
{
  assh_status_t err;
  ASSH_RETURN(assh_key_algo_enumerate_static(c->algos, cl, count, table, 0));
}

assh_status_t
assh_key_algo_by_name(const struct assh_context_s *c,
		      enum assh_algo_class_e cl,
		      const char *name, size_t name_len,
		      const struct assh_key_algo_s **algo)
{
  uint_fast16_t i;

  for (i = 0; i < c->algo_cnt; i++)
    {
      const struct assh_algo_with_key_s *awk =
	assh_algo_with_key(c->algos[i]);

      if (!awk)
	continue;

      if (cl != ASSH_ALGO_ANY && cl != awk->algo.class_)
	continue;

      if (awk->key_algo && !assh_string_strcmp(name, name_len, awk->key_algo->name))
	{
	  *algo = awk->key_algo;
	  return ASSH_OK;
	}
    }

  return ASSH_NOT_FOUND;
}

assh_status_t
assh_key_output(struct assh_context_s *c,
                const struct assh_key_s *key,
                uint8_t *blob, size_t *blob_len,
                enum assh_key_format_e format)
{
  return key->algo->f_output(c, key, blob, blob_len, format);
}

assh_bool_t
assh_key_cmp(struct assh_context_s *c, const struct assh_key_s *key,
	     const struct assh_key_s *b, assh_bool_t pub)
{
  return key->algo->f_cmp(c, key, b, pub);
}

void
assh_key_flush(struct assh_context_s *c,
               struct assh_key_s **head)
{
  while (*head != NULL)
    assh_key_drop(c, head);
}

void
assh_key_insert(struct assh_key_s **head,
                struct assh_key_s *key)
{
  key->next = *head;
  *head = key;
}

void
assh_key_refinc(struct assh_key_s *key)
{
  key->ref_count++;
}

#ifdef CONFIG_ASSH_KEY_VALIDATE
assh_status_t
assh_key_validate(struct assh_context_s *c,
                  const struct assh_key_s *key,
                  enum assh_key_validate_result_e *result)
{
  *result = ASSH_KEY_BAD;
  return key->algo->f_validate(c, key, result);
}
#endif

const char *
assh_key_type_name(struct assh_key_s *key)
{
  return key->type ? key->type : key->algo->name;
}

assh_safety_t
assh_key_safety(struct assh_key_s *key)
{
  return key->safety;
}

size_t
assh_key_bits(struct assh_key_s *key)
{
  return key->bits;
}

const char *
assh_key_safety_name(struct assh_key_s *key)
{
  return assh_safety_name(key->safety);
}

static const struct assh_key_format_desc_s
assh_key_format_table[ASSH_KEY_FMT_LAST + 1] = {
  [ASSH_KEY_FMT_PV_OPENSSH_V1] = {
    "openssh_v1", "openssh v1 ASCII private keys",
    .public = 0, .internal = 0, .encrypted = 1, .pub_part = 0
  },
  [ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB] = {
    "openssh_v1_bin", "openssh_v1 underlying binary",
    .public = 0, .internal = 1, .encrypted = 1, .pub_part = 0
  },
  [ASSH_KEY_FMT_PV_OPENSSH_V1_KEY] = {
    "openssh_v1_pv", "openssh_v1_bin underlying single private key",
    .public = 0, .internal = 1, .encrypted = 0, .pub_part = 0
  },
  [ASSH_KEY_FMT_PV_PEM] = {
    "pem_pv", "PEM ASCII private key",
    .public = 0, .internal = 0, .encrypted = 1, .pub_part = 0
  },
  [ASSH_KEY_FMT_PV_PEM_ASN1] = {
    "pem_pv_bin", "PEM private key underlying binary",
    .public = 0, .internal = 1, .encrypted = 0, .pub_part = 0
  },
  [ASSH_KEY_FMT_PUB_RFC4716] = {
    "rfc4716", "ssh standard ASCII public key",
    .public = 1, .internal = 0, .encrypted = 0, .pub_part = 0
  },
  [ASSH_KEY_FMT_PUB_RFC4253] = {
    "rfc4253", "ssh standard binary public key",
    .public = 1, .internal = 1, .encrypted = 0, .pub_part = 0
  },
  [ASSH_KEY_FMT_PUB_OPENSSH] = {
    "openssh_pub", "openssh legacy ASCII public key",
    .public = 1, .internal = 0, .encrypted = 0, .pub_part = 0
  },
  [ASSH_KEY_FMT_PUB_OPENSSH_V1] = {
    "openssh_v1_pub", "openssh v1 ASCII key, public part",
    .public = 1, .internal = 0, .encrypted = 0, .pub_part = 1
  },
  [ASSH_KEY_FMT_PUB_OPENSSH_V1_BLOB] = {
    "openssh_v1_pub_bin", "openssh_v1 underlying binary, public part",
    .public = 1, .internal = 1, .encrypted = 0, .pub_part = 1
  },
  [ASSH_KEY_FMT_PUB_PEM] = {
    "pem_pub", "PEM ASCII public key",
    .public = 1, .internal = 0, .encrypted = 0, .pub_part = 0
  },
  [ASSH_KEY_FMT_PUB_PEM_ASN1] = {
    "pem_pub_bin", "PEM public key underlying binary",
    .public = 1, .internal = 1, .encrypted = 0, .pub_part = 0
  },
};

const struct assh_key_format_desc_s *
assh_key_format_desc(enum assh_key_format_e fmt)
{
  if (fmt > ASSH_KEY_FMT_LAST)
    return NULL;
  return assh_key_format_table + fmt;
}
