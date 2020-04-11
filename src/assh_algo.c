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

#include "config.h"

#include <assh/assh_context.h>
#include <assh/assh_algo.h>
#include <assh/assh_alloc.h>
#include <assh/assh_buffer.h>
#include <assh/assh_key.h>

#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

static int_fast16_t assh_algo_order(const struct assh_algo_s *a,
                                    const struct assh_algo_s *b,
                                    assh_safety_t safety)
{
  if (a->class_ != b->class_)
    return a->class_ - b->class_;
  return ASSH_ALGO_SCORE(b, safety) - ASSH_ALGO_SCORE(a, safety);
}

#ifdef CONFIG_ASSH_GNU_QSORTR
static int assh_algo_qsort_cmp(const void *a, const void *b, void *arg)
{
  struct assh_algo_s * const *a_ = a;
  struct assh_algo_s * const *b_ = b;
  uint_fast8_t *s = arg;
  return assh_algo_order(*a_, *b_, *s);
}
#endif

static void assh_algo_filter_variants(struct assh_context_s *c,
                                      assh_safety_t min_safety,
                                      assh_speed_t min_speed)
{
  /* remove duplicated names in the same class */
  int_fast16_t i, j, k;
  for (i = 0; i < c->algo_cnt; i++)
    {
      for (k = j = i + 1; j < c->algo_cnt; j++)
	{
	  const struct assh_algo_s *a = c->algos[i];
	  const struct assh_algo_s *b = c->algos[j];

	  assh_bool_t d = a->class_ != b->class_;
	  if (k < j)
	    c->algos[k] = b;
	  else if (d)
	    goto next;
          const struct assh_algo_name_s *na, *nb;
          if (!d++)
            for (na = a->names; d && na->spec; na++)
              for (nb = b->names; d && nb->spec; nb++)
                if (!strcmp(na->name, nb->name))
                  d = 0;
          if (d)
            k++;
	  else if (a->priority < b->priority ||
                   a->safety < min_safety ||
                   a->speed < min_speed)
	    ASSH_SWAP(const struct assh_algo_s *,
		      c->algos[k], c->algos[i]);
	}
      c->algo_cnt = k;
    next:;
    }
}

static void assh_algo_sort(struct assh_context_s *c,
                           assh_safety_t safety,
                           assh_safety_t min_safety,
                           assh_speed_t min_speed)
{
  assh_algo_filter_variants(c, min_safety, min_speed);

  /* sort algorithms by class and safety/speed factor */
#ifdef CONFIG_ASSH_GNU_QSORTR
  qsort_r(c->algos, c->algo_cnt, sizeof(void*), assh_algo_qsort_cmp, &safety);
#else
  int_fast16_t i;

  for (i = 0; i < c->algo_cnt; i++)
    {
      const struct assh_algo_s *a = c->algos[i];
      int_fast16_t j;

      for (j = i - 1; j >= 0; j--)
	{
	  const struct assh_algo_s *b = c->algos[j];
	  if (assh_algo_order(a, b, safety) > 0)
	    break;
	  c->algos[j + 1] = b;
	}
      c->algos[j + 1] = a;
    }
#endif
}

static void assh_algo_kex_init_size(struct assh_context_s *c)
{
  int_fast16_t i;
  size_t kex_init_size = /* random cookie */ 16;
  enum assh_algo_class_e last = ASSH_ALGO_ANY;

  for (i = 0; i < c->algo_cnt; i++)
    {
      const struct assh_algo_s *a = c->algos[i];
      size_t l = 0;

      if (a->class_ == last)
	l++;	/* strlen(",") */
      else
	l += 4;	/* string header */
      const struct assh_algo_name_s *n;
      for (n = a->names; n->spec; n++)
        l += /* strlen(",") */ (n != a->names)
          + strlen(n->name);
      switch (a->class_)
	{
	case ASSH_ALGO_KEX:
	case ASSH_ALGO_SIGN:
	  kex_init_size += l;
	  break;
	case ASSH_ALGO_CIPHER:
	case ASSH_ALGO_MAC:
	case ASSH_ALGO_COMPRESS:
	  kex_init_size += l * 2;
	default:
	  break;
        }
      last = a->class_;
    }
  kex_init_size += /* empty languages */ 4 * 2 + /* fkpf */ 1 + /* reserved */ 4;
  c->kex_init_size = kex_init_size;
}

static assh_status_t assh_algo_extend(struct assh_context_s *c)
{
  assh_status_t err;

  ASSH_RET_IF_TRUE(!c->algo_realloc && c->algos, ASSH_ERR_NOTSUP);
  size_t count = c->algo_max + 16;
  ASSH_RET_ON_ERR(assh_realloc(c, (void**)&c->algos,
                    sizeof(void*) * count, ASSH_ALLOC_INTERNAL));
  c->algo_max = count;
  c->algo_realloc = 1;

  return ASSH_OK;
}

assh_status_t assh_algo_register_static(struct assh_context_s *c,
                                       const struct assh_algo_s *table[])
{
  size_t i = 0;
  uint_fast8_t m = 0;
  assh_status_t err;
  const struct assh_algo_s *l, *a = table[0];

  ASSH_RET_IF_TRUE(c->session_count, ASSH_ERR_BUSY);
  ASSH_RET_IF_TRUE(c->algo_realloc && c->algos, ASSH_ERR_BUSY);

  while ((l = table[i]))
    {
      /* check class order */
      m |= 1 << l->class_;
      ASSH_RET_IF_TRUE(a->class_ > l->class_, ASSH_ERR_BAD_ARG);
      i++;
      a = l;
    }

  /* check that all classes are represented */
  ASSH_RET_IF_TRUE(m != 0x1f, ASSH_ERR_BAD_ARG);

  c->algo_cnt = c->algo_max = i;
  c->algo_realloc = 0;
  c->algos = table;

  assh_algo_kex_init_size(c);

  return ASSH_OK;
}

assh_status_t assh_algo_register(struct assh_context_s *c, assh_safety_t safety,
				assh_safety_t min_safety, assh_speed_t min_speed,
                                const struct assh_algo_s *table[])
{
  assh_status_t err = ASSH_OK;
  size_t i, count = c->algo_cnt;

  ASSH_RET_IF_TRUE(c->session_count, ASSH_ERR_BUSY);
  ASSH_RET_IF_TRUE(safety > 99, ASSH_ERR_BAD_ARG);

  for (i = 0; table[i] != NULL; i++)
    {
      const struct assh_algo_s *algo = table[i];
      ASSH_RET_IF_TRUE(algo->api != ASSH_ALGO_API_VERSION, ASSH_ERR_BAD_ARG);
      if (algo->safety < min_safety || algo->speed < min_speed)
	continue;
      if (count == c->algo_max)
        ASSH_RET_ON_ERR(assh_algo_extend(c));
      c->algos[count++] = algo;
    }

  c->algo_cnt = count;
  assh_algo_sort(c, safety, min_safety, min_speed);
  assh_algo_kex_init_size(c);

  return ASSH_OK;
}

const struct assh_algo_s *
assh_algo_registered(struct assh_context_s *c, uint_fast16_t i)
{
  if (i >= c->algo_cnt)
    return NULL;
  return c->algos[i];
}

assh_status_t assh_algo_register_va(struct assh_context_s *c, assh_safety_t safety,
				   assh_safety_t min_safety, assh_speed_t min_speed, ...)
{
  assh_status_t err = ASSH_OK;
  va_list ap;
  size_t count = c->algo_cnt;

  ASSH_RET_IF_TRUE(c->session_count, ASSH_ERR_BUSY);
  ASSH_RET_IF_TRUE(safety > 99, ASSH_ERR_BAD_ARG);

  va_start(ap, min_speed);

  /* append algorithms to the array */
  while (1)
    {
      struct assh_algo_s *algo = va_arg(ap, void*);
      if (algo == NULL)
        break;
      ASSH_JMP_IF_TRUE(algo->api != ASSH_ALGO_API_VERSION, ASSH_ERR_BAD_ARG, err_);
      if (algo->safety < min_safety || algo->speed < min_speed)
	continue;
      if (count == c->algo_max)
        ASSH_JMP_ON_ERR(assh_algo_extend(c), err_);
      c->algos[count++] = algo;
    }

  c->algo_cnt = count;
  assh_algo_sort(c, safety, min_safety, min_speed);
  assh_algo_kex_init_size(c);

 err_:
  va_end(ap);
  return err;
}

assh_status_t assh_algo_register_names_va(struct assh_context_s *c, assh_safety_t safety,
					  assh_safety_t min_safety, assh_speed_t min_speed,
					  enum assh_algo_class_e class_, ...)
{
  assh_status_t err = ASSH_OK;
  va_list ap;
  size_t count = c->algo_cnt;
  const char *name;

  ASSH_RET_IF_TRUE(c->session_count, ASSH_ERR_BUSY);
  ASSH_RET_IF_TRUE(safety > 99, ASSH_ERR_BAD_ARG);

  va_start(ap, class_);

  /* append algorithms to the array */
  while ((name = va_arg(ap, const char *)))
    {
      const struct assh_algo_s *algo;

      if (assh_algo_by_name_static(assh_algo_table, class_,
				   name, strlen(name), &algo, NULL))
	continue;

      if (algo->safety < min_safety || algo->speed < min_speed)
	continue;
      if (count == c->algo_max)
        ASSH_JMP_ON_ERR(assh_algo_extend(c), err_);
      c->algos[count++] = algo;
    }

  ASSH_JMP_IF_TRUE(c->algo_cnt == count, ASSH_ERR_MISSING_ALGO, err_);

  c->algo_cnt = count;
  assh_algo_sort(c, safety, min_safety, min_speed);
  assh_algo_kex_init_size(c);

 err_:
  va_end(ap);
  return err;
}

assh_status_t assh_algo_unregister(struct assh_context_s *c)
{
  assh_status_t err;

  ASSH_RET_IF_TRUE(c->session_count, ASSH_ERR_BUSY);

  if (c->algo_realloc)
    assh_free(c, c->algos);

  c->algo_cnt = c->algo_max = 0;
  c->algos = NULL;

  return ASSH_OK;
}

const struct assh_algo_name_s *
assh_algo_name_match(const struct assh_algo_s *a,
                     enum assh_algo_class_e class_,
                     const char *name, size_t name_len)
{
  if (class_ == ASSH_ALGO_ANY || a->class_ == class_)
    {
      const struct assh_algo_name_s *n;
      for (n = a->names; n->spec; n++)
	if (!assh_string_strcmp(name, name_len, n->name))
	  return n;
    }
  return NULL;
}

assh_status_t
assh_algo_by_name_static(const struct assh_algo_s **table,
                         enum assh_algo_class_e class_, const char *name,
                         size_t name_len, const struct assh_algo_s **algo,
                         const struct assh_algo_name_s **namep)
{
  const struct assh_algo_s *a;

  while ((a = *table++) != NULL)
    {
      const struct assh_algo_name_s *n
        = assh_algo_name_match(a, class_, name, name_len);
      if (n != NULL)
        {
          *algo = a;
          if (namep != NULL)
            *namep = n;
          return ASSH_OK;
        }
    }

  return ASSH_NOT_FOUND;
}

assh_status_t
assh_algo_by_name(struct assh_context_s *c,
                  enum assh_algo_class_e class_, const char *name,
                  size_t name_len, const struct assh_algo_s **algo,
                  const struct assh_algo_name_s **namep)
{
  uint_fast16_t i;

  for (i = 0; i < c->algo_cnt; i++)
    {
      const struct assh_algo_s *a = c->algos[i];
      const struct assh_algo_name_s *n
        = assh_algo_name_match(a, class_, name, name_len);
      if (n != NULL)
        {
          *algo = a;
          if (namep != NULL)
            *namep = n;
          return ASSH_OK;
        }
    }
  return ASSH_NOT_FOUND;
}

assh_status_t assh_algo_by_key(struct assh_context_s *c,
			      const struct assh_key_s *key, uint16_t *pos,
			      const struct assh_algo_with_key_s **awk_)
{
  uint_fast16_t i = pos == NULL ? 0 : *pos;
  const struct assh_algo_with_key_s *awk;

  for (; i < c->algo_cnt; i++)
    {
      awk = assh_algo_with_key(c->algos[i]);

      if (awk && awk->algo.class_ == key->role &&
	  awk->f_suitable_key != NULL &&
	  awk->f_suitable_key(c, awk, key))
	break;
    }

  if (i >= c->algo_cnt)
    return ASSH_NOT_FOUND;

  if (pos != NULL)
    *pos = i;
  *awk_ = awk;
  return ASSH_OK;
}

assh_bool_t
assh_algo_suitable_key(struct assh_context_s *c,
                       const struct assh_algo_with_key_s *awk,
                       const struct assh_key_s *key)
{
  if (awk->f_suitable_key == NULL)
    return 0;
  if (key != NULL &&
      key->role != awk->algo.class_)
    return 0;
  return awk->f_suitable_key(c, awk, key);
}

