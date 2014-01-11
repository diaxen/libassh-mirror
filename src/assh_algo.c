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


#include <assh/assh_context.h>
#include <assh/assh_algo.h>
#include <assh/assh_kex.h>
#include <assh/assh_cipher.h>
#include <assh/assh_mac.h>
#include <assh/assh_sign.h>
#include <assh/assh_compress.h>

#include <string.h>
#include <stdarg.h>

static int assh_algo_order(const struct assh_algo_s *a,
			   const struct assh_algo_s *b,
			   unsigned int safety)
{
  if (a->class_ != b->class_)
    return a->class_ - b->class_;
  return ((b->speed * (99 - safety) + b->safety * safety) -
	  (a->speed * (99 - safety) + a->safety * safety));
}

assh_error_t assh_algo_register_va(struct assh_context_s *c, unsigned int safety,
				   unsigned int min_safety, ...)
{
  assh_error_t err = ASSH_OK;
  va_list ap;
  va_start(ap, min_safety);

  /* append algorithms to the array */
  while (1)
    {
      struct assh_algo_s *algo = va_arg(ap, void*);
      if (algo == NULL)
        break;
      if (algo->safety < min_safety)
	continue;
      ASSH_ERR_GTO(c->algos_count == ASSH_MAX_ALGORITHMS ? ASSH_ERR_MEM : 0, err_);
      c->algos[c->algos_count++] = algo;
    }
 err_:

  va_end(ap);

  if (safety == (unsigned int)-1)
    return err;

  ASSH_ERR_RET(safety > 99 ? ASSH_ERR_OVERFLOW : 0);

  /* sort algorithms by class and safety/speed factor */
  int i, j, k;
  for (i = 0; i < c->algos_count; i++)
    {
      const struct assh_algo_s *a = c->algos[i];
      for (j = i - 1; j >= 0; j--)
	{
	  const struct assh_algo_s *b = c->algos[j];
	  if (assh_algo_order(a, b, safety) > 0)
	    break;
	  c->algos[j + 1] = b;
	}
      c->algos[j + 1] = a;
    }

  /* remove duplicated names in the same class */
  for (i = 0; i < c->algos_count; i++)
    {
      for (k = j = i + 1; j < c->algos_count; j++)
	{
	  const struct assh_algo_s *a = c->algos[i];
	  const struct assh_algo_s *b = c->algos[j];

	  int d = a->class_ != b->class_;
	  if (k < j)
	    c->algos[k] = b;
	  else if (d)
	    goto next;
	  if (d || strcmp(a->name, b->name))
	    k++;
	}
      c->algos_count = k;
    next:;
    }

  return err;
}

assh_error_t assh_algo_register_default(struct assh_context_s *c, unsigned int safety,
					unsigned int min_safety)
{
  assh_error_t err;

#ifdef CONFIG_ASSH_USE_GCRYPT_CIPHERS
  ASSH_ERR_RET(assh_cipher_register_gcrypt(c, -1, min_safety));
#endif

  ASSH_ERR_RET(assh_algo_register_va(c, safety, min_safety,
			/* kex_dh.c */
			&assh_kex_dh_group1_sha1,
			&assh_kex_dh_group14_sha1,
			/* sign_dss.c */
			&assh_sign_dss,

#ifndef CONFIG_ASSH_USE_GCRYPT_CIPHERS
			/* cipher_arc4_builting.c */
			&assh_cipher_arc4,
			&assh_cipher_arc4_128,
			&assh_cipher_arc4_256,
#endif
			/* mac_sha1.c */
			&assh_hmac_sha1,
			&assh_hmac_sha1_96,
			/* compress_none.c */
			&assh_compress_none,
				     NULL));

  return ASSH_OK;
}

assh_error_t assh_algo_by_name(struct assh_context_s *c,
			       enum assh_algo_class_e class_, const char *name,
			       size_t name_len, const struct assh_algo_s **algo)
{
  unsigned int i;
  const struct assh_algo_s *a;

  for (i = 0; i < c->algos_count; i++)
    {
      a = c->algos[i];

      if (a->class_ == class_ &&
          !strncmp(name, a->name, name_len) && 
          a->name[name_len] == '\0')
	break;
    }

  if (i == c->algos_count)
    return ASSH_NOT_FOUND;

  *algo = a;
  return ASSH_OK;
}

