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

#ifdef CONFIG_ASSH_USE_GCRYPT
#include <assh/cipher_gcrypt.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

static assh_error_t assh_algo_register_(struct assh_context_s *c,
                                        struct assh_algo_s *algo)
{
  assh_error_t err;

  ASSH_ERR_RET(c->algos_count == ASSH_MAX_ALGORITHMS ? ASSH_ERR_OVERFLOW : 0);
  c->algos[c->algos_count++] = algo;
  return ASSH_OK;
}

static int assh_algo_order(const void *a_, const void *b_)
{
  const struct assh_algo_s *a = *(const struct assh_algo_s **)a_,
                           *b = *(const struct assh_algo_s **)b_;

  if (a->class_ != b->class_)
    return a->class_ - b->class_;
  return b->priority - a->priority;
}

assh_error_t assh_algo_register(struct assh_context_s *c,
                                struct assh_algo_s *algo)
{
  assh_error_t err;

  ASSH_ERR_RET(assh_algo_register_(c, algo));
  qsort(c->algos, c->algos_count, sizeof(struct assh_algo_s *), assh_algo_order);

  return ASSH_OK;
}

assh_error_t assh_algo_register_va(struct assh_context_s *c, ...)
{
  assh_error_t err = ASSH_OK;
  va_list ap;
  va_start(ap, c);

  while (1)
    {
      struct assh_algo_s *algo = va_arg(ap, void*);
      if (algo == NULL)
        break;
      ASSH_ERR_GTO(assh_algo_register_(c, algo), err_);
    }
 err_:
  qsort(c->algos, c->algos_count, sizeof(struct assh_algo_s *), assh_algo_order);

  va_end(ap);
  return err;
}

assh_error_t assh_kex_register_builtin(struct assh_context_s *c)
{
  return assh_algo_register_va(c, 
                               /* kex_dh.c */
                               &assh_kex_dh_group1_sha1,
                               &assh_kex_dh_group14_sha1,
                               NULL);
}

assh_error_t assh_sign_register_builtin(struct assh_context_s *c)
{
  return assh_algo_register_va(c, 
                               /* sign_dss.c */
                               &assh_sign_dss,
                               NULL);
}

assh_error_t assh_cipher_register_builtin(struct assh_context_s *c)
{
  return assh_algo_register_va(c,
                               /* cipher_arc4.c */
                               &assh_cipher_arc4,
                               &assh_cipher_arc4_128,
                               &assh_cipher_arc4_256,
                               NULL);
}

assh_error_t assh_mac_register_builtin(struct assh_context_s *c)
{
  return assh_algo_register_va(c, 
                               /* mac_sha1.c */
                               &assh_hmac_sha1,
                               &assh_hmac_sha1_96,
                               NULL);
}

assh_error_t assh_compress_register_builtin(struct assh_context_s *c)
{
  return assh_algo_register_va(c,
                               /* compress_none.c */
                               &assh_compress_none,
                               NULL);
}

assh_error_t assh_algo_register_builtin(struct assh_context_s *c)
{
  return assh_algo_register_va(c, 
                               /* kex_dh.c */
                               &assh_kex_dh_group1_sha1,
                               &assh_kex_dh_group14_sha1,
                               /* sign_dss.c */
                               &assh_sign_dss,
                               /* cipher_arc4.c */
                               &assh_cipher_arc4,
                               &assh_cipher_arc4_128,
                               &assh_cipher_arc4_256,
                               /* mac_sha1.c */
                               &assh_hmac_sha1,
                               &assh_hmac_sha1_96,
                               /* compress_none.c */
                               &assh_compress_none,
                               NULL);
}

assh_error_t assh_algo_register_default(struct assh_context_s *c)
{
  assh_error_t err;
#ifdef CONFIG_ASSH_USE_GCRYPT
  ASSH_ERR_RET(assh_kex_register_builtin(c));
  ASSH_ERR_RET(assh_sign_register_builtin(c));
  ASSH_ERR_RET(assh_cipher_register_gcrypt(c));
  ASSH_ERR_RET(assh_mac_register_builtin(c));
  ASSH_ERR_RET(assh_compress_register_builtin(c));
#else
  ASSH_ERR_RET(assh_algo_register_builtin(c));
#endif

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

