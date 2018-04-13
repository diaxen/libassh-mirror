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

#include "config.h"

#include <assh/assh_context.h>
#include <assh/assh_algo.h>
#include <assh/assh_kex.h>
#include <assh/assh_cipher.h>
#include <assh/assh_mac.h>
#include <assh/assh_sign.h>
#include <assh/assh_compress.h>
#include <assh/assh_alloc.h>

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

#ifdef CONFIG_ASSH_QSORTR
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
                                      uint_fast8_t min_speed)
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
	    ASSH_SWAP(c->algos[k], c->algos[i]);
	}
      c->algo_cnt = k;
    next:;
    }
}

static void assh_algo_sort(struct assh_context_s *c,
                           assh_safety_t safety,
                           assh_safety_t min_safety,
                           uint_fast8_t min_speed)
{
  assh_algo_filter_variants(c, min_safety, min_speed);

  /* sort algorithms by class and safety/speed factor */
#ifdef CONFIG_ASSH_QSORTR
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

static assh_error_t assh_algo_extend(struct assh_context_s *c)
{
  assh_error_t err;

  ASSH_RET_IF_TRUE(!c->algo_realloc && c->algos, ASSH_ERR_NOTSUP);
  size_t count = c->algo_max + 16;
  ASSH_RET_ON_ERR(assh_realloc(c, (void**)&c->algos,
                    sizeof(void*) * count, ASSH_ALLOC_INTERNAL));
  c->algo_max = count;
  c->algo_realloc = 1;

  return ASSH_OK;
}

assh_error_t assh_algo_register_static(struct assh_context_s *c,
                                       const struct assh_algo_s *table[])
{
  size_t i = 0;
  uint_fast8_t m = 0;
  assh_error_t err;
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

assh_error_t assh_algo_register(struct assh_context_s *c, assh_safety_t safety,
				assh_safety_t min_safety, uint8_t min_speed,
                                const struct assh_algo_s *table[])
{
  assh_error_t err = ASSH_OK;
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

assh_error_t assh_algo_register_va(struct assh_context_s *c, assh_safety_t safety,
				   assh_safety_t min_safety, uint8_t min_speed, ...)
{
  assh_error_t err = ASSH_OK;
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
      ASSH_RET_IF_TRUE(algo->api != ASSH_ALGO_API_VERSION, ASSH_ERR_BAD_ARG);
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

assh_error_t assh_algo_unregister(struct assh_context_s *c)
{
  assh_error_t err;

  ASSH_RET_IF_TRUE(c->session_count, ASSH_ERR_BUSY);

  if (c->algo_realloc)
    assh_free(c, c->algos);

  c->algo_cnt = c->algo_max = 0;
  c->algos = NULL;

  return ASSH_OK;
}

const struct assh_algo_s *assh_algo_table[] = {
  /* kex */
  &assh_kex_curve25519_sha256.algo,
  &assh_kex_m383_sha384.algo,
  &assh_kex_m511_sha512.algo,
  &assh_kex_dh_group1_sha1.algo,
  &assh_kex_dh_group14_sha1.algo,
  &assh_kex_dh_group14_sha256.algo,
  &assh_kex_dh_group15_sha512.algo,
  &assh_kex_dh_group16_sha512.algo,
  &assh_kex_dh_group17_sha512.algo,
  &assh_kex_dh_group18_sha512.algo,
  &assh_kex_dh_gex_sha1.algo,
  &assh_kex_dh_gex_sha256_12.algo,
  &assh_kex_dh_gex_sha256_8.algo,
  &assh_kex_dh_gex_sha256_4.algo,
  &assh_kex_rsa1024_sha1.algo,
  &assh_kex_rsa2048_sha256.algo,
  &assh_kex_sha2_nistp256.algo,
  &assh_kex_sha2_nistp384.algo,
  &assh_kex_sha2_nistp521.algo,
  /* sign */
  &assh_sign_dsa768.algo,
  &assh_sign_dsa1024.algo,
  &assh_sign_dsa2048_sha224.algo,
  &assh_sign_dsa2048_sha256.algo,
  &assh_sign_dsa3072_sha256.algo,
  &assh_sign_rsa_sha1_md5.algo,
  &assh_sign_rsa_sha1.algo,
  &assh_sign_rsa_sha1_2048.algo,
  &assh_sign_rsa_sha256.algo,
  &assh_sign_rsa_sha512.algo,
  &assh_sign_ed25519.algo,
  &assh_sign_eddsa_e382.algo,
  &assh_sign_eddsa_e521.algo,
  &assh_sign_nistp256.algo,
  &assh_sign_nistp384.algo,
  &assh_sign_nistp521.algo,
  /* ciphers */

# ifdef CONFIG_ASSH_CIPHER_TDES
  &assh_cipher_tdes_cbc.algo,
#  ifdef CONFIG_ASSH_MODE_CTR
  &assh_cipher_tdes_ctr.algo,
#  endif
# endif

# ifdef CONFIG_ASSH_CIPHER_CAST128
  &assh_cipher_cast128_cbc.algo,
#  ifdef CONFIG_ASSH_MODE_CTR
  &assh_cipher_cast128_ctr.algo,
#  endif
# endif

# ifdef CONFIG_ASSH_CIPHER_IDEA
  &assh_cipher_idea_cbc.algo,
#  ifdef CONFIG_ASSH_MODE_CTR
  &assh_cipher_idea_ctr.algo,
#  endif
# endif

# ifdef CONFIG_ASSH_CIPHER_BLOWFISH
  &assh_cipher_blowfish_cbc.algo,
#  ifdef CONFIG_ASSH_MODE_CTR
  &assh_cipher_blowfish_ctr.algo,
#  endif
# endif

# ifdef CONFIG_ASSH_CIPHER_TWOFISH
  &assh_cipher_twofish128_cbc.algo,
  &assh_cipher_twofish256_cbc.algo,
#  ifdef CONFIG_ASSH_MODE_CTR
  &assh_cipher_twofish128_ctr.algo,
  &assh_cipher_twofish256_ctr.algo,
#  endif
#  ifdef CONFIG_ASSH_MODE_GCM
  &assh_cipher_twofish128_gcm.algo,
  &assh_cipher_twofish256_gcm.algo,
#  endif
# endif

# ifdef CONFIG_ASSH_CIPHER_SERPENT
  &assh_cipher_serpent128_cbc.algo,
  &assh_cipher_serpent192_cbc.algo,
  &assh_cipher_serpent256_cbc.algo,
#  ifdef CONFIG_ASSH_MODE_CTR
  &assh_cipher_serpent128_ctr.algo,
  &assh_cipher_serpent192_ctr.algo,
  &assh_cipher_serpent256_ctr.algo,
#  endif
#  ifdef CONFIG_ASSH_MODE_GCM
  &assh_cipher_serpent128_gcm.algo,
  &assh_cipher_serpent256_gcm.algo,
#  endif
# endif

# ifdef CONFIG_ASSH_CIPHER_ARCFOUR
  &assh_cipher_arc4.algo,
  &assh_cipher_arc4_128.algo,
  &assh_cipher_arc4_256.algo,
# endif

# ifdef CONFIG_ASSH_CIPHER_AES
  &assh_cipher_aes128_cbc.algo,
  &assh_cipher_aes192_cbc.algo,
  &assh_cipher_aes256_cbc.algo,
#  ifdef CONFIG_ASSH_MODE_CTR
  &assh_cipher_aes128_ctr.algo,
  &assh_cipher_aes192_ctr.algo,
  &assh_cipher_aes256_ctr.algo,
#  endif
#  ifdef CONFIG_ASSH_MODE_GCM
  &assh_cipher_aes128_gcm.algo,
  &assh_cipher_aes256_gcm.algo,
#  endif
# endif

# ifdef CONFIG_ASSH_CIPHER_CAMELLIA
  &assh_cipher_camellia128_cbc.algo,
  &assh_cipher_camellia192_cbc.algo,
  &assh_cipher_camellia256_cbc.algo,
#  ifdef CONFIG_ASSH_MODE_CTR
  &assh_cipher_camellia128_ctr.algo,
  &assh_cipher_camellia192_ctr.algo,
  &assh_cipher_camellia256_ctr.algo,
#  endif
# endif

# ifdef CONFIG_ASSH_CIPHER_CHACHAPOLY
  &assh_cipher_chachapoly.algo,
# endif

  /* mac */
# ifdef CONFIG_ASSH_HASH_MD5
  &assh_hmac_md5.algo,
  &assh_hmac_md5_96.algo,
  &assh_hmac_md5_etm.algo,
  &assh_hmac_md5_96_etm.algo,
# endif
# ifdef CONFIG_ASSH_HASH_SHA1
  &assh_hmac_sha1.algo,
  &assh_hmac_sha1_96.algo,
  &assh_hmac_sha1_etm.algo,
  &assh_hmac_sha1_96_etm.algo,
# endif
# ifdef CONFIG_ASSH_HASH_SHA2
  &assh_hmac_sha256.algo,
  &assh_hmac_sha512.algo,
  &assh_hmac_sha256_etm.algo,
  &assh_hmac_sha512_etm.algo,
# endif
# ifdef CONFIG_ASSH_HASH_RIPEMD160
  &assh_hmac_ripemd160.algo,
  &assh_hmac_ripemd160_etm.algo,
# endif
  /* compress */
  &assh_compress_none.algo,
# ifdef CONFIG_ASSH_USE_ZLIB
  &assh_compress_zlib.algo,
  &assh_compress_zlib_openssh.algo,
# endif
  NULL
};

assh_error_t assh_algo_by_name(struct assh_context_s *c,
			       enum assh_algo_class_e class_, const char *name,
			       size_t name_len, const struct assh_algo_s **algo,
                               const struct assh_algo_name_s **namep)
{
  uint_fast16_t i;
  const struct assh_algo_s *a;

  for (i = 0; i < c->algo_cnt; i++)
    {
      a = c->algos[i];

      if (class_ == ASSH_ALGO_ANY || a->class_ == class_)
        {
          const struct assh_algo_name_s *n;
          for (n = a->names; n->spec; n++)
            {
              if (!strncmp(name, n->name, name_len) && 
                  n->name[name_len] == '\0')
                {
                  *algo = a;
                  if (namep != NULL)
                    *namep = n;
                  return ASSH_OK;
                }
            }
        }
    }
  return ASSH_NOT_FOUND;
}

assh_error_t assh_algo_by_key(struct assh_context_s *c,
			      const struct assh_key_s *key, uint16_t *pos,
			      const struct assh_algo_s **algo)
{
  uint_fast16_t i = pos == NULL ? 0 : *pos;
  const struct assh_algo_s *a;

  for (; i < c->algo_cnt; i++)
    {
      a = c->algos[i];

      if (a->class_ == key->role &&
          a->f_suitable_key != NULL &&
	  a->f_suitable_key(c, a, key))
	break;
    }

  if (i >= c->algo_cnt)
    return ASSH_NOT_FOUND;

  if (pos != NULL)
    *pos = i;
  *algo = a;
  return ASSH_OK;
}

assh_bool_t
assh_algo_suitable_key(struct assh_context_s *c,
                       const struct assh_algo_s *algo,
                       const struct assh_key_s *key)
{
  if (algo->f_suitable_key == NULL)
    return 0;
  if (key != NULL &&
      key->role != algo->class_)
    return 0;
  return algo->f_suitable_key(c, algo, key);
}

