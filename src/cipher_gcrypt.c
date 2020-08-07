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

#include <assh/assh_cipher.h>
#include <assh/mod_gcrypt.h>

#include <gcrypt.h>

#ifdef CONFIG_ASSH_VALGRIND
# include <valgrind/memcheck.h>
#endif

struct assh_cipher_gcrypt_context_s
{
  const struct assh_algo_cipher_s *ca;
  gcry_cipher_hd_t hd;
  assh_bool_t encrypt;
  uint8_t iv[12];
};

static assh_status_t
assh_cipher_gcrypt_init(const struct assh_algo_cipher_s *ca,
			struct assh_cipher_gcrypt_context_s *ctx,
			const uint8_t *key, const uint8_t *iv,
			int algo, int mode, assh_bool_t encrypt)
{
  assh_status_t err;

  ASSH_RET_IF_TRUE(!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P),
               ASSH_ERR_CRYPTO);

  ASSH_RET_IF_TRUE(gcry_cipher_open(&ctx->hd, algo, mode, 0),
	       ASSH_ERR_CRYPTO);

  ASSH_JMP_IF_TRUE(gcry_cipher_setkey(ctx->hd, key, ca->key_size),
	       ASSH_ERR_CRYPTO, err_open);

  ctx->ca = ca;
  ctx->encrypt = encrypt;

  switch (mode)
    {
    case GCRY_CIPHER_MODE_GCM:
      memcpy(ctx->iv, iv, ca->iv_size);
      break;

    case GCRY_CIPHER_MODE_CBC:
      ASSH_JMP_IF_TRUE(gcry_cipher_setiv(ctx->hd, iv, ca->block_size),
		   ASSH_ERR_CRYPTO, err_open);
      break;

    case GCRY_CIPHER_MODE_CTR:
      ASSH_JMP_IF_TRUE(gcry_cipher_setctr(ctx->hd, iv, ca->block_size),
		   ASSH_ERR_CRYPTO, err_open);
      break;

    case GCRY_CIPHER_MODE_STREAM:

      if (ca == &assh_cipher_gcrypt_arc4_128 ||
	  ca == &assh_cipher_gcrypt_arc4_256)
	{
	  uint8_t dummy[128];
	  uint_fast16_t i;

# ifdef CONFIG_ASSH_VALGRIND
          VALGRIND_MAKE_MEM_DEFINED(dummy, sizeof(dummy));
# endif
	  for (i = 0; i < 1536; i += sizeof(dummy))
	    if (encrypt)
	      ASSH_JMP_IF_TRUE(gcry_cipher_encrypt(ctx->hd, dummy, sizeof(dummy), NULL, 0),
			   ASSH_ERR_CRYPTO, err_open);
	    else
	      ASSH_JMP_IF_TRUE(gcry_cipher_decrypt(ctx->hd, dummy, sizeof(dummy), NULL, 0),
			   ASSH_ERR_CRYPTO, err_open);
	}

      break;
    }

  return ASSH_OK;

 err_open:
  gcry_cipher_close(ctx->hd);
  return err;
}

static ASSH_CIPHER_PROCESS_FCN(assh_cipher_gcrypt_process_GCM)
{
  assh_status_t err;
  struct assh_cipher_gcrypt_context_s *ctx = ctx_;
  size_t auth_size = ctx->ca->auth_size;
  size_t block_size = ctx->ca->block_size;
  size_t csize = len - 4 - auth_size;

  if (op == ASSH_CIPHER_PCK_HEAD)
    return ASSH_OK;

  ASSH_RET_IF_TRUE(csize & (block_size - 1),
               ASSH_ERR_INPUT_OVERFLOW);

  gcry_cipher_setiv(ctx->hd, ctx->iv, 12);
  gcry_cipher_authenticate(ctx->hd, data, 4);

  if (ctx->encrypt)
    {
      ASSH_RET_IF_TRUE(gcry_cipher_encrypt(ctx->hd, data + 4,
				       csize, NULL, 0),
		   ASSH_ERR_CRYPTO);
      gcry_cipher_gettag(ctx->hd, data + len - auth_size, auth_size);
    }
  else
    {
      ASSH_RET_IF_TRUE(gcry_cipher_decrypt(ctx->hd, data + 4,
				       csize, NULL, 0),
		   ASSH_ERR_CRYPTO);
      ASSH_RET_IF_TRUE(gcry_cipher_checktag(ctx->hd,
					data + len - auth_size, auth_size),
		   ASSH_ERR_CRYPTO);
    }

  uint8_t *iv_cnt64 = ctx->iv + 4;
  assh_store_u64(iv_cnt64, assh_load_u64(iv_cnt64) + 1);

  return ASSH_OK;
}

static ASSH_CIPHER_PROCESS_FCN(assh_cipher_gcrypt_process)
{
  assh_status_t err;
  struct assh_cipher_gcrypt_context_s *ctx = ctx_;
  size_t block_size = ctx->ca->block_size;

  ASSH_RET_IF_TRUE(len & (block_size - 1),
	       ASSH_ERR_INPUT_OVERFLOW);

  if (ctx->encrypt)
    ASSH_RET_IF_TRUE(gcry_cipher_encrypt(ctx->hd, data, len, NULL, 0),
		 ASSH_ERR_CRYPTO);
  else
    ASSH_RET_IF_TRUE(gcry_cipher_decrypt(ctx->hd, data, len, NULL, 0),
		 ASSH_ERR_CRYPTO);

  return ASSH_OK;
}

#define assh_cipher_gcrypt_process_CBC assh_cipher_gcrypt_process
#define assh_cipher_gcrypt_process_CTR assh_cipher_gcrypt_process
#define assh_cipher_gcrypt_process_STREAM assh_cipher_gcrypt_process

static ASSH_CIPHER_CLEANUP_FCN(assh_cipher_gcrypt_cleanup)
{
  struct assh_cipher_gcrypt_context_s *ctx = ctx_;
  gcry_cipher_close(ctx->hd);
}

#define ASSH_GCRYPT_CIPHER(id_, algo_, mode_, bsize_, head_size_,       \
			   isize_, ksize_, auth_size_, saf_, spd_, ...) \
									\
extern const struct assh_algo_cipher_s assh_cipher_gcrypt_##id_;	\
									\
static ASSH_CIPHER_INIT_FCN(assh_cipher_gcrypt_##id_##_init)		\
{									\
  return assh_cipher_gcrypt_init(&assh_cipher_gcrypt_##id_, ctx_, key, iv, \
	 GCRY_CIPHER_##algo_, GCRY_CIPHER_MODE_##mode_, encrypt);	\
}									\
									\
const struct assh_algo_cipher_s assh_cipher_gcrypt_##id_ =		\
{									\
  ASSH_ALGO_BASE(CIPHER, "assh-gcrypt", saf_, spd_,                     \
                 ASSH_ALGO_NAMES(__VA_ARGS__)),                         \
  .ctx_size = sizeof(struct assh_cipher_gcrypt_context_s),		\
  .block_size = bsize_,							\
  .iv_size = isize_,							\
  .key_size = ksize_,							\
  .auth_size = auth_size_,						\
  .head_size = head_size_,						\
  .f_init = assh_cipher_gcrypt_##id_##_init,				\
  .f_process = assh_cipher_gcrypt_process_##mode_,			\
  .f_cleanup = assh_cipher_gcrypt_cleanup,				\
};

ASSH_GCRYPT_CIPHER(arc4, ARCFOUR, STREAM,
                   8,  8,  0, 16,  0,  5, 34,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "arcfour" } );
ASSH_GCRYPT_CIPHER(arc4_128, ARCFOUR, STREAM,
                   8,  8,  0, 16,  0, 10, 34,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "arcfour128" } );
ASSH_GCRYPT_CIPHER(arc4_256, ARCFOUR, STREAM,
                   8,  8,  0, 32,  0, 15, 34,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "arcfour256" } );

ASSH_GCRYPT_CIPHER(tdes_cbc, 3DES, CBC,
                   8,  8,  8,  24, 0, 20, 0,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "3des-cbc" } );

ASSH_GCRYPT_CIPHER(tdes_ctr, 3DES, CTR,
                   8,  8,  8,  24, 0, 21, 0,
                   { ASSH_ALGO_STD_IETF, "3des-ctr" } );

ASSH_GCRYPT_CIPHER(cast128_cbc, CAST5, CBC,
                   8, 8, 8, 16, 0, 25, 5,
                   { ASSH_ALGO_STD_IETF, "cast128-cbc" } );

ASSH_GCRYPT_CIPHER(cast128_ctr, CAST5, CTR,
                   8, 8, 8, 16, 0, 26, 17,
                   { ASSH_ALGO_STD_IETF, "cast128-ctr" });

ASSH_GCRYPT_CIPHER(idea_cbc,  IDEA, CBC,
                   8, 8, 8, 16, 0, 25, 4,
                   { ASSH_ALGO_STD_IETF, "idea-cbc" });

ASSH_GCRYPT_CIPHER(idea_ctr,  IDEA, CTR,
                   8, 8, 8, 16, 0, 26, 4,
                   { ASSH_ALGO_STD_IETF, "idea-ctr" });

ASSH_GCRYPT_CIPHER(blowfish_cbc, BLOWFISH, CBC,
                   8,  8,  8,  16, 0, 30, 5,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "blowfish-cbc" });

ASSH_GCRYPT_CIPHER(blowfish_ctr,      BLOWFISH,   CTR,
                   8,  8,  8,  32, 0, 35, 21,
                   { ASSH_ALGO_STD_IETF, "blowfish-ctr" });

ASSH_GCRYPT_CIPHER(aes128_cbc, AES128, CBC,
                   16, 16, 16, 16, 0, 40, 54,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "aes128-cbc" });

ASSH_GCRYPT_CIPHER(aes192_cbc, AES192, CBC,
                   16, 16, 16, 24, 0, 50, 47,
                   { ASSH_ALGO_STD_IETF, "aes192-cbc" });

ASSH_GCRYPT_CIPHER(aes256_cbc,          AES256,     CBC,
                   16, 16, 16, 32, 0, 60, 42,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "aes256-cbc" },
                   { ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_OLDNAME, "rijndael-cbc@lysator.liu.se" });

ASSH_GCRYPT_CIPHER(aes128_ctr,          AES128,     CTR,
                   16, 16, 16, 16, 0, 41, 143,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "aes128-ctr" });

ASSH_GCRYPT_CIPHER(aes192_ctr,          AES192,     CTR,
                   16, 16, 16, 24, 0, 51, 129,
                   { ASSH_ALGO_STD_IETF, "aes192-ctr" });

ASSH_GCRYPT_CIPHER(aes256_ctr,          AES256,     CTR,
                   16, 16, 16, 32, 0, 61, 118,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "aes256-ctr" });

ASSH_GCRYPT_CIPHER(aes128_gcm,  AES128, GCM,
                   16,  4, 12, 16, 16, 41, 96,
                   { ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_COMMON, "aes128-gcm@openssh.com" });

ASSH_GCRYPT_CIPHER(aes256_gcm,  AES256, GCM,
                   16,  4, 12, 32, 16, 61, 85,
                   { ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_COMMON, "aes256-gcm@openssh.com" });

ASSH_GCRYPT_CIPHER(twofish128_cbc,  TWOFISH128, CBC,
                   16, 16, 16, 16, 0, 50, 10,
                   { ASSH_ALGO_STD_IETF, "twofish128-cbc" });

ASSH_GCRYPT_CIPHER(twofish256_cbc,  TWOFISH   , CBC,
                   16, 16, 16, 32, 0, 70, 10,
                   { ASSH_ALGO_STD_IETF, "twofish256-cbc" });

ASSH_GCRYPT_CIPHER(twofish128_ctr,  TWOFISH128, CTR,
                   16, 16, 16, 16, 0, 51, 25,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "twofish128-ctr" });

ASSH_GCRYPT_CIPHER(twofish256_ctr,  TWOFISH,    CTR,
                   16, 16, 16, 32, 0, 71, 25,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "twofish256-ctr" });

ASSH_GCRYPT_CIPHER(twofish128_gcm,  TWOFISH128, GCM,
                   16, 4, 12, 16, 16, 51, 23,
                   { ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_ASSH,
                     "twofish128-gcm@libassh.org" });

ASSH_GCRYPT_CIPHER(twofish256_gcm,  TWOFISH, GCM,
                   16, 4, 12, 32, 16, 71, 23,
                   { ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_ASSH,
                     "twofish256-gcm@libassh.org" });

ASSH_GCRYPT_CIPHER(serpent128_cbc, SERPENT128, CBC,
                   16, 16, 16, 16, 0, 55, 3,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "serpent128-cbc" });

ASSH_GCRYPT_CIPHER(serpent192_cbc, SERPENT192, CBC,
                   16, 16, 16, 24, 0, 65, 3,
                   { ASSH_ALGO_STD_IETF, "serpent192-cbc" });

ASSH_GCRYPT_CIPHER(serpent256_cbc, SERPENT256, CBC,
                   16, 16, 16, 32, 0, 75, 3,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "serpent256-cbc" });

ASSH_GCRYPT_CIPHER(serpent128_ctr,  SERPENT128, CTR,
                   16, 16, 16, 16, 0, 56, 34,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "serpent128-ctr" });

ASSH_GCRYPT_CIPHER(serpent192_ctr,  SERPENT192, CTR,
                   16, 16, 16, 24, 0, 66, 34,
                   { ASSH_ALGO_STD_IETF, "serpent192-ctr" });

ASSH_GCRYPT_CIPHER(serpent256_ctr,  SERPENT256, CTR,
                   16, 16, 16, 32, 0, 76, 34,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "serpent256-ctr" });

ASSH_GCRYPT_CIPHER(serpent128_gcm,  SERPENT128, GCM,
                   16, 4, 12, 16, 16, 56, 31,
                   { ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_ASSH,
                     "serpent128-gcm@libassh.org" });

ASSH_GCRYPT_CIPHER(serpent256_gcm,  SERPENT256, GCM,
                   16, 4, 12, 32, 16, 76, 31,
                   { ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_ASSH,
                     "serpent256-gcm@libassh.org" });

/* https://tools.ietf.org/html/draft-kanno-secsh-camellia-02 */
ASSH_GCRYPT_CIPHER(camellia128_cbc,  CAMELLIA128, CBC,
                   16, 16, 16, 16, 0, 40, 8,
                   { ASSH_ALGO_STD_DRAFT,
                     "camellia128-cbc" });

ASSH_GCRYPT_CIPHER(camellia192_cbc,  CAMELLIA192, CBC,
                   16, 16, 16, 24, 0, 50, 6,
                   { ASSH_ALGO_STD_DRAFT,
                     "camellia192-cbc" });

ASSH_GCRYPT_CIPHER(camellia256_cbc,  CAMELLIA256, CBC,
                   16, 16, 16, 32, 0, 60, 6,
                   { ASSH_ALGO_STD_DRAFT,
                     "camellia256-cbc" });

ASSH_GCRYPT_CIPHER(camellia128_ctr,  CAMELLIA128, CTR,
                   16, 16, 16, 16, 0, 40, 49,
                   { ASSH_ALGO_STD_DRAFT,
                     "camellia128-ctr" });

ASSH_GCRYPT_CIPHER(camellia192_ctr,  CAMELLIA192, CTR,
                   16, 16, 16, 24, 0, 50, 39,
                   { ASSH_ALGO_STD_DRAFT,
                     "camellia192-ctr" });

ASSH_GCRYPT_CIPHER(camellia256_ctr,  CAMELLIA256, CTR,
                   16, 16, 16, 32, 0, 60, 39,
                   { ASSH_ALGO_STD_DRAFT,
                     "camellia256-ctr" });
