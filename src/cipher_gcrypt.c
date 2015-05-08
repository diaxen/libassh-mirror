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

#include <assh/assh_cipher.h>

#include <gcrypt.h>

struct assh_cipher_gcrypt_context_s
{
  const struct assh_algo_cipher_s *cipher;
  gcry_cipher_hd_t hd;
  assh_bool_t encrypt;
  uint8_t *iv;
};

static assh_error_t
assh_cipher_gcrypt_init(const struct assh_algo_cipher_s *cipher,
			struct assh_cipher_gcrypt_context_s *ctx,
			const uint8_t *key, const uint8_t *iv,
			int algo, int mode, assh_bool_t encrypt)
{
  assh_error_t err;

  ASSH_CHK_RET(gcry_cipher_open(&ctx->hd, algo, mode, 0),
	       ASSH_ERR_CRYPTO);

  ASSH_CHK_GTO(gcry_cipher_setkey(ctx->hd, key, cipher->key_size),
	       ASSH_ERR_CRYPTO, err_open);

  ctx->cipher = cipher;
  ctx->encrypt = encrypt;
  ctx->iv = NULL;

  switch (mode)
    {
    case GCRY_CIPHER_MODE_GCM:
      ctx->iv = gcry_malloc_secure(cipher->iv_size);
      ASSH_CHK_GTO(ctx->iv == NULL, ASSH_ERR_MEM, err_open);
      memcpy(ctx->iv, iv, cipher->iv_size);
      break;

    case GCRY_CIPHER_MODE_CBC:
      ASSH_CHK_GTO(gcry_cipher_setiv(ctx->hd, iv, cipher->block_size),
		   ASSH_ERR_CRYPTO, err_open);
      break;

    case GCRY_CIPHER_MODE_CTR:
      ASSH_CHK_GTO(gcry_cipher_setctr(ctx->hd, iv, cipher->block_size),
		   ASSH_ERR_CRYPTO, err_open);
      break;

    case GCRY_CIPHER_MODE_STREAM:
      if (cipher == &assh_cipher_arc4_128 ||
	  cipher == &assh_cipher_arc4_256)
	{
	  uint8_t dummy[128];
	  unsigned int i;

	  memset(dummy, 0, sizeof(dummy));
	  for (i = 0; i < 1536; i += sizeof(dummy))
	    if (encrypt)
	      ASSH_CHK_GTO(gcry_cipher_encrypt(ctx->hd, dummy, sizeof(dummy), NULL, 0),
			   ASSH_ERR_CRYPTO, err_open);
	    else
	      ASSH_CHK_GTO(gcry_cipher_decrypt(ctx->hd, dummy, sizeof(dummy), NULL, 0),
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
  assh_error_t err;
  struct assh_cipher_gcrypt_context_s *ctx = ctx_;
  size_t auth_size = ctx->cipher->auth_size;

  if (op == ASSH_CIPHER_PCK_HEAD)
    return ASSH_OK;

  gcry_cipher_setiv(ctx->hd, ctx->iv, 12);
  gcry_cipher_authenticate(ctx->hd, data, 4);

  if (ctx->encrypt)
    {
      ASSH_CHK_RET(gcry_cipher_encrypt(ctx->hd, data + 4,
				       len - 4 - auth_size, NULL, 0),
		   ASSH_ERR_CRYPTO);
      gcry_cipher_gettag(ctx->hd, data + len - auth_size, auth_size);
    }
  else
    {
      ASSH_CHK_RET(gcry_cipher_decrypt(ctx->hd, data + 4,
				       len - 4 - auth_size, NULL, 0),
		   ASSH_ERR_CRYPTO);
      ASSH_CHK_RET(gcry_cipher_checktag(ctx->hd,
					data + len - auth_size, auth_size),
		   ASSH_ERR_CRYPTO);
    }

  uint8_t *iv_cnt64 = ctx->iv + 4;
  assh_store_u64(iv_cnt64, assh_load_u64(iv_cnt64) + 1);

  return ASSH_OK;
}

static ASSH_CIPHER_PROCESS_FCN(assh_cipher_gcrypt_process)
{
  assh_error_t err;
  struct assh_cipher_gcrypt_context_s *ctx = ctx_;
  size_t block_size = ctx->cipher->block_size;

  ASSH_CHK_RET(len % block_size,
	       ASSH_ERR_INPUT_OVERFLOW | ASSH_ERRSV_DISCONNECT);

  if (ctx->encrypt)
    ASSH_CHK_RET(gcry_cipher_encrypt(ctx->hd, data, len, NULL, 0),
		 ASSH_ERR_CRYPTO);
  else
    ASSH_CHK_RET(gcry_cipher_decrypt(ctx->hd, data, len, NULL, 0),
		 ASSH_ERR_CRYPTO);

  return ASSH_OK;
}

#define assh_cipher_gcrypt_process_CBC assh_cipher_gcrypt_process
#define assh_cipher_gcrypt_process_CTR assh_cipher_gcrypt_process
#define assh_cipher_gcrypt_process_STREAM assh_cipher_gcrypt_process

static ASSH_CIPHER_CLEANUP_FCN(assh_cipher_gcrypt_cleanup)
{
  struct assh_cipher_gcrypt_context_s *ctx = ctx_;
  gcry_free(ctx->iv);
  gcry_cipher_close(ctx->hd);
}

#define ASSH_GCRYPT_CIPHER(id_, name_, algo_, mode_, bsize_, head_size_, \
			   isize_, ksize_, saf_, spd_, auth_size_)	\
extern const struct assh_algo_cipher_s assh_cipher_##id_;		\
									\
static ASSH_CIPHER_INIT_FCN(assh_cipher_gcrypt_##id_##_init)		\
{									\
  return assh_cipher_gcrypt_init(&assh_cipher_##id_, ctx_, key, iv,	\
	 GCRY_CIPHER_##algo_, GCRY_CIPHER_MODE_##mode_, encrypt);	\
}									\
									\
const struct assh_algo_cipher_s assh_cipher_##id_ =			\
{									\
  .algo = { .name = name_, .class_ = ASSH_ALGO_CIPHER, .safety = saf_, .speed = spd_ }, \
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

ASSH_GCRYPT_CIPHER(arc4,           "arcfour",        ARCFOUR,    STREAM, 8,  8,  0, 16, 5,  80, 0);
ASSH_GCRYPT_CIPHER(arc4_128,       "arcfour128",     ARCFOUR,    STREAM, 8,  8,  0, 16, 10, 80, 0);
ASSH_GCRYPT_CIPHER(arc4_256,       "arcfour256",     ARCFOUR,    STREAM, 8,  8,  0, 32, 15, 80, 0);

ASSH_GCRYPT_CIPHER(tdes_cbc,       "3des-cbc",       3DES,       CBC,    8,  8,  8,  24, 20, 30, 0);
ASSH_GCRYPT_CIPHER(tdes_ctr,       "3des-ctr",       3DES,       CTR,    8,  8,  8,  24, 21, 30, 0);

ASSH_GCRYPT_CIPHER(cast128_cbc,    "cast128-cbc",    CAST5,      CBC,    16, 16, 16, 16, 25, 50, 0);
ASSH_GCRYPT_CIPHER(cast128_ctr,    "cast128-ctr",    CAST5,      CTR,    16, 16, 16, 16, 26, 50, 0);

ASSH_GCRYPT_CIPHER(blowfish_cbc,   "blowfish-cbc",   BLOWFISH,   CBC,    8,  8,  8,  16, 30, 60, 0);
ASSH_GCRYPT_CIPHER(blowfish_ctr,   "blowfish-ctr",   BLOWFISH,   CTR,    8,  8,  8,  32, 35, 60, 0);

ASSH_GCRYPT_CIPHER(aes128_cbc, "aes128-cbc",         AES128,     CBC,    16, 16, 16, 16, 40, 70, 0);
ASSH_GCRYPT_CIPHER(aes192_cbc, "aes192-cbc",         AES192,     CBC,    16, 16, 16, 24, 50, 65, 0);
ASSH_GCRYPT_CIPHER(aes256_cbc, "aes256-cbc",         AES256,     CBC,    16, 16, 16, 32, 60, 60, 0);
ASSH_GCRYPT_CIPHER(aes128_ctr, "aes128-ctr",         AES128,     CTR,    16, 16, 16, 16, 41, 70, 0);
ASSH_GCRYPT_CIPHER(aes192_ctr, "aes192-ctr",         AES192,     CTR,    16, 16, 16, 24, 51, 65, 0);
ASSH_GCRYPT_CIPHER(aes256_ctr, "aes256-ctr",         AES256,     CTR,    16, 16, 16, 32, 61, 60, 0);
ASSH_GCRYPT_CIPHER(aes128_gcm, "aes128-gcm@openssh.com", AES128, GCM,    16,  4, 12, 16, 41, 75, 16);
ASSH_GCRYPT_CIPHER(aes256_gcm, "aes256-gcm@openssh.com", AES256, GCM,    16,  4, 12, 32, 61, 65, 16);

ASSH_GCRYPT_CIPHER(twofish128_cbc, "twofish128-cbc", TWOFISH128, CBC,    16, 16, 16, 16, 50, 60, 0);
ASSH_GCRYPT_CIPHER(twofish256_cbc, "twofish256-cbc", TWOFISH   , CBC,    16, 16, 16, 32, 70, 60, 0);
ASSH_GCRYPT_CIPHER(twofish128_ctr, "twofish128-ctr", TWOFISH128, CTR,    16, 16, 16, 16, 51, 60, 0);
ASSH_GCRYPT_CIPHER(twofish256_ctr, "twofish256-ctr", TWOFISH,    CTR,    16, 16, 16, 32, 71, 60, 0);
ASSH_GCRYPT_CIPHER(twofish128_gcm, "twofish128-gcm@libassh.org", TWOFISH128, GCM, 16, 4, 12, 16, 51, 65, 16);
ASSH_GCRYPT_CIPHER(twofish256_gcm, "twofish256-gcm@libassh.org", TWOFISH, GCM,    16, 4, 12, 32, 71, 65, 16);

ASSH_GCRYPT_CIPHER(serpent128_cbc, "serpent128-cbc", SERPENT128, CBC,    16, 16, 16, 16, 55, 40, 0);
ASSH_GCRYPT_CIPHER(serpent192_cbc, "serpent192-cbc", SERPENT192, CBC,    16, 16, 16, 24, 65, 40, 0);
ASSH_GCRYPT_CIPHER(serpent256_cbc, "serpent256-cbc", SERPENT256, CBC,    16, 16, 16, 32, 75, 40, 0);
ASSH_GCRYPT_CIPHER(serpent128_ctr, "serpent128-ctr", SERPENT128, CTR,    16, 16, 16, 16, 56, 40, 0);
ASSH_GCRYPT_CIPHER(serpent192_ctr, "serpent192-ctr", SERPENT192, CTR,    16, 16, 16, 24, 66, 40, 0);
ASSH_GCRYPT_CIPHER(serpent256_ctr, "serpent256-ctr", SERPENT256, CTR,    16, 16, 16, 32, 76, 40, 0);
ASSH_GCRYPT_CIPHER(serpent128_gcm, "serpent128-gcm@libassh.org", SERPENT128, GCM, 16, 4, 12, 16, 56, 45, 16);
ASSH_GCRYPT_CIPHER(serpent256_gcm, "serpent256-gcm@libassh.org", SERPENT256, GCM, 16, 4, 12, 32, 76, 45, 16);

