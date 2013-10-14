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

#include <assh/cipher_gcrypt.h>

#include <gcrypt.h>

struct assh_cipher_gcrypt_context_s
{
  gcry_cipher_hd_t hd;
  assh_bool_t encrypt;
};

static assh_error_t
assh_cipher_gcrypt_init(const struct assh_algo_cipher_s *cipher,
			struct assh_cipher_gcrypt_context_s *ctx,
			const uint8_t *key, const uint8_t *iv,
			int algo, int mode, assh_bool_t encrypt)
{
  assh_error_t err;

  ASSH_ERR_RET(gcry_cipher_open(&ctx->hd, algo, mode, 0)
	       ? ASSH_ERR_CRYPTO : 0);

  ASSH_ERR_GTO(gcry_cipher_setkey(ctx->hd, key, cipher->key_size)
	       ? ASSH_ERR_CRYPTO : 0, err_open);

  ctx->encrypt = encrypt;

  switch (mode)
    {
    case GCRY_CIPHER_MODE_CBC:
      ASSH_ERR_GTO(gcry_cipher_setiv(ctx->hd, iv, cipher->block_size)
	? ASSH_ERR_CRYPTO : 0, err_open);
      break;

    case GCRY_CIPHER_MODE_CTR:
      ASSH_ERR_GTO(gcry_cipher_setctr(ctx->hd, iv, cipher->block_size)
	? ASSH_ERR_CRYPTO : 0, err_open);
      break;

    case GCRY_CIPHER_MODE_STREAM:
      assert(cipher->is_stream);

      if (cipher == &assh_cipher_gcrypt_arc4_128 ||
	  cipher == &assh_cipher_gcrypt_arc4_256)
	{
	  uint8_t dummy[128];
	  unsigned int i;

	  memset(dummy, 0, sizeof(dummy));
	  for (i = 0; i < 1536; i += sizeof(dummy))
	    if (encrypt)
	      ASSH_ERR_GTO(gcry_cipher_encrypt(ctx->hd, dummy, sizeof(dummy), NULL, 0)
			   ? ASSH_ERR_CRYPTO : 0, err_open);
	    else
	      ASSH_ERR_GTO(gcry_cipher_decrypt(ctx->hd, dummy, sizeof(dummy), NULL, 0)
			   ? ASSH_ERR_CRYPTO : 0, err_open);
	}
      break;
    }

  return ASSH_OK;

 err_open:
  gcry_cipher_close(ctx->hd);
  return err;
}

static ASSH_CIPHER_PROCESS_FCN(assh_gcrypt_process)
{
  assh_error_t err;
  struct assh_cipher_gcrypt_context_s *ctx = ctx_;

  if (ctx->encrypt)
    ASSH_ERR_RET(gcry_cipher_encrypt(ctx->hd, data, len, NULL, 0)
		 ? ASSH_ERR_CRYPTO : 0);
  else
    ASSH_ERR_RET(gcry_cipher_decrypt(ctx->hd, data, len, NULL, 0)
		 ? ASSH_ERR_CRYPTO : 0);

  return ASSH_OK;
}

static ASSH_CIPHER_CLEANUP_FCN(assh_gcrypt_cleanup)
{
  struct assh_cipher_gcrypt_context_s *ctx = ctx_;
  gcry_cipher_close(ctx->hd);
}

#define ASSH_GCRYPT_CIPHER(id_, name_, algo_, mode_, bsize_, ksize_, prio_, is_stream_) \
extern struct assh_algo_cipher_s assh_cipher_##id_;			\
									\
static ASSH_CIPHER_INIT_FCN(assh_gcrypt_##id_##_init)			\
{									\
  return assh_cipher_gcrypt_init(&assh_cipher_##id_, ctx_, key, iv,	\
				 algo_, mode_, encrypt);		\
}									\
									\
struct assh_algo_cipher_s assh_cipher_##id_ =				\
{									\
  .algo = { .name = name_, .class_ = ASSH_ALGO_CIPHER, .priority = prio_ }, \
  .ctx_size = sizeof(struct assh_cipher_gcrypt_context_s),		\
  .block_size = bsize_,							\
  .key_size = ksize_,							\
  .is_stream = is_stream_,						\
  .f_init = assh_gcrypt_##id_##_init,					\
  .f_process = assh_gcrypt_process,					\
  .f_cleanup = assh_gcrypt_cleanup,					\
};

ASSH_GCRYPT_CIPHER(gcrypt_arc4,           "arcfour",        GCRY_CIPHER_ARCFOUR,    GCRY_CIPHER_MODE_STREAM, 1, 16, 10, 1);
ASSH_GCRYPT_CIPHER(gcrypt_arc4_128,       "arcfour128",     GCRY_CIPHER_ARCFOUR,    GCRY_CIPHER_MODE_STREAM, 1, 16, 110, 1);
ASSH_GCRYPT_CIPHER(gcrypt_arc4_256,       "arcfour256",     GCRY_CIPHER_ARCFOUR,    GCRY_CIPHER_MODE_STREAM, 1, 32, 111, 1);

ASSH_GCRYPT_CIPHER(gcrypt_tdes_cbc,       "3des-cbc",       GCRY_CIPHER_3DES,       GCRY_CIPHER_MODE_CBC,    8, 24, 20, 0);
ASSH_GCRYPT_CIPHER(gcrypt_tdes_ctr,       "3des-ctr",       GCRY_CIPHER_3DES,       GCRY_CIPHER_MODE_CTR,    8, 24, 120, 0);

ASSH_GCRYPT_CIPHER(gcrypt_cast128_cbc,    "cast128-cbc",    GCRY_CIPHER_CAST5,      GCRY_CIPHER_MODE_CBC,    16, 16, 30, 0);
ASSH_GCRYPT_CIPHER(gcrypt_cast128_ctr,    "cast128-ctr",    GCRY_CIPHER_CAST5,      GCRY_CIPHER_MODE_CTR,    16, 16, 130, 0);

ASSH_GCRYPT_CIPHER(gcrypt_blowfish_cbc,   "blowfish-cbc",   GCRY_CIPHER_BLOWFISH,   GCRY_CIPHER_MODE_CBC,    8, 16, 40, 0);
ASSH_GCRYPT_CIPHER(gcrypt_blowfish_ctr,   "blowfish-ctr",   GCRY_CIPHER_BLOWFISH,   GCRY_CIPHER_MODE_CTR,    8, 32, 140, 0);

ASSH_GCRYPT_CIPHER(gcrypt_aes128_cbc,     "aes128-cbc",     GCRY_CIPHER_AES128,     GCRY_CIPHER_MODE_CBC,    16, 16, 70, 0);
ASSH_GCRYPT_CIPHER(gcrypt_aes192_cbc,     "aes192-cbc",     GCRY_CIPHER_AES192,     GCRY_CIPHER_MODE_CBC,    16, 24, 71, 0);
ASSH_GCRYPT_CIPHER(gcrypt_aes256_cbc,     "aes256-cbc",     GCRY_CIPHER_AES256,     GCRY_CIPHER_MODE_CBC,    16, 32, 72, 0);
ASSH_GCRYPT_CIPHER(gcrypt_aes128_ctr,     "aes128-ctr",     GCRY_CIPHER_AES128,     GCRY_CIPHER_MODE_CTR,    16, 16, 170, 0);
ASSH_GCRYPT_CIPHER(gcrypt_aes192_ctr,     "aes192-ctr",     GCRY_CIPHER_AES192,     GCRY_CIPHER_MODE_CTR,    16, 24, 171, 0);
ASSH_GCRYPT_CIPHER(gcrypt_aes256_ctr,     "aes256-ctr",     GCRY_CIPHER_AES256,     GCRY_CIPHER_MODE_CTR,    16, 32, 172, 0);

ASSH_GCRYPT_CIPHER(gcrypt_twofish128_cbc, "twofish128-cbc", GCRY_CIPHER_TWOFISH128, GCRY_CIPHER_MODE_CBC,    16, 16, 80, 0);
ASSH_GCRYPT_CIPHER(gcrypt_twofish256_cbc, "twofish256-cbc", GCRY_CIPHER_TWOFISH   , GCRY_CIPHER_MODE_CBC,    16, 32, 81, 0);
ASSH_GCRYPT_CIPHER(gcrypt_twofish128_ctr, "twofish128-ctr", GCRY_CIPHER_TWOFISH128, GCRY_CIPHER_MODE_CTR,    16, 16, 180, 0);
ASSH_GCRYPT_CIPHER(gcrypt_twofish256_ctr, "twofish256-ctr", GCRY_CIPHER_TWOFISH,    GCRY_CIPHER_MODE_CTR,    16, 32, 181, 0);

ASSH_GCRYPT_CIPHER(gcrypt_serpent128_cbc, "serpent128-cbc", GCRY_CIPHER_SERPENT128, GCRY_CIPHER_MODE_CBC,    16, 16, 90, 0);
ASSH_GCRYPT_CIPHER(gcrypt_serpent192_cbc, "serpent192-cbc", GCRY_CIPHER_SERPENT192, GCRY_CIPHER_MODE_CBC,    16, 24, 91, 0);
ASSH_GCRYPT_CIPHER(gcrypt_serpent256_cbc, "serpent256-cbc", GCRY_CIPHER_SERPENT256, GCRY_CIPHER_MODE_CBC,    16, 32, 92, 0);
ASSH_GCRYPT_CIPHER(gcrypt_serpent128_ctr, "serpent128-ctr", GCRY_CIPHER_SERPENT128, GCRY_CIPHER_MODE_CTR,    16, 16, 190, 0);
ASSH_GCRYPT_CIPHER(gcrypt_serpent192_ctr, "serpent192-ctr", GCRY_CIPHER_SERPENT192, GCRY_CIPHER_MODE_CTR,    16, 24, 191, 0);
ASSH_GCRYPT_CIPHER(gcrypt_serpent256_ctr, "serpent256-ctr", GCRY_CIPHER_SERPENT256, GCRY_CIPHER_MODE_CTR,    16, 32, 192, 0);

assh_error_t assh_cipher_register_gcrypt(struct assh_context_s *c)
{
  return assh_algo_register_va(c,
    &assh_cipher_gcrypt_arc4, &assh_cipher_gcrypt_arc4_128, &assh_cipher_gcrypt_arc4_256,
    &assh_cipher_gcrypt_tdes_cbc, &assh_cipher_gcrypt_tdes_ctr,
    &assh_cipher_gcrypt_cast128_cbc, &assh_cipher_gcrypt_cast128_ctr,
    &assh_cipher_gcrypt_blowfish_cbc, &assh_cipher_gcrypt_blowfish_ctr,
    &assh_cipher_gcrypt_aes128_cbc, &assh_cipher_gcrypt_aes192_cbc, &assh_cipher_gcrypt_aes256_cbc,
    &assh_cipher_gcrypt_aes128_ctr, &assh_cipher_gcrypt_aes192_ctr, &assh_cipher_gcrypt_aes256_ctr,
    &assh_cipher_gcrypt_twofish128_cbc, &assh_cipher_gcrypt_twofish256_cbc,
    &assh_cipher_gcrypt_twofish128_ctr, &assh_cipher_gcrypt_twofish256_ctr,
    &assh_cipher_gcrypt_serpent128_cbc, &assh_cipher_gcrypt_serpent192_cbc, &assh_cipher_gcrypt_serpent256_cbc,
    &assh_cipher_gcrypt_serpent128_ctr, &assh_cipher_gcrypt_serpent192_ctr, &assh_cipher_gcrypt_serpent256_ctr,
    NULL);
}

