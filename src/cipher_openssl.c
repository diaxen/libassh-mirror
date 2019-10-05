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
#include <assh/assh_alloc.h>
#include <assh/assh_packet.h>
#include <assh/assh_buffer.h>

#include <openssl/evp.h>

#ifdef CONFIG_ASSH_VALGRIND
# include <valgrind/memcheck.h>
#endif

/* Using the same buffer for both input and output of openssl EVP
   functions might not be supported by all cipher/modes. However, it
   saves a lot of memory and appears to work when padding is disabled. */
#define CONFIG_ASSH_OPENSSL_CIPHER_OVERLAP

struct assh_cipher_openssl_context_s
{
  const struct assh_algo_cipher_s *cipher;
  EVP_CIPHER_CTX *octx;
  const EVP_CIPHER *evp;
#ifndef CONFIG_ASSH_OPENSSL_CIPHER_OVERLAP
  uint8_t *scratch;
#endif
  uint8_t iv[12];
};

static assh_status_t
assh_cipher_openssl_init(struct assh_context_s *c,
                         const struct assh_algo_cipher_s *cipher,
                         struct assh_cipher_openssl_context_s *ctx,
                         const uint8_t *key, const uint8_t *iv,
                         const EVP_CIPHER *evp, assh_bool_t encrypt)
{
  assh_status_t err;

  ctx->octx = EVP_CIPHER_CTX_new();

  ASSH_RET_IF_TRUE(ctx->octx == NULL, ASSH_ERR_CRYPTO);

  ctx->evp = evp;
  ctx->cipher = cipher;

#ifndef CONFIG_ASSH_OPENSSL_CIPHER_OVERLAP
  ASSH_RET_ON_ERR(assh_alloc(c, ASSH_PACKET_MAX_OVERHEAD + CONFIG_ASSH_MAX_PAYLOAD,
                             ASSH_ALLOC_INTERNAL, (void*)&ctx->scratch));
#endif

  switch (EVP_CIPHER_flags(evp) & EVP_CIPH_MODE)
    {
    case EVP_CIPH_GCM_MODE:
      memcpy(ctx->iv, iv, cipher->iv_size);
      ASSH_JMP_IF_TRUE(!EVP_CipherInit_ex(ctx->octx, evp, NULL, key, NULL, encrypt) ||
                       !EVP_CIPHER_CTX_set_padding(ctx->octx, 0),
                       ASSH_ERR_CRYPTO, err_open);
      break;

    case EVP_CIPH_CBC_MODE:
    case EVP_CIPH_CTR_MODE:
      ASSH_JMP_IF_TRUE(!EVP_CipherInit_ex(ctx->octx, evp, NULL, key, iv, encrypt) ||
                       !EVP_CIPHER_CTX_set_padding(ctx->octx, 0),
                       ASSH_ERR_CRYPTO, err_open);
      break;

    case EVP_CIPH_STREAM_CIPHER:
      ASSH_JMP_IF_TRUE(!EVP_CipherInit_ex(ctx->octx, evp, NULL, NULL, NULL, encrypt) ||
                       !EVP_CIPHER_CTX_set_key_length(ctx->octx, cipher->key_size) ||
                       !EVP_CipherInit_ex(ctx->octx, NULL, NULL, key, NULL, encrypt),
                       ASSH_ERR_CRYPTO, err_open);

#ifdef CONFIG_ASSH_CIPHER_ARCFOUR
      if (cipher == &assh_cipher_arc4_128 ||
	  cipher == &assh_cipher_arc4_256)
	{
	  uint8_t dummy[128];
	  uint_fast16_t i;
          int s;

# ifdef CONFIG_ASSH_VALGRIND
          VALGRIND_MAKE_MEM_DEFINED(dummy, sizeof(dummy));
# endif
	  for (i = 0; i < 1536; i += sizeof(dummy))
            ASSH_JMP_IF_TRUE(!EVP_CipherUpdate(ctx->octx, dummy, &s, dummy, sizeof(dummy)),
                             ASSH_ERR_CRYPTO, err_open);
	}
#endif
      break;

    default:
      ASSH_UNREACHABLE();
    }

  return ASSH_OK;

 err_open:
#ifndef CONFIG_ASSH_OPENSSL_CIPHER_OVERLAP
  assh_free(c, ctx->scratch);
#endif
  EVP_CIPHER_CTX_free(ctx->octx);
  return err;
}

static ASSH_CIPHER_PROCESS_FCN(assh_cipher_openssl_process_GCM)
{
  assh_status_t err;
  struct assh_cipher_openssl_context_s *ctx = ctx_;
  size_t block_size = ctx->cipher->block_size;
  size_t csize = len - 4 - ctx->cipher->auth_size;

  ASSH_RET_IF_TRUE(csize & (block_size - 1),
	       ASSH_ERR_INPUT_OVERFLOW);

  if (op == ASSH_CIPHER_PCK_HEAD)
    return ASSH_OK;

  ASSH_RET_IF_TRUE(!EVP_CipherInit_ex(ctx->octx, NULL, NULL, NULL, ctx->iv, -1),
                   ASSH_ERR_CRYPTO);

  int s = 0;
  ASSH_RET_IF_TRUE(!EVP_CipherUpdate(ctx->octx, NULL, &s, data, 4),
                   ASSH_ERR_CRYPTO);

  s = csize;
  ASSH_RET_IF_TRUE(!EVP_CipherUpdate(ctx->octx, data + 4, &s, data + 4, csize)
                   || s != csize, ASSH_ERR_CRYPTO);

  if (!EVP_CIPHER_CTX_encrypting(ctx->octx))
    {
      ASSH_RET_IF_TRUE(!EVP_CIPHER_CTX_ctrl(ctx->octx, EVP_CTRL_GCM_SET_TAG,
                                            16, data + 4 + csize),
                       ASSH_ERR_CRYPTO);
    }

  ASSH_RET_IF_TRUE(!EVP_CipherFinal(ctx->octx, data + s, &s),
                   ASSH_ERR_CRYPTO);

  if (EVP_CIPHER_CTX_encrypting(ctx->octx))
    {
      ASSH_RET_IF_TRUE(!EVP_CIPHER_CTX_ctrl(ctx->octx, EVP_CTRL_GCM_GET_TAG,
                                            16, data + 4 + csize),
                       ASSH_ERR_CRYPTO);
    }

  uint8_t *iv_cnt64 = ctx->iv + 4;
  assh_store_u64(iv_cnt64, assh_load_u64(iv_cnt64) + 1);

  return ASSH_OK;
}

static ASSH_CIPHER_PROCESS_FCN(assh_cipher_openssl_process)
{
  assh_status_t err;
  struct assh_cipher_openssl_context_s *ctx = ctx_;
  size_t block_size = ctx->cipher->block_size;

  ASSH_RET_IF_TRUE(len & (block_size - 1),
	       ASSH_ERR_INPUT_OVERFLOW);

  int s = len;
#ifndef CONFIG_ASSH_OPENSSL_CIPHER_OVERLAP
  /* always store encrypted data in the scratch buffer */
  if (EVP_CIPHER_CTX_encrypting(ctx->octx))
    {
      ASSH_RET_IF_TRUE(!EVP_EncryptUpdate(ctx->octx, ctx->scratch, &s, data, len)
                       || s != len, ASSH_ERR_CRYPTO);
      memcpy(data, ctx->scratch, len);
    }
  else
    {
      memcpy(ctx->scratch, data, len);
      ASSH_RET_IF_TRUE(!EVP_DecryptUpdate(ctx->octx, data, &s, ctx->scratch, len)
                       || s != len, ASSH_ERR_CRYPTO);
    }
#else
  ASSH_RET_IF_TRUE(!EVP_CipherUpdate(ctx->octx, data, &s, data, len)
                   || s != len, ASSH_ERR_CRYPTO);
#endif

  return ASSH_OK;
}

#define assh_cipher_openssl_process_CBC assh_cipher_openssl_process
#define assh_cipher_openssl_process_CTR assh_cipher_openssl_process
#define assh_cipher_openssl_process_STREAM assh_cipher_openssl_process

static ASSH_CIPHER_CLEANUP_FCN(assh_cipher_openssl_cleanup)
{
  struct assh_cipher_openssl_context_s *ctx = ctx_;
  EVP_CIPHER_CTX_free(ctx->octx);
#ifndef CONFIG_ASSH_OPENSSL_CIPHER_OVERLAP
  assh_free(c, ctx->scratch);
#endif
}

#define ASSH_OPENSSL_CIPHER(id_, evp_, mode_, bsize_, head_size_,       \
			   isize_, ksize_, auth_size_, saf_, spd_, ...) \
									\
extern const struct assh_algo_cipher_s assh_cipher_##id_;		\
									\
static ASSH_CIPHER_INIT_FCN(assh_cipher_openssl_##id_##_init)		\
{									\
  return assh_cipher_openssl_init(c, &assh_cipher_##id_, ctx_, key, iv,	\
                                  evp_, encrypt);                       \
}									\
									\
const struct assh_algo_cipher_s assh_cipher_##id_ =			\
{									\
  ASSH_ALGO_BASE(CIPHER, "assh-openssl", saf_, spd_,                    \
                 ASSH_ALGO_NAMES(__VA_ARGS__)),                         \
  .ctx_size = sizeof(struct assh_cipher_openssl_context_s),		\
  .block_size = bsize_,							\
  .iv_size = isize_,							\
  .key_size = ksize_,							\
  .auth_size = auth_size_,						\
  .head_size = head_size_,						\
  .f_init = assh_cipher_openssl_##id_##_init,				\
  .f_process = assh_cipher_openssl_process_##mode_,			\
  .f_cleanup = assh_cipher_openssl_cleanup,				\
};

#ifdef CONFIG_ASSH_CIPHER_ARCFOUR
ASSH_OPENSSL_CIPHER(arc4, EVP_rc4(), STREAM,
                   8,  8,  0, 16,  0,  5, 80,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "arcfour" } );
ASSH_OPENSSL_CIPHER(arc4_128, EVP_rc4(), STREAM,
                   8,  8,  0, 16,  0, 10, 80,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "arcfour128" } );
ASSH_OPENSSL_CIPHER(arc4_256, EVP_rc4(), STREAM,
                   8,  8,  0, 32,  0, 15, 80,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "arcfour256" } );
#endif

#ifdef CONFIG_ASSH_CIPHER_TDES_CBC
ASSH_OPENSSL_CIPHER(tdes_cbc, EVP_des_ede3_cbc(), CBC,
                   8,  8,  8,  24, 0, 20, 30,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "3des-cbc" } );
#endif

#ifdef CONFIG_ASSH_CIPHER_CAST128_CBC
ASSH_OPENSSL_CIPHER(cast128_cbc, EVP_cast5_cbc(), CBC,
                   8, 8, 8, 16, 0, 25, 50,
                   { ASSH_ALGO_STD_IETF, "cast128-cbc" } );
#endif

#ifdef CONFIG_ASSH_CIPHER_IDEA_CBC
ASSH_OPENSSL_CIPHER(idea_cbc,  EVP_idea_cbc(), CBC,
                   8, 8, 8, 16, 0, 25, 50,
                   { ASSH_ALGO_STD_IETF, "idea-cbc" });
#endif

#ifdef CONFIG_ASSH_CIPHER_BLOWFISH_CBC
ASSH_OPENSSL_CIPHER(blowfish_cbc, EVP_bf_cbc(), CBC,
                   8,  8,  8,  16, 0, 30, 60,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "blowfish-cbc" });
#endif

#ifdef CONFIG_ASSH_CIPHER_AES128_CBC
ASSH_OPENSSL_CIPHER(aes128_cbc, EVP_aes_128_cbc(), CBC,
                   16, 16, 16, 16, 0, 40, 70,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "aes128-cbc" });
#endif
#ifdef CONFIG_ASSH_CIPHER_AES192_CBC
ASSH_OPENSSL_CIPHER(aes192_cbc, EVP_aes_192_cbc(), CBC,
                   16, 16, 16, 24, 0, 50, 65,
                   { ASSH_ALGO_STD_IETF, "aes192-cbc" });
#endif
#ifdef CONFIG_ASSH_CIPHER_AES256_CBC
ASSH_OPENSSL_CIPHER(aes256_cbc, EVP_aes_256_cbc(), CBC,
                   16, 16, 16, 32, 0, 60, 60,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "aes256-cbc" },
                   { ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_OLDNAME, "rijndael-cbc@lysator.liu.se" });
#endif

#ifdef CONFIG_ASSH_CIPHER_AES128_CTR
ASSH_OPENSSL_CIPHER(aes128_ctr, EVP_aes_128_ctr(),     CTR,
                   16, 16, 16, 16, 0, 41, 70,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "aes128-ctr" });
#endif
#ifdef CONFIG_ASSH_CIPHER_AES192_CTR
ASSH_OPENSSL_CIPHER(aes192_ctr, EVP_aes_192_ctr(),     CTR,
                   16, 16, 16, 24, 0, 51, 65,
                   { ASSH_ALGO_STD_IETF, "aes192-ctr" });
#endif
#ifdef CONFIG_ASSH_CIPHER_AES256_CTR
ASSH_OPENSSL_CIPHER(aes256_ctr, EVP_aes_256_ctr(),     CTR,
                   16, 16, 16, 32, 0, 61, 60,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "aes256-ctr" });
#endif

#ifdef CONFIG_ASSH_CIPHER_AES128_GCM
ASSH_OPENSSL_CIPHER(aes128_gcm, EVP_aes_128_gcm(), GCM,
                   16,  4, 12, 16, 16, 41, 75,
                   { ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_COMMON, "aes128-gcm@openssh.com" });
#endif
#ifdef CONFIG_ASSH_CIPHER_AES256_GCM
ASSH_OPENSSL_CIPHER(aes256_gcm, EVP_aes_256_gcm(), GCM,
                   16,  4, 12, 32, 16, 61, 65,
                   { ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_COMMON, "aes256-gcm@openssh.com" });
#endif

/* https://tools.ietf.org/html/draft-kanno-secsh-camellia-02 */
#ifdef CONFIG_ASSH_CIPHER_CAMELLIA128_CBC
ASSH_OPENSSL_CIPHER(camellia128_cbc, EVP_camellia_128_cbc(), CBC,
                   16, 16, 16, 16, 0, 40, 40,
                   { ASSH_ALGO_STD_DRAFT,
                     "camellia128-cbc" });
#endif
#ifdef CONFIG_ASSH_CIPHER_CAMELLIA192_CBC
ASSH_OPENSSL_CIPHER(camellia192_cbc, EVP_camellia_192_cbc(), CBC,
                   16, 16, 16, 24, 0, 50, 40,
                   { ASSH_ALGO_STD_DRAFT,
                     "camellia192-cbc" });
#endif
#ifdef CONFIG_ASSH_CIPHER_CAMELLIA256_CBC
ASSH_OPENSSL_CIPHER(camellia256_cbc, EVP_camellia_256_cbc(), CBC,
                   16, 16, 16, 32, 0, 60, 40,
                   { ASSH_ALGO_STD_DRAFT,
                     "camellia256-cbc" });
#endif

#ifdef CONFIG_ASSH_CIPHER_CAMELLIA128_CTR
ASSH_OPENSSL_CIPHER(camellia128_ctr, EVP_camellia_128_ctr(), CTR,
                   16, 16, 16, 16, 0, 40, 40,
                   { ASSH_ALGO_STD_DRAFT,
                     "camellia128-ctr" });
#endif
#ifdef CONFIG_ASSH_CIPHER_CAMELLIA192_CTR
ASSH_OPENSSL_CIPHER(camellia192_ctr, EVP_camellia_192_ctr(), CTR,
                   16, 16, 16, 24, 0, 50, 40,
                   { ASSH_ALGO_STD_DRAFT,
                     "camellia192-ctr" });
#endif
#ifdef CONFIG_ASSH_CIPHER_CAMELLIA256_CTR
ASSH_OPENSSL_CIPHER(camellia256_ctr, EVP_camellia_256_ctr(), CTR,
                   16, 16, 16, 32, 0, 60, 40,
                   { ASSH_ALGO_STD_DRAFT,
                     "camellia256-ctr" });
#endif
