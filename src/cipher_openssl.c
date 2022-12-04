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
#include <assh/assh_alloc.h>
#include <assh/assh_packet.h>
#include <assh/mod_openssl.h>

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
  const struct assh_algo_cipher_s *ca;
  EVP_CIPHER_CTX *octx;
  const EVP_CIPHER *evp;
#ifndef CONFIG_ASSH_OPENSSL_CIPHER_OVERLAP
  uint8_t *scratch;
#endif
  uint8_t iv[12];
};

static assh_status_t
assh_cipher_openssl_init(struct assh_context_s *c,
                         const struct assh_algo_cipher_s *ca,
                         struct assh_cipher_openssl_context_s *ctx,
                         const uint8_t *key, const uint8_t *iv,
                         const EVP_CIPHER *evp, assh_bool_t encrypt)
{
  assh_status_t err;

  ctx->octx = EVP_CIPHER_CTX_new();

  ASSH_RET_IF_TRUE(ctx->octx == NULL, ASSH_ERR_CRYPTO);

  ctx->evp = evp;
  ctx->ca = ca;

#ifndef CONFIG_ASSH_OPENSSL_CIPHER_OVERLAP
  ASSH_RET_ON_ERR(assh_alloc(c, CONFIG_ASSH_MAX_PACKET_LEN,
                             ASSH_ALLOC_INTERNAL, (void*)&ctx->scratch));
#endif

  switch (EVP_CIPHER_flags(evp) & EVP_CIPH_MODE)
    {
    case EVP_CIPH_OCB_MODE:
    case EVP_CIPH_GCM_MODE:
      memcpy(ctx->iv, iv, ca->iv_size);
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
      ASSH_JMP_IF_TRUE(!EVP_CipherInit_ex(ctx->octx, evp, NULL, NULL, NULL, encrypt),
                       ASSH_ERR_CRYPTO, err_open);
      ASSH_JMP_IF_TRUE(!EVP_CIPHER_CTX_set_key_length(ctx->octx, ca->key_size),
                       ASSH_ERR_CRYPTO, err_open);
      ASSH_JMP_IF_TRUE(!EVP_CipherInit_ex(ctx->octx, NULL, NULL, key, NULL, encrypt),
                       ASSH_ERR_CRYPTO, err_open);

      if (ca == &assh_cipher_openssl_arc4_128 ||
	  ca == &assh_cipher_openssl_arc4_256)
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

	  assh_clear(dummy, sizeof(dummy));
	}

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

static assh_bool_t
assh_cipher_openssl_supported(const struct assh_algo_cipher_s *ca,
			      const EVP_CIPHER *evp)
{
  assh_status_t err;
  EVP_CIPHER_CTX *octx = EVP_CIPHER_CTX_new();
  uint8_t iv[64];
  memset(iv, 0x55, sizeof(iv));

  ASSH_RET_IF_TRUE(octx == NULL, ASSH_ERR_CRYPTO);

  switch (EVP_CIPHER_flags(evp) & EVP_CIPH_MODE)
    {
    case EVP_CIPH_OCB_MODE:
    case EVP_CIPH_GCM_MODE:
      ASSH_JMP_IF_TRUE(!EVP_CipherInit_ex(octx, evp, NULL, iv, NULL, 1) ||
                       !EVP_CIPHER_CTX_set_padding(octx, 0),
                       ASSH_ERR_CRYPTO, err);
      break;

    case EVP_CIPH_CBC_MODE:
    case EVP_CIPH_CTR_MODE:
      ASSH_JMP_IF_TRUE(!EVP_CipherInit_ex(octx, evp, NULL, iv, iv, 1) ||
                       !EVP_CIPHER_CTX_set_padding(octx, 0),
                       ASSH_ERR_CRYPTO, err);
      break;

    case EVP_CIPH_STREAM_CIPHER:
      ASSH_JMP_IF_TRUE(!EVP_CipherInit_ex(octx, evp, NULL, NULL, NULL, 1),
                       ASSH_ERR_CRYPTO, err);
      ASSH_JMP_IF_TRUE(!EVP_CIPHER_CTX_set_key_length(octx, ca->key_size),
                       ASSH_ERR_CRYPTO, err);
      ASSH_JMP_IF_TRUE(!EVP_CipherInit_ex(octx, NULL, NULL, iv, NULL, 1),
                       ASSH_ERR_CRYPTO, err);
      break;

    default:
      ASSH_UNREACHABLE();
    }

  EVP_CIPHER_CTX_free(octx);
  return 1;

 err:
  EVP_CIPHER_CTX_free(octx);
  return 0;
}

static ASSH_CIPHER_PROCESS_FCN(assh_cipher_openssl_process_AEAD)
{
  assh_status_t err;
  struct assh_cipher_openssl_context_s *ctx = ctx_;
  size_t csize = len - 4 - ctx->ca->auth_size;

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
      ASSH_RET_IF_TRUE(!EVP_CIPHER_CTX_ctrl(ctx->octx, EVP_CTRL_AEAD_SET_TAG,
                                            16, data + 4 + csize),
                       ASSH_ERR_CRYPTO);
    }

  ASSH_RET_IF_TRUE(!EVP_CipherFinal(ctx->octx, data + s, &s),
                   ASSH_ERR_CRYPTO);

  if (EVP_CIPHER_CTX_encrypting(ctx->octx))
    {
      ASSH_RET_IF_TRUE(!EVP_CIPHER_CTX_ctrl(ctx->octx, EVP_CTRL_AEAD_GET_TAG,
                                            16, data + 4 + csize),
                       ASSH_ERR_CRYPTO);
    }

  return ASSH_OK;
}

static ASSH_CIPHER_PROCESS_FCN(assh_cipher_openssl_process_GCM)
{
  assh_status_t err;
  struct assh_cipher_openssl_context_s *ctx = ctx_;

  if (op == ASSH_CIPHER_PCK_HEAD)
    return ASSH_OK;

  ASSH_RET_ON_ERR(assh_cipher_openssl_process_AEAD(ctx, data, len, op, seq));

  uint8_t *iv_cnt64 = ctx->iv + 4;
  assh_store_u64(iv_cnt64, assh_load_u64(iv_cnt64) + 1);

  return ASSH_OK;
}

static ASSH_CIPHER_PROCESS_FCN(assh_cipher_openssl_process_OCB)
{
  assh_status_t err;
  struct assh_cipher_openssl_context_s *ctx = ctx_;

  if (op == ASSH_CIPHER_PCK_HEAD)
    return ASSH_OK;

  ASSH_RET_ON_ERR(assh_cipher_openssl_process_AEAD(ctx, data, len, op, seq));

  uint8_t *iv = ctx->iv;
  uint64_t c = assh_load_u32(iv + 8) + 1ULL;
  assh_store_u32(iv + 8, c);
  c = assh_load_u32(iv + 4) + (c >> 32);
  assh_store_u32(iv + 4, c);
  c = assh_load_u32(iv) + (c >> 32);
  assh_store_u32(iv, c);

  return ASSH_OK;
}

static ASSH_CIPHER_PROCESS_FCN(assh_cipher_openssl_process)
{
  assh_status_t err;
  struct assh_cipher_openssl_context_s *ctx = ctx_;

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
extern const struct assh_algo_cipher_s assh_cipher_openssl_##id_;	\
									\
static ASSH_CIPHER_INIT_FCN(assh_cipher_openssl_##id_##_init)		\
{									\
  return assh_cipher_openssl_init(c, &assh_cipher_openssl_##id_,	\
				  ctx_, key, iv, evp_, encrypt);	\
}									\
									\
static ASSH_ALGO_SUPPORTED_FCN(assh_cipher_openssl_##id_##_supported)	\
{									\
  return assh_cipher_openssl_supported(&assh_cipher_openssl_##id_, evp_); \
}									\
									\
const struct assh_algo_cipher_s assh_cipher_openssl_##id_ =		\
{									\
  ASSH_ALGO_BASE(CIPHER, "assh-openssl", saf_, spd_,                    \
    .f_supported = assh_cipher_openssl_##id_##_supported,		\
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

#ifndef OPENSSL_NO_RC4
ASSH_OPENSSL_CIPHER(arc4, EVP_rc4(), STREAM,
                   8,  8,  0, 16,  0,  5, 26,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "arcfour" } );
ASSH_OPENSSL_CIPHER(arc4_128, EVP_rc4(), STREAM,
                   8,  8,  0, 16,  0, 10, 26,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "arcfour128" } );
ASSH_OPENSSL_CIPHER(arc4_256, EVP_rc4(), STREAM,
                   8,  8,  0, 32,  0, 15, 26,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "arcfour256" } );
#endif

#ifndef OPENSSL_NO_DES
ASSH_OPENSSL_CIPHER(tdes_cbc, EVP_des_ede3_cbc(), CBC,
                   8,  8,  8,  24, 0, 20, 0,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "3des-cbc" } );
#endif

#ifndef OPENSSL_NO_CAST
ASSH_OPENSSL_CIPHER(cast128_cbc, EVP_cast5_cbc(), CBC,
                   8, 8, 8, 16, 0, 25, 5,
                   { ASSH_ALGO_STD_IETF, "cast128-cbc" } );
#endif

#ifndef OPENSSL_NO_IDEA
ASSH_OPENSSL_CIPHER(idea_cbc,  EVP_idea_cbc(), CBC,
                   8, 8, 8, 16, 0, 25, 4,
                   { ASSH_ALGO_STD_IETF, "idea-cbc" });
#endif

#ifndef OPENSSL_NO_BF
ASSH_OPENSSL_CIPHER(blowfish_cbc, EVP_bf_cbc(), CBC,
                   8,  8,  8,  16, 0, 30, 5,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "blowfish-cbc" });
#endif

ASSH_OPENSSL_CIPHER(aes128_cbc, EVP_aes_128_cbc(), CBC,
                   16, 16, 16, 16, 0, 40, 56,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "aes128-cbc" });

ASSH_OPENSSL_CIPHER(aes192_cbc, EVP_aes_192_cbc(), CBC,
                   16, 16, 16, 24, 0, 50, 48,
                   { ASSH_ALGO_STD_IETF, "aes192-cbc" });

ASSH_OPENSSL_CIPHER(aes256_cbc, EVP_aes_256_cbc(), CBC,
                   16, 16, 16, 32, 0, 60, 43,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "aes256-cbc" },
                   { ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_OLDNAME, "rijndael-cbc@lysator.liu.se" });

ASSH_OPENSSL_CIPHER(aes128_ctr, EVP_aes_128_ctr(),     CTR,
                   16, 16, 16, 16, 0, 41, 143,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "aes128-ctr" });

ASSH_OPENSSL_CIPHER(aes192_ctr, EVP_aes_192_ctr(),     CTR,
                   16, 16, 16, 24, 0, 51, 129,
                   { ASSH_ALGO_STD_IETF, "aes192-ctr" });

ASSH_OPENSSL_CIPHER(aes256_ctr, EVP_aes_256_ctr(),     CTR,
                   16, 16, 16, 32, 0, 61, 119,
                   { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "aes256-ctr" });

ASSH_OPENSSL_CIPHER(aes128_gcm, EVP_aes_128_gcm(), GCM,
                   16,  4, 12, 16, 16, 41, 142,
                   { ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_COMMON, "aes128-gcm@openssh.com" });

ASSH_OPENSSL_CIPHER(aes256_gcm, EVP_aes_256_gcm(), GCM,
                   16,  4, 12, 32, 16, 61, 118,
                   { ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_COMMON, "aes256-gcm@openssh.com" });

#  ifndef OPENSSL_NO_OCB
ASSH_OPENSSL_CIPHER(aes128_ocb, EVP_aes_128_ocb(), OCB,
                   16,  4, 12, 16, 16, 41, 142,
                   { ASSH_ALGO_STD_PRIVATE, "aes128-ocb@libassh.org" });

ASSH_OPENSSL_CIPHER(aes256_ocb, EVP_aes_256_ocb(), OCB,
                   16,  4, 12, 32, 16, 61, 118,
                   { ASSH_ALGO_STD_PRIVATE, "aes256-ocb@libassh.org" });
#  endif

/* https://tools.ietf.org/html/draft-kanno-secsh-camellia-02 */
#  ifndef OPENSSL_NO_CAMELLIA
ASSH_OPENSSL_CIPHER(camellia128_cbc, EVP_camellia_128_cbc(), CBC,
                   16, 16, 16, 16, 0, 40, 8,
                   { ASSH_ALGO_STD_DRAFT,
                     "camellia128-cbc" });

ASSH_OPENSSL_CIPHER(camellia192_cbc, EVP_camellia_192_cbc(), CBC,
                   16, 16, 16, 24, 0, 50, 7,
                   { ASSH_ALGO_STD_DRAFT,
                     "camellia192-cbc" });

ASSH_OPENSSL_CIPHER(camellia256_cbc, EVP_camellia_256_cbc(), CBC,
                   16, 16, 16, 32, 0, 60, 7,
                   { ASSH_ALGO_STD_DRAFT,
                     "camellia256-cbc" });

ASSH_OPENSSL_CIPHER(camellia128_ctr, EVP_camellia_128_ctr(), CTR,
                   16, 16, 16, 16, 0, 40, 8,
                   { ASSH_ALGO_STD_DRAFT,
                     "camellia128-ctr" });

ASSH_OPENSSL_CIPHER(camellia192_ctr, EVP_camellia_192_ctr(), CTR,
                   16, 16, 16, 24, 0, 50, 7,
                   { ASSH_ALGO_STD_DRAFT,
                     "camellia192-ctr" });

ASSH_OPENSSL_CIPHER(camellia256_ctr, EVP_camellia_256_ctr(), CTR,
                   16, 16, 16, 32, 0, 60, 5,
                   { ASSH_ALGO_STD_DRAFT,
                     "camellia256-ctr" });
#endif
