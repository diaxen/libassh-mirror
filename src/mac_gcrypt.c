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

#include <assh/assh_mac.h>
#include <assh/mod_gcrypt.h>
#include <assh/assh_packet.h>

#include <gcrypt.h>

struct assh_hmac_gcrypt_context_s
{
  const struct assh_algo_mac_s *ma;
  gcry_mac_hd_t hd;
  assh_bool_t generate;
};

static ASSH_MAC_CLEANUP_FCN(assh_hmac_gcrypt_cleanup)
{
  struct assh_hmac_gcrypt_context_s *ctx = ctx_;
  gcry_mac_close(ctx->hd);
}

static ASSH_MAC_PROCESS_FCN(assh_hmac_gcrypt_process)
{
  struct assh_hmac_gcrypt_context_s *ctx = ctx_;
  assh_status_t err;

  ASSH_RET_IF_TRUE(gcry_mac_reset(ctx->hd), ASSH_ERR_CRYPTO);

  uint8_t be_seq[4];
  assh_store_u32(be_seq, seq);

  ASSH_RET_IF_TRUE(gcry_mac_write(ctx->hd, be_seq, 4), ASSH_ERR_CRYPTO);
  ASSH_RET_IF_TRUE(gcry_mac_write(ctx->hd, data, len), ASSH_ERR_CRYPTO);

  if (ctx->generate)
    {
      size_t s = ctx->ma->mac_size;
      ASSH_RET_IF_TRUE(gcry_mac_read(ctx->hd, mac, &s), ASSH_ERR_CRYPTO);
    }
  else
    {
      ASSH_RET_IF_TRUE(gcry_mac_verify(ctx->hd, mac, ctx->ma->mac_size), ASSH_ERR_CRYPTO);
    }

  return ASSH_OK;
}

static assh_status_t assh_hmac_gcrypt_init(const struct assh_algo_mac_s *ma,
				   struct assh_hmac_gcrypt_context_s *ctx,
				   const uint8_t *key, int algo, assh_bool_t generate)
{
  assh_status_t err;
  ctx->ma = ma;
  ctx->generate = generate;

  ASSH_RET_IF_TRUE(!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P),
               ASSH_ERR_CRYPTO);

  ASSH_RET_IF_TRUE(gcry_mac_open(&ctx->hd, algo, GCRY_MAC_FLAG_SECURE,
			     NULL), ASSH_ERR_CRYPTO);
  ASSH_JMP_IF_TRUE(gcry_mac_setkey(ctx->hd, key, ma->key_size),
	       ASSH_ERR_CRYPTO, err_hd);

  return ASSH_OK;
 err_hd:
  gcry_mac_close(ctx->hd);
  return err;
}

#define ASSH_GCRYPT_HMAC(id_, name_, algo_, ksize_, msize_,             \
                         saf_, spd_, etm_, ...)                         \
									\
extern const struct assh_algo_mac_s assh_hmac_gcrypt_##id_;		\
									\
static ASSH_MAC_INIT_FCN(assh_hmac_gcrypt_##id_##_init)			\
{									\
  return assh_hmac_gcrypt_init(&assh_mac_gcrypt_##id_, ctx_, key,	\
			       GCRY_MAC_HMAC_##algo_, generate);	\
}									\
									\
const struct assh_algo_mac_s assh_mac_gcrypt_##id_ =			\
{									\
  ASSH_ALGO_BASE(MAC, "assh-gcrypt", saf_, spd_,                        \
                 ASSH_ALGO_NAMES(__VA_ARGS__)),                         \
  .ctx_size = sizeof(struct assh_hmac_gcrypt_context_s),		\
  .key_size = ksize_,							\
  .mac_size = msize_,							\
  .etm = etm_,                                                          \
  .f_init = assh_hmac_gcrypt_##id_##_init,				\
  .f_process = assh_hmac_gcrypt_process,				\
  .f_cleanup = assh_hmac_gcrypt_cleanup,				\
};

ASSH_GCRYPT_HMAC(md5,           , MD5,    16, 16, 30, 70, 0,
                 { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
                   "hmac-md5" });
ASSH_GCRYPT_HMAC(md5_etm,       , MD5,    16, 16, 31, 70, 1,
                 { ASSH_ALGO_STD_PRIVATE,
                   "hmac-md5-etm@openssh.com" });
ASSH_GCRYPT_HMAC(md5_96,        , MD5,    16, 12, 20, 75, 0,
                 { ASSH_ALGO_STD_IETF,
                   "hmac-md5-96" });
ASSH_GCRYPT_HMAC(md5_96_etm,    , MD5,    16, 12, 21, 75, 1,
                 { ASSH_ALGO_STD_PRIVATE,
                   "hmac-md5-96-etm@openssh.com" });

ASSH_GCRYPT_HMAC(sha1,          , SHA1,   20, 20, 35, 70, 0,
                 { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
                   "hmac-sha1" });
ASSH_GCRYPT_HMAC(sha1_etm,      , SHA1,   20, 20, 36, 70, 1,
                 { ASSH_ALGO_STD_PRIVATE,
                   "hmac-sha1-etm@openssh.com" });
ASSH_GCRYPT_HMAC(sha1_96,       , SHA1,   20, 12, 25, 75, 0,
                 { ASSH_ALGO_STD_IETF,
                   "hmac-sha1-96" });
ASSH_GCRYPT_HMAC(sha1_96_etm,   , SHA1,   20, 12, 26, 75, 1,
                 { ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_COMMON,
                   "hmac-sha1-96-etm@openssh.com" });

ASSH_GCRYPT_HMAC(sha256,        , SHA256, 32, 32, 40, 60, 0,
                 { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
                   "hmac-sha2-256" });
ASSH_GCRYPT_HMAC(sha256_etm,    , SHA256, 32, 32, 41, 60, 1,
                 { ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_COMMON,
                   "hmac-sha2-256-etm@openssh.com" });

ASSH_GCRYPT_HMAC(sha512,        , SHA512, 64, 64, 50, 50, 0,
                 { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
                   "hmac-sha2-512" });
ASSH_GCRYPT_HMAC(sha512_etm,    , SHA512, 64, 64, 51, 50, 1,
                 { ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_COMMON,
                   "hmac-sha2-512-etm@openssh.com" });

ASSH_GCRYPT_HMAC(ripemd160,     , RMD160, 20, 20, 30, 70, 0,
                 { ASSH_ALGO_STD_IETF,
                   "hmac-ripemd160" });
ASSH_GCRYPT_HMAC(ripemd160_etm, , RMD160, 20, 20, 31, 70, 1,
                 { ASSH_ALGO_STD_PRIVATE,
                   "hmac-ripemd160-etm@openssh.com" });

