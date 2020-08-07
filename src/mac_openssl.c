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

#include <assh/assh_mac.h>
#include <assh/assh_packet.h>
#include <assh/assh_buffer.h>
#include <assh/mod_openssl.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>

struct assh_hmac_openssl_context_s
{
  const struct assh_algo_mac_s *ma;
  HMAC_CTX *octx;
  assh_bool_t generate;
};

static ASSH_MAC_CLEANUP_FCN(assh_hmac_openssl_cleanup)
{
  struct assh_hmac_openssl_context_s *ctx = ctx_;
  HMAC_CTX_free(ctx->octx);
}

static ASSH_MAC_PROCESS_FCN(assh_hmac_openssl_process)
{
  struct assh_hmac_openssl_context_s *ctx = ctx_;
  assh_status_t err;

  ASSH_RET_IF_TRUE(!HMAC_Init_ex(ctx->octx, NULL, 0, NULL, NULL), ASSH_ERR_CRYPTO);

  uint8_t be_seq[4];
  assh_store_u32(be_seq, seq);

  ASSH_RET_IF_TRUE(!HMAC_Update(ctx->octx, be_seq, 4), ASSH_ERR_CRYPTO);
  ASSH_RET_IF_TRUE(!HMAC_Update(ctx->octx, data, len), ASSH_ERR_CRYPTO);

  uint8_t rmac[64];
  ASSH_RET_IF_TRUE(!HMAC_Final(ctx->octx, rmac, NULL), ASSH_ERR_CRYPTO);
  if (ctx->generate)
    memcpy(mac, rmac, ctx->ma->mac_size);
  else
    ASSH_RET_IF_TRUE(assh_memcmp(mac, rmac, ctx->ma->mac_size), ASSH_ERR_CRYPTO);

  return ASSH_OK;
}

static assh_status_t assh_hmac_openssl_init(const struct assh_algo_mac_s *ma,
					    struct assh_hmac_openssl_context_s *ctx,
					    const uint8_t *key, const EVP_MD *md,
					    assh_bool_t generate)
{
  assh_status_t err;
  ctx->ma = ma;
  ctx->octx = HMAC_CTX_new();
  ctx->generate = generate;

  ASSH_RET_IF_TRUE(ctx->octx == NULL, ASSH_ERR_CRYPTO);
  ASSH_JMP_IF_TRUE(!HMAC_Init_ex(ctx->octx, key, ma->key_size, md, NULL),
                   ASSH_ERR_CRYPTO, err_octx);

  return ASSH_OK;

 err_octx:
  HMAC_CTX_free(ctx->octx);
  return err;
}

#define ASSH_OPENSSL_HMAC(id_, evp_, ksize_, msize_,                    \
                         saf_, spd_, etm_, ...)                         \
extern const struct assh_algo_mac_s assh_mac_openssl_##id_;		\
									\
static ASSH_MAC_INIT_FCN(assh_hmac_openssl_##id_##_init)                \
{									\
  return assh_hmac_openssl_init(&assh_mac_openssl_##id_, ctx_,		\
				key, evp_, generate);			\
}									\
									\
const struct assh_algo_mac_s assh_mac_openssl_##id_ =			\
{									\
  ASSH_ALGO_BASE(MAC, "assh-openssl", saf_, spd_,                       \
                 ASSH_ALGO_NAMES(__VA_ARGS__)),                         \
  .ctx_size = sizeof(struct assh_hmac_openssl_context_s),		\
  .key_size = ksize_,							\
  .mac_size = msize_,							\
  .etm = etm_,                                                          \
  .f_init = assh_hmac_openssl_##id_##_init,				\
  .f_process = assh_hmac_openssl_process,				\
  .f_cleanup = assh_hmac_openssl_cleanup,				\
};

# ifndef OPENSSL_NO_MD5
ASSH_OPENSSL_HMAC(md5,           EVP_md5(),    16, 16, 30, 18, 0,
                 { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
                   "hmac-md5" });
ASSH_OPENSSL_HMAC(md5_etm,       EVP_md5(),    16, 16, 31, 18, 1,
                 { ASSH_ALGO_STD_PRIVATE,
                   "hmac-md5-etm@openssh.com" });
ASSH_OPENSSL_HMAC(md5_96,        EVP_md5(),    16, 12, 20, 18, 0,
                 { ASSH_ALGO_STD_IETF,
                   "hmac-md5-96" });
ASSH_OPENSSL_HMAC(md5_96_etm,    EVP_md5(),    16, 12, 21, 18, 1,
                 { ASSH_ALGO_STD_PRIVATE,
                   "hmac-md5-96-etm@openssh.com" });
#endif


ASSH_OPENSSL_HMAC(sha1,          EVP_sha1(),   20, 20, 35, 25, 0,
                 { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
                   "hmac-sha1" });
ASSH_OPENSSL_HMAC(sha1_etm,      EVP_sha1(),   20, 20, 36, 25, 1,
                 { ASSH_ALGO_STD_PRIVATE,
                   "hmac-sha1-etm@openssh.com" });
ASSH_OPENSSL_HMAC(sha1_96,       EVP_sha1(),   20, 12, 25, 25, 0,
                 { ASSH_ALGO_STD_IETF,
                   "hmac-sha1-96" });
ASSH_OPENSSL_HMAC(sha1_96_etm,   EVP_sha1(),   20, 12, 26, 25, 1,
                 { ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_COMMON,
                   "hmac-sha1-96-etm@openssh.com" });

ASSH_OPENSSL_HMAC(sha256,        EVP_sha256(), 32, 32, 40, 12, 0,
                 { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
                   "hmac-sha2-256" });
ASSH_OPENSSL_HMAC(sha256_etm,    EVP_sha256(), 32, 32, 41, 12, 1,
                 { ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_COMMON,
                   "hmac-sha2-256-etm@openssh.com" });

ASSH_OPENSSL_HMAC(sha512,        EVP_sha512(), 64, 64, 50, 18, 0,
                 { ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
                   "hmac-sha2-512" });
ASSH_OPENSSL_HMAC(sha512_etm,    EVP_sha512(), 64, 64, 51, 18, 1,
                 { ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_COMMON,
                   "hmac-sha2-512-etm@openssh.com" });

# ifndef OPENSSL_NO_RMD160
ASSH_OPENSSL_HMAC(ripemd160,     EVP_ripemd160(), 20, 20, 30, 7, 0,
                 { ASSH_ALGO_STD_IETF,
                   "hmac-ripemd160" });
ASSH_OPENSSL_HMAC(ripemd160_etm, EVP_ripemd160(), 20, 20, 31, 7, 1,
                 { ASSH_ALGO_STD_PRIVATE,
                   "hmac-ripemd160-etm@openssh.com" });
#endif
