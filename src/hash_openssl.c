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

#include <assh/assh_hash.h>

#include <openssl/sha.h>
#include <openssl/md5.h>

#define ASSH_OPENSSL_HASH(id_, ctx_, prefix_, hsize_, bsize_, safety_)	\
									\
struct assh_hash_openssl_##id_##_context_s				\
{									\
  struct assh_hash_ctx_s ctx;						\
  ctx_ octx;								\
};									\
									\
ASSH_FIRST_FIELD_ASSERT(assh_hash_openssl_##id_##_context_s, ctx);	\
									\
static ASSH_HASH_COPY_FCN(assh_openssl_##id_##_hash_copy)		\
{									\
  memcpy(hctx_dst, hctx_src, sizeof(struct assh_hash_openssl_##id_##_context_s)); \
  return ASSH_OK;							\
}									\
									\
static ASSH_HASH_UPDATE_FCN(assh_openssl_##id_##_hash_update)		\
{									\
  struct assh_hash_openssl_##id_##_context_s *ctx = (void*)hctx;	\
  prefix_##_Update(&ctx->octx, data, len);				\
}									\
									\
static ASSH_HASH_CLEANUP_FCN(assh_openssl_##id_##_hash_cleanup)		\
{									\
}									\
									\
static ASSH_HASH_INIT_FCN(assh_openssl_##id_##_hash_##id_##_init)	\
{									\
  struct assh_hash_openssl_##id_##_context_s *ctx = (void*)hctx;	\
  assh_status_t err;							\
  ASSH_RET_IF_TRUE(!prefix_##_Init(&ctx->octx), ASSH_ERR_CRYPTO);	\
  return ASSH_OK;							\
}									\
									\
static ASSH_HASH_FINAL_FCN(assh_openssl_##id_##_hash_##id_##_final)	\
{									\
  struct assh_hash_openssl_##id_##_context_s *ctx = (void*)hctx;	\
  assert(len == hsize_);						\
  if (hash != NULL)							\
    prefix_##_Final(hash, &ctx->octx);					\
}									\
									\
const struct assh_hash_algo_s assh_hash_##id_ =				\
{									\
  .name = #id_,								\
  .ctx_size = sizeof(struct assh_hash_openssl_##id_##_context_s),	\
  .hash_size = hsize_,							\
  .block_size = bsize_,							\
  .sign_safety = safety_,						\
  .f_init = assh_openssl_##id_##_hash_##id_##_init,			\
  .f_copy = assh_openssl_##id_##_hash_copy,				\
  .f_update = assh_openssl_##id_##_hash_update,				\
  .f_final = assh_openssl_##id_##_hash_##id_##_final,			\
  .f_cleanup = assh_openssl_##id_##_hash_cleanup,			\
};

#ifndef CONFIG_ASSH_BUILTIN_MD5
ASSH_OPENSSL_HASH(md5,    MD5_CTX,    MD5,    16, 64,   ASSH_SAFETY_MD5);
#endif

#ifndef CONFIG_ASSH_BUILTIN_SHA1
ASSH_OPENSSL_HASH(sha1,   SHA_CTX,    SHA1,   20, 64,   ASSH_SAFETY_SHA1);
#endif

#ifndef CONFIG_ASSH_BUILTIN_SHA2
ASSH_OPENSSL_HASH(sha224, SHA256_CTX, SHA224, 28, 64,   ASSH_SAFETY_SHA2_224);
ASSH_OPENSSL_HASH(sha256, SHA256_CTX, SHA256, 32, 64,   ASSH_SAFETY_SHA2_256);
ASSH_OPENSSL_HASH(sha384, SHA512_CTX, SHA384, 48, 128,  ASSH_SAFETY_SHA2_384);
ASSH_OPENSSL_HASH(sha512, SHA512_CTX, SHA512, 64, 128,  ASSH_SAFETY_SHA2_512);
#endif
