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

#include <assh/assh_hash.h>

#include <gcrypt.h>

struct assh_hash_gcrypt_context_s
{
  struct assh_hash_ctx_s ctx;
  gcry_md_hd_t hd;
};

ASSH_FIRST_FIELD_ASSERT(assh_hash_gcrypt_context_s, ctx);

static ASSH_HASH_COPY_FCN(assh_gcrypt_hash_copy)
{
  const struct assh_hash_gcrypt_context_s *src = (const void*)hctx_src;
  struct assh_hash_gcrypt_context_s *dst = (void*)hctx_dst;
  assh_status_t err;

  dst->ctx = src->ctx;
  ASSH_RET_IF_TRUE(gcry_md_copy(&dst->hd, src->hd),
	       ASSH_ERR_CRYPTO);

  return ASSH_OK;
}

static ASSH_HASH_UPDATE_FCN(assh_gcrypt_hash_update)
{
  struct assh_hash_gcrypt_context_s *gctx = (void*)hctx;

  gcry_md_write(gctx->hd, data, len);
}

static ASSH_HASH_CLEANUP_FCN(assh_gcrypt_hash_cleanup)
{
  struct assh_hash_gcrypt_context_s *gctx = (void*)hctx;

  gcry_md_close(gctx->hd);
}

#define ASSH_GCRYPT_HASH_FINAL_FIXED(id_, hsize_)                       \
static ASSH_HASH_FINAL_FCN(assh_gcrypt_hash_##id_##_final)              \
{                                                                       \
  struct assh_hash_gcrypt_context_s *gctx = (void*)hctx;                \
                                                                        \
  assert(len == hsize_);                                                \
                                                                        \
  if (hash != NULL)                                                     \
    memcpy(hash, gcry_md_read(gctx->hd, 0), len);                       \
}

#define ASSH_GCRYPT_HASH_FINAL_XOF(id_, hsize_)                         \
static ASSH_HASH_FINAL_FCN(assh_gcrypt_hash_##id_##_final)              \
{                                                                       \
  struct assh_hash_gcrypt_context_s *gctx = (void*)hctx;                \
                                                                        \
  if (hash != NULL)                                                     \
    gcry_md_extract(gctx->hd, 0, hash, len);                            \
}

#define ASSH_GCRYPT_HASH(id_, algo_, hsize_, bsize_, safety_, out_)     \
                                                                        \
static ASSH_HASH_INIT_FCN(assh_gcrypt_hash_##id_##_init)                \
{                                                                       \
  struct assh_hash_gcrypt_context_s *gctx = (void*)hctx;                \
  assh_status_t err;                                                     \
                                                                        \
  ASSH_RET_IF_TRUE(!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P),    \
               ASSH_ERR_CRYPTO);                                        \
                                                                        \
  ASSH_RET_IF_TRUE(gcry_md_open(&gctx->hd, algo_, GCRY_MD_FLAG_SECURE), \
	       ASSH_ERR_CRYPTO);                                        \
                                                                        \
  return ASSH_OK;                                                       \
}                                                                       \
                                                                        \
ASSH_GCRYPT_HASH_FINAL_##out_(id_, hsize_);                             \
                                                                        \
const struct assh_hash_algo_s assh_hash_##id_ =                         \
{                                                                       \
  .name = #id_,                                                         \
  .ctx_size = sizeof(struct assh_hash_gcrypt_context_s),                \
  .hash_size = hsize_,                                                  \
  .block_size = bsize_,                                                 \
  .safety = safety_,                                                    \
  .f_init = assh_gcrypt_hash_##id_##_init,                              \
  .f_copy = assh_gcrypt_hash_copy,                                      \
  .f_update = assh_gcrypt_hash_update,                                  \
  .f_final = assh_gcrypt_hash_##id_##_final,                            \
  .f_cleanup = assh_gcrypt_hash_cleanup,                                \
};

ASSH_GCRYPT_HASH(md5,    GCRY_MD_MD5,    16, 64,  ASSH_SAFETY_MD5, FIXED);
ASSH_GCRYPT_HASH(sha1,   GCRY_MD_SHA1,   20, 64,  ASSH_SAFETY_SHA1, FIXED);
ASSH_GCRYPT_HASH(sha224, GCRY_MD_SHA224, 28, 64,  ASSH_SAFETY_SHA2_224, FIXED);
ASSH_GCRYPT_HASH(sha256, GCRY_MD_SHA256, 32, 64,  ASSH_SAFETY_SHA2_256, FIXED);
ASSH_GCRYPT_HASH(sha384, GCRY_MD_SHA384, 48, 128, ASSH_SAFETY_SHA2_384, FIXED);
ASSH_GCRYPT_HASH(sha512, GCRY_MD_SHA512, 64, 128, ASSH_SAFETY_SHA2_512, FIXED);

#ifdef CONFIG_ASSH_GCRYPT_HAS_SHA3
ASSH_GCRYPT_HASH(sha3_224, GCRY_MD_SHA3_224, 28, 144, ASSH_SAFETY_SHA3_224, FIXED);
ASSH_GCRYPT_HASH(sha3_256, GCRY_MD_SHA3_256, 32, 136, ASSH_SAFETY_SHA3_256, FIXED);
ASSH_GCRYPT_HASH(sha3_384, GCRY_MD_SHA3_384, 48, 104, ASSH_SAFETY_SHA3_384, FIXED);
ASSH_GCRYPT_HASH(sha3_512, GCRY_MD_SHA3_512, 64, 72,  ASSH_SAFETY_SHA3_512, FIXED);
ASSH_GCRYPT_HASH(shake_128, GCRY_MD_SHAKE128, 0, 168,  ASSH_SAFETY_SHAKE128, XOF);
ASSH_GCRYPT_HASH(shake_256, GCRY_MD_SHAKE256, 0, 136,  ASSH_SAFETY_SHAKE256, XOF);
#endif
