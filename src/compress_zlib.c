/*

  libassh - asynchronous ssh2 client/server library.

  Copyright (C) 2016 Alexandre Becoulet <alexandre.becoulet@free.fr>

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

#include <assh/assh_compress.h>
#include <assh/assh_packet.h>
#include <assh/assh_alloc.h>

#include <zlib.h>
#include <stdio.h>
struct assh_zlib_ctx_s
{
  z_stream stream;
  uint8_t *buf;
  assh_bool_t compress;
};

#ifdef CONFIG_ASSH_ZLIB_ALLOC
static voidpf assh_zlib_alloc(voidpf opaque, uInt items, uInt size)
{
  struct assh_context_s *c = opaque;
  void *r;
  if (assh_alloc(c, size * items, CONFIG_ASSH_ZLIB_ALLOC, &r) != ASSH_OK)
    return NULL;
  return r;
}

static void assh_zlib_free(voidpf opaque, voidpf address)
{
  struct assh_context_s *c = opaque;
  assh_free(c, address);
}
#endif

static ASSH_COMPRESS_INIT_FCN(assh_compress_zlib_init)
{
  struct assh_zlib_ctx_s *ctx = ctx_;
  z_stream *s = &ctx->stream;
  assh_status_t err;

  ASSH_RET_ON_ERR(assh_alloc(c, CONFIG_ASSH_MAX_PAYLOAD,
                          ASSH_ALLOC_INTERNAL, (void**)&ctx->buf));

#ifdef CONFIG_ASSH_ZLIB_ALLOC
  /* zlib uses the assh allocator with given storage type */
  s->zalloc = assh_zlib_alloc;
  s->zfree = assh_zlib_free;
  s->opaque = c;
#else
  /* zlib uses its default allocator */
  s->zalloc = NULL;
  s->zfree = NULL;
#endif

  ctx->compress = compress;
  if (compress)
    ASSH_JMP_IF_TRUE(deflateInit(s, Z_DEFAULT_COMPRESSION), ASSH_ERR_MEM, err);
  else
    ASSH_JMP_IF_TRUE(inflateInit(s), ASSH_ERR_MEM, err);

  return ASSH_OK;

 err:
  assh_free(c, ctx->buf);
  return err;
}

static ASSH_COMPRESS_PROCESS_FCN(assh_compress_zlib_process)
{
  struct assh_zlib_ctx_s *ctx = ctx_;
  z_stream *s = &ctx->stream;
  struct assh_packet_s *pin = *p_;
  assh_status_t err;

  size_t payload_size = pin->data_size - ASSH_PACKET_HEADLEN;

  /* feed packet payload to zlib */
  s->next_in = &pin->head.msg;
  s->avail_in = payload_size;

  s->next_out = ctx->buf;       /* store in temp buffer */
  s->avail_out = CONFIG_ASSH_MAX_PAYLOAD;

  if (ctx->compress)
    ASSH_RET_IF_TRUE(deflate(s, Z_SYNC_FLUSH), ASSH_ERR_CRYPTO);
  else
    ASSH_RET_IF_TRUE(inflate(s, Z_SYNC_FLUSH), ASSH_ERR_CRYPTO);

  payload_size = s->next_out - ctx->buf;

  ASSH_RET_ON_ERR(assh_packet_realloc_raw(c, p_,
                 ASSH_PACKET_MIN_OVERHEAD + payload_size));

  struct assh_packet_s *pout = *p_;

  /* update packet content */
  size_t pad_len = pin->head.pad_len;
  pout->head.pad_len = pad_len;
  assh_store_u32(pout->head.pck_len, 1 + payload_size + pad_len);

  memcpy(&pout->head.msg, ctx->buf, payload_size);
  pout->data_size = ASSH_PACKET_HEADLEN + payload_size;

  return ASSH_OK;
}

static ASSH_COMPRESS_PROCESS_FCN(assh_compress_zlib_openssh_process)
{
  struct assh_zlib_ctx_s *ctx = ctx_;

  if (auth_done)
    return assh_compress_zlib_process(c, ctx, p_, 1);

  return ASSH_OK;
}

static ASSH_COMPRESS_CLEANUP_FCN(assh_compress_zlib_cleanup)
{
  struct assh_zlib_ctx_s *ctx = ctx_;

  if (ctx->compress)
    deflateEnd(&ctx->stream);
  else
    inflateEnd(&ctx->stream);

  assh_free(c, ctx->buf);
}

const struct assh_algo_compress_s assh_compress_zlib =
{
  ASSH_ALGO_BASE(COMPRESS, "assh-builtin", 10, 50,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON, "zlib" })
  ),
  .ctx_size = sizeof(struct assh_zlib_ctx_s),
  .f_init = assh_compress_zlib_init,
  .f_process = assh_compress_zlib_process,
  .f_cleanup = assh_compress_zlib_cleanup,
};

const struct assh_algo_compress_s assh_compress_zlib_openssh =
{
  ASSH_ALGO_BASE(COMPRESS, "assh-builtin", 20, 50,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_COMMON, "zlib@openssh.com" })
  ),
  .ctx_size = sizeof(struct assh_zlib_ctx_s),
  .f_init = assh_compress_zlib_init,
  .f_process = assh_compress_zlib_openssh_process,
  .f_cleanup = assh_compress_zlib_cleanup,
};

