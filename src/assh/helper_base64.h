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

/**
   @file
   @internal
   @short Base64 encoder and decoder
*/

#ifndef ASSH_HELPER_BASE64_H_
#define ASSH_HELPER_BASE64_H_

#include "assh.h"

#include <stdint.h>

/** @internal */
struct asshh_base64_ctx_s
{
  ASSH_PV uint8_t *out, *out_start, *out_end;
  ASSH_PV size_t in, pad;
  ASSH_PV uint32_t x;
};

/** @internal */
ASSH_PV void
asshh_base64_init(struct asshh_base64_ctx_s *ctx,
			uint8_t *out, size_t out_len);

/** @internal */
ASSH_PV ASSH_WARN_UNUSED_RESULT assh_status_t
asshh_base64_decode_update(struct asshh_base64_ctx_s *ctx,
			  const uint8_t *b64, size_t b64_len);

/** @internal */
ASSH_PV ASSH_WARN_UNUSED_RESULT assh_status_t
asshh_base64_decode_final(struct asshh_base64_ctx_s *ctx);

/** @internal */
ASSH_PV ASSH_WARN_UNUSED_RESULT assh_status_t
asshh_base64_encode_update(struct asshh_base64_ctx_s *ctx,
			  const uint8_t *bin, size_t bin_len);

/** @internal */
ASSH_PV ASSH_WARN_UNUSED_RESULT assh_status_t
asshh_base64_encode_final(struct asshh_base64_ctx_s *ctx);

/** @internal */
ASSH_PV ASSH_INLINE size_t
asshh_base64_outsize(struct asshh_base64_ctx_s *ctx)
{
  return ctx->out - ctx->out_start;
}

/** @internal */
ASSH_PV ASSH_INLINE size_t
asshh_base64_max_encoded_size(size_t t)
{
  return ASSH_ALIGN(4, t * 4 / 3);
}

ASSH_PV ASSH_INLINE size_t
asshh_base64_max_decoded_size(size_t t)
{
  return t * 3 / 4;
}

#endif
