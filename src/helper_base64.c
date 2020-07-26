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

#include <assh/helper_base64.h>

void asshh_base64_init(struct asshh_base64_ctx_s *ctx, uint8_t *out,
		      size_t out_len)
{
  ctx->out_start = ctx->out = out;
  ctx->out_end = out + out_len;
  ctx->pad = ctx->in = 0;
  ctx->x = 0;
}

static const char bin2b64[64] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const int8_t b642bin[128] =
  {
    -4, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,  /* blanks */
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1,
    62, -1, -1, -1, 63,                              /* '+' and '/' */
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61,          /* '0' to '9'  */
    -1, -1, -1, -3, -1, -1, -1,                      /* '=' */
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,    /* A to Z */
    14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    -1, -1, -1, -1, -1, -1,
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, /* a to z */
    39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    -1, -1, -1, -1, -1
  };

assh_status_t
asshh_base64_encode_update(struct asshh_base64_ctx_s *ctx,
			  const uint8_t *bin, size_t bin_len)
{
  assh_status_t err;
  uint32_t x = ctx->x;
  size_t in = ctx->in;
  uint8_t *out = ctx->out;

  while (bin_len--)
    {
      x = (x << 8) | *bin++;
      in++;
      if (in == 3)
	{
	  ASSH_RET_IF_TRUE(out + 4 >= ctx->out_end, ASSH_ERR_OUTPUT_OVERFLOW);
	  *out++ = bin2b64[(x >> 18) & 63];
	  *out++ = bin2b64[(x >> 12) & 63];
	  *out++ = bin2b64[(x >> 6) & 63];
	  *out++ = bin2b64[x & 63];
	  x >>= 24;
	  in = 0;
	}
    }

  ctx->x = x;
  ctx->in = in;
  ctx->out = out;

  return ASSH_OK;
}

assh_status_t
asshh_base64_decode_update(struct asshh_base64_ctx_s *ctx,
			  const uint8_t *b64, size_t b64_len)
{
  assh_status_t err;

  while (b64_len--)
    {
      int8_t x = *b64++, c = b642bin[(x | (x >> 7)) & 0x7f];

      switch (c)
        {
        case -1:
          ASSH_RETURN(ASSH_ERR_BAD_DATA);
        case -3:     /* padding char = */
          ASSH_RET_IF_TRUE(ctx->pad++ >= 2, ASSH_ERR_BAD_DATA);
        case -2:
          continue;  /* ignore blank chars */
        case -4:
	  return ASSH_OK;  /* NUL termination */
        default:
	  ASSH_RET_IF_TRUE(ctx->pad > 0, ASSH_ERR_BAD_DATA);
          ctx->x = (ctx->x << 6) | c;
	  if ((++ctx->in & 3) != 0)
	    continue;
	  ASSH_RET_IF_TRUE(ctx->out + 2 >= ctx->out_end, ASSH_ERR_OUTPUT_OVERFLOW);
	  *ctx->out++ = ctx->x >> 16;
	  *ctx->out++ = ctx->x >> 8;
	  *ctx->out++ = ctx->x;
	  ctx->x = 0;
        }
    }
  return ASSH_OK;
}

assh_status_t
asshh_base64_decode_final(struct asshh_base64_ctx_s *ctx)
{
  assh_status_t err;

  ASSH_RET_IF_TRUE((ctx->in + ctx->pad) & 3, ASSH_ERR_BAD_DATA);

  ASSH_RET_IF_TRUE(ctx->out + ((2 - ctx->pad) % 2) >= ctx->out_end,
	       ASSH_ERR_OUTPUT_OVERFLOW);
  switch (ctx->pad)
    {
    case 2:
      *ctx->out++ = ctx->x >> 4;
      break;
    case 1:
      *ctx->out++ = ctx->x >> 10;
      *ctx->out++ = ctx->x >> 2;
    case 0:;
    }
  return ASSH_OK;
}

assh_status_t
asshh_base64_encode_final(struct asshh_base64_ctx_s *ctx)
{
  assh_status_t err;
  uint8_t *out = ctx->out;
  uint32_t x = ctx->x;
  size_t in = ctx->in;

  if (in == 0)
    return ASSH_OK;

  ASSH_RET_IF_TRUE(out + 4 > ctx->out_end, ASSH_ERR_OUTPUT_OVERFLOW);
  x <<= 24 - in * 8;
  *out++ = bin2b64[(x >> 18) & 63];
  *out++ = bin2b64[(x >> 12) & 63];

  if (in > 1)
    *out++ = bin2b64[(x >> 6) & 63];
  else
    *out++ = '=';

  *out++ = '=';
  ctx->out = out;

  return ASSH_OK;
}

