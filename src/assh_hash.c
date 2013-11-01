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

#include <assh/assh_hash.h>
#include <assh/assh_bignum.h>
#include <assh/assh_packet.h>

void assh_hash_bytes_as_string(void *ctx_, assh_hash_update_t *update, const uint8_t *bytes, size_t len)
{
  uint8_t s[4];
  assh_store_u32(s, len);
  update(ctx_, s, 4);
  update(ctx_, bytes, len);
}

void assh_hash_string(void *ctx_, assh_hash_update_t *update, const uint8_t *str)
{
  uint32_t s = assh_load_u32(str);
  update(ctx_, str, s + 4);
}

assh_error_t assh_hash_bignum(void *ctx_, assh_hash_update_t *update, const struct assh_bignum_s *bn)
{
  assh_error_t err;
  size_t l = assh_bignum_mpint_size(bn);
  uint8_t s[l];

  ASSH_ERR_RET(assh_bignum_to_mpint(bn, s));
  update(ctx_, s, assh_load_u32(s) + 4);

  return ASSH_OK;
}

void assh_hash_payload_as_string(void *ctx_, assh_hash_update_t *update, const struct assh_packet_s *p)
{ 
  uint32_t len = assh_load_u32(p->data) /* pad_len */ - 1 /* padding */ - p->head.pad_len;
  uint8_t s[4];
  assert(len < p->data_size);
  assh_store_u32(s, len);
  update(ctx_, s, 4);
  update(ctx_, p->data + 5, len);
}

