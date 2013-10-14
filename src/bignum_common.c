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

#include <assh/assh_bignum.h>
#include <assh/assh_packet.h>

assh_error_t assh_bignum_from_bytes(struct assh_bignum_s *bn, unsigned int *bits,
                                    const uint8_t * __restrict__ data, size_t data_len)
{
  assh_error_t err;

  /* skip leading zeros */
  while (data_len > 0 && *data == 0)
    data++, data_len--;

  if (bits != NULL)
    *bits = data_len * 8;

  if (bn != NULL)
    ASSH_ERR_RET(assh_bignum_from_data(bn, data, data_len));

  return ASSH_OK;
}

static inline uint8_t assh_bignum_hex_char(char hexc)
{
  return hexc <= '9' ? hexc - '0' : (hexc | 32) - 'a' + 10;
}

assh_error_t assh_bignum_from_hex(struct assh_bignum_s *bn, unsigned int *bits,
				  const char * __restrict__ hex, size_t hex_len)
{
  assh_error_t err;
  int i;

  ASSH_ERR_RET((hex_len % 2) ? ASSH_ERR_BAD_DATA : 0);

  uint8_t buf[hex_len / 2];

  for (i = 0; i < hex_len; i += 2)
    {
      uint8_t a = assh_bignum_hex_char(hex[i]);
      uint8_t b = assh_bignum_hex_char(hex[i + 1]);
      ASSH_ERR_RET(a > 15 || b > 15 ? ASSH_ERR_BAD_DATA : 0);
      buf[i/2] = (a << 4) | b;
    }

  ASSH_ERR_RET(assh_bignum_from_bytes(bn, bits, buf, hex_len / 2));
  return ASSH_OK;  
}

assh_error_t assh_bignum_from_mpint(struct assh_bignum_s *bn, unsigned int *bits,
				    const uint8_t * __restrict__ mpint)
{
  size_t s = assh_load_u32(mpint);
  /* uint8_t sign = s > 0 && (mpint[4] & 0x80); */
  return assh_bignum_from_bytes(bn, bits, mpint + 4, s);
}

assh_error_t assh_bignum_from_asn1(struct assh_bignum_s *bn, unsigned int *bits,
                                   const uint8_t * __restrict__ integer)
{
  assh_error_t err;
  ASSH_ERR_RET(*integer++ != 0x02 ? ASSH_ERR_BAD_DATA : 0);

  unsigned int l = *integer++;
  if (l & 0x80)  /* long length form ? */
    {
      unsigned int ll = l & 0x7f;
      for (l = 0; ll > 0; ll--, integer++)
        l = (l << 8) | *integer;
    }

  ASSH_ERR_RET(assh_bignum_from_bytes(bn, bits, integer, l));
  return ASSH_OK;
}

