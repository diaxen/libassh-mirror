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

#include <stdarg.h>

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
  unsigned int i;

  if (hex_len == 0)
    hex_len = strlen(hex);

  ASSH_CHK_RET(hex_len % 2, ASSH_ERR_INPUT_OVERFLOW);

  uint8_t buf[hex_len / 2];

  for (i = 0; i < hex_len; i += 2)
    {
      uint8_t a = assh_bignum_hex_char(hex[i]);
      uint8_t b = assh_bignum_hex_char(hex[i + 1]);
      ASSH_CHK_RET(a > 15 || b > 15, ASSH_ERR_NUM_OVERFLOW);
      buf[i/2] = (a << 4) | b;
    }

  ASSH_ERR_RET(assh_bignum_from_bytes(bn, bits, buf, hex_len / 2));
  return ASSH_OK;
}

assh_error_t assh_bignum_from_mpint(struct assh_bignum_s *bn, unsigned int *bits,
				    const uint8_t * __restrict__ mpint)
{
  assh_error_t err;
  size_t s = assh_load_u32(mpint);
  /* uint8_t sign = s > 0 && (mpint[4] & 0x80); */
  ASSH_ERR_RET(assh_bignum_from_bytes(bn, bits, mpint + 4, s));
  return ASSH_OK;
}

assh_error_t assh_bignum_from_asn1(struct assh_bignum_s *bn, unsigned int *bits,
                                   const uint8_t * __restrict__ integer)
{
  assh_error_t err;
  ASSH_CHK_RET(*integer++ != 0x02, ASSH_ERR_BAD_DATA);

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

assh_error_t assh_bignum_bytecode(struct assh_context_s *c,
                                  const assh_bignum_op_t *ops,
                                  const char *format, ...)
{
  uint_fast8_t flen = strlen(format);
  uint_fast8_t tlen = 0;
  assh_error_t err;

  while (format[flen - tlen - 1] == 'T')
    {
      tlen++;
      assert(tlen < flen);
    }

  uint_fast8_t ndlen = flen - tlen;

  va_list ap;
  void *args[flen];
  uint_fast16_t tbsize[tlen];
  uint_fast8_t i;
  size_t tsize = 0;

  va_start(ap, format);
  for (i = 0; i < ndlen; i++)
    args[i] = va_arg(ap, void *);
  for (i = 0; i < tlen; i++)
    {
      uint_fast16_t bs = va_arg(ap, unsigned int);
      tbsize[i] = bs;
      tsize += assh_bignum_sizeof(bs);
    }
  va_end(ap);

  ASSH_SCRATCH_ALLOC(c, uint8_t, scratch, tsize, ASSH_ERRSV_CONTINUE, err_);

  uint8_t *bn = scratch;
  for (i = 0; i < tlen; i++)
    {
      uint_fast16_t bs = tbsize[i];
      assh_bignum_init(c, (void*)bn, bs);
      args[ndlen + i] = (void*)bn;
      bn += assh_bignum_sizeof(bs);
    }
  uint_fast8_t modidx = 0;
  uint_fast8_t repeat = 1;

  while (*ops != 0)
    {
      uint_fast8_t op = *ops >> 24;
      uint_fast8_t dst = *ops & 0x000000ff;
      uint_fast8_t src1 = (*ops & 0x0000ff00) >> 8;
      uint_fast8_t src2 = (*ops & 0x00ff0000) >> 16;
      uint_fast8_t value = (*ops & 0x00ffff00) >> 8;

      ASSH_DEBUG("exec=%p op=%u dst=%u, src1=%u, src2=%u, value=%u\n",
                 ops, op, dst, src1, src2, value);

      switch (op)
        {
        case 0:
          if (dst == src1)
            goto end;
          if (format[src1] == 'N' || format[src1] == 'T')
            {
              switch (format[dst])
                {
                case 'N':
                case 'T':
                  ASSH_ERR_GTO(assh_bignum_copy(args[dst], args[src1]), err_sc);
                  break;
                case 'M':
                  ASSH_ERR_GTO(assh_bignum_to_mpint(args[src1], args[dst]), err_sc);
                  break;
                case 'D':
                  ASSH_ERR_GTO(assh_bignum_msb_to_data(args[src1], args[dst],
                                                       assh_bignum_bits(args[src1]) / 8), err_sc);
                  break;
                default:
                  abort();
                }
            }
          else
            {
              assert(format[dst] == 'N' || format[dst] == 'T');

              switch (format[src1])
                {
                case 'M':
                  ASSH_ERR_GTO(assh_bignum_from_mpint(args[dst], NULL, args[src1]), err_sc);
                  break;
                case 'S':
                  ASSH_ERR_GTO(assh_bignum_from_data(args[dst], (uint8_t*)args[src1] + 4,
                                                     assh_load_u32(args[src1])), err_sc);
                  break;
                case 'H':
                  ASSH_ERR_GTO(assh_bignum_from_hex(args[dst], NULL, args[src1], 0), err_sc);
                  break;
                case 'D':
                  ASSH_ERR_GTO(assh_bignum_from_data(args[dst], args[src1],
                                                     assh_bignum_bits(args[dst]) / 8), err_sc);
                  break;
                default:
                  abort();
                }
            }
          break;
        case 1:
          ASSH_ERR_GTO(assh_bignum_add(args[dst], args[src1], args[src2]), err_sc);
          break;
        case 2:
          ASSH_ERR_GTO(assh_bignum_sub(args[dst], args[src1], args[src2]), err_sc);
          break;
        case 3:
          ASSH_ERR_GTO(assh_bignum_mul(args[dst], args[src1], args[src2]), err_sc);
          break;
        case 4: {
          void *s = src1 == src2 ? NULL : args[src1];
          ASSH_ERR_GTO(assh_bignum_div(args[dst], s, args[dst], args[src2]), err_sc);
          break;
        }
        case 5:
          ASSH_ERR_GTO(assh_bignum_add(args[dst], args[src1], args[src2]), err_sc);
          ASSH_ERR_GTO(assh_bignum_div(args[dst], NULL, args[dst], args[modidx]), err_sc);
          break;
        case 6:
          ASSH_ERR_GTO(assh_bignum_sub(args[dst], args[src1], args[src2]), err_sc);
          ASSH_ERR_GTO(assh_bignum_div(args[dst], NULL, args[dst], args[modidx]), err_sc);
          break;
        case 7:
          ASSH_ERR_GTO(assh_bignum_mulmod(args[dst], args[src1], args[src2], args[modidx]), err_sc);
          break;
        case 8:
          ASSH_ERR_GTO(assh_bignum_expmod(args[dst], args[src1], args[src2], args[modidx]), err_sc);
          break;
        case 9:
          ASSH_ERR_GTO(assh_bignum_modinv(args[dst], args[src1], args[src2]), err_sc);
          break;
        case 10:
          modidx = src1;
          break;
        case 11:
          ASSH_ERR_GTO(assh_bignum_rand(c, args[dst], src1), err_sc);
          break;
        case 12: {
          int r = assh_bignum_cmp(args[src1], args[src2]);
          switch (dst)
            {
            case 0:             /* cmpeq */
              ASSH_CHK_GTO(r != 0, ASSH_ERR_NUM_COMPARE_FAILED, err_sc);
              break;
            case 1:             /* cmpne */
              ASSH_CHK_GTO(r == 0, ASSH_ERR_NUM_COMPARE_FAILED, err_sc);
              break;
            case 2:             /* cmplt */
              ASSH_CHK_GTO(r <= 0, ASSH_ERR_NUM_COMPARE_FAILED, err_sc);
              break;
            case 3:             /* cmplteq */
              ASSH_CHK_GTO(r < 0, ASSH_ERR_NUM_COMPARE_FAILED, err_sc);
              break;
            }
          break;
        }
        case 13:
          repeat = value;
          ops++;
          continue;
        case 14:
          ASSH_ERR_GTO(assh_bignum_from_uint(args[dst], value), err_sc);
          break;
        case 15:
          assh_bignum_print(stderr, "bc", args[src1]);
          break;
        }

      if (repeat == 1)
        ops++;
      else
        repeat--;
    }

 end:
  err = ASSH_OK;
 err_sc:;
  ASSH_SCRATCH_FREE(c, scratch);  
 err_:
  return err;
}

