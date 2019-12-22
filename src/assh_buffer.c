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

#include "bignum_builtin.h"

#include <assh/assh_bignum.h>
#include <assh/assh_buffer.h>
#include <assh/assh_alloc.h>

#include <assh/assh_packet.h>
#include <assh/assh_bignum.h>

#include <ctype.h>

#define ASSH_BLOB_STACK_SIZE 5

static assh_bool_t
assh_scan_compare(const char **format_, size_t a, size_t b)
{
  assh_bool_t r;
  const char *format = *format_;

  char f = format[0];
  assh_bool_t eq = 0;

  if (f)
    eq = (format[1] == '=');

  switch (f)
    {
    case '<':
      b += eq;
      r = a < b;
      break;

    case '>':
      a += eq;
      r = a > b;
      break;

    case '!':
      r = (a != b);
      break;

    case '=':
      r = (a == b);
      break;

    default:
      return (a == b);
    }

  *format_ = format + 1 + eq;
  return r;
}

assh_status_t
assh_blob_scan_va(struct assh_context_s *c, const char *format,
		  const uint8_t **blob, size_t *blob_len, va_list ap)
{
  assh_status_t err;

  struct {
    const uint8_t *blob, *next;
    size_t blob_len;
  } stack[ASSH_BLOB_STACK_SIZE], *st = stack;

  const uint8_t *s = NULL, *r = *blob;

  st->next = st->blob = r;
  st->blob_len = *blob_len;

  enum assh_bignum_fmt_e bnfmt = bnfmt;
  struct assh_bignum_s *bn;

  while (1)
    {
      switch (*format++)
        {
        case ' ':
        case '_':
          continue;

        case 's':
          bnfmt = ASSH_BIGNUM_MPINT;
          s = st->next;
          r = s + 4;
          ASSH_RET_ON_ERR(assh_check_string(st->blob, st->blob_len,
                                            s, &st->next));
          break;

        case 'a': {
          bnfmt = ASSH_BIGNUM_ASN1;
          s = st->next;
          uint_fast8_t id = strtoul(format, (char**)&format, 0);
          ASSH_RET_ON_ERR(assh_check_asn1(st->blob, st->blob_len,
                                          s, &r, &st->next, id));
          break;
        }

        case 'g': {
          bnfmt = ASSH_BIGNUM_MSB_RAW;
	  bn = va_arg(ap, struct assh_bignum_s *);
          size_t l = ASSH_ALIGN8(bn->bits) / 8;
          r = s = st->next;
          ASSH_RET_ON_ERR(assh_check_array(st->blob, st->blob_len,
                                           s, l, &st->next));
	  goto format_G;
	}

        case 'b': {
          bnfmt = ASSH_BIGNUM_MSB_RAW;
          size_t l;
	  if (isdigit(*format))
	    {
	      l = strtoul(format, (char**)&format, 0);
	      if (l == 0)
		l = st->next - r;
	    }
	  else
	    {
	      l = va_arg(ap, size_t);
	    }
          r = s = st->next;
          ASSH_RET_ON_ERR(assh_check_array(st->blob, st->blob_len,
                                           s, l, &st->next));
          break;
        }

	case 'o':
	  ASSH_RET_IF_TRUE(st->blob + st->blob_len != st->next,
			   ASSH_ERR_OUTPUT_OVERFLOW);
	  break;

        case 't': {
	  size_t k = st->next - r;
	  goto do_compare;
	case 'u':;
          size_t l = st->next - s;
          ASSH_RET_ON_ERR(assh_bignum_size_of_data(bnfmt,
                            s, &l, NULL, &k));
	  do_compare:
	  if (isdigit(*format))
	    l = strtoul(format, (char**)&format, 0);
	  else
	    l = va_arg(ap, size_t);
          ASSH_RET_IF_TRUE(!assh_scan_compare(&format, k, l),
                           ASSH_ERR_BAD_DATA);
          break;
        }

        case 'z': {
          const char *p = va_arg(ap, const void *);
          size_t l = strlen(p);
          ASSH_RET_IF_TRUE(l != st->next - r ||
                           memcmp(p, r, l),
                           ASSH_ERR_BAD_DATA);
          break;
        }

        case 'd': {
          const uint8_t *p = va_arg(ap, const void *);
          size_t l = va_arg(ap, size_t);
          ASSH_RET_IF_TRUE(l != st->next - r ||
                           memcmp(p, r, l),
                           ASSH_ERR_BAD_DATA);
          break;
        }

        case 'e': {
          size_t o = strtoul(format, (char**)&format, 0);
          assert(*format == ';');
          format++;
          size_t l = strtoul(format, (char**)&format, 0);
          assert(*format == ';');
          format++;
          ASSH_RET_IF_TRUE(o + l > st->next - r,
			   ASSH_ERR_INPUT_OVERFLOW);
          ASSH_RET_IF_TRUE(memcmp(format, r + o, l),
                           ASSH_ERR_BAD_DATA);
          format += l;
          break;
        }

        case 'H':
          assert(s != NULL);
          *va_arg(ap, const uint8_t**) = s;
          break;

        case 'C':
          assert(r != NULL);
          *va_arg(ap, const uint8_t**) = r;
          break;

        case 'N':
          *va_arg(ap, const uint8_t**) = st->next;
          break;

        case 'B': {
          struct assh_cbuffer_s *b = va_arg(ap, void *);
	  b->data = r;
	  b->size = st->next - r;
          break;
	}

        case 'S':
          assert(s != NULL);
          *va_arg(ap, size_t*) = st->next - s;
          break;

        case 'T':
          assert(r != NULL);
          *va_arg(ap, size_t*) = st->next - r;
          break;

        case 'Z':
        case 'D': {
          assert(r != NULL);
          uint8_t *b = va_arg(ap, void*);
	  size_t l = st->next - r;
	  memcpy(b, r, l);
	  if (format[-1] == 'Z')
	    b[l] = 0;
          break;
	}

	case 'L': {
	  assh_bool_t lg = 1;
	  goto do_int;
	case 'I':
	  lg = 0;
	do_int:;
	  int64_t x = 0;
          size_t l = st->next - r;
	  const uint8_t *n;
	  ASSH_RET_IF_TRUE(l > lg * 4 + 4,
			   ASSH_ERR_INPUT_OVERFLOW);
	  if (*format == 'r')
	    {
	      format++;
	      for (n = st->next - 1; n >= r; n--)
		x = (x << 8) | *n;
	    }
	  else
	    {
	      for (n = r; n < st->next; n++)
		x = (x << 8) | *n;
	    }
	  if (lg)
	    *va_arg(ap, long long int*) = x;
	  else
	    *va_arg(ap, int*) = x;
	  break;
	}

        case 'J': {
          assert(s != NULL);
          size_t bits, l = st->next - s;
          ASSH_RET_ON_ERR(assh_bignum_size_of_data(bnfmt,
                            s, &l, NULL, &bits));
          *va_arg(ap, size_t*) = bits;
          break;
        }

        case 'K': {
          bn = va_arg(ap, struct assh_bignum_s *);
          assert(s != NULL);

	  if (!bn)
	    break;

          size_t bits, l = st->next - s;
          ASSH_RET_ON_ERR(assh_bignum_size_of_data(bnfmt,
                            s, &l, NULL, &bits));
	  assh_bignum_init(c, bn, bits);
          break;
        }

        case 'G': {
          bn = va_arg(ap, struct assh_bignum_s *);
	format_G:
          assert(s != NULL);
	  assh_bool_t secret = 0;

	  while (1)
	    {
	      switch (*format)
		{
		case '!':
		  secret = 1;
		  format++;
		  continue;
		case 'r':
		  bnfmt = ASSH_BIGNUM_LSB_RAW;
		  format++;
		  continue;
		}
	      break;
	    }

	  if (!bn)
	    break;

          size_t bits, l = st->next - s;
          ASSH_RET_ON_ERR(assh_bignum_size_of_data(bnfmt,
                            s, &l, NULL, &bits));

	  if (bn->bits == 0 && !bn->n)
	    {
	      ASSH_RET_IF_TRUE(bits > 16384,
			       ASSH_ERR_INPUT_OVERFLOW);
	      bn->bits = bits;
	    }
	  else
	    {
	      ASSH_RET_IF_TRUE(bits > bn->bits,
			       ASSH_ERR_OUTPUT_OVERFLOW);
	    }

	  ASSH_RET_ON_ERR(assh_bignum_convert(c, bnfmt,
			   ASSH_BIGNUM_NATIVE, s, bn, NULL, secret));
          break;
        }

	case 'F': {
	  assh_blob_scan_fcn_t *fcn = va_arg(ap, assh_blob_scan_fcn_t*);
	  void *pv = va_arg(ap, void*);
	  ASSH_RET_ON_ERR(fcn(c, r, st->next - r, pv));
	  break;
	}

        case '(': {
          size_t l = s ? st->next - r : st->blob_len;
          st++;
          st->blob = st->next = r;
	  s = NULL;
          st->blob_len = l;
          break;
        }

        case ')':
          st--;
          s = NULL;
	  r = st->next;
          break;

	case '$':
	  *blob_len -= st->next - *blob;
	  *blob = st->next;
	  break;

        case '\0':
	  assert(st == stack);
	  return ASSH_OK;

        default:
	  ASSH_RETURN(ASSH_ERR_BAD_ARG);
        }
    }
}

assh_status_t
assh_blob_scan(struct assh_context_s *c, const char *format,
	       const uint8_t **blob, size_t *blob_len, ...)
{
  assh_status_t err;
  va_list ap;

  va_start(ap, blob_len);
  err = assh_blob_scan_va(c, format, blob, blob_len, ap);
  va_end(ap);

  ASSH_RETURN(err);
}

assh_status_t
assh_blob_write_va(const char *format, uint8_t *blob, size_t *blob_len, va_list ap)
{
  uint8_t *b = blob;
  uint8_t *e = blob + *blob_len;
  uint8_t *n;
  assh_status_t err;

  struct {
    uint8_t *head;
  } stack[ASSH_BLOB_STACK_SIZE], *st = stack;

  uint8_t int_buf[8];

  while (1)
    {
      char odata = *format++;
      size_t len;
      const void *data;

      /* content specifiers */
      switch (odata)
	{
	case 'G': {
	  const struct assh_bignum_s *bn = va_arg(ap, void*);

	  enum assh_bignum_fmt_e bn_fmt;
	  char ofmt = *format++;

	  switch (ofmt)
	    {
	    case 's':
	      bn_fmt = ASSH_BIGNUM_MPINT;
	      break;
	    case 'a': {
	      /* id = */ strtoul(format, (char**)&format, 0);
	      bn_fmt = ASSH_BIGNUM_ASN1;
	      break;
	    }
	    case 'b':
	      bn_fmt = ASSH_BIGNUM_MSB_RAW;
	      break;
	    case 'r':
	      ASSH_RET_IF_TRUE(*format++ != 'b', ASSH_ERR_BAD_ARG);
	      bn_fmt = ASSH_BIGNUM_LSB_RAW;
	      break;
	    default:
	      ASSH_RETURN(ASSH_ERR_BAD_ARG);
	    }

	  len = assh_bignum_size_of_num(bn_fmt, bn);
	  n = b + len;

	  if (blob)
	    {
	      ASSH_RET_IF_TRUE(n > e, ASSH_ERR_OUTPUT_OVERFLOW);
	      assh_bignum_to_buffer(bn, b, &b, bn_fmt);
	    }
	  else
	    {
	      b = n;
	    }

	  continue;
	}

	case 'Z': {
	  const char *s = va_arg(ap, void*);
	  data = s;
	  len = strlen(s);
	  break;
	}

	case 'B': {
	  struct assh_cbuffer_s *bf = va_arg(ap, void*);
	  data = bf->data;
	  len = bf->size;
	  break;
	}

	case 'D': {
	  data = va_arg(ap, void*);
	  len = va_arg(ap, size_t);
	  break;
	}

	case 'E': {
	  len = strtoul(format, (char**)&format, 0);
	  ASSH_RET_IF_TRUE(*format++ != ';',
			   ASSH_ERR_BAD_DATA);
	  data = format;
	  format += len;
	  break;
	}

	case 'I': {
	  uint32_t x = va_arg(ap, unsigned int);
	  len = 4;
	  data = int_buf;
	  if (*format == 'r')
	    {
	      assh_store_u32le(int_buf, x);
	      format++;
	    }
	  else
	    {
	      assh_store_u32(int_buf, x);
	    }
	  break;
	}

	case 'L': {
	  uint64_t x = va_arg(ap, unsigned long long);
	  len = 8;
	  data = int_buf;
	  if (*format == 'r')
	    {
	      assh_store_u64le(int_buf, x);
	      format++;
	    }
	  else
	    {
	      assh_store_u64(int_buf, x);
	    }
	  break;
	}

	case '(': {
	  st->head = b;
	  st++;
	  assert(st - stack <= ASSH_BLOB_STACK_SIZE);
	  continue;
	}

	case ')': {
	  assert(st > stack);
	  st--;

	  uint8_t *a = st->head;
	  size_t s = b - a;

	  char ofmt = *format++;

	  switch (ofmt)
	    {
	    case 's':
	      b += 4;
	      if (blob)
		{
		  ASSH_RET_IF_TRUE(b > e, ASSH_ERR_OUTPUT_OVERFLOW);
		  memmove(a + 4, a, s);
		  assh_store_u32(a, s);
		}
	      continue;

	    case 'a': {
	      uint_fast8_t id = strtoul(format, (char**)&format, 0);
	      size_t hl = assh_asn1_headlen(s);
	      b += hl;
	      if (blob)
		{
		  ASSH_RET_IF_TRUE(b > e, ASSH_ERR_OUTPUT_OVERFLOW);
		  memmove(a + hl, a, s);
		  assh_append_asn1(&a, id, s);
		}
	      continue;
	    }

	    case 'b':
	      continue;

	    default:
	      ASSH_RETURN(ASSH_ERR_BAD_ARG);
	    }
	  break;
	}

	case ' ':
        case '_':
	  continue;

	case '\0':
	  assert(st == stack);
	  *blob_len = b - blob;
	  return ASSH_OK;

	default:
	  ASSH_RETURN(ASSH_ERR_BAD_ARG);
	}

      size_t rpad = 0, lpad = 0;
      uint8_t vpad = 0;

      /* modifiers */
      while (1)
	{
	  switch (*format)
	    {
	    case '[':
	      lpad = strtoul(++format, (char**)&format, 0);
	      if (lpad <= len)
		{
		  data += len - lpad;
		  len = lpad;
		  lpad = 0;
		}
	      else
		{
		  lpad -= len;
		}
	      continue;

	    case ']':
	      rpad = strtoul(++format, (char**)&format, 0);
	      if (rpad <= len)
		{
		  len = rpad;
		  rpad = 0;
		}
	      else
		{
		  rpad -= len;
		}
	      continue;

	    case 'p':
	      vpad = strtoul(++format, (char**)&format, 0);
	      continue;

	    case ' ':
	    case '_':
	      format++;
	      continue;

	    default:
	      break;
	    }
	  break;
	}

      size_t wlen = lpad + len + rpad;
      n = b + wlen;

      /* format specifiers */
      char ofmt = *format++;
      switch (ofmt)
	{
	case 'a': {
	  uint_fast8_t id = strtoul(format, (char**)&format, 0);
	  size_t hl = assh_asn1_headlen(wlen);
	  n += hl;
	  if (blob)
	    {
	      ASSH_RET_IF_TRUE(n > e, ASSH_ERR_OUTPUT_OVERFLOW);
	      assh_append_asn1(&b, id, wlen);
	    }
	  break;
	}

	case 's':
	  n += 4;
	  if (blob)
	    {
	      ASSH_RET_IF_TRUE(n > e, ASSH_ERR_OUTPUT_OVERFLOW);
	      assh_store_u32(b, wlen);
	      b += 4;
	    }
	  break;

	case 'b':
	  if (blob)
	    ASSH_RET_IF_TRUE(n > e, ASSH_ERR_OUTPUT_OVERFLOW);
	  break;

	default:
	  ASSH_RETURN(ASSH_ERR_BAD_ARG);
	}

      if (blob)
	{
	  memset(b, vpad, lpad);
	  memcpy(b + lpad, data, len);
	  memset(b + lpad + len, vpad, rpad);
	}

      b = n;
    }
}

ASSH_WARN_UNUSED_RESULT assh_status_t
assh_blob_write(const char *format, uint8_t *blob, size_t *blob_len, ...)
{
  assh_status_t err;
  va_list ap;

  va_start(ap, blob_len);
  err = assh_blob_write_va(format, blob, blob_len, ap);
  va_end(ap);

  ASSH_RETURN(err);
}

assh_status_t
assh_check_asn1(const uint8_t *buffer, size_t buffer_len, const uint8_t *str,
                const uint8_t **value, const uint8_t **next, uint8_t id)
{
  assh_status_t err;

  const uint8_t *e = buffer + buffer_len;
  ASSH_RET_IF_TRUE(str < buffer || str > e - 2, ASSH_ERR_INPUT_OVERFLOW);
  ASSH_RET_IF_TRUE(id != 0 && str[0] != id, ASSH_ERR_BAD_DATA);

  str++; /* discard type identifer */
  uint_fast32_t l = *str++;
  if (l & 0x80)  /* long length form ? */
    {
      uint8_t ll = l & 0x7f;
      ASSH_RET_IF_TRUE(e - str < ll, ASSH_ERR_INPUT_OVERFLOW);
      for (l = 0; ll > 0; ll--)
        l = (l << 8) | *str++;
    }
  ASSH_RET_IF_TRUE(e - str < l, ASSH_ERR_INPUT_OVERFLOW);
  if (value != NULL)
    *value = str;
  if (next != NULL)
    *next = str + l;
  return ASSH_OK;
}

assh_status_t
assh_check_string(const uint8_t *buffer, size_t buffer_len,
                  const uint8_t *str, const uint8_t **next)
{
  assh_status_t err;

  const uint8_t *e = buffer + buffer_len;
  ASSH_RET_IF_TRUE(str < buffer || str > e - 4, ASSH_ERR_INPUT_OVERFLOW);
  size_t s = assh_load_u32(str);
  ASSH_RET_IF_TRUE(e - 4 - str < s, ASSH_ERR_INPUT_OVERFLOW);
  if (next != NULL)
    *next = str + 4 + s;
  return ASSH_OK;
}

assh_status_t
assh_check_array(const uint8_t *buffer, size_t buffer_len,
                 const uint8_t *array, size_t array_len, const uint8_t **next)
{
  assh_status_t err;

  const uint8_t *e = buffer + buffer_len;
  ASSH_RET_IF_TRUE(array < buffer || array > e, ASSH_ERR_INPUT_OVERFLOW);
  ASSH_RET_IF_TRUE(e - array < array_len, ASSH_ERR_INPUT_OVERFLOW);
  if (next != NULL)
    *next = array + array_len;
  return ASSH_OK;
}

assh_status_t
assh_ssh_string_copy(const uint8_t *ssh_str, char *nul_str, size_t max_len)
{
  assh_status_t err;

  size_t len = assh_load_u32(ssh_str);
  assert(max_len > 0);
  ASSH_RET_IF_TRUE(len > max_len - 1, ASSH_ERR_OUTPUT_OVERFLOW);
  memcpy(nul_str, ssh_str + 4, len);
  nul_str[len] = '\0';
  return ASSH_OK;
}

void
assh_append_asn1(uint8_t **dst, uint8_t id, size_t len)
{
  uint8_t *d = *dst;
  *d++ = id;
  if (len < 0x80)
    {
      *d++ = len;
    }
  else
    {
      uint_fast8_t i = 0;
      if (len & 0xff000000)
        d[++i] = len >> 24;
      if (len & 0xffff0000)
        d[++i] = len >> 16;
      if (len & 0xffffff00)
        d[++i] = len >> 8;
      d[++i] = len;
      d[0] = 0x80 | i;
      d += i + 1;
    }
  *dst = d;
}

assh_status_t assh_strdup(struct assh_context_s *c, char **r,
                         const char *str, enum assh_alloc_type_e type)
{
  assh_status_t err;
  *r = NULL;
  if (str != NULL)
    {
      size_t l = strlen(str) + 1;
      ASSH_RET_ON_ERR(assh_alloc(c, l, type, (void**)r));
      memcpy(*r, str, l);
    }
  return ASSH_OK;
}

uint_fast8_t
assh_string_strcmp(const char *str, size_t str_len, const char *nul_str)
{
  size_t i;
  for (i = 0; i < str_len; i++)
    if (!nul_str[i] || str[i] != nul_str[i])
      return 1;
  return nul_str[i];
}
