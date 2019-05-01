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

/**
   @file
   @short SSH string buffers

   Because the @em ssh2 protocol deals with strings that are not null
   terminated, the library relies on buffer handling functions
   declared in this header file.

   @see{@assh/assh_packet.h}
*/

#ifndef ASSH_BUFFER_H_
#define ASSH_BUFFER_H_

#include "assh.h"

#include <stdarg.h>

/** @This holds a pointer and a size value used as a string or buffer.
    @see assh_cbuffer_s */
struct assh_buffer_s
{
  union {
    char *str;
    uint8_t *data;
  };
  union {
    size_t size;
    size_t len;
  };
};

/** @This holds a const pointer and a size value used as a string or buffer.
    @see assh_buffer_s */
struct assh_cbuffer_s
{
  union {
    const char *str;
    const uint8_t *data;
  };
  union {
    size_t size;
    size_t len;
  };
};

/** @This casts from a non-const buffer to a const buffer. */
ASSH_INLINE const struct assh_cbuffer_s *
assh_cbuffer(const struct assh_buffer_s *b)
{
  return (void*)b;
}

/** @This compares the content of an @ref assh_buffer_s object with a
    nul terminated string. This is @b not performed in constant
    time. */
ASSH_INLINE ASSH_WARN_UNUSED_RESULT uint_fast8_t
assh_buffer_strcmp(const struct assh_cbuffer_s *buf, const char *nul_str)
{
  uint_fast16_t i;
  for (i = 0; i < buf->len; i++)
    if (!nul_str[i] || buf->str[i] != nul_str[i])
      return 1;
  return nul_str[i];
}

/** @This initializes an @ref assh_buffer_s
    object with a nul terminated string. */
ASSH_INLINE void
assh_buffer_strset(struct assh_cbuffer_s *buf, const char *nul_str)
{
  buf->str = (void*)nul_str;
  buf->len = strlen(nul_str);
}

/** @This initializes an @ref assh_buffer_s
    object with a nul terminated string. */
ASSH_INLINE void
assh_buffer_strcpy(struct assh_buffer_s *buf, const char *nul_str)
{
  buf->len = strlen(nul_str);
  memcpy(buf->str, nul_str, buf->len);
}

/** @This allocates a string buffer using @tt malloc then copies the
    content of the @ref assh_cbuffer_s object to the string and nul
    terminates it. */
ASSH_INLINE ASSH_WARN_UNUSED_RESULT const char *
assh_buffer_strdup(const struct assh_cbuffer_s *buf)
{
  size_t sz = buf->size;
  char *str = malloc(sz + 1);
  if (str)
    {
      memcpy(str, buf->str, sz);
      str[sz] = 0;
    }
  return str;
}

/** @This copies the content of the @ref assh_cbuffer_s object to the
    provided string buffer and nul terminates it. It returns @tt NULL if the
    provided buffer is not large enough. */
ASSH_INLINE ASSH_WARN_UNUSED_RESULT const char *
assh_buffer_tostr(char *str, size_t len,
                  const struct assh_cbuffer_s *buf)
{
  size_t sz = buf->size;
  if (sz + 1 > len)
    return NULL;
  memcpy(str, buf->str, sz);
  str[sz] = 0;
  return str;
}

/** @This compares two arrays of bytes of the same length in
    constant time. */
ASSH_INLINE ASSH_WARN_UNUSED_RESULT uint8_t
assh_memcmp(const uint8_t *nula, const uint8_t *nulb, size_t len)
{
  uint8_t r = 0;
  while (len--)
    r |= nula[len] ^ nulb[len];
  return r;
}

/** @see assh_blob_scan_fcn_t */
#define ASSH_BLOB_SCAN_FCN(n) assh_error_t (n)                          \
    (struct assh_context_s *c, const uint8_t *content,                  \
     size_t len, void *pv)

/** @This is called when the @tt{F} character is used in the format
    string passed to the @ref assh_blob_scan_va function. */
typedef ASSH_BLOB_SCAN_FCN(assh_blob_scan_fcn_t);

/** @This scans a blob as a sequence of ASN1 objects, @em ssh2
    strings and numbers. It can extract pointers, lengths and
    perform some checks on the parsed fields.

    The format string can contain the following characters which
    specify how to parse the next field of the input blob:

    @table 2
     @item Character   @item Associated behavior
     @item @tt s       @item Parse an ssh string or mpint.
     @item @tt {a}X    @item Parse an ASN1 object of given type.
     @item @tt a       @item Parse an ASN1 object of any type.
     @item @tt {b}X    @item Eat a fixed size byte array of given byte size.
     @item @tt b0      @item Eat the end of the blob as a byte array.
     @item @tt b       @item Eat a fixed size byte array. Size is passed as argument.
    @ifnopt hide_internal
     @item @tt g       @item Eat a fixed size byte array then act as @tt{G}.
                       The size of the array is defined by the number of bits of the
                       big number passed as argument.
    @end if

     @item @em SPACE and @tt _  @item Ignored
    @end table

    Once parsed, the following characters can be used to check and
    store the content of the field in arguments:

    @table 2
     @item Character   @item Associated behavior
     @item @tt t       @item Check that the content of the field matches the bytes size passed as argument.
                       The comparison operators can be used, default is @tt {==}.
     @item @tt {t}X    @item Check that the content of the field matches bytes size @em {X}.
    @ifnopt hide_internal
     @item @tt u       @item Check that the content of the field has a big number bits size passed as argument.
     @item @tt {u}X    @item Check that the content of the field has a big number bits size @em {X}.
    @end if
     @item @tt {e}O@tt{;}L@tt{;}X @item Check that the content of the field matches string X of len L at offset O.
     @item @tt {o}     @item Check that the end of the input has been reached

     @item @tt H       @item Store a pointer to the header of the field in the blob.
     @item @tt C       @item Store a pointer to the content of the field in the blob.
     @item @tt N       @item Store a pointer to the header of the next field in the blob.
     @item @tt B       @item Make an @ref assh_cbuffer_s object point to the field content in the blob.
     @item @tt S       @item Store the overall size of the field in a @tt{size_t}.
     @item @tt T       @item Store the size of the content of the field in a @tt{size_t}.
     @item @tt D       @item Copy the content of the field to a pointer passed as argument.
     @item @tt Z       @item Same as @tt D then append a null byte.
     @item @tt I       @item interpret the content as an MSB number and store an @tt {int}.
     @item @tt Ir      @item interpret the content as an LSB number and store an @tt {int}.
     @item @tt L       @item interpret the content as an MSB number and store a @tt {long long int}.
     @item @tt Lr      @item interpret the content as an LSB number and store a @tt {long long int}.
     @item @tt F       @item Call an @ref assh_blob_scan_fcn_t function. The function pointer along with
                             its private pointer must be passed as arguments.
    @ifnopt hide_internal
     @item @tt J       @item Store the bits size of the big number value of the field as a size_t.
     @item @tt K       @item Initializes a @ref assh_bignum_s object with the bits size
                       of the big number value of the field.
                       The bits size of the big number object is updated if currently 0.
     @item @tt G       @item Store the content of the field in an @ref assh_bignum_s object.
                       The bits size of the big number object is updated only if currently 0.
     @item @tt G!      @item Same as @tt {G}, flag the number as secret.
     @item @tt Gr      @item Same as @tt {G}, interpret a byte array LSB first instead of MSB first.
    @end if

     @item @tt (       @item The content of a field can also be parsed as a nested blob.
                             This starts scanning the content of the field instead of juming over.
                             This can also be used to perform multiple passes on the same blob.
                              5 levels of nesting can be used.
     @item @tt )       @item End nested scanning

     @item @tt $       @item Update the @tt blob and @tt blob_len parameters
    @end table

    Example usage:
    @code
// store the content of an ssh string in a buffer and null terminates it,
// then advances the blob pointer and decreases blob_len accordingly.
err = assh_blob_scan("s t< Z $", &blob, &blob_len, out_size, out);

// read two integers embedded in a single ssh string
err = assh_blob_scan("s( b4I b2I o )", &blob, &blob_len, &x, &y);
    @end code
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_blob_scan(struct assh_context_s *c, const char *format,
               const uint8_t **blob, size_t *blob_len, ...);

/** @see assh_blob_scan */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_blob_scan_va(struct assh_context_s *c, const char *format,
                    const uint8_t **blob, size_t *blob_len, va_list ap);

#endif
