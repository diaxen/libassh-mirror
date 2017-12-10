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
*/

#ifndef ASSH_BUFFER_H_
#define ASSH_BUFFER_H_

#include "assh.h"

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
    string buffer and nul terminates it. It returns @tt NULL if the
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

#endif
