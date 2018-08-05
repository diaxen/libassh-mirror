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


#include <assh/assh.h>

#include <stdio.h>

void assh_hexdump(const char *name, const void *data, size_t len)
{
  size_t i, j;
  const uint8_t *data_ = data;
  const size_t width = 32;

  fprintf(stderr, "--- %s (%zu bytes) ---\n", name, len);
  for (i = 0; i < len; i += width)
    {
#if 1
      for (j = 0; j < width && i + j < len; j++)
        fprintf(stderr, "%02x ", data_[i + j]);
      for (; j < width; j++)
        fputs("   ", stderr);
      for (j = 0; j < width && i + j < len; j++)
        fprintf(stderr, "%c", (unsigned)data_[i + j] - 32 < 96 ? data_[i + j] : '.');
      fputc('\n', stderr);
#else
      fputc('"', stderr);
      for (j = 0; j < width && i + j < len; j++)
        fprintf(stderr, "\\x%02x", data_[i + j]);
      fputc('"', stderr);
      fputc('\n', stderr);
#endif
    }
  fputc('\n', stderr);
}
