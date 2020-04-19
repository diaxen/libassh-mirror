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


#include <assh/assh.h>

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif

void assh_hexdump(void *stream, const char *name,
		  const void *data, size_t len)
{
#ifdef HAVE_STDIO_H
  FILE *out = stream;
  size_t i, j;
  const uint8_t *data_ = data;
  const size_t width = 32;

  fprintf(out, "--- %s (%zu bytes) ---\n", name, len);
  for (i = 0; i < len; i += width)
    {
#if 1
      for (j = 0; j < width && i + j < len; j++)
        fprintf(out, "%02x ", data_[i + j]);
      for (; j < width; j++)
        fputs("   ", out);
      for (j = 0; j < width && i + j < len; j++)
        fprintf(out, "%c", (unsigned)data_[i + j] - 32 < 96 ? data_[i + j] : '.');
      fputc('\n', out);
#else
      /* C string style output */
      fputc('"', out);
      for (j = 0; j < width && i + j < len; j++)
        fprintf(out, "\\x%02x", data_[i + j]);
      fputc('"', out);
      fputc('\n', out);
#endif
    }
  fputc('\n', out);
#endif
}
