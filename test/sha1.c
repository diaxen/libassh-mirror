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

#include <assh/hash_sha1.h>

#ifdef CONFIG_ASSH_USE_GCRYPT
# include <gcrypt.h>
#endif

#define BUFSIZE 4096

int
main(int argc, char **argv)
{
  struct assh_hash_sha1_context_s ctx;
  size_t bs = BUFSIZE;

#ifdef CONFIG_ASSH_USE_GCRYPT
  if (!gcry_check_version(GCRYPT_VERSION))
    return -1;
#endif

  do
    {
      bs /= 2;

      unsigned char hash[20], buf[bs];
      int i;

      for(i = 0; i < bs; i++)
        buf[i] = i;

      assh_sha1_init(&ctx);
      for(i = 0; i <= bs; i++)
        assh_sha1_update(&ctx, buf, bs);
      assh_sha1_final(&ctx, hash);

      printf("SHA1=");
      for(i=0;i<20;i++)
        printf("%02x", hash[i]);
      printf("\n");

    }
  while (bs);

  return 0;
}

