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
#include <assh/assh_algo.h>
#include <assh/assh_cipher.h>
#include <assh/assh_context.h>

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "test.h"

static void *data;
static size_t data_size = 1 << 20;
static size_t cycles = 10;

static void bench(const struct assh_algo_cipher_s *cipher)
{
  fprintf(stderr, "%-30s %-13s  ",
	  assh_algo_name(&cipher->algo),
	  cipher->algo.implem);

  struct assh_context_s context;

  if (assh_context_init(&context, ASSH_CLIENT_SERVER,
			NULL, NULL, NULL, NULL))
    TEST_FAIL("context init");

  if (assh_algo_register_va(&context, 0, 0, 0, &cipher->algo, NULL))
    TEST_FAIL("algo register");

  void *ectx = malloc(cipher->ctx_size);
  void *dctx = malloc(cipher->ctx_size);
  if (!ectx || !dctx)
    TEST_FAIL("cipher ctx alloc");

  const uint8_t *key_iv = (const uint8_t *)
    "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55"
    "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55"
    "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55"
    "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55";

  struct timeval tp_start, tp_end;
  uint64_t dte, dtd;

  /* encryption */
  {
    size_t c = cycles;
    size_t s = data_size;

    if (cipher->f_init(&context, ectx, key_iv, key_iv, 1))
      TEST_FAIL("encrypt init");

    s = s - 128 + cipher->auth_size + cipher->head_size;

    gettimeofday(&tp_start, NULL);
    while (c--)
      if (cipher->f_process(ectx, data, s, ASSH_CIPHER_PCK_TAIL, c))
	TEST_FAIL("encrypt");
    gettimeofday(&tp_end, NULL);

    dte = ((uint64_t)tp_end.tv_sec * 1000000 + tp_end.tv_usec) -
      ((uint64_t)tp_start.tv_sec * 1000000 + tp_start.tv_usec);

    ssize_t l = 15 - fprintf(stderr, "%.2f MB/s",
			     ((double)s * cycles) / dte);
    while (l-- > 0)
      fputc(' ', stderr);

    cipher->f_cleanup(&context, ectx);
  }

  /* decryption */
  {
    size_t c = cycles;
    size_t s = data_size;

    if (cipher->f_init(&context, ectx, key_iv, key_iv, 1))
      TEST_FAIL("encrypt init");

    if (cipher->f_init(&context, dctx, key_iv, key_iv, 0))
      TEST_FAIL("decrypt init");

    if (cipher->auth_size)
      {
	s = s - 128 + cipher->auth_size + cipher->head_size;
	gettimeofday(&tp_start, NULL);
	while (c--)
	  {
	    if (cipher->f_process(ectx, data, s, ASSH_CIPHER_PCK_TAIL, c))
	      TEST_FAIL("encrypt");

	    if (cipher->f_process(dctx, data, cipher->head_size, ASSH_CIPHER_PCK_HEAD, c))
	      TEST_FAIL("decrypt");

	    if (cipher->f_process(dctx, data, s, ASSH_CIPHER_PCK_TAIL, c))
	      TEST_FAIL("decrypt");
	  }
	gettimeofday(&tp_end, NULL);
      }
    else
      {
	gettimeofday(&tp_start, NULL);
	while (c--)
	  {
	    if (cipher->head_size &&
		cipher->f_process(dctx, data, cipher->head_size, ASSH_CIPHER_PCK_HEAD, c))
	      TEST_FAIL("decrypt");

	    if (cipher->f_process(dctx, data + cipher->head_size, s - cipher->head_size, ASSH_CIPHER_PCK_TAIL, c))
	      TEST_FAIL("decrypt");
	  }
	gettimeofday(&tp_end, NULL);
      }

    dtd = ((uint64_t)tp_end.tv_sec * 1000000 + tp_end.tv_usec) -
      ((uint64_t)tp_start.tv_sec * 1000000 + tp_start.tv_usec);

    if (cipher->auth_size)
      dtd -= dte;

    fprintf(stderr, " %.2f MB/s\n",
	    ((double)s * cycles) / dtd);

    cipher->f_cleanup(&context, ectx);
    cipher->f_cleanup(&context, dctx);
  }

  free(ectx);
  free(dctx);

  assh_context_cleanup(&context);
}

int main()
{
  if (assh_deps_init())
    return -1;

  fprintf(stderr,
	  "  Algorithm                      Implem       Encrypt         Decrypt\n"
	  "--------------------------------------------------------------------------\n");

  if (data_size < 1024)
    TEST_FAIL("small data size");

  data = malloc(data_size);
  if (!data)
    TEST_FAIL("cipher data alloc");
  memset(data, 0xaa, data_size);

  const struct assh_algo_s **table = assh_algo_table;
  const struct assh_algo_s *a;

  while ((a = *table++) != NULL)
    {
      if (a->class_ != ASSH_ALGO_CIPHER)
	continue;

      bench((const struct assh_algo_cipher_s *)a);
    }

  free(data);
}
