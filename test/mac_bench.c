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
#include <assh/assh_mac.h>
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

static void bench(const struct assh_algo_mac_s *mac)
{
  fprintf(stderr, "%-30s %-13s  ",
	  assh_algo_name(&mac->algo),
	  mac->algo.implem);

  struct assh_context_s context;

  if (assh_context_init(&context, ASSH_CLIENT_SERVER,
			NULL, NULL, NULL, NULL))
    TEST_FAIL("context init");

  if (assh_algo_register_va(&context, 0, 0, 0, &mac->algo, NULL))
    TEST_FAIL("algo register");

  void *ectx = malloc(mac->ctx_size);
  void *dctx = malloc(mac->ctx_size);
  if (!ectx || !dctx)
    TEST_FAIL("mac ctx alloc");

  const uint8_t *key = (const uint8_t *)
    "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55"
    "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55"
    "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55"
    "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55";
  uint8_t code[128];

  struct timeval tp_start, tp_end;
  uint64_t dte, dtd;

  /* generate mac */
  {
    size_t c = cycles;

    if (mac->f_init(&context, ectx, key))
      TEST_FAIL("encrypt init");

    gettimeofday(&tp_start, NULL);
    while (c--)
      if (mac->f_compute(ectx, c, data, data_size, code))
	TEST_FAIL("generate");
    gettimeofday(&tp_end, NULL);

    dte = ((uint64_t)tp_end.tv_sec * 1000000 + tp_end.tv_usec) -
      ((uint64_t)tp_start.tv_sec * 1000000 + tp_start.tv_usec);

    ssize_t l = 15 - fprintf(stderr, "%.2f MB/s",
			     ((double)data_size * cycles) / dte);
    while (l-- > 0)
      fputc(' ', stderr);

    mac->f_cleanup(&context, ectx);
  }

  /* mac verify */
  {
    size_t c = cycles;

    if (mac->f_init(&context, ectx, key))
      TEST_FAIL("generate init");

    if (mac->f_init(&context, dctx, key))
      TEST_FAIL("verify init");

    gettimeofday(&tp_start, NULL);
    while (c--)
      {
	if (mac->f_compute(ectx, c, data, data_size, code))
	  TEST_FAIL("generate");
	if (mac->f_compute(dctx, c, data, data_size, code))
	  TEST_FAIL("verify");
      }
    gettimeofday(&tp_end, NULL);

    dtd = ((uint64_t)tp_end.tv_sec * 1000000 + tp_end.tv_usec) -
      ((uint64_t)tp_start.tv_sec * 1000000 + tp_start.tv_usec) - dte;

    fprintf(stderr, " %.2f MB/s\n",
	    ((double)data_size * cycles) / dtd);

    mac->f_cleanup(&context, ectx);
    mac->f_cleanup(&context, dctx);
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
	  "  Algorithm                      Implem       Generate        Verify \n"
	  "--------------------------------------------------------------------------\n");

  if (data_size < 1024)
    TEST_FAIL("small data size");

  data = malloc(data_size);
  if (!data)
    TEST_FAIL("mac data alloc");
  memset(data, 0xaa, data_size);

  const struct assh_algo_s **table = assh_algo_table;
  const struct assh_algo_s *a;

  while ((a = *table++) != NULL)
    {
      if (a->class_ != ASSH_ALGO_MAC)
	continue;

      bench((const struct assh_algo_mac_s *)a);
    }

  free(data);
}
