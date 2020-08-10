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

#define ASSH_PV
#define ASSH_ABI_UNSAFE  /* do not warn */

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

static void bench(const struct assh_algo_mac_s *ma)
{
  printf("%-30s %-13s  ",
	  assh_algo_name(&ma->algo),
	  ma->algo.implem);

  struct assh_context_s context;

  if (assh_context_init(&context, ASSH_CLIENT_SERVER,
			NULL, NULL, NULL, NULL))
    TEST_FAIL("context init");

  if (assh_algo_register_va(&context, 0, &ma->algo, NULL))
    TEST_FAIL("algo register");

  void *ectx = malloc(ma->ctx_size);
  void *dctx = malloc(ma->ctx_size);
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

    if (ma->f_init(&context, ectx, key, 1))
      TEST_FAIL("encrypt init");

    /* warm up */
    for (c = cycles; c--; )
      if (ma->f_process(ectx, data, data_size, code, c))
	TEST_FAIL("generate");

    gettimeofday(&tp_start, NULL);
    for (c = cycles; c--; )
      if (ma->f_process(ectx, data, data_size, code, c))
	TEST_FAIL("generate");
    gettimeofday(&tp_end, NULL);

    dte = ((uint64_t)tp_end.tv_sec * 1000000 + tp_end.tv_usec) -
      ((uint64_t)tp_start.tv_sec * 1000000 + tp_start.tv_usec);

    ssize_t l = 15 - printf("%.2f MB/s",
			     ((double)data_size * cycles) / dte);
    while (l-- > 0)
      putchar(' ');

    ma->f_cleanup(&context, ectx);
  }

  /* mac verify */
  {
    size_t c;

    if (ma->f_init(&context, ectx, key, 1))
      TEST_FAIL("generate init");

    if (ma->f_init(&context, dctx, key, 0))
      TEST_FAIL("verify init");

    /* warm up */
    for (c = cycles; c--; )
      {
	if (ma->f_process(ectx, data, data_size, code, c))
	  TEST_FAIL("generate");
	if (ma->f_process(dctx, data, data_size, code, c))
	  TEST_FAIL("verify");
      }

    gettimeofday(&tp_start, NULL);
    for (c = cycles; c--; )
      {
	if (ma->f_process(ectx, data, data_size, code, c))
	  TEST_FAIL("generate");
	if (ma->f_process(dctx, data, data_size, code, c))
	  TEST_FAIL("verify");
      }
    gettimeofday(&tp_end, NULL);

    dtd = ((uint64_t)tp_end.tv_sec * 1000000 + tp_end.tv_usec) -
      ((uint64_t)tp_start.tv_sec * 1000000 + tp_start.tv_usec) - dte;

    printf(" %.2f MB/s\n",
	    ((double)data_size * cycles) / dtd);

    ma->f_cleanup(&context, ectx);
    ma->f_cleanup(&context, dctx);
  }

  free(ectx);
  free(dctx);

  assh_context_cleanup(&context);
}

int main()
{
  if (assh_deps_init())
    return -1;

  printf(	  "  Algorithm                      Implem       Generate        Verify \n"
	  "--------------------------------------------------------------------------\n");

  if (data_size < 1024)
    TEST_FAIL("small data size");

  data = malloc(data_size);
  if (!data)
    TEST_FAIL("mac data alloc");
  memset(data, 0xaa, data_size);

  const struct assh_algo_s **a;
  for (a = assh_algo_table; *a; a++)
    {
      const struct assh_algo_mac_s *ma = assh_algo_mac(*a);
      if (ma)
	bench(ma);
    }

  free(data);
}
