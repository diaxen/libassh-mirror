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
#include <assh/assh_cipher.h>
#include <assh/assh_context.h>
#include <assh/assh_packet.h>

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <sys/time.h>
#ifdef __linux__
# include <sched.h>
#endif

#include "test.h"

#define WARNUP_DELAY 500000

static void *data;
static size_t data_size = 1024;

static void bench(const struct assh_algo_cipher_s *ca)
{
  printf("%-30s %-13s  ",
	  assh_algo_name(&ca->algo),
	  ca->algo.implem);

  struct assh_context_s context;

  if (assh_context_init(&context, ASSH_CLIENT_SERVER,
			NULL, NULL, NULL, NULL))
    TEST_FAIL("context init");

  if (assh_algo_register_va(&context, 0, &ca->algo, NULL))
    TEST_FAIL("algo register");

  void *ectx = malloc(ca->ctx_size);
  void *dctx = malloc(ca->ctx_size);
  if (!ectx || !dctx)
    TEST_FAIL("cipher ctx alloc");

  const uint8_t *key_iv = (const uint8_t *)
    "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55"
    "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55"
    "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55"
    "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55";

  struct timeval tp_start, tp_end;
  uint64_t dte, dtd;
  size_t c, cycles;

  /* encryption */
  {
    size_t s = data_size;

    if (ca->f_init(&context, ectx, key_iv, key_iv, 1))
      TEST_FAIL("encrypt init");

    s = s - 128 + ca->auth_size + ca->head_size;

    /* warm up & find cycles count */
    gettimeofday(&tp_start, NULL);
    for (cycles = 0; ; cycles++)
      {
	if (ca->f_process(ectx, data, s, ASSH_CIPHER_PCK_TAIL, cycles))
	  TEST_FAIL("encrypt");

	gettimeofday(&tp_end, NULL);

	if (((uint64_t)tp_end.tv_sec * 1000000 + tp_end.tv_usec) -
	    ((uint64_t)tp_start.tv_sec * 1000000 + tp_start.tv_usec) > WARNUP_DELAY)
	  break;
      }

    gettimeofday(&tp_start, NULL);
    for (c = cycles; c--; )
      if (ca->f_process(ectx, data, s, ASSH_CIPHER_PCK_TAIL, c))
	TEST_FAIL("encrypt");
    gettimeofday(&tp_end, NULL);

    dte = ((uint64_t)tp_end.tv_sec * 1000000 + tp_end.tv_usec) -
      ((uint64_t)tp_start.tv_sec * 1000000 + tp_start.tv_usec);

    ssize_t l = 15 - printf("%.2f MB/s",
			     ((double)s * cycles) / dte);
    while (l-- > 0)
      putchar(' ');

    ca->f_cleanup(&context, ectx);
  }

  /* decryption */
  {
    size_t s = data_size;

    if (ca->f_init(&context, ectx, key_iv, key_iv, 1))
      TEST_FAIL("encrypt init");

    if (ca->f_init(&context, dctx, key_iv, key_iv, 0))
      TEST_FAIL("decrypt init");

    if (ca->auth_size)
      {
	s = s - 128 + ca->auth_size + ca->head_size;

	/* warm up */
	for (c = cycles; c--; )
	  {
	    if (ca->f_process(ectx, data, s, ASSH_CIPHER_PCK_TAIL, cycles))
	      TEST_FAIL("encrypt");

	    if (ca->f_process(dctx, data, ca->head_size, ASSH_CIPHER_PCK_HEAD, cycles))
	      TEST_FAIL("decrypt");

	    if (ca->f_process(dctx, data, s, ASSH_CIPHER_PCK_TAIL, cycles))
	      TEST_FAIL("decrypt");
	  }

	gettimeofday(&tp_start, NULL);
	for (c = cycles; c--; )
	  {
	    if (ca->f_process(ectx, data, s, ASSH_CIPHER_PCK_TAIL, c))
	      TEST_FAIL("encrypt");

	    if (ca->f_process(dctx, data, ca->head_size, ASSH_CIPHER_PCK_HEAD, c))
	      TEST_FAIL("decrypt");

	    if (ca->f_process(dctx, data, s, ASSH_CIPHER_PCK_TAIL, c))
	      TEST_FAIL("decrypt");
	  }
	gettimeofday(&tp_end, NULL);
      }
    else
      {
	/* warm up */
	for (c = cycles; c--; )
	  {
	    if (ca->head_size &&
		ca->f_process(dctx, data, ca->head_size, ASSH_CIPHER_PCK_HEAD, cycles))
	      TEST_FAIL("decrypt");

	    if (ca->f_process(dctx, data + ca->head_size, s - ca->head_size, ASSH_CIPHER_PCK_TAIL, cycles))
	      TEST_FAIL("decrypt");
	  }

	gettimeofday(&tp_start, NULL);
	for (c = cycles; c--; )
	  {
	    if (ca->head_size &&
		ca->f_process(dctx, data, ca->head_size, ASSH_CIPHER_PCK_HEAD, c))
	      TEST_FAIL("decrypt");

	    if (ca->f_process(dctx, data + ca->head_size, s - ca->head_size, ASSH_CIPHER_PCK_TAIL, c))
	      TEST_FAIL("decrypt");
	  }
	gettimeofday(&tp_end, NULL);
      }

    dtd = ((uint64_t)tp_end.tv_sec * 1000000 + tp_end.tv_usec) -
      ((uint64_t)tp_start.tv_sec * 1000000 + tp_start.tv_usec);

    if (ca->auth_size)
      dtd -= dte;

    printf(" %.2f MB/s\n",
	    ((double)s * cycles) / dtd);

    ca->f_cleanup(&context, ectx);
    ca->f_cleanup(&context, dctx);
  }

  free(ectx);
  free(dctx);

  assh_context_cleanup(&context);
}

static void usage()
{
  printf("usage: cipher_bench [options]\n");

  printf(	  "Options:\n\n"

	  "    -h         show help\n"
	  "    -A         ciphers with authentication only\n"
	  "    -p size    specify packet size in bytes\n"
	  "    -C substr  filter by cipher name\n"
	  "    -I substr  filter by cipher implementation\n"
	  );
}

int main(int argc, char **argv)
{
  if (assh_deps_init())
    return -1;

  int opt;
  const char *cipher_filter = NULL;
  const char *implem_filter = NULL;
  int auth_only = 0;

  while ((opt = getopt(argc, argv, "hp:C:I:A")) != -1)
    {
      switch (opt)
	{
	case 'p':
	  data_size = atoi(optarg) & ~127;
	  if (!data_size || data_size > CONFIG_ASSH_MAX_PACKET_LEN)
	    TEST_FAIL("valid data size range is [128, %u]\n", CONFIG_ASSH_MAX_PACKET_LEN);
	  break;
	case 'C':
	  cipher_filter = optarg;
	  break;
	case 'I':
	  implem_filter = optarg;
	  break;
	case 'A':
	  auth_only = 1;
	  break;
	case 'h':
	  usage();
	default:
	  return 1;
	}
    }

  printf("Using packets of %zu bytes\n", data_size);

  data = malloc(data_size);
  if (!data)
    TEST_FAIL("cipher data alloc");
  memset(data, 0xaa, data_size);

#ifdef __linux__
  struct sched_param sp = { .sched_priority = 1 };
  if (sched_setscheduler(0, SCHED_FIFO, &sp) == -1)
    fprintf(stderr, "warning: unable to change scheduler policy\n");
#endif

  printf(	  "\n  Algorithm                      Implem       Encrypt         Decrypt\n"
	  "--------------------------------------------------------------------------\n");

  const struct assh_algo_s **a;
  for (a = assh_algo_table; *a; a++)
    {
      const char *name = assh_algo_name(*a);
      const char *implem = assh_algo_implem(*a);

      if (cipher_filter && !strstr(name, cipher_filter))
	continue;

      if (implem_filter && !strstr(implem, implem_filter))
	continue;

      const struct assh_algo_cipher_s *ca = assh_algo_cipher(*a);

      if (!ca)
	continue;

      if (!ca->auth_size && auth_only)
	continue;

      if (!assh_algo_supported(*a))
	{
	  printf("%-30s %-13s  missing platform support\n",
		 name, implem);
	  continue;
	}

      bench(ca);
#ifdef __linux__
      sched_yield();
#endif
    }

  free(data);
  return 0;
}
