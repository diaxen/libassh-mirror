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

#include <assh/assh_session.h>
#include <assh/assh_context.h>
#include <assh/assh_kex.h>
#include <assh/assh_cipher.h>
#include <assh/assh_sign.h>
#include <assh/assh_mac.h>
#include <assh/assh_prng.h>
#include <assh/assh_compress.h>
#include <assh/assh_transport.h>
#include <assh/assh_connection.h>
#include <assh/assh_service.h>
#include <assh/assh_event.h>
#include <assh/assh_userauth.h>
#include <assh/assh_key.h>

#define FIFO_BUF_SIZE 65536

#include "fifo.h"
#include "keys.h"
#include "test.h"
#include "leaks_check.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>

struct fifo_s fifo[2];

struct kex_bench_s
{
  const char *kex_name;
  size_t key_bits;
  const struct assh_algo_cipher_s *cipher_algo;
};

static ASSH_CIPHER_INIT_FCN(assh_none_init)
{
  return ASSH_OK;
}

static ASSH_CIPHER_PROCESS_FCN(assh_none_process)
{
  return ASSH_OK;
}

static ASSH_CIPHER_CLEANUP_FCN(assh_none_cleanup)
{
}

const struct assh_algo_cipher_s assh_cipher_none_64 =
{
  ASSH_ALGO_BASE(CIPHER, "assh-builtin", 0, 99,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_ASSH,
                      "none" })
  ),
  .ctx_size = 0,
  .block_size = 8,
  .head_size = 4,
  .key_size = 8,
  .f_init = assh_none_init,
  .f_process = assh_none_process,
  .f_cleanup = assh_none_cleanup,
};

const struct assh_algo_cipher_s assh_cipher_none_128 =
{
  ASSH_ALGO_BASE(CIPHER, "assh-builtin", 0, 99,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_ASSH,
                      "none" })
  ),
  .ctx_size = 0,
  .block_size = 8,
  .head_size = 4,
  .key_size = 16,
  .f_init = assh_none_init,
  .f_process = assh_none_process,
  .f_cleanup = assh_none_cleanup,
};

const struct assh_algo_cipher_s assh_cipher_none_192 =
{
  ASSH_ALGO_BASE(CIPHER, "assh-builtin", 0, 99,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_ASSH,
                      "none" })
  ),
  .ctx_size = 0,
  .block_size = 8,
  .head_size = 4,
  .key_size = 24,
  .f_init = assh_none_init,
  .f_process = assh_none_process,
  .f_cleanup = assh_none_cleanup,
};

const struct assh_algo_cipher_s assh_cipher_none_256 =
{
  ASSH_ALGO_BASE(CIPHER, "assh-builtin", 0, 99,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_ASSH,
                      "none" })
  ),
  .ctx_size = 0,
  .block_size = 8,
  .head_size = 4,
  .key_size = 32,
  .f_init = assh_none_init,
  .f_process = assh_none_process,
  .f_cleanup = assh_none_cleanup,
};

const struct kex_bench_s vectors[] =
{
  { "curve25519-sha256@libssh.org"         , 0, &assh_cipher_none_128 },
  { "m383-sha384@libassh.org"              , 0, &assh_cipher_none_128 },
  { "m511-sha512@libassh.org"              , 0, &assh_cipher_none_128 },
  { "ecdh-sha2-nistp256"                   , 0, &assh_cipher_none_128 },
  { "ecdh-sha2-nistp384"                   , 0, &assh_cipher_none_128 },
  { "ecdh-sha2-nistp521"                   , 0, &assh_cipher_none_128 },
  { "rsa1024-sha1"                         , 1024, &assh_cipher_none_128 },
  { "rsa2048-sha256"                       , 2048, &assh_cipher_none_128 },
  { "diffie-hellman-group1-sha1"           , 0, &assh_cipher_none_64  },
  { "diffie-hellman-group1-sha1"           , 0, &assh_cipher_none_128 },
  { "diffie-hellman-group1-sha1"           , 0, &assh_cipher_none_192 },
  { "diffie-hellman-group1-sha1"           , 0, &assh_cipher_none_256 },
  { "diffie-hellman-group14-sha1"          , 0, &assh_cipher_none_64  },
  { "diffie-hellman-group14-sha1"          , 0, &assh_cipher_none_128 },
  { "diffie-hellman-group14-sha1"          , 0, &assh_cipher_none_192 },
  { "diffie-hellman-group14-sha1"          , 0, &assh_cipher_none_256 },
  { "diffie-hellman-group-exchange-sha1"   , 0, &assh_cipher_none_64  },
  { "diffie-hellman-group-exchange-sha1"   , 0, &assh_cipher_none_128 },
  { "diffie-hellman-group-exchange-sha1"   , 0, &assh_cipher_none_192 },
  { "diffie-hellman-group-exchange-sha1"   , 0, &assh_cipher_none_256 },
  { "diffie-hellman-group-exchange-sha256" , 0, &assh_cipher_none_64  },
  { "diffie-hellman-group-exchange-sha256" , 0, &assh_cipher_none_128 },
  { "diffie-hellman-group-exchange-sha256" , 0, &assh_cipher_none_192 },
  { "diffie-hellman-group-exchange-sha256" , 0, &assh_cipher_none_256 },
  { "diffie-hellman-group14-sha256"        , 0, &assh_cipher_none_64  },
  { "diffie-hellman-group14-sha256"        , 0, &assh_cipher_none_128 },
  { "diffie-hellman-group14-sha256"        , 0, &assh_cipher_none_192 },
  { "diffie-hellman-group14-sha256"        , 0, &assh_cipher_none_256 },
  { "diffie-hellman-group15-sha512"        , 0, &assh_cipher_none_64  },
  { "diffie-hellman-group15-sha512"        , 0, &assh_cipher_none_128 },
  { "diffie-hellman-group15-sha512"        , 0, &assh_cipher_none_192 },
  { "diffie-hellman-group15-sha512"        , 0, &assh_cipher_none_256 },
  { "diffie-hellman-group16-sha512"        , 0, &assh_cipher_none_64  },
  { "diffie-hellman-group16-sha512"        , 0, &assh_cipher_none_128 },
  { "diffie-hellman-group16-sha512"        , 0, &assh_cipher_none_192 },
  { "diffie-hellman-group16-sha512"        , 0, &assh_cipher_none_256 },
  { "diffie-hellman-group17-sha512"        , 0, &assh_cipher_none_64  },
  { "diffie-hellman-group17-sha512"        , 0, &assh_cipher_none_128 },
  { "diffie-hellman-group17-sha512"        , 0, &assh_cipher_none_192 },
  { "diffie-hellman-group17-sha512"        , 0, &assh_cipher_none_256 },
  { "diffie-hellman-group18-sha512"        , 0, &assh_cipher_none_64  },
  { "diffie-hellman-group18-sha512"        , 0, &assh_cipher_none_128 },
  { "diffie-hellman-group18-sha512"        , 0, &assh_cipher_none_192 },
  { "diffie-hellman-group18-sha512"        , 0, &assh_cipher_none_256 },
  { NULL },
};

void bench(const struct kex_bench_s *t,
	   const struct assh_algo_kex_s *ka)
{
  struct assh_context_s context[2];

  unsigned i;

  if (assh_context_init(&context[0], ASSH_SERVER,
			&assh_leaks_allocator, NULL, &assh_prng_dummy, NULL) ||
      assh_context_init(&context[1], ASSH_CLIENT,
			&assh_leaks_allocator, NULL, &assh_prng_dummy, NULL))
    TEST_FAIL("ctx init\n");

  printf("%-36s %-13s %3u-bit   ",
	  assh_algo_name(&ka->algo_wk.algo),
	  ka->algo_wk.algo.implem,
	  t->cipher_algo->key_size * 8);

  for (i = 0; i < 2; i++)
    {
      struct assh_context_s *c = &context[i];

      if (assh_algo_register_va(c, 0, 0, 0,
				&ka->algo_wk.algo, &assh_sign_none.algo_wk.algo,
				&assh_mac_none.algo, &assh_compress_none.algo,
				t->cipher_algo,
				NULL))
	TEST_FAIL("algo register\n");

      if (assh_service_register_va(c, &assh_service_connection, NULL))
	TEST_FAIL("service register\n");

      if (i == 0 && assh_key_create(context, assh_context_keys(context),
				    0, &assh_key_none, ASSH_ALGO_SIGN))
	TEST_FAIL("host key\n");

      if (t->key_bits && assh_key_create(context, assh_context_keys(context),
				 t->key_bits, ka->algo_wk.key_algo, ASSH_ALGO_KEX))
	TEST_FAIL("kex key\n");
    }

  unsigned c = 0;
  uint64_t dt[2] = { 0, 0 };

  do {
    struct assh_session_s session[2];

    for (i = 0; i < 2; i++)
      {
	if (assh_session_init(&context[i], &session[i]))
	  TEST_FAIL("sessions init");
	fifo_init(&fifo[i]);

	assh_userauth_done(&session[i]);
      }

    uint_fast8_t done = 0;

    struct timeval tp_start, tp_end;
    gettimeofday(&tp_start, NULL);

    while (done != 3)
      {
	for (i = 0; i < 2; i++)
	  {
	    struct assh_event_s event;

	    if (!assh_event_get(&session[i], &event, 0))
	      TEST_FAIL("terminted before KEX_DONE");

	    switch (event.id)
	      {
	      case ASSH_EVENT_SESSION_ERROR:
		TEST_FAIL("error %lx\n", event.session.error.code);
		break;

	      case ASSH_EVENT_KEX_HOSTKEY_LOOKUP:
		event.kex.hostkey_lookup.accept = 1;
		break;

	      case ASSH_EVENT_KEX_DONE:
		done |= 1 << i;
		break;

	      case ASSH_EVENT_READ:
		fifo_rw_event(fifo, &event, i);
		break;

	      case ASSH_EVENT_WRITE:
		fifo_rw_event(fifo, &event, i);
		break;

	      default:
		ASSH_DEBUG("event %u not handled\n", event.id);
	      }

	    assh_event_done(&session[i], &event, ASSH_OK);

	    gettimeofday(&tp_end, NULL);

	    dt[i] += ((uint64_t)tp_end.tv_sec * 1000000 + tp_end.tv_usec) -
	             ((uint64_t)tp_start.tv_sec * 1000000 + tp_start.tv_usec);

	    tp_start = tp_end;
	  }
      }

    c++;

    assh_session_cleanup(&session[0]);
    assh_session_cleanup(&session[1]);

  } while (dt[0] + dt[1] < 1000000);

  assh_context_cleanup(&context[0]);
  assh_context_cleanup(&context[1]);

  if (alloc_size != 0)
    TEST_FAIL("memory leak detected, %zu bytes allocated\n", alloc_size);

  ssize_t l = 9 - printf("%.1f", 1000000. * c / dt[0]);
  while (l-- > 0)
    putchar(' ');

  l = 9 - printf("%.1f", 1000000. * c / dt[1]);
  while (l-- > 0)
    putchar(' ');

  if (ka->algo_wk.algo.variant)
    printf("   (%s)\n", ka->algo_wk.algo.variant);
  else
    putchar('\n');
}

int main(int argc, char **argv)
{
  if (assh_deps_init())
    return -1;

  printf(	  "  Kex algorithm                      Implem        Cipher    Sv.Kex/s Cl.Kex/s\n"
	  "----------------------------------------------------------------------------------\n");

  uint_fast16_t i;
  for (i = 0; vectors[i].kex_name != NULL; i++)
    {
      const struct kex_bench_s *t = &vectors[i];
      const struct assh_algo_s **a;

      for (a = assh_algo_table; *a; a++)
	{
	  if (!assh_algo_name_match(*a, ASSH_ALGO_KEX,
				    t->kex_name, strlen(t->kex_name)))
	    continue;

	  bench(t, (void*)*a);
	}
    }

  return 0;
}
