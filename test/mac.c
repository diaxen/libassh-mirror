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

#define ASSH_ABI_UNSAFE  /* do not warn */

#include <assh/assh.h>
#include <assh/assh_mac.h>
#include <assh/assh_context.h>

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "test.h"

struct mac_test_s
{
  const char *algo;
  const char *key;
  const char *in;
  const char *out;
  uint32_t seq;
  uint_fast8_t in_size;
  uint_fast8_t key_size;
  uint_fast8_t mac_size;
};

const struct mac_test_s vectors[] =
{
  { .algo = "hmac-md5",
    .in_size = 16, .seq = 42,
    .key_size = 16, .mac_size = 16,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x14\xe6\x64\x01\xdd\x34\x89\xa7\xc6\x33\x2d\xed\x75\x46\x88\xc1"
  },

  { .algo = "hmac-md5",
    .in_size = 112, .seq = 42,
    .key_size = 16, .mac_size = 16,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\xa2\x89\x6a\x6b\x5d\xa3\x44\xee\xee\x84\x1e\x8a\xeb\xa4\xd8\x5d"
  },

  { .algo = "hmac-md5-etm@openssh.com",
    .in_size = 16, .seq = 42,
    .key_size = 16, .mac_size = 16,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x14\xe6\x64\x01\xdd\x34\x89\xa7\xc6\x33\x2d\xed\x75\x46\x88\xc1"
  },

  { .algo = "hmac-md5-etm@openssh.com",
    .in_size = 112, .seq = 42,
    .key_size = 16, .mac_size = 16,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\xa2\x89\x6a\x6b\x5d\xa3\x44\xee\xee\x84\x1e\x8a\xeb\xa4\xd8\x5d"
  },

  { .algo = "hmac-md5-96",
    .in_size = 16, .seq = 42,
    .key_size = 16, .mac_size = 12,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x14\xe6\x64\x01\xdd\x34\x89\xa7\xc6\x33\x2d\xed"
  },

  { .algo = "hmac-md5-96",
    .in_size = 112, .seq = 42,
    .key_size = 16, .mac_size = 12,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\xa2\x89\x6a\x6b\x5d\xa3\x44\xee\xee\x84\x1e\x8a"
  },

  { .algo = "hmac-md5-96-etm@openssh.com",
    .in_size = 16, .seq = 42,
    .key_size = 16, .mac_size = 12,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x14\xe6\x64\x01\xdd\x34\x89\xa7\xc6\x33\x2d\xed"
  },

  { .algo = "hmac-md5-96-etm@openssh.com",
    .in_size = 112, .seq = 42,
    .key_size = 16, .mac_size = 12,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\xa2\x89\x6a\x6b\x5d\xa3\x44\xee\xee\x84\x1e\x8a"
  },

  { .algo = "hmac-sha1",
    .in_size = 16, .seq = 42,
    .key_size = 20, .mac_size = 20,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x9d\x8a\x35\x43\x75\x57\x9f\x24\xe5\x6d\x04\x9a\xcf\xf4\x73\xef\x52\x19\x72\x89"
  },

  { .algo = "hmac-sha1",
    .in_size = 112, .seq = 42,
    .key_size = 20, .mac_size = 20,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x23\x12\x3f\xc6\xe4\xb8\xd7\xa9\xe0\x3b\x4d\x07\x03\x52\x67\x19\x30\xec\x43\xf6"
  },

  { .algo = "hmac-sha1-etm@openssh.com",
    .in_size = 16, .seq = 42,
    .key_size = 20, .mac_size = 20,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x9d\x8a\x35\x43\x75\x57\x9f\x24\xe5\x6d\x04\x9a\xcf\xf4\x73\xef\x52\x19\x72\x89"
  },

  { .algo = "hmac-sha1-etm@openssh.com",
    .in_size = 112, .seq = 42,
    .key_size = 20, .mac_size = 20,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x23\x12\x3f\xc6\xe4\xb8\xd7\xa9\xe0\x3b\x4d\x07\x03\x52\x67\x19\x30\xec\x43\xf6"
  },

  { .algo = "hmac-sha1-96",
    .in_size = 16, .seq = 42,
    .key_size = 20, .mac_size = 12,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x9d\x8a\x35\x43\x75\x57\x9f\x24\xe5\x6d\x04\x9a"
  },

  { .algo = "hmac-sha1-96",
    .in_size = 112, .seq = 42,
    .key_size = 20, .mac_size = 12,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x23\x12\x3f\xc6\xe4\xb8\xd7\xa9\xe0\x3b\x4d\x07"
  },

  { .algo = "hmac-sha1-96-etm@openssh.com",
    .in_size = 16, .seq = 42,
    .key_size = 20, .mac_size = 12,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x9d\x8a\x35\x43\x75\x57\x9f\x24\xe5\x6d\x04\x9a"
  },

  { .algo = "hmac-sha1-96-etm@openssh.com",
    .in_size = 112, .seq = 42,
    .key_size = 20, .mac_size = 12,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x23\x12\x3f\xc6\xe4\xb8\xd7\xa9\xe0\x3b\x4d\x07"
  },

  { .algo = "hmac-sha2-256",
    .in_size = 16, .seq = 42,
    .key_size = 32, .mac_size = 32,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a"
           "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x30\xb8\x3d\x67\xe7\x60\x37\xf7\x6a\x59\xcb\x18\xdc\xe8\xcb\xfd"
           "\xa3\xea\x32\xe7\x00\xdb\x60\xc2\x14\x3d\x9b\x56\xa0\xec\x53\xeb"
  },

  { .algo = "hmac-sha2-256",
    .in_size = 112, .seq = 42,
    .key_size = 32, .mac_size = 32,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a"
           "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\xd8\xff\x14\x1f\x27\x19\x1c\xd3\x3d\x1f\x2c\x30\x8c\x6c\x83\xf2"
           "\x4b\x44\xbf\x82\xef\xa6\x22\xa1\x3f\xf7\x31\xcf\x0e\x07\x46\x84"
  },

  { .algo = "hmac-sha2-256-etm@openssh.com",
    .in_size = 16, .seq = 42,
    .key_size = 32, .mac_size = 32,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a"
           "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x30\xb8\x3d\x67\xe7\x60\x37\xf7\x6a\x59\xcb\x18\xdc\xe8\xcb\xfd"
           "\xa3\xea\x32\xe7\x00\xdb\x60\xc2\x14\x3d\x9b\x56\xa0\xec\x53\xeb"
  },

  { .algo = "hmac-sha2-256-etm@openssh.com",
    .in_size = 112, .seq = 42,
    .key_size = 32, .mac_size = 32,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a"
           "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\xd8\xff\x14\x1f\x27\x19\x1c\xd3\x3d\x1f\x2c\x30\x8c\x6c\x83\xf2"
           "\x4b\x44\xbf\x82\xef\xa6\x22\xa1\x3f\xf7\x31\xcf\x0e\x07\x46\x84"
  },

  { .algo = "hmac-sha2-512",
    .in_size = 16, .seq = 42,
    .key_size = 64, .mac_size = 64,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a"
           "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a"
           "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a"
           "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x10\x95\x1e\xa9\x2d\xe9\x23\x90\x13\x49\x99\x21\x23\xa0\x7b\x9e"
           "\xf6\x1d\x72\xd4\x89\x31\xc8\xc2\xcd\xe3\xe4\x5a\x78\x40\x7a\x16"
           "\x4c\x17\x7e\xd7\x05\xbf\x21\x3f\x58\x57\x38\x26\xcd\x77\xc3\x08"
           "\x85\x4c\xd9\x88\x4d\x2f\xbb\xa1\x8a\x16\xb0\xd5\xe4\xae\xc4\xfc"
  },

  { .algo = "hmac-sha2-512",
    .in_size = 216, .seq = 42,
    .key_size = 64, .mac_size = 64,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a"
           "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a"
           "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a"
           "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x61\x49\xb3\x3c\x85\x2d\x40\x82\x2e\x31\x2c\x5a\xed\xd0\xfd\x2d"
           "\xda\x55\x41\x61\x85\x37\x2c\x8d\x31\x7d\x7e\xbc\xea\x78\x57\xdc"
           "\x08\xde\xb2\x11\xa7\xab\xe5\xc6\x1e\xc4\x2c\xf1\xb2\x82\x7f\xe0"
           "\x02\x81\x73\x3e\xf2\xec\x53\x75\x0d\xe2\x03\xc3\xa7\x8a\x8e\xf7"
  },

  { .algo = "hmac-sha2-512-etm@openssh.com",
    .in_size = 16, .seq = 42,
    .key_size = 64, .mac_size = 64,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a"
           "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a"
           "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a"
           "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x10\x95\x1e\xa9\x2d\xe9\x23\x90\x13\x49\x99\x21\x23\xa0\x7b\x9e"
           "\xf6\x1d\x72\xd4\x89\x31\xc8\xc2\xcd\xe3\xe4\x5a\x78\x40\x7a\x16"
           "\x4c\x17\x7e\xd7\x05\xbf\x21\x3f\x58\x57\x38\x26\xcd\x77\xc3\x08"
           "\x85\x4c\xd9\x88\x4d\x2f\xbb\xa1\x8a\x16\xb0\xd5\xe4\xae\xc4\xfc"
  },

  { .algo = "hmac-sha2-512-etm@openssh.com",
    .in_size = 216, .seq = 42,
    .key_size = 64, .mac_size = 64,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a"
           "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a"
           "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a"
           "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\x61\x49\xb3\x3c\x85\x2d\x40\x82\x2e\x31\x2c\x5a\xed\xd0\xfd\x2d"
           "\xda\x55\x41\x61\x85\x37\x2c\x8d\x31\x7d\x7e\xbc\xea\x78\x57\xdc"
           "\x08\xde\xb2\x11\xa7\xab\xe5\xc6\x1e\xc4\x2c\xf1\xb2\x82\x7f\xe0"
           "\x02\x81\x73\x3e\xf2\xec\x53\x75\x0d\xe2\x03\xc3\xa7\x8a\x8e\xf7"
  },

  { .algo = "hmac-ripemd160",
    .in_size = 16, .seq = 42,
    .key_size = 20, .mac_size = 20,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\xb8\xb2\x50\xee\x82\x1e\x32\x0a\x14\x39\xce\x41\xa4\x83\x08\x38\xed\xce\xd6\x4d"
  },

  { .algo = "hmac-ripemd160-etm@openssh.com",
    .in_size = 16, .seq = 42,
    .key_size = 20, .mac_size = 20,
    .key = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a",
    .out = "\xb8\xb2\x50\xee\x82\x1e\x32\x0a\x14\x39\xce\x41\xa4\x83\x08\x38\xed\xce\xd6\x4d"
  },

  { 0 }
};

void test_mac(const struct mac_test_s *t,
	      const struct assh_algo_mac_s *ma)
{
  struct assh_context_s context;

  if (assh_context_init(&context, ASSH_CLIENT_SERVER,
			test_leaks_allocator,
			NULL, NULL, NULL))
    TEST_FAIL("context init");

  if (t->key_size != ma->key_size)
    TEST_FAIL("key size");
  if (t->mac_size != ma->mac_size)
    TEST_FAIL("mac size");

  size_t in_size = t->in_size;
  size_t out_size = t->mac_size;
  uint32_t seq = t->seq;

  uint8_t *in;

  if (t->in != NULL)
    {
      /* use static input data */
      in = (uint8_t *)t->in;
    }
  else
    {
      /* use randomly generated input */
      in = malloc(in_size);
      uint64_t seed = t->seq;
      unsigned i;

      for (i = 0; i < in_size; i++)
	in[i] = test_prng_rand_seed(&seed);
    }

  uint8_t out[out_size];
  memset(out, 0, out_size);

  void *ectx = malloc(ma->ctx_size);
  void *dctx = malloc(ma->ctx_size);

  printf("testing %s, %s (%zu bytes): ",
	  t->algo, ma->algo.implem, in_size);

  if (ma->f_init(&context, ectx, (const uint8_t*)t->key, 1))
    TEST_FAIL("process init");

  if (ma->f_init(&context, dctx, (const uint8_t*)t->key, 0))
    TEST_FAIL("process init");

  putchar('C');
  if (ma->f_process(ectx, in, in_size, out, seq))
    TEST_FAIL("process");

  if (memcmp(out, t->out, out_size))
    {
      assh_hexdump(stderr, "output", out, out_size);
      assh_hexdump(stderr, "expected", t->out, out_size);
      TEST_FAIL("mac wrong output");
    }

  putchar('1');
  if (ma->f_process(dctx, in, in_size, out, seq))
    TEST_FAIL("check good");

  putchar('t');
  out[rand() % out_size] ^= 1 << (rand() % 8);

  putchar('2');
  if (!ma->f_process(dctx, in, in_size, out, seq))
    TEST_FAIL("check wrong");

  if (t->in == NULL)
    {
      putchar('T');
      in[rand() % in_size] ^= 1 << (rand() % 8);

      putchar('3');
      if (!ma->f_process(dctx, in, in_size, (uint8_t*)t->out, seq))
	TEST_FAIL("check wrong");

      putchar('c');
      if (ma->f_process(ectx, in, in_size, out, seq))
	TEST_FAIL("process");

      if (!memcmp(out, t->out, out_size))
	{
	  assh_hexdump(stderr, "output", out, out_size);
	  assh_hexdump(stderr, "expected", t->out, out_size);
	  TEST_FAIL("mac good output");
	}
    }

  printf("\n");

  if (t->in == NULL)
    free(in);

  ma->f_cleanup(&context, ectx);
  ma->f_cleanup(&context, dctx);
  free(ectx);
  free(dctx);

  assh_context_cleanup(&context);
}

int
main(int argc, char **argv)
{
  setvbuf(stdout, NULL, _IONBF, 0);

  if (assh_deps_init())
    return -1;

  uint_fast16_t i;
  for (i = 0; vectors[i].algo != NULL; i++)
    {
      const struct mac_test_s *t = &vectors[i];

      if (!strcmp(t->algo, "none"))
	{
	  test_mac(t, &assh_mac_none);
	  continue;
	}

      assh_bool_t done = 0;
      const struct assh_algo_s **a;

      for (a = assh_algo_table; *a; a++)
	{
	  if (!assh_algo_name_match(*a, ASSH_ALGO_MAC,
				    t->algo, strlen(t->algo)))
	    continue;

	  done = 1;
	  test_mac(t, (void*)*a);

	  if (test_alloc_size != 0)
	    TEST_FAIL("memory leak detected, %zu bytes allocated\n", test_alloc_size);
	}

      if (!done)
	printf("skipping %s, no implementation\n", t->algo);
    }

  puts("\nTest passed");
  return 0;
}
