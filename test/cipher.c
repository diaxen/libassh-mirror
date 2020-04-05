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
#include <assh/assh_cipher.h>
#include <assh/assh_context.h>

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "test.h"
#include "leaks_check.h"

struct cipher_test_s
{
  const char *algo;
  const char *key;
  const char *iv;
  const char *out;
  uint32_t seq;
  int_fast16_t head_size;
  int_fast16_t tail_size;
  int_fast16_t key_size;
  int_fast16_t iv_size;
  uint_fast8_t out_count;
};

const struct cipher_test_s vectors[] =
{
  { .algo = "none",
    .head_size = 16, .tail_size = 24, .out_count = 1,
    .out = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a"
    "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a"
    "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a" },

  { .algo = "arcfour",
    .head_size = 16, .tail_size = 24, .key_size = 16, .out_count = 2,
    .key = "\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10",
    .out = "\x78\xd5\xfb\x2e\xa0\xbd\x04\x28\x80\x9b\x8b\x00\x00\xe1\xa3\xa9"
    "\xe4\xd1\xcf\x96\x4e\xe3\x6b\xba\x84\xb5\x29\x3a\x0b\x99\x48\x83"
    "\x8c\x75\x3a\x60\x72\xd1\x7f\x79"
    /* 1 */ "\x6a\x49\x9f\x65\xd3\x45\x6f\x19\x93\xec\x1b\xd9\x76\x66\x1c\x96"
    "\x76\x94\x26\x97\x3b\x65\x04\x74\x73\x4c\xc4\x75\x01\x11\x0b\x7c"
    "\xf1\xdf\x86\x47\x33\x27\x46\xc1" },
  { .algo = "arcfour128",
    .head_size = 16, .tail_size = 24, .key_size = 16, .out_count = 1,
    .key = "\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10",
    .out = "\x6c\x74\x0d\xc2\xae\x11\xff\x9c\x7a\x92\xb4\xe6\x0e\xb4\x05\x4b"
    "\x29\x44\xdf\x3a\x8a\x1a\x8a\xd9\x4f\x42\xa2\x70\x2e\x01\x1b\xdc"
    "\xdf\x65\x4b\x17\x0f\x62\xaa\xfa" },
  { .algo = "arcfour256",
    .head_size = 16, .tail_size = 24, .key_size = 32, .out_count = 1,
    .key = "\xab\xcd\xef\x01\x23\x45\x67\x89\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98"
    "\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10\xab\xcd\xef\x01\x23\x45\x67\x89",
    .out = "\xed\x7f\xd7\x49\x07\x61\xf5\x4a\x84\x96\x38\x82\xa6\x05\x91\x16"
    "\x72\x6c\x43\x50\xfc\x01\xa7\xfa\x80\xc3\x27\xe3\xde\xcb\xd8\xeb"
    "\x76\xbf\xa4\x9e\x3f\x30\x09\x28" },

  { .algo = "3des-cbc",
    .head_size = 16, .tail_size = 24, .key_size = 24, .iv_size = 8, .out_count = 2,
    .key = "\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10"
    "\xab\xcd\xef\x01\x23\x45\x67\x89",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77",
    .out = "\xcd\xa5\xf2\xc2\xae\x8f\xb0\x0a\x51\xff\xbb\xca\x06\x98\xb4\xb9"
    "\x0f\xa8\x4e\xe5\x12\x01\x7a\x97\xbe\xae\x77\x07\x45\x0b\xc5\xf1"
    "\x3c\x39\x91\x8d\xfc\x9e\x28\xae"
    /* 1 */ "\x71\x88\x80\xf3\xae\xda\xbd\x5c\x1a\x73\x96\x29\xaa\x34\x35\x11"
    "\x05\x63\xd5\xda\x3b\x3b\xfb\xb0\x54\x8a\x56\xbe\xbd\xaa\x9a\x8e"
    "\x7b\xfa\x5c\xde\xbc\x84\x1c\xeb"},

  { .algo = "3des-ctr",
    .head_size = 16, .tail_size = 24, .key_size = 24, .iv_size = 8, .out_count = 1,
    .key = "\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10"
    "\xab\xcd\xef\x01\x23\x45\x67\x89",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77",
    .out = "\x54\x73\xad\x19\x4d\x42\x0b\x8a\x5d\xf9\xf4\x32\x7a\xa6\xe7\x15"
    "\x48\xa3\x0d\x98\x85\xdd\xe5\xf0\x05\xc0\x0b\x3d\xdd\x4f\xea\xaf"
    "\xd4\xd7\xe5\xcd\xcd\x3a\xdc\xff" },

  { .algo = "cast128-cbc",
    .head_size = 16, .tail_size = 24, .key_size = 16, .iv_size = 8, .out_count = 1,
    .key = "\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77",
    .out = "\xa7\x16\xae\x9e\xb9\x8d\xe0\xfc\xac\xda\xbd\x86\x2a\x08\x43\x81"
    "\x49\x9b\xf4\x92\x7e\xae\x46\x9c\xba\x13\x7d\x2b\x49\xd7\x08\xa7"
    "\x09\x00\x1b\xa1\xf1\x79\x11\x24" },

  { .algo = "cast128-ctr",
    .head_size = 16, .tail_size = 24, .key_size = 16, .iv_size = 8, .out_count = 1,
    .key = "\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77",
    .out = "\x34\x6c\x72\x35\x54\xbd\x5c\x0d\xfc\x2d\x2e\xde\x0a\xc7\x26\xec"
    "\x66\x69\xdf\x6f\x3b\x43\x3d\x50\xf0\x2c\x66\xf3\x6d\xfa\x23\x60"
    "\xae\xec\xae\x3f\x5b\x94\x0f\xa8" },

  { .algo = "idea-cbc",
    .head_size = 16, .tail_size = 24, .key_size = 16, .iv_size = 8, .out_count = 1,
    .key = "\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77",
    .out = "\x08\xce\xb1\x3a\x97\x4d\xd0\x46\x28\x4a\x37\x6a\x24\x4f\x23\xa2"
    "\x87\x62\xae\x1f\x3d\xb9\xb8\x10\x7b\xa0\x79\xde\x2b\xd0\x35\x49"
    "\xe8\xe1\x41\xeb\x8c\x93\x3e\x97" },

  { .algo = "idea-ctr",
    .head_size = 16, .tail_size = 24, .key_size = 16, .iv_size = 8, .out_count = 1,
    .key = "\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77",
    .out = "\x9d\xaf\x40\xf9\x53\x5a\x4d\xfc\xdd\xb3\xc6\xe9\x25\xc1\x61\x6f"
    "\xbf\x8d\x05\x10\xb2\x54\xb2\xdb\xd7\x37\x11\x99\x17\xdf\x30\x07"
    "\x00\x39\x2f\x21\xd7\xf8\xf2\x21" },

  { .algo = "blowfish-cbc",
    .head_size = 16, .tail_size = 24, .key_size = 16, .iv_size = 8, .out_count = 1,
    .key = "\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77",
    .out = "\x92\xec\x1b\xc7\x64\x15\xbe\x7f\xb7\xe8\x4f\xd4\x00\x8c\xaf\xb6"
    "\x86\x7c\x25\xb0\xf0\x84\x05\x16\xb4\xda\x01\x1c\x9c\x6e\xf0\x2f"
    "\xaa\x58\xc5\x06\x04\x01\xfc\x8b" },

  { .algo = "blowfish-ctr",
    .head_size = 16, .tail_size = 24, .key_size = 32, .iv_size = 8, .out_count = 1,
    .key = "\xab\xcd\xef\x01\x23\x45\x67\x89\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98"
    "\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10\xab\xcd\xef\x01\x23\x45\x67\x89",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77",
    .out = "\xd0\xf0\x55\xe3\xc0\x72\xf3\x40\x94\xc6\x63\x04\x00\xcb\xe9\xaa"
    "\xf4\x7f\x19\xb1\x48\x46\xc8\x72\x41\x8b\x08\xf4\x13\x0c\x4c\x6e"
    "\x6d\x98\xa8\x3d\x04\x09\x6b\x61" },

  { .algo = "aes128-cbc",
    .head_size = 16, .tail_size = 32, .key_size = 16, .iv_size = 16, .out_count = 2,
    .key = "\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
    .out = "\xd9\xa1\x54\x09\x9a\x33\x9a\x5a\x6d\xcc\x0c\x37\x3b\x79\xc2\xb7"
    "\xd5\x91\x01\xc9\xed\xa7\x82\x95\xf1\x23\x35\xc6\xf4\xfd\x3b\xba"
    "\xcc\xf9\xa1\xa8\xa5\xdf\x64\x9e\xf3\xae\x63\x4e\x0e\xc8\x90\xc0"
    /* 1 */ "\x2c\x44\x3f\xe5\xb4\x8c\x7d\x69\xe7\xd5\xeb\xfa\x61\x59\x3d\x6a"
    "\x9d\x93\xe5\xda\x0b\xe4\x11\x12\x12\xa8\x44\x1c\x83\x71\x3f\x5c"
    "\x30\xa3\x97\x93\x58\x96\xe0\x4f\x9b\x46\x05\x2b\xa4\x8a\xec\x64" },

  { .algo = "aes192-cbc",
    .head_size = 16, .tail_size = 32, .key_size = 24, .iv_size = 16, .out_count = 1,
    .key = "\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10"
    "\xab\xcd\xef\x01\x23\x45\x67\x89",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
    .out = "\x17\x1a\x32\xd8\x27\xf9\xb8\xb2\x44\x11\xd7\x0d\xa0\x03\x32\x7c"
    "\x90\xe9\xab\xc3\xbc\xde\xf2\x0e\xd1\xd5\x78\x12\xcd\x69\x51\x4f"
    "\xad\x73\x68\x9e\xea\x7f\x93\x54\x0c\x62\x28\x00\xa1\x01\x29\x8f" },

  { .algo = "aes256-cbc",
    .head_size = 16, .tail_size = 32, .key_size = 32, .iv_size = 16, .out_count = 1,
    .key = "\xab\xcd\xef\x01\x23\x45\x67\x89\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98"
    "\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10\xab\xcd\xef\x01\x23\x45\x67\x89",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
    .out = "\x3e\xb1\x2b\x8e\xcd\xa9\x69\xb2\x5d\xa1\xc9\xc4\x74\x4d\x5e\x06"
    "\x3d\xa8\x85\xdf\x8b\xa5\x7d\xf8\x48\xa3\x61\x07\x1a\xf9\x56\xef"
    "\x91\xa2\x24\xb6\x38\x49\x40\xa3\xb5\x59\xc9\x33\x87\x11\xc3\xfc" },

  { .algo = "aes128-ctr",
    .head_size = 16, .tail_size = 32, .key_size = 16, .iv_size = 16, .out_count = 2,
    .key = "\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
    .out = "\xfc\x1a\xf3\x90\x9f\xad\x96\xbb\x61\xad\xb8\x33\x99\xd1\xcf\x07"
    "\x4c\xa3\xc3\x69\xad\x57\x3c\x58\x63\xb6\x0f\xf7\x68\xe6\xf7\x06"
    "\xa9\x53\x59\xc2\x41\x79\x0b\x25\xa6\x8c\xa6\x29\x7f\xf2\x3e\x91"
    /* 1 */ "\xa4\xbf\x3f\x48\x40\x33\x1c\xb8\xac\x77\x1b\x9f\x62\xba\xc3\xc0"
    "\x31\x74\xa8\x46\x54\x7f\x85\x71\xf9\x5f\xb7\xf8\x41\xaf\xf3\x70"
    "\xfd\x9d\x5e\x6a\x42\x86\x1d\xe1\x41\x6c\x86\x61\x44\x2a\x59\xf0" },

  { .algo = "aes192-ctr",
    .head_size = 16, .tail_size = 32, .key_size = 24, .iv_size = 16, .out_count = 1,
    .key = "\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10"
    "\xab\xcd\xef\x01\x23\x45\x67\x89",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
    .out = "\xab\x81\x34\xfc\x66\x8b\x50\xad\xe4\x75\x1c\x1a\x95\xea\x92\xfe"
    "\xc0\x4b\x15\x4e\xd8\xf2\xc1\xe0\x75\x5e\x1f\xdd\xe8\x03\x90\x88"
    "\xea\x11\xf1\x02\xa3\x13\x7f\xf6\xca\xab\xd9\x05\x05\x3d\x1a\xa0" },

  { .algo = "aes256-ctr",
    .head_size = 16, .tail_size = 32, .key_size = 32, .iv_size = 16, .out_count = 1,
    .key = "\xab\xcd\xef\x01\x23\x45\x67\x89\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98"
    "\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10\xab\xcd\xef\x01\x23\x45\x67\x89",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
    .out = "\x86\xf2\x5c\x8a\x6c\xa7\xfe\x7f\xaf\x9c\xad\x7d\x6d\xf6\xca\xf1"
    "\xa4\x70\x57\x13\x6a\x18\xb7\x6c\x68\x14\x7c\xf2\x7e\xcb\xb8\x0d"
    "\x1f\x2e\x5a\xa9\x69\x5b\xf3\x88\xd6\x26\xe2\x35\x12\x55\x8f\x57" },

  { .algo = "aes128-gcm@openssh.com",
    .head_size = 0, .tail_size = 32 + 4, .key_size = 16, .iv_size = 12, .out_count = 2,
    .key = "\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb",
    .out = "\x2a\x2a\x2a\x2a\x6c\x3e\x2c\xce\x1d\xae\x68\x00\xed\xb8\x49\x31"
    "\x13\xfa\x4b\xe1\xb6\xc2\xae\x17\x4e\xb3\xca\xd0\x0e\x3e\x37\xc2"
    "\x0c\x57\x3f\x5f"
    /* 1 */ "\x2a\x2a\x2a\x2a\x1b\xaf\x5d\xbc\x07\xf3\xe2\xdb\xda\xcb\xb3\xd8"
    "\x2c\x8a\xe5\x13\x74\xfc\x42\x28\xc4\x19\x7a\x62\x8f\x7f\x4c\x90"
    "\x20\xea\x91\xd2" },

  { .algo = "aes256-gcm@openssh.com",
    .head_size = 0, .tail_size = 32 + 4, .key_size = 32, .iv_size = 12, .out_count = 1,
    .key = "\xab\xcd\xef\x01\x23\x45\x67\x89\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98"
    "\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10\xab\xcd\xef\x01\x23\x45\x67\x89",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb",
    .out = "\x2a\x2a\x2a\x2a\x5c\x40\x0c\xc2\x78\x6a\x6d\x52\xef\x9a\xb5\x0a"
    "\xfc\xe6\xeb\x4e\x77\xea\x7e\xcf\xf1\x25\xf0\x4a\xe9\xba\x18\x55"
    "\x8f\x56\xb5\x70" },

  { .algo = "twofish128-cbc",
    .head_size = 16, .tail_size = 32, .key_size = 16, .iv_size = 16, .out_count = 1,
    .key = "\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
    .out = "\x37\xfa\xc6\xa9\x9e\x46\x3e\x02\x8c\xd1\x4b\x76\xfe\x36\x69\xa1"
    "\x74\xa9\x44\x03\xa7\xdc\x7e\xb5\xe5\xeb\x12\x61\x63\xe9\xcc\x47"
    "\xf2\xa4\xec\xc1\x7c\x30\x19\x2c\xbc\x96\xfc\xb8\xf0\x90\xca\xed" },

  { .algo = "twofish256-cbc",
    .head_size = 16, .tail_size = 32, .key_size = 32, .iv_size = 16, .out_count = 1,
    .key = "\xab\xcd\xef\x01\x23\x45\x67\x89\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98"
    "\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10\xab\xcd\xef\x01\x23\x45\x67\x89",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
    .out = "\xc3\x71\x2a\x1c\x64\x77\x93\xc5\xca\x57\x69\xca\xfe\xae\xd8\xf8"
    "\xb7\x20\x07\xd2\xfc\x23\x54\xd8\x62\x5d\x31\x2b\x46\x36\x9c\x1f"
    "\xd4\x99\xc3\xa1\x0e\xd4\x9e\x57\xba\x8d\x13\xb3\x69\x7e\x3f\x8b" },

  { .algo = "twofish128-ctr",
    .head_size = 16, .tail_size = 32, .key_size = 16, .iv_size = 16, .out_count = 1,
    .key = "\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
    .out = "\x6b\x00\x55\xc3\x8c\x61\xf7\xc0\x08\x2e\x23\xe7\x5c\x25\xe3\x8a"
    "\xdc\xc5\xfd\xce\x73\x79\xf3\x96\xc5\xf6\x3e\xb9\xa3\x2c\xba\xf5"
    "\x4e\x8f\xb8\x2c\x68\x7a\x07\x4c\x16\xbf\xd5\xb9\x24\x5e\x2e\xba" },

  { .algo = "twofish256-ctr",
    .head_size = 16, .tail_size = 32, .key_size = 32, .iv_size = 16, .out_count = 1,
    .key = "\xab\xcd\xef\x01\x23\x45\x67\x89\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98"
    "\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10\xab\xcd\xef\x01\x23\x45\x67\x89",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
    .out = "\xee\xbc\xb4\x60\xc1\xc3\xad\xf1\xc8\x42\x1a\x6a\xdd\x64\xfb\xe7"
    "\x31\xb1\xb6\x68\x76\x95\xb7\x72\x1d\x63\x7d\x43\xf2\x8f\x21\x49"
    "\x8f\x80\x87\xac\xff\xf6\x94\x82\xcd\x6d\x0e\x53\x8e\xa4\x90\x80" },

  { .algo = "twofish128-gcm@libassh.org",
    .head_size = 0, .tail_size = 32 + 4, .key_size = 16, .iv_size = 12, .out_count = 1,
    .key = "\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb",
    .out = "\x2a\x2a\x2a\x2a\x26\x48\x15\xd2\xb6\x3b\x98\xd1\xbc\x8b\xff\x71"
    "\x75\x71\x25\x5d\x6b\xc1\x58\x74\x0c\xe6\xbf\xc3\x56\x91\xb1\xf2"
    "\x5f\x70\xe1\x99" },

  { .algo = "twofish256-gcm@libassh.org",
    .head_size = 0, .tail_size = 32 + 4, .key_size = 32, .iv_size = 12, .out_count = 1,
    .key = "\xab\xcd\xef\x01\x23\x45\x67\x89\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98"
    "\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10\xab\xcd\xef\x01\x23\x45\x67\x89",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb",
    .out = "\x2a\x2a\x2a\x2a\x07\x33\xc3\xa1\x99\xa8\x27\xf3\x51\xb9\x78\xb1"
    "\x13\xad\xd4\xe3\x00\x5f\xf1\xc8\xae\xeb\x9c\xc0\x40\x56\xe0\xef"
    "\x8b\x9a\x58\x92" },

  { .algo = "serpent128-cbc",
    .head_size = 16, .tail_size = 32, .key_size = 16, .iv_size = 16, .out_count = 1,
    .key = "\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
    .out = "\xaf\x30\x0f\x0d\x50\x1f\xbc\x10\x5b\xd0\x03\x82\xf4\x9e\xba\x96"
    "\x74\x3d\x98\x32\xf4\x92\xde\x33\x53\x96\xc5\x3c\x8f\xbb\x5b\x29"
    "\x62\xc4\x58\x43\x8d\x83\x97\x37\x63\x08\xd2\xbd\x53\x5d\x0e\xe6" },

  { .algo = "serpent192-cbc",
    .head_size = 16, .tail_size = 32, .key_size = 24, .iv_size = 16, .out_count = 1,
    .key = "\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10"
    "\xab\xcd\xef\x01\x23\x45\x67\x89",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
    .out = "\x7a\x43\x57\x3d\xa6\x5c\xac\x7a\xb2\xc6\x47\xe0\x5a\x2d\xc0\xd7"
    "\x13\xea\x59\xce\x62\x00\x27\x9d\xf9\x3f\x3e\x61\x55\xbf\xa3\x0f"
    "\x58\x61\x38\x48\x8c\x91\xad\xec\xa3\x9a\x2e\xf1\xb7\x58\x82\x5e" },

  { .algo = "serpent256-cbc",
    .head_size = 16, .tail_size = 32, .key_size = 32, .iv_size = 16, .out_count = 1,
    .key = "\xab\xcd\xef\x01\x23\x45\x67\x89\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98"
    "\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10\xab\xcd\xef\x01\x23\x45\x67\x89",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
    .out = "\x79\x32\x82\xa3\x22\x6c\xff\x54\xeb\xc2\x06\x38\x66\xdf\xcd\xc3"
    "\x38\x03\x7a\x40\x21\xa6\xe7\xc3\xe2\x6e\x37\xe5\xd5\xdc\xc3\x4a"
    "\xc8\x9d\x04\x09\xae\x56\x55\xc1\x90\x11\xec\xb7\x92\xc0\x7d\x8c" },

  { .algo = "serpent128-ctr",
    .head_size = 16, .tail_size = 32, .key_size = 16, .iv_size = 16, .out_count = 1,
    .key = "\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
    .out = "\xae\x2a\x53\x6c\x30\x38\xbe\x5d\x36\x77\x47\xed\x42\xa8\xf9\x03"
    "\x65\x91\x4e\x17\x6c\xd9\x4a\xa0\x93\xb3\x42\x4d\x88\xc3\x42\x6b"
    "\x6f\x06\xd9\x27\xad\x79\x50\xec\xf1\xdf\xab\x06\x69\xe0\x9d\x43" },

  { .algo = "serpent192-ctr",
    .head_size = 16, .tail_size = 32, .key_size = 24, .iv_size = 16, .out_count = 1,
    .key = "\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10"
    "\xab\xcd\xef\x01\x23\x45\x67\x89",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
    .out = "\x70\xe3\x58\xf6\x61\xcf\x39\xa1\x81\xbf\xb2\x1b\xd8\x6f\xdc\xe4"
    "\x6b\xf1\x6e\xe8\x81\x9e\xe2\x7f\x4f\xe3\xe6\x5c\xbf\xad\x01\xb2"
    "\x18\xaf\x72\xd9\xe5\x03\xbe\xb4\x55\x8d\x59\x83\x5a\x92\x18\x5a" },

  { .algo = "serpent256-ctr",
    .head_size = 16, .tail_size = 32, .key_size = 32, .iv_size = 16, .out_count = 1,
    .key = "\xab\xcd\xef\x01\x23\x45\x67\x89\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98"
    "\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10\xab\xcd\xef\x01\x23\x45\x67\x89",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
    .out = "\xed\x94\xf7\xef\x18\x11\xc1\xb1\xeb\xf6\x43\x28\x08\x6b\x40\x01"
    "\x3e\x83\x69\x59\x11\xff\xb3\x5a\xf9\xd8\xaf\xc4\x78\x17\x31\x85"
    "\xc2\xf6\x76\x7c\x00\x68\x48\xe5\x22\xa5\x56\x79\xed\xe9\x91\x20" },

  { .algo = "serpent128-gcm@libassh.org",
    .head_size = 0, .tail_size = 32 + 4, .key_size = 16, .iv_size = 12, .out_count = 2,
    .key = "\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb",
    .out = "\x2a\x2a\x2a\x2a\xa1\x0a\x76\xff\x96\xed\x5c\xbd\xb9\x1c\x1e\xc0"
    "\xf5\xd9\x76\x2e\xef\x3d\xcc\x57\x03\xfa\xdc\x6e\x61\xbc\x03\xa5"
    "\x90\x5a\xe0\xe4"
    /* 1 */ "\x2a\x2a\x2a\x2a\xf1\x84\xf7\x4b\x87\x0e\x8f\x1f\x0b\x6c\xc2\xd1"
    "\xbc\xe4\x3c\x3b\xd6\xef\x52\x0d\x62\xdf\xda\xf8\x75\xbd\x70\x51"
    "\xc9\x06\x62\x01" },

  { .algo = "serpent256-gcm@libassh.org",
    .head_size = 0, .tail_size = 32 + 4, .key_size = 32, .iv_size = 12, .out_count = 1,
    .key = "\xab\xcd\xef\x01\x23\x45\x67\x89\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98"
    "\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10\xab\xcd\xef\x01\x23\x45\x67\x89",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb",
    .out = "\x2a\x2a\x2a\x2a\x91\xd7\xa0\x1f\x4d\x6f\xba\x1b\xdd\x09\x0e\x14"
    "\x6d\x24\xc0\x56\xee\xb8\x68\x1e\x2d\x38\xb4\x89\x21\x0d\x70\xac"
    "\xcb\xad\xed\x4c" },

  { .algo = "camellia128-cbc",
    .head_size = 16, .tail_size = 32, .key_size = 16, .iv_size = 16, .out_count = 1,
    .key = "\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
    .out = "\x19\xab\x2f\xe7\x69\x4c\xb6\x08\x6a\xb4\x8a\x66\x80\x03\x6d\x26"
    "\x94\xd0\xfe\xa5\x65\xa2\x36\xd5\xeb\xe2\x7e\x4c\xba\x0b\x26\x9b"
    "\xa9\x60\xe7\x59\x57\x53\xbd\xaa\x59\x26\x5c\xa9\x85\xb8\xc5\x9e" },

  { .algo = "camellia192-cbc",
    .head_size = 16, .tail_size = 32, .key_size = 24, .iv_size = 16, .out_count = 1,
    .key = "\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10"
    "\xab\xcd\xef\x01\x23\x45\x67\x89",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
    .out = "\x7c\x10\x34\xdd\x53\x71\xdc\x60\xd6\xd9\xfe\x0e\xc3\x3d\x21\xc0"
    "\x82\x0a\xa9\xb1\x90\x97\x8f\x2a\x0b\x3e\x11\xd6\xee\x7f\xff\x8b"
    "\x99\xc0\x52\x0d\x00\x0d\x02\x30\x22\x91\x80\xc2\xd4\xf9\x6f\xaa" },

  { .algo = "camellia256-cbc",
    .head_size = 16, .tail_size = 32, .key_size = 32, .iv_size = 16, .out_count = 1,
    .key = "\xab\xcd\xef\x01\x23\x45\x67\x89\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98"
    "\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10\xab\xcd\xef\x01\x23\x45\x67\x89",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
    .out = "\x6d\x5a\x79\x49\x5a\xb6\x97\x0c\x3c\x1a\xa8\xfd\xe2\xc1\x27\x59"
    "\xfa\x54\x48\x7e\x25\x46\x01\x78\xe5\x9d\xf1\xe1\x7c\x2c\x77\xe3"
    "\x5f\x8f\xe0\x7c\xf6\x4b\x70\xaa\x50\x34\x51\x5d\xfa\xac\xea\x65" },

  { .algo = "camellia128-ctr",
    .head_size = 16, .tail_size = 32, .key_size = 16, .iv_size = 16, .out_count = 1,
    .key = "\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
    .out = "\xc2\x30\xa5\x98\xd8\x8e\x5c\xfc\x9c\x5e\x33\x9a\x10\xc3\xa9\x99"
    "\x59\x46\x27\xb9\xa2\x3e\xba\x50\xa0\x0e\x63\x98\x4b\xba\xdb\x6d"
    "\x07\x7d\xb4\x6d\x78\x4e\x59\x03\xdb\x6c\x67\xeb\xd3\x0e\x1f\x0a" },

  { .algo = "camellia192-ctr",
    .head_size = 16, .tail_size = 32, .key_size = 24, .iv_size = 16, .out_count = 1,
    .key = "\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10"
    "\xab\xcd\xef\x01\x23\x45\x67\x89",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
    .out = "\xb9\xb7\x04\xb8\x7b\xf0\x6e\x99\xb7\x04\x3b\xc7\x8d\xab\x37\x0d"
    "\x48\x28\xa9\xd2\x57\x9b\x92\xb6\xea\x20\x88\x28\xdc\x38\x33\xa0"
    "\xc9\x53\x3b\x9b\x4c\xe2\x55\xa9\xe7\xf1\xef\x0c\xfa\x0d\x21\x65" },

  { .algo = "camellia256-ctr",
    .head_size = 16, .tail_size = 32, .key_size = 32, .iv_size = 16, .out_count = 1,
    .key = "\xab\xcd\xef\x01\x23\x45\x67\x89\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98"
    "\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10\xab\xcd\xef\x01\x23\x45\x67\x89",
    .iv =  "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
    .out = "\x9a\x30\xd4\x2b\xd9\x01\x6e\x0e\x78\x06\x11\x7b\x29\xe0\x47\x06"
    "\x2b\x7d\x7f\x9f\x3f\x98\x99\xd6\x3f\x4e\x61\x48\x54\x2f\x44\xfe"
    "\x97\xd9\x83\x67\xfd\x5b\x47\xe9\xf0\xe0\xa9\x94\x12\x36\xe5\xbd" },

  { .algo = "chacha20-poly1305@openssh.com",
    .head_size = 4, .tail_size = 44, .key_size = 64, .out_count = 2, .seq = 101,
    .key = "\xab\xcd\xef\x01\x23\x45\x67\x89\x01\xf2\xe3\xd4\xc5\xb6\xa7\x98"
    "\x89\x7a\x6b\x5c\x4d\x3e\x2f\x10\xab\xcd\xef\x01\x23\x45\x67\x89"
    "\xab\xcd\xef\x10\x23\x45\x76\x89\x01\x2f\xe3\xd4\x5c\xb6\xa7\x98"
    "\x89\x7a\x6b\xc5\x4d\x3e\x2f\x10\xba\xcd\xef\x01\x32\x45\x67\x89",
    .out = "\xc5\x0e\x97\x98\xf0\x27\x6d\xa5\xbb\x39\xaf\x71\x6a\xe9\x01\x2b"
    "\x20\x0e\x69\x2b\xaa\xc2\x0c\x15\x66\x83\xcd\xa8\x84\x1b\x2e\x6b"
    "\xb3\x3f\x35\x1a\xf0\xf7\x77\x3b\x92\x88\xec\x14\xe8\x26\x73\x19"
    /* 1 */ "\xa0\x60\x89\x4d\x1f\x7f\xa1\x78\x0a\x12\x68\x19\x63\x72\xef\x08"
    "\x6d\x09\x9e\xce\x92\xbd\x92\xcf\xb6\x64\x44\x1b\x76\x4b\xf2\x95"
    "\x34\x31\x7b\xe8\xfa\xed\xf4\xa7\x35\x8f\xf1\x86\xc4\x42\x2b\x99" },

  { 0 }
};

void test_cipher(const struct cipher_test_s *t,
		 const struct assh_algo_cipher_s *ca)
{
  struct assh_context_s context;

  if (assh_context_init(&context, ASSH_CLIENT_SERVER, assh_leaks_allocator,
			NULL, NULL, NULL))
    TEST_FAIL("context init");

  if (t->iv_size != ca->iv_size)
    TEST_FAIL("iv size");
  if (t->key_size != ca->key_size)
    TEST_FAIL("key size");

  if (!t->out_count)
    TEST_FAIL("no output");

  size_t size = t->head_size + t->tail_size;

  uint8_t buf[size];
  memset(buf, 42, size);

  void *ctx = malloc(ca->ctx_size);
  void *ctx2 = malloc(ca->ctx_size);

  fprintf(stderr, "testing %s, %s: ",
	  t->algo, ca->algo.implem);

  if (ca->f_init(&context, ctx, (const uint8_t*)t->key,
		 t->iv_size ? (const uint8_t*)t->iv : NULL, 1))
    TEST_FAIL("encrypt init");
  if (ca->f_init(&context, ctx2, (const uint8_t*)t->key,
		 t->iv_size ? (const uint8_t*)t->iv : NULL, 0))
    TEST_FAIL("decrypt init");

  uint32_t seq = t->seq;
  const size_t count = 3;
  uint_fast8_t  i;

  for (i = 0; i < count; i++, seq++)
    {
      assh_bool_t check_output = (i < t->out_count);
      assh_bool_t tamper = ca->auth_size && (i == count - 1);

      /* encrypt */
      fprintf(stderr, "E");
      if (ca->f_process(ctx, buf, size, ASSH_CIPHER_PCK_TAIL, seq))
	TEST_FAIL("encrypt %u", i);

      if (check_output)
	{
	  fprintf(stderr, "Q");
	  if (memcmp(buf, t->out + size * i, size))
	    {
	      assh_hexdump("output", buf, size);
	      assh_hexdump("expected   ", t->out + size * i, size);
	      TEST_FAIL("encrypt output %u", i);
	    }
	}

      if (tamper)
	{
	  fprintf(stderr, "t");
	  buf[rand() % size] ^= 1 << (rand() % 8);
	}

      /* decrypt */
      fprintf(stderr, "d");
      if (ca->f_process(ctx2, buf, t->head_size, ASSH_CIPHER_PCK_HEAD, seq))
	TEST_FAIL("decrypt head %u", i);

      fprintf(stderr, "D");
      if (ca->auth_size)
	{
	  if (tamper == !ca->f_process(ctx2, buf, size, ASSH_CIPHER_PCK_TAIL, seq))
	    TEST_FAIL("decrypt tail %u", i);
	}
      else
	{
	  if (ca->f_process(ctx2, buf + t->head_size, t->tail_size,
			    ASSH_CIPHER_PCK_TAIL, seq))
	    TEST_FAIL("decrypt tail %u", i);
	}

      if (!tamper)
	{
	  size_t j;

	  fprintf(stderr, "q");
	  for (j = 0; j < size - ca->auth_size; j++)
	    if (buf[j] != 42)
	      {
		assh_hexdump("output", buf, size);
		TEST_FAIL("decrypt output %u", i);
	      }
	}
    }

  fprintf(stderr, "\n");

  ca->f_cleanup(&context, ctx);
  free(ctx);

  ca->f_cleanup(&context, ctx2);
  free(ctx2);

  assh_context_cleanup(&context);
}

int
main(int argc, char **argv)
{
  if (assh_deps_init())
    return -1;

  uint_fast16_t i;
  for (i = 0; vectors[i].algo != NULL; i++)
    {
      const struct cipher_test_s *t = &vectors[i];

      if (!strcmp(t->algo, "none"))
	{
	  test_cipher(t, &assh_cipher_none);
	  continue;
	}

      assh_bool_t done = 0;
      const struct assh_algo_s **a;

      for (a = assh_algo_table; *a; a++)
	{
	  if (!assh_algo_name_match(*a, ASSH_ALGO_CIPHER,
				    t->algo, strlen(t->algo)))
	    continue;

	  done = 1;
	  test_cipher(t, (void*)*a);

	  if (alloc_size != 0)
	    TEST_FAIL("memory leak detected, %zu bytes allocated\n", alloc_size);
	}

      if (!done)
	fprintf(stderr, "skipping %s, no implementation\n", t->algo);
    }
  return 0;
}
