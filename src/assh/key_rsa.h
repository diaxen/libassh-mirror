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

#ifndef ASSH_KEY_RSA_H_
#define ASSH_KEY_RSA_H_

#include <assh/assh_key.h>
#include <assh/assh_bignum.h>

struct assh_key_rsa_s
{
  struct assh_key_s key;

  /* RSA modulus */
  struct assh_bignum_s nn;
  /* RSA exponents */
  struct assh_bignum_s en;
  struct assh_bignum_s dn;
};

ASSH_FIRST_FIELD_ASSERT(assh_key_rsa_s, key);

extern const struct assh_algo_key_s assh_key_rsa;

static const char *assh_rsa_id = "\x00\x00\x00\x07ssh-rsa";
static const size_t assh_rsa_id_len = 4 + 7;

#endif

