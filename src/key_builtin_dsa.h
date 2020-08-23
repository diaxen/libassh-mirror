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

#ifndef ASSH_KEY_BUILTIN_DSA_H_
#define ASSH_KEY_BUILTIN_DSA_H_

#include <assh/assh_key.h>
#include <assh/assh_bignum.h>

/** @internal DSA key storage */
struct assh_key_dsa_s
{
  struct assh_key_s key;
  /** public p */
  struct assh_bignum_s pn;
  /** public q */
  struct assh_bignum_s qn;
  /** public g */
  struct assh_bignum_s gn;
  /** public y */
  struct assh_bignum_s yn;
  /** private x, may be empty */
  struct assh_bignum_s xn;
};

ASSH_FIRST_FIELD_ASSERT(assh_key_dsa_s, key);

/** @internal */
#define ASSH_DSA_ID     "\x00\x00\x00\x07ssh-dss"
/** @internal */
#define ASSH_DSA_ID_LEN (sizeof(ASSH_DSA_ID) - 1)

#define ASSH_DSA_SAFETY(l, n)                           \
  ASSH_MIN(ASSH_SAFETY_PRIMEFIELD(l),			\
           99 * (n) / 512)

#endif

