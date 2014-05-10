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


#ifndef ASSH_HASH_SHA256_H_
#define ASSH_HASH_SHA256_H_

#include "assh_hash.h"

struct assh_hash_sha256_context_s
{
  uint32_t state[8];
  uint32_t count[2];
  uint8_t buffer[64];
};

ASSH_HASH_INIT_FCN(assh_sha256_init);
ASSH_HASH_UPDATE_FCN(assh_sha256_update);
ASSH_HASH_FINAL_FCN(assh_sha256_final);

extern const struct assh_hash_s assh_hash_sha256;

#endif

