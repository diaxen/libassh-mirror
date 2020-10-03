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

/**
   @file
   @short Descriptors for algorithms and modules based on libsodium
*/

#ifndef ASSH_MOD_SODIUM_H_
#define ASSH_MOD_SODIUM_H_

#include "assh_kex.h"
#include "assh_sign.h"
#include "assh_prng.h"

# ifdef CONFIG_ASSH_USE_SODIUM_KEX
extern const struct assh_algo_kex_s assh_kex_sodium_curve25519_sha256;
# endif

# ifdef CONFIG_ASSH_USE_SODIUM_SIGN
extern const struct assh_algo_sign_s assh_sign_sodium_ed25519;
extern const struct assh_key_algo_s assh_key_sodium_ed25519;
# endif

# ifdef CONFIG_ASSH_USE_SODIUM_PRNG
extern const struct assh_prng_s assh_prng_sodium;
# endif

#endif
