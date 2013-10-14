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

#ifndef ASSH_CIPHER_GCRYPT_H_
#define ASSH_CIPHER_GCRYPT_H_

#include "assh_cipher.h"

extern struct assh_algo_cipher_s assh_cipher_gcrypt_arc4;
extern struct assh_algo_cipher_s assh_cipher_gcrypt_arc4_128;
extern struct assh_algo_cipher_s assh_cipher_gcrypt_arc4_256;

extern struct assh_algo_cipher_s assh_cipher_gcrypt_tdes_cbc;
extern struct assh_algo_cipher_s assh_cipher_gcrypt_tdes_ctr;

extern struct assh_algo_cipher_s assh_cipher_gcrypt_cast128_cbc;
extern struct assh_algo_cipher_s assh_cipher_gcrypt_cast128_ctr;

extern struct assh_algo_cipher_s assh_cipher_gcrypt_blowfish_cbc;
extern struct assh_algo_cipher_s assh_cipher_gcrypt_blowfish_ctr;

extern struct assh_algo_cipher_s assh_cipher_gcrypt_aes128_cbc;
extern struct assh_algo_cipher_s assh_cipher_gcrypt_aes192_cbc;
extern struct assh_algo_cipher_s assh_cipher_gcrypt_aes256_cbc;
extern struct assh_algo_cipher_s assh_cipher_gcrypt_aes128_ctr;
extern struct assh_algo_cipher_s assh_cipher_gcrypt_aes192_ctr;
extern struct assh_algo_cipher_s assh_cipher_gcrypt_aes256_ctr;

extern struct assh_algo_cipher_s assh_cipher_gcrypt_twofish128_cbc;
extern struct assh_algo_cipher_s assh_cipher_gcrypt_twofish256_cbc;
extern struct assh_algo_cipher_s assh_cipher_gcrypt_twofish128_ctr;
extern struct assh_algo_cipher_s assh_cipher_gcrypt_twofish256_ctr;

extern struct assh_algo_cipher_s assh_cipher_gcrypt_serpent128_cbc;
extern struct assh_algo_cipher_s assh_cipher_gcrypt_serpent192_cbc;
extern struct assh_algo_cipher_s assh_cipher_gcrypt_serpent256_cbc;
extern struct assh_algo_cipher_s assh_cipher_gcrypt_serpent128_ctr;
extern struct assh_algo_cipher_s assh_cipher_gcrypt_serpent192_ctr;
extern struct assh_algo_cipher_s assh_cipher_gcrypt_serpent256_ctr;

/** @This register all gcrypt ciphers */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_cipher_register_gcrypt(struct assh_context_s *c);

#endif

