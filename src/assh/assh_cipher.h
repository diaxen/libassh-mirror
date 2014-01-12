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


#ifndef ASSH_CIPHER_H_
#define ASSH_CIPHER_H_

#include "assh_algo.h"

#define ASSH_CIPHER_INIT_FCN(n) \
  ASSH_WARN_UNUSED_RESULT assh_error_t (n)(struct assh_context_s *c, void *ctx_, \
                                           const uint8_t *key, const uint8_t *iv, assh_bool_t encrypt)
typedef ASSH_CIPHER_INIT_FCN(assh_cipher_init_t);

#define ASSH_CIPHER_PROCESS_FCN(n) \
  ASSH_WARN_UNUSED_RESULT assh_error_t (n)(void *ctx_, uint8_t *iv,     \
                                           uint8_t *data, size_t len)
typedef ASSH_CIPHER_PROCESS_FCN(assh_cipher_process_t);

#define ASSH_CIPHER_CLEANUP_FCN(n) \
  void (n)(struct assh_context_s *c, void *ctx_)
typedef ASSH_CIPHER_CLEANUP_FCN(assh_cipher_cleanup_t);

struct assh_algo_cipher_s
{
  struct assh_algo_s algo;
  size_t ctx_size;
  size_t block_size;
  size_t key_size;
  assh_bool_t is_stream;
  assh_cipher_init_t *f_init;
  assh_cipher_process_t *f_process;
  assh_cipher_cleanup_t *f_cleanup;
};

extern struct assh_algo_cipher_s assh_cipher_none;

extern struct assh_algo_cipher_s assh_cipher_arc4;
extern struct assh_algo_cipher_s assh_cipher_arc4_128;
extern struct assh_algo_cipher_s assh_cipher_arc4_256;

extern struct assh_algo_cipher_s assh_cipher_aes128_cbc;
extern struct assh_algo_cipher_s assh_cipher_aes192_cbc;
extern struct assh_algo_cipher_s assh_cipher_aes256_cbc;
extern struct assh_algo_cipher_s assh_cipher_aes128_ctr;
extern struct assh_algo_cipher_s assh_cipher_aes192_ctr;
extern struct assh_algo_cipher_s assh_cipher_aes256_ctr;

#ifdef CONFIG_ASSH_USE_GCRYPT_CIPHERS

/** @This registers all gcrypt based ciphers algorithms. @see
    assh_algo_register_va */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_cipher_register_gcrypt(struct assh_context_s *c, unsigned int safety,
			    unsigned int min_safety);

extern struct assh_algo_cipher_s assh_cipher_tdes_cbc;
extern struct assh_algo_cipher_s assh_cipher_tdes_ctr;

extern struct assh_algo_cipher_s assh_cipher_cast128_cbc;
extern struct assh_algo_cipher_s assh_cipher_cast128_ctr;

extern struct assh_algo_cipher_s assh_cipher_blowfish_cbc;
extern struct assh_algo_cipher_s assh_cipher_blowfish_ctr;

extern struct assh_algo_cipher_s assh_cipher_aes128_cbc;
extern struct assh_algo_cipher_s assh_cipher_aes192_cbc;
extern struct assh_algo_cipher_s assh_cipher_aes256_cbc;
extern struct assh_algo_cipher_s assh_cipher_aes128_ctr;
extern struct assh_algo_cipher_s assh_cipher_aes192_ctr;
extern struct assh_algo_cipher_s assh_cipher_aes256_ctr;

extern struct assh_algo_cipher_s assh_cipher_twofish128_cbc;
extern struct assh_algo_cipher_s assh_cipher_twofish256_cbc;
extern struct assh_algo_cipher_s assh_cipher_twofish128_ctr;
extern struct assh_algo_cipher_s assh_cipher_twofish256_ctr;

extern struct assh_algo_cipher_s assh_cipher_serpent128_cbc;
extern struct assh_algo_cipher_s assh_cipher_serpent192_cbc;
extern struct assh_algo_cipher_s assh_cipher_serpent256_cbc;
extern struct assh_algo_cipher_s assh_cipher_serpent128_ctr;
extern struct assh_algo_cipher_s assh_cipher_serpent192_ctr;
extern struct assh_algo_cipher_s assh_cipher_serpent256_ctr;
#endif
#endif


