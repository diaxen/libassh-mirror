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

#ifndef ASSH_ALGO_H_
#define ASSH_ALGO_H_

#include "assh.h"

enum assh_algo_class_e
{
  ASSH_ALGO_KEX,
  ASSH_ALGO_SIGN,
  ASSH_ALGO_CIPHER,
  ASSH_ALGO_MAC,
  ASSH_ALGO_COMPRESS,
  ASSH_ALGO_ANY,
};

struct assh_algo_s
{
  const char *name;
  enum assh_algo_class_e class_;
  int_fast16_t priority;
  assh_bool_t need_host_key;
  struct assh_algo_s *next;
};

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_algo_register(struct assh_context_s *c,
                   struct assh_algo_s *algo);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_algo_register_va(struct assh_context_s *c, ...);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_algo_by_name(struct assh_context_s *c,
		  enum assh_algo_class_e class_, const char *name,
                  size_t name_len, const struct assh_algo_s **algo);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_kex_register_builtin(struct assh_context_s *c);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_sign_register_builtin(struct assh_context_s *c);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_cipher_register_builtin(struct assh_context_s *c);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_mac_register_builtin(struct assh_context_s *c);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_compress_register_builtin(struct assh_context_s *c);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_algo_register_builtin(struct assh_context_s *c);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_algo_register_default(struct assh_context_s *c);

#endif

