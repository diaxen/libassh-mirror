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


#ifndef ASSH_COMPRESS_H_
#define ASSH_COMPRESS_H_

#include "assh_algo.h"

#define ASSH_COMPRESS_INIT_FCN(n) \
  ASSH_WARN_UNUSED_RESULT assh_error_t (n)(struct assh_context_s *c,	\
					   void *ctx_, assh_bool_t compress)
typedef ASSH_COMPRESS_INIT_FCN(assh_compress_init_t);

#define ASSH_COMPRESS_PROCESS_FCN(n) \
  ASSH_WARN_UNUSED_RESULT assh_error_t (n)(void *ctx_, struct assh_packet_s *p)
typedef ASSH_COMPRESS_PROCESS_FCN(assh_compress_process_t);

#define ASSH_COMPRESS_CLEANUP_FCN(n) \
  void (n)(struct assh_context_s *c, void *ctx_)
typedef ASSH_COMPRESS_CLEANUP_FCN(assh_compress_cleanup_t);

struct assh_algo_compress_s
{
  struct assh_algo_s algo;
  size_t ctx_size;
  assh_compress_init_t *f_init;
  assh_compress_process_t *f_process;
  assh_compress_cleanup_t *f_cleanup;
};

ASSH_FIRST_FIELD_ASSERT(assh_algo_compress_s, algo);

extern struct assh_algo_compress_s assh_compress_none;
extern struct assh_algo_compress_s assh_compress_zlib;

#endif

