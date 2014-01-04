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
  int_fast16_t safety;          //< safety factor in range [0, 99]
  int_fast16_t speed;           //< speed factor in range [0, 99]
  assh_bool_t need_host_key;
  struct assh_algo_s *next;
};

/**
   This function registers the specified algoritms for use by the
   given context. The last parameter must be @tt NULL.

   The algorithms are sorted depending on their safety factor and
   speed factor. The @tt safety parameter indicates how algorithms
   safety must be favored over speed. Valid range for this parameter
   is [0, 99]. The order is relevant for client sessions. 

   Algorithms with a safety factor less than @tt min_safety are
   skipped.

   If multiple implementations of the same algorithm are registered,
   the algorithm which appears first in the list after sorting is kept
   an other entries with the same name are discarded.
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_algo_register_va(struct assh_context_s *c, unsigned int safety,
		      unsigned int min_safety, ...);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_algo_by_name(struct assh_context_s *c,
		  enum assh_algo_class_e class_, const char *name,
                  size_t name_len, const struct assh_algo_s **algo);

/**
   This function registers the default set of available algorithms
   depending on the library configuration. It relies on the @ref
   assh_algo_register_va function.
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_algo_register_default(struct assh_context_s *c, unsigned int safety,
			   unsigned int min_safety);

#endif

