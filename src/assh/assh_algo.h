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

#define ASSH_ALGO_SUITABLE_KEY_FCN(n) assh_bool_t (n)    \
  (const struct assh_algo_s *algo,                       \
   const struct assh_key_s *key)

typedef ASSH_ALGO_SUITABLE_KEY_FCN(assh_algo_suitable_key_t);

enum assh_algo_class_e
{
  ASSH_ALGO_KEX,
  ASSH_ALGO_SIGN,
  ASSH_ALGO_CIPHER,
  ASSH_ALGO_MAC,
  ASSH_ALGO_COMPRESS,
  ASSH_ALGO_ANY,
};

/**
   Safety factor is as follow:

   @list
   @item 0-19: weak, broken
   @item 20-25: borderline
   @item 26-49: suitable for general use
   @item 50-99: strong
   @end list
 */
struct assh_algo_s
{
  const char *name;
  const char *variant;
  enum assh_algo_class_e class_;
  int_fast16_t safety;          //< safety factor in range [0, 99]
  int_fast16_t speed;           //< speed factor in range [0, 99]
  /** The function must return true is the passed key can be used to
      with the algorithm. This pointer must be @tt NULL if the
      algorithm does not require an @ref assh_key_s object to run. */
  assh_algo_suitable_key_t *f_suitable_key;

  /** used to choose between entries with the same name */
  int_fast8_t priority;
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

/** Find a registered algorithm which can be used with the given key.
    If the @tt pos parameter is not @tt NULL, it specifies the
    starting index of the search and it will be updated with the index
    of the matching entry. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_algo_by_key(struct assh_context_s *c,
                 enum assh_algo_class_e class_,
                 const struct assh_key_s *key, uint_fast16_t *pos,
                 const struct assh_algo_s **algo);

/** Return true if the algorithm can use the given key. */
static inline assh_bool_t
assh_algo_suitable_key(const struct assh_algo_s *algo,
                       const struct assh_key_s *key)
{
  return algo->f_suitable_key != NULL
    && algo->f_suitable_key(algo, key);
}

/** Return true if the algorithm needs a key to be used. */
static inline assh_bool_t
assh_algo_needs_key(const struct assh_algo_s *algo)
{
  return algo->f_suitable_key != NULL;
}

/**
   This function registers the default set of available algorithms
   depending on the library configuration. It relies on the @ref
   assh_algo_register_va function.
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_algo_register_default(struct assh_context_s *c, unsigned int safety,
			   unsigned int min_safety);

#endif

