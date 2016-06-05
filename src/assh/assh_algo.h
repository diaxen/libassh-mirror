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

/**
   @file
   @short SSH algorithms base descriptor structure and related functions
*/

#ifndef ASSH_ALGO_H_
#define ASSH_ALGO_H_

#include "assh.h"

/** @internal @see assh_algo_suitable_key_t */
#define ASSH_ALGO_SUITABLE_KEY_FCN(n) assh_bool_t (n)    \
  (struct assh_context_s *c,                             \
   const struct assh_algo_s *algo,                       \
   const struct assh_key_s *key)

/** @internal @This defines the function type for the key
    compatibility checking operation common to all the algorithm
    module interfaces. @see assh_algo_suitable_key */
typedef ASSH_ALGO_SUITABLE_KEY_FCN(assh_algo_suitable_key_t);

/** @internal @This specifies classes of SSH algorithm */
enum assh_algo_class_e
{
  ASSH_ALGO_KEX,
  ASSH_ALGO_SIGN,
  ASSH_ALGO_CIPHER,
  ASSH_ALGO_MAC,
  ASSH_ALGO_COMPRESS,
  ASSH_ALGO_ANY,
};

/** @internal @see assh_algo_class_e */
#define ASSH_ALGO_CLASS_NAMES \
  { "KEX", "SIGN", "CIPHER", "MAC", "COMPRESS", "ANY" }

/** @This specifies various algorithm specification status. */
enum assh_algo_spec_e
{
  /** The algorithm is specified in an approved IETF standard. */
  ASSH_ALGO_STD_IETF = 0x01,
  /** The algorithm is specified in an IETF draft document. */
  ASSH_ALGO_STD_DRAFT = 0x02,
  /** The algorithm is private and specified as an extension of some
      ssh implementations. */
  ASSH_ALGO_STD_PRIVATE = 0x04,
  /** The algorithm is private and specified as an extension of assh. */
  ASSH_ALGO_ASSH = 0x08,
  /** The algorithm is common under this name. */
  ASSH_ALGO_COMMON = 0x10,
  /** The algorithm is private under this name but is now available
      under a different name specified as an approved IETF standard. */
  ASSH_ALGO_OLDNAME = 0x20,
};

/** @internal @see assh_algo_s */
struct assh_algo_name_s
{
  /** Specification status flags */
  enum assh_algo_spec_e spec:8;
  /** algorithm name */
  const char *name;
};

#define ASSH_ALGO_SCORE(algo_, safety_) \
  ((algo_)->speed * (100 - (safety_)) + (algo_)->safety * ((safety_) + 1))

#define ASSH_ALGO_NAMES(...) \
  .names = (const struct assh_algo_name_s[]){ __VA_ARGS__, { 0 } }

#define ASSH_ALGO_VARIANT(priority_, description_)                        \
  .priority = priority_,                                                  \
  .variant = description_

#define ASSH_ALGO_API_VERSION 0

/** @internal @This initializes the fields of the @ref assh_algo_s structure */
#define ASSH_ALGO_BASE(class__, safety_, speed_, ...)                   \
  .algo = {                                                             \
    .class_ = ASSH_ALGO_##class__,                                      \
    .api = ASSH_ALGO_API_VERSION,                                       \
    .safety = safety_,                                                  \
    .speed = speed_,                                                    \
    __VA_ARGS__                                                         \
  }

/** @internal map prime field size to assh safety factor,
    See @sourcelink doc/dh @see assh_algo_register_va */
#define ASSH_SAFETY_PRIMEFIELD(n) ((n) / 128 + 12)

/** @internalmembers @This is the generic algorithm descriptor
    structure. Other algorithm descriptor structures iherit from this
    type. */
struct assh_algo_s
{
  /** module API version */
  uint8_t api;

  /** Class of algorithm */
  enum assh_algo_class_e class_:3;
  /** used to choose between entries with the same name */
  uint8_t priority:5;

  /** safety factor in range [0, 99] */
  assh_safety_t safety;
  /** speed factor in range [0, 99] */
  uint8_t speed;

  /** List of SSH algorithm identifiers, used during key exchange */
  const struct assh_algo_name_s *names;

  /** Variant description string, used when multiple declarations of
      the same algorithm name exist. */
  const char *variant;

  /** Pointer to associated key operations, may be @tt NULL. */
  const struct assh_key_ops_s *key;
  /** Test if a key can be used with the algorithm, may be @tt NULL. */
  assh_algo_suitable_key_t *f_suitable_key;
};

/**
   @This registers the specified @ref assh_algo_s objects for use by
   the given context. The last parameter must be @tt NULL.

   The algorithms are sorted depending on their safety factor and
   speed factor. The @tt safety parameter indicates how algorithms
   safety must be favored over speed. Valid range for this parameter
   is [0, 99]. Algorithms with a safety factor or speed factor less
   than @tt min_safety and  @tt min_speed are skipped.

   The Safety factor is defined as follow:

   @list
     @item 0-19: weak, broken
     @item 20-25: borderline
     @item 26-49: suitable for general use
     @item 50-99: strong
   @end list

   If multiple implementations of the same algorithm are registered,
   the variant which appears first in the list after sorting is kept
   and subsequent variants with the same name are discarded. This
   should retain the less secure variants of the same algorithm not
   filtered by the value of @tt min_safety.
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_algo_register_va(struct assh_context_s *c, assh_safety_t safety,
		      assh_safety_t min_safety, uint8_t min_speed, ...);

/**
   @This registers the specified @ref assh_algo_s objects for use by
   the given context. The last table entry must be @tt NULL.
   @see assh_algo_register_va
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_algo_register(struct assh_context_s *c, assh_safety_t safety,
		   assh_safety_t min_safety, uint8_t min_speed,
                   const struct assh_algo_s *table[]);

/** NULL terminated array of available algorithms. */
extern const struct assh_algo_s *assh_algo_table[];

/** @This returns registered algorithms indexed from 0. @tt NULL is
    returned when out of range. */
const struct assh_algo_s *
assh_algo_registered(struct assh_context_s *c, uint_fast16_t i);

/** @internal @This registers the default set of available algorithms
    depending on the library configuration. It relies on the @ref
    assh_algo_register_va function. */
ASSH_INLINE ASSH_WARN_UNUSED_RESULT assh_error_t
assh_algo_register_default(struct assh_context_s *c,
                           assh_safety_t safety,
			   assh_safety_t min_safety,
                           uint8_t min_speed)
{
  return assh_algo_register(c, safety, min_safety, min_speed, assh_algo_table);
}

/** Unregister all algorithms */
void assh_algo_unregister(struct assh_context_s *c);

/** @This returns the algorithm default name */
ASSH_INLINE const char * assh_algo_name(const struct assh_algo_s *algo)
{
  return algo->names[0].name;
}

/** @internal @This finds a registered algorithm with matching class
    and name. If the @tt namep parameter is not @tt NULL, the matched
    algorithm name is returned. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_algo_by_name(struct assh_context_s *c,
		  enum assh_algo_class_e class_, const char *name,
                  size_t name_len, const struct assh_algo_s **algo,
                  const struct assh_algo_name_s **namep);

/** @internal @This finds a registered algorithm which can be used
    with the given key. If the @tt pos parameter is not @tt NULL, it
    specifies the starting index of the search and it will be updated
    with the index of the matching entry. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_algo_by_key(struct assh_context_s *c,
                 const struct assh_key_s *key, uint16_t *pos,
                 const struct assh_algo_s **algo);

/** @internal @This returns true if the provided key can be used with
    the algorithm and has been loaded or created for that purpose.
    When the @tt key parameter is @tt NULL, the return value indicates
    if the algorithm needs a key when used during a key exchange.

    This does not check the validity of the key, the @ref
    assh_key_validate function is provided for that purpose. */
assh_bool_t
assh_algo_suitable_key(struct assh_context_s *c,
                       const struct assh_algo_s *algo,
                       const struct assh_key_s *key);

#endif

