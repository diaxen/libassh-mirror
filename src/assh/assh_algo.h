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
   @short SSH algorithms base descriptor structure and related functions

   This header file contains the declaration of the @hl algorithm
   base module interface common to all five types of algorithms used
   by @em ssh2. It also provides functions to register
   @hl algorithms on an @ref assh_context_s object.

   @xsee{suppalgos}
   @xsee{coremod}
   @see{@assh/assh_kex.h}
   @see{@assh/assh_sign.h}
   @see{@assh/assh_cipher.h}
   @see{@assh/assh_mac.h}
   @see{@assh/assh_compress.h}
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
    compatibility checking operation common to all the
    algorithm module interfaces. @see assh_algo_suitable_key */
typedef ASSH_ALGO_SUITABLE_KEY_FCN(assh_algo_suitable_key_t);

/** @This specifies classes for SSH @hl algorithms. */
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

/** @This specifies various @hl algorithms specification status.
    Values can be ored together. */
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
#define ASSH_ALGO_BASE(class__, implem_, safety_, speed_, ...)		\
  .algo = {                                                             \
    .class_ = ASSH_ALGO_##class__,                                      \
    .api = ASSH_ALGO_API_VERSION,                                       \
    .safety = safety_,                                                  \
    .speed = speed_,                                                    \
    .implem = implem_,                                                  \
    __VA_ARGS__                                                         \
  }

/** @internal map prime field size to assh safety factor,
    See @sourcelink doc/dh @see assh_algo_register_va */
#define ASSH_SAFETY_PRIMEFIELD(n) ((n) / 128 + 12)

/** @internalmembers @This is the generic @hl algorithm descriptor
    structure.

    Descriptor structures for specific algorithm types inherit from
    this structure. This means that algorithm descriptors have this
    structure as first field.

    @xsee{coremod} @see{assh_algo_cipher_s, assh_algo_mac_s,
    assh_algo_sign_s, assh_algo_kex_s, assh_algo_compress_s} */
struct assh_algo_s
{
  /** module API version */
  uint8_t api;

  /** Class of algorithm */
  enum assh_algo_class_e class_:3;
  /** used to choose between entries with the same name */
  uint8_t priority:5;

  /** safety factor in range [0, 99] */
  uint8_t safety:7;
  /** speed factor in range [0, 99] */
  uint8_t speed:7;

  /** Must be set when a different implementation may yield a
      different result due to use of random data. */
  uint8_t nondeterministic:1;

  /** List of SSH algorithm identifiers, used during key exchange */
  const struct assh_algo_name_s *names;

  /** Variant description string. */
  const char *variant;

  /** Implementation identification string.  Format is @em {vendor-library}. */
  const char *implem;

  /** Pointer to associated key operations, may be @tt NULL. */
  const struct assh_key_algo_s *key_algo;
  /** Test if a key can be used with the algorithm, may be @tt NULL. */
  assh_algo_suitable_key_t *f_suitable_key;
};

/**
   @This registers the specified array of @hl algorithms for use by
   the given library context. The last entry must be @tt NULL.

   If this function is called more than once, the internal array of
   algorithms is resized and new algorithms are appended.

   It is not possible to modify the list of registered algorithms when
   some sessions are associated to the context. The @ref
   assh_session_algo_filter function can still be used to setup a per
   session algorithm filter for the @hl key-exchange.

   @see assh_algo_register_names_va
   @see assh_algo_register_default
   @see assh_algo_register
   @xcsee {algoreg}
*/
ASSH_WARN_UNUSED_RESULT assh_status_t
assh_algo_register_va(struct assh_context_s *c, assh_safety_t safety,
		      assh_safety_t min_safety, uint8_t min_speed, ...);

/**
   @This registers the algorithms with the given names for specified
   class for use the given library context. The last entry must be @tt
   NULL.

   This function needs to be called more than once to register
   different classes of algorithms.

   It is not possible to modify the list of registered algorithms when
   some sessions are associated to the context. The @ref
   assh_session_algo_filter function can still be used to setup a per
   session algorithm filter for the @hl key-exchange.

   The function is successful when at least one of the designated
   algorithms has been registered successfully.

   @see assh_algo_register_va
   @see assh_algo_register_default
   @see assh_algo_register
   @xcsee {algoreg}
*/
ASSH_WARN_UNUSED_RESULT assh_status_t
assh_algo_register_names_va(struct assh_context_s *c, assh_safety_t safety,
			    assh_safety_t min_safety, uint8_t min_speed,
			    enum assh_algo_class_e class_, ...);

/**
   @This registers the specified array of @hl algorithms for use by
   the given library context. The last entry must be @tt NULL.

   The array is copied and the algorithms are sorted depending on
   their safety factor and speed factor. The @tt safety weight
   parameter indicates how algorithms safety must be favored over
   speed. Valid range for this parameter is [0, 99]. Algorithms with a
   safety factor or speed factor less than @tt min_safety and @tt
   min_speed are discarded.

   When multiple implementations of the same algorithm are registered,
   the variant which appears first in the list after sorting is kept
   and subsequent variants with the same name are discarded. This
   should retain the less secure variants of the same algorithm not
   filtered by the value of @tt min_safety.

   @see assh_algo_register_default
   @xcsee {algoreg}
*/
ASSH_WARN_UNUSED_RESULT assh_status_t
assh_algo_register(struct assh_context_s *c, assh_safety_t safety,
		   assh_safety_t min_safety, uint8_t min_speed,
                   const struct assh_algo_s *table[]);

/**
   @This registers the specified array of @hl algorithms for use by
   the given library context. The last entry must be @tt NULL.

   The algorithms must be sorted in ascending class order. The array
   is not copied and must remain valid.

   If this function is called more than once, the array of algorithms
   is replaced.

   When this function has been called, it is not possible to register
   more algorithms by calling @ref assh_algo_register without first
   calling @ref assh_algo_unregister.

   It is not possible to modify registered algorithms when some
   sessions are associated to the context.  The @ref
   assh_session_algo_filter function can still be used to setup a per
   session algorithm filter for the @hl key-exchange.

   @xcsee {algoreg}
*/
ASSH_WARN_UNUSED_RESULT assh_status_t
assh_algo_register_static(struct assh_context_s *c,
                          const struct assh_algo_s *table[]);

/** This is a @tt NULL terminated array of descriptors for
    @hl algorithm provided by the library. Multiple variants of the
    same algorithm may exist. */
extern const struct assh_algo_s *assh_algo_table[];

/** @This returns a pointer to the descriptor of the registered
    @hl algorithm at specified index. The first valid index is
    0. @tt NULL is returned when out of range. */
const struct assh_algo_s *
assh_algo_registered(struct assh_context_s *c, uint_fast16_t i);

/** @This registers the default set of available @hl algorithms
    depending on the library configuration. It relies on the @ref
    assh_algo_register function.

    @xcsee {algoreg}
*/
ASSH_INLINE ASSH_WARN_UNUSED_RESULT assh_status_t
assh_algo_register_default(struct assh_context_s *c,
                           assh_safety_t safety,
			   assh_safety_t min_safety,
                           uint8_t min_speed)
{
  return assh_algo_register(c, safety, min_safety, min_speed, assh_algo_table);
}

/** Unregister all @hl algorithms.

    It is not possible to modify registered algorithms when some
    sessions are associated to the context.
*/
ASSH_WARN_UNUSED_RESULT assh_status_t
assh_algo_unregister(struct assh_context_s *c);

/** @This returns the @hl algorithm default name from its descriptor. */
ASSH_INLINE const char * assh_algo_name(const struct assh_algo_s *algo)
{
  return algo->names[0].name;
}

/** @This returns the name of the @hl algorithm variant from its
    descriptor. */
ASSH_INLINE const char *
assh_algo_variant(const struct assh_algo_s *algo)
{
  return algo->variant ? algo->variant : "default";
}

/** @This returns the estimated @hl algorithm safety factor value
    from its descriptor.
    @see assh_algo_register */
ASSH_INLINE assh_safety_t
assh_algo_safety(const struct assh_algo_s *algo)
{
  return algo->safety;
}

/* @see assh_safety_name @see assh_algo_safety. */
ASSH_INLINE const char *
assh_algo_safety_name(const struct assh_algo_s *algo)
{
  return assh_safety_name(algo->safety);
}

/** @This finds an @hl algorithm with matching class and name in a
    @tt NULL terminated array of pointers to algorithm descriptors.
    @see assh_algo_table */
ASSH_WARN_UNUSED_RESULT assh_status_t
assh_algo_by_name_static(const struct assh_algo_s **table,
                         enum assh_algo_class_e class_, const char *name,
                         size_t name_len, const struct assh_algo_s **algo,
                         const struct assh_algo_name_s **namep);

/** @internal */
const struct assh_algo_name_s *
assh_algo_name_match(const struct assh_algo_s *a,
                     enum assh_algo_class_e class_,
                     const char *name, size_t name_len);

/** @internal @This finds a registered @hl algorithm with matching
    class and name. If the @tt namep parameter is not @tt NULL, the
    matched algorithm name is returned. */
ASSH_WARN_UNUSED_RESULT assh_status_t
assh_algo_by_name(struct assh_context_s *c,
		  enum assh_algo_class_e class_, const char *name,
                  size_t name_len, const struct assh_algo_s **algo,
                  const struct assh_algo_name_s **namep);

/** @internal @This finds a registered @hl algorithm which can be
    used with the given key. If the @tt pos parameter is not @tt NULL,
    it specifies the starting index of the search and it will be
    updated with the index of the matching entry. */
ASSH_WARN_UNUSED_RESULT assh_status_t
assh_algo_by_key(struct assh_context_s *c,
                 const struct assh_key_s *key, uint16_t *pos,
                 const struct assh_algo_s **algo);

/** @internal @This returns true if the provided key can be used with
    the @hl algorithm and has been loaded or created for that purpose.
    When the @tt key parameter is @tt NULL, the return value indicates
    if the algorithm needs a key when used during a key exchange.

    This does not check the validity of the key, the @ref
    assh_key_validate function is provided for that purpose. */
assh_bool_t
assh_algo_suitable_key(struct assh_context_s *c,
                       const struct assh_algo_s *algo,
                       const struct assh_key_s *key);

#endif

