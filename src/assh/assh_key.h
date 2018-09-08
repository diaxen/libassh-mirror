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
   @short SSH keys base structure and related functions
*/

#ifndef ASSH_KEY_H_
#define ASSH_KEY_H_

#include "assh_algo.h"

#include <string.h>

/** @This specifies the storage formats of SSH keys.
    Private key formats are listed first.
    @see assh_key_format_desc_s */
enum assh_key_format_e
{
  ASSH_KEY_FMT_NONE,

  /** Keys openssh-key-v1 base64 format */
  ASSH_KEY_FMT_PV_OPENSSH_V1,
  /** Keys blob openssh-key-v1 binary format */
  ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB,
  /** Single private key encoding used as part of the @ref
      ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB format. */
  ASSH_KEY_FMT_PV_OPENSSH_V1_KEY,
  /** Private key in rfc2440 like format.
      Base64 encoding of @ref ASSH_KEY_FMT_PV_PEM_ASN1. */
  ASSH_KEY_FMT_PV_PEM,
  /** Private key in PEM Asn1 DER format. */
  ASSH_KEY_FMT_PV_PEM_ASN1,

  /** Public key in standard base64 format as described in rfc4716. */
  ASSH_KEY_FMT_PUB_RFC4716,
  /** Public key in standard binary format as described in rfc4253
      section 6.6. */
  ASSH_KEY_FMT_PUB_RFC4253,
  /** Public key in legacy openssh base64 format. */
  ASSH_KEY_FMT_PUB_OPENSSH,
  /** Keys openssh-key-v1 base64 format.
      Load public key part only */
  ASSH_KEY_FMT_PUB_OPENSSH_V1,
  /** Keys blob openssh-key-v1 binary format,
      Load public key part only */
  ASSH_KEY_FMT_PUB_OPENSSH_V1_BLOB,
  /** Public key in rfc2440 like format.
      Base64 encoding of @ref ASSH_KEY_FMT_PUB_PEM_ASN1. */
  ASSH_KEY_FMT_PUB_PEM,
  /** Public key in PEM Asn1 DER format. */
  ASSH_KEY_FMT_PUB_PEM_ASN1,

  ASSH_KEY_FMT_LAST = ASSH_KEY_FMT_PUB_PEM_ASN1,
};

/** @This returns true if the specified key format store public content only. */
ASSH_INLINE assh_bool_t assh_key_pub_fmt(enum assh_key_format_e f)
{
  const uint32_t c = (1 << ASSH_KEY_FMT_PUB_RFC4716)
    | (1 << ASSH_KEY_FMT_PUB_RFC4253)
    | (1 << ASSH_KEY_FMT_PUB_OPENSSH)
    | (1 << ASSH_KEY_FMT_PUB_PEM)
    | (1 << ASSH_KEY_FMT_PUB_PEM_ASN1);

  return (c >> f) & 1;
}

/** @internal @see assh_key_load_t */
#define ASSH_KEY_LOAD_FCN(n) ASSH_WARN_UNUSED_RESULT assh_error_t (n)   \
  (struct assh_context_s *c,                                            \
   const struct assh_key_algo_s *algo,                                   \
   const uint8_t **blob_, size_t blob_len,                              \
   struct assh_key_s **key,                                             \
   enum assh_key_format_e format)

/** @internal @This defines the function type for the key loading
    operation of the key module interface. @see assh_key_load */
typedef ASSH_KEY_LOAD_FCN(assh_key_load_t);

#ifdef CONFIG_ASSH_KEY_CREATE
/** @internal @see assh_key_create_t */
#define ASSH_KEY_CREATE_FCN(n) ASSH_WARN_UNUSED_RESULT assh_error_t (n) \
  (struct assh_context_s *c,                                            \
   const struct assh_key_algo_s *algo,                                  \
   size_t bits, struct assh_key_s **key)

/** @internal @This defines the function type for the key create
    operation of the key module interface. @see assh_key_create */
typedef ASSH_KEY_CREATE_FCN(assh_key_create_t);
#endif

#ifdef CONFIG_ASSH_KEY_VALIDATE
/** @This specifies the possible results of key validation. */
enum assh_key_validate_result_e
{
  /** Something is wrong with the key. */
  ASSH_KEY_BAD = -2,
  /** The key may not be bad but some of its parameters have unusual
      values which make this key not supported by the implementation. */
  ASSH_KEY_NOT_SUPPORTED = -1,
  /** Checking this type of key is not supported yet or there is no
      way to check this type of public key due to the algorithm design. */
  ASSH_KEY_NOT_CHECKED = 2,
  /** Some checks have been performed but there is no way to fully
      validate this type of public key due to the algorithm design. */
  ASSH_KEY_PARTIALLY_CHECKED = 3,
  /** The key has passed a full validation check. */
  ASSH_KEY_GOOD = 4,
};

/** @internal @see assh_key_validate_t */
#define ASSH_KEY_VALIDATE_FCN(n) ASSH_WARN_UNUSED_RESULT assh_error_t (n) \
  (struct assh_context_s *c,                                            \
   const struct assh_key_s *key,                                        \
   enum assh_key_validate_result_e *result)

/** @internal @This defines the function type for the key validation
    operation of the key module interface. @see assh_key_validate */
typedef ASSH_KEY_VALIDATE_FCN(assh_key_validate_t);
#endif

/** @internal @see assh_key_output_t */
#define ASSH_KEY_OUTPUT_FCN(n) ASSH_WARN_UNUSED_RESULT assh_error_t (n) \
  (struct assh_context_s *c,                                            \
   const struct assh_key_s *key,                                        \
   uint8_t *blob, size_t *blob_len,                                     \
   enum assh_key_format_e format)

/** @internal @This defines the function type for the key output
    operation of the key module interface. @see assh_key_output */
typedef ASSH_KEY_OUTPUT_FCN(assh_key_output_t);

/** @internal @see assh_key_cmp_t */
#define ASSH_KEY_CMP_FCN(n) ASSH_WARN_UNUSED_RESULT assh_bool_t (n)     \
  (struct assh_context_s *c,                                            \
   const struct assh_key_s *key,                                        \
   const struct assh_key_s *b, assh_bool_t pub)

/** @internal @This defines the function type for the key compare
    operation of the key module interface. @see assh_key_cmp */
typedef ASSH_KEY_CMP_FCN(assh_key_cmp_t);

/** @internal @see assh_key_cleanup_t */
#define ASSH_KEY_CLEANUP_FCN(n) void (n)                                \
  (struct assh_context_s *c,                                            \
   struct assh_key_s *key)

/** @internal @This defines the function type for the key cleanup
    operation of the key module interface.
    @see assh_key_drop @see assh_key_flush */
typedef ASSH_KEY_CLEANUP_FCN(assh_key_cleanup_t);

/** @internalmembers @This is the key algorithm descriptor of the SSH
    key module interface. */
struct assh_key_algo_s
{
  const char *name;

  assh_key_load_t *f_load;
#ifdef CONFIG_ASSH_KEY_CREATE
  assh_key_create_t *f_create;
#endif
  assh_key_output_t *f_output;
#ifdef CONFIG_ASSH_KEY_VALIDATE
  assh_key_validate_t *f_validate;
#endif
  assh_key_cmp_t *f_cmp;
  assh_key_cleanup_t *f_cleanup;

  /** Supported storage formats, zero terminated. This includes
      container formats supported by helper functions. The preferred
      storage formats for private and public keys are the first and
      second entries respectively. */
  const enum assh_key_format_e *formats;

  /** minimum number of bits for @ref assh_key_create */
  uint16_t min_bits;
  /** suggested number of bits for @ref assh_key_create */
  uint16_t bits;
  /** maximuu number of bits for @ref assh_key_create */
  uint16_t max_bits;
};

/** @tt NULL terminated array of key algorithms supported by the library. */
extern const struct assh_key_algo_s *assh_key_algo_table[];

/** @This describes a key format.
    @see assh_key_format_table */
struct assh_key_format_desc_s
{
  /** A short human readable identifier for the format. */
  const char *name;
  /** A long description string for the format. */
  const char *desc;
  /** True for public key only formats. */
  assh_bool_t public:1;
  /** True when the format is not commonly used for key storage. */
  assh_bool_t internal:1;
  /** True when the format supports encryption. */
  assh_bool_t encrypted:1;
  /** True when this format is a public subset of a private format.
      Only loading feature is provided in this case. */
  assh_bool_t pub_part:1;
  /** True when this format only contains the private key data. The
      loading function will complete an exisiting public key. */
  assh_bool_t pv_part:1;
};

/** Array of descritors for key storage formats supported by the
    library. Valid array indices are defined in @ref
    assh_key_format_e. Any entry with a @tt NULL name must be
    ignored. */
extern const struct assh_key_format_desc_s
assh_key_format_table[ASSH_KEY_FMT_LAST + 1];

/** @internalmembers @This is the generic SSH key structure. Other key
    structures inherit from this type. */
struct assh_key_s
{
  const char *type;
  char *comment;

  /** Next key in the list */
  struct assh_key_s *next;

  /** Key algorithm */
  const struct assh_key_algo_s *algo;

  /** Class of algorithm the key is intended to be used with */
  enum assh_algo_class_e role:3;

  assh_bool_t private:1;
  assh_bool_t stored:1;

  assh_safety_t safety;
  uint8_t ref_count;
};

/** @This allocates and intiailizes the key structure from
    the passed key blob data. The @tt blob pointer is updated so that
    the key blob is skipped.

    This function will only support some binary key formats specific
    to a given key algorithm. More formats are handled by helper
    functions provided by @ref @assh/helper_key.h */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_key_load(struct assh_context_s *c,
              struct assh_key_s **key,
              const struct assh_key_algo_s *algo,
              enum assh_algo_class_e role,
              enum assh_key_format_e format,
              const uint8_t **blob, size_t blob_len);

ASSH_WARN_UNUSED_RESULT assh_error_t
assh_key_load_pv(struct assh_context_s *c,
                 struct assh_key_s *key,
                 enum assh_key_format_e format,
                 const uint8_t **blob, size_t blob_len);

#ifdef CONFIG_ASSH_KEY_CREATE
/** @This creates a new key of specified type and bits
    size. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_key_create(struct assh_context_s *c,
                struct assh_key_s **key, size_t bits,
                const struct assh_key_algo_s *algo,
                enum assh_algo_class_e role);
#endif

/** @This changes the key comment string. */
assh_error_t
assh_key_comment(struct assh_context_s *c,
                 struct assh_key_s *key,
                 const char *comment);

/** @This writes the key in blob representation to
    the @tt blob buffer. The @tt blob_len parameter is updated with
    the actual size of the key blob.

    If the @tt blob parameter is @tt NULL, the function updates the
    @tt blob_len parmeter with a size value which is equal or slightly
    greater to what is needed to actually store the blob.

    This function will only support some binary key formats specific
    to a given key algorithm. More formats are handled by helper
    functions provided by @ref @assh/helper_key.h */
ASSH_INLINE ASSH_WARN_UNUSED_RESULT assh_error_t
assh_key_output(struct assh_context_s *c,
                const struct assh_key_s *key,
                uint8_t *blob, size_t *blob_len,
                enum assh_key_format_e format)
{
  return key->algo->f_output(c, key, blob, blob_len, format);
}

/** @This returns true if both keys are equals. If the @tt
    pub parameter is set, only the public parts of the key are taken
    into account. */
ASSH_INLINE ASSH_WARN_UNUSED_RESULT assh_bool_t
assh_key_cmp(struct assh_context_s *c, const struct assh_key_s *key,
	     const struct assh_key_s *b, assh_bool_t pub)
{
  return key->algo->f_cmp(c, key, b, pub);
}

/** @This removes the first key from the singly linked list. The key is
    also released unless @ref assh_key_refinc has been called. */
void assh_key_drop(struct assh_context_s *c,
                   struct assh_key_s **head);

/** @This releases all the keys on the linked list
    and set the list head to @tt NULL. */
ASSH_INLINE void
assh_key_flush(struct assh_context_s *c,
               struct assh_key_s **head)
{
  while (*head != NULL)
    assh_key_drop(c, head);
}

/** @This inserts a key in a list of keys. */
ASSH_INLINE void
assh_key_insert(struct assh_key_s **head,
                struct assh_key_s *key)
{
  key->next = *head;
  *head = key;
}

/** @This increases the reference counter of the key so that it is not
    released by the next call to @ref assh_key_drop. */
ASSH_INLINE void
assh_key_refinc(struct assh_key_s *key)
{
  key->ref_count++;
}

#ifdef CONFIG_ASSH_KEY_VALIDATE
/** @This checks the validity of the key. */
ASSH_INLINE ASSH_WARN_UNUSED_RESULT assh_error_t
assh_key_validate(struct assh_context_s *c,
                  const struct assh_key_s *key,
                  enum assh_key_validate_result_e *result)
{
  *result = ASSH_KEY_BAD;
  return key->algo->f_validate(c, key, result);
}
#endif

/** @internal @This looks for a key usable with the given algorithm
    among keys registered on the context. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_key_lookup(struct assh_context_s *c,
                struct assh_key_s **key,
                const struct assh_algo_s *algo);

/** @This returns the type name of the key. */
ASSH_INLINE const char *
assh_key_type_name(struct assh_key_s *key)
{
  return key->type ? key->type : key->algo->name;
}

/** @This returns the estimated algorithm safety. */
ASSH_INLINE assh_safety_t
assh_key_safety(struct assh_key_s *key)
{
  return key->safety;
}

/* @see assh_safety_name @see assh_key_safety */
ASSH_INLINE const char *
assh_key_safety_name(struct assh_key_s *key)
{
  return assh_safety_name(key->safety);
}

/** Dummy key algorithm */
extern const struct assh_key_algo_s assh_key_none;

/** @This find a key algorithm with matching  name in a @tt NULL
    terminated array of pointers to algorithm descriptors. @see
    assh_key_algo_table */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_key_algo_by_name_static(const struct assh_key_algo_s **table,
                             const char *name, size_t name_len,
                             const struct assh_key_algo_s **algo);

#endif

