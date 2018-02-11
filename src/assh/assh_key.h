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

/** @This specifies the storage formats of SSH keys. */
enum assh_key_format_e
{
  ASSH_KEY_FMT_NONE,

  /** Public key in standard base64 format as described in rfc4716. */
  ASSH_KEY_FMT_PUB_RFC4716,
  /** Public key in standard binary format as described in rfc4253
      section 6.6. */
  ASSH_KEY_FMT_PUB_RFC4253,
  /** Public key in legacy openssh base64 format. */
  ASSH_KEY_FMT_PUB_OPENSSH,
  /** Public key in rfc2440 like format.
      Base64 encoding of @ref ASSH_KEY_FMT_PUB_PEM_ASN1. */
  ASSH_KEY_FMT_PUB_PEM,
  /** Public key in PEM Asn1 DER format. */
  ASSH_KEY_FMT_PUB_PEM_ASN1,

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

  ASSH_KEY_FMT_LAST = ASSH_KEY_FMT_PV_PEM_ASN1,
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
   const struct assh_key_ops_s *algo,                                   \
   const uint8_t **blob_, size_t blob_len,                              \
   struct assh_key_s **key,                                             \
   enum assh_key_format_e format)

/** @internal @This defines the function type for the key loading
    operation of the key module interface. @see assh_key_load */
typedef ASSH_KEY_LOAD_FCN(assh_key_load_t);

/** @internal @see assh_key_create_t */
#define ASSH_KEY_CREATE_FCN(n) ASSH_WARN_UNUSED_RESULT assh_error_t (n) \
  (struct assh_context_s *c,                                            \
   const struct assh_key_ops_s *algo,                                  \
   size_t bits, struct assh_key_s **key)

/** @internal @This defines the function type for the key create
    operation of the key module interface. @see assh_key_create */
typedef ASSH_KEY_CREATE_FCN(assh_key_create_t);

/** @internal @see assh_key_validate_t */
#define ASSH_KEY_VALIDATE_FCN(n) ASSH_WARN_UNUSED_RESULT assh_error_t (n) \
  (struct assh_context_s *c,                                            \
   const struct assh_key_s *key)

/** @internal @This defines the function type for the key validation
    operation of the key module interface. @see assh_key_validate */
typedef ASSH_KEY_VALIDATE_FCN(assh_key_validate_t);

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
struct assh_key_ops_s
{
  const char *type;
  assh_key_load_t *f_load;
  assh_key_create_t *f_create;
  assh_key_output_t *f_output;
  assh_key_validate_t *f_validate;
  assh_key_cmp_t *f_cmp;
  assh_key_cleanup_t *f_cleanup;
};

/** @internalmembers @This is the generic SSH key structure. Other key
    structures inherit from this type. */
struct assh_key_s
{
  const char *type;
  char *comment;

  /* Next key in the list */
  struct assh_key_s *next;

  /* Functions operating on this key */
  const struct assh_key_ops_s *algo;

  /* Class of algorithm the key is intended to be used with */
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
              const struct assh_key_ops_s *algo,
              enum assh_algo_class_e role,
              enum assh_key_format_e format,
              const uint8_t **blob, size_t blob_len);

/** @This creates a new key of specified type and bits
    size. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_key_create(struct assh_context_s *c,
                struct assh_key_s **key, size_t bits,
                const struct assh_key_ops_s *algo,
                enum assh_algo_class_e role);

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

/** @This checks the validity of the key. */
ASSH_INLINE ASSH_WARN_UNUSED_RESULT assh_error_t
assh_key_validate(struct assh_context_s *c,
                  const struct assh_key_s *key)
{
  return key->algo->f_validate(c, key);
}

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
  return key->type ? key->type : key->algo->type;
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
extern const struct assh_key_ops_s assh_key_none;

#endif

