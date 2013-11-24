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

#ifndef ASSH_KEY_H_
#define ASSH_KEY_H_

#include "assh.h"

#include <string.h>

/** @This specifies the storage formats of SSH keys. */
enum assh_key_format_e
{
  /** public key in rfc4716, base64 ascii format. */
  ASSH_KEY_FMT_PUB_RFC4716,
  /** public key in rfc4253, section 6.6 binary format. */
  ASSH_KEY_FMT_PUB_RFC4253_6_6,

  /** private key in rfc2440 like, base64 ascii format with PEM Asn1 inside. */
  ASSH_KEY_FMT_PV_RFC2440_PEM_ASN1,
  /** private key in PEM Asn1 DER binary format. */
  ASSH_KEY_FMT_PV_PEM_ASN1,
};

struct assh_key_s;

/** @internal This function allocates and intiailizes the key
    structure from the passed key blob data.

    This function may only support binary key formats; ascii formats
    are handled by helper functions.
*/
#define ASSH_KEY_LOAD_FCN(n) assh_error_t (n)(struct assh_context_s *c, \
                                              const uint8_t *blob, size_t blob_len, \
                                              struct assh_key_s **key, \
                                              enum assh_key_format_e format)
typedef ASSH_KEY_LOAD_FCN(assh_key_load_t);


/** @internal This function checks the key validity. */
#define ASSH_KEY_VALIDATE_FCN(n) assh_error_t (n)(struct assh_context_s *c, \
                                                  const struct assh_key_s *key, \
                                                  assh_bool_t *valid)
typedef ASSH_KEY_VALIDATE_FCN(assh_key_validate_t);


/** @internal This function write the key in blob representation to
    the @tt blob buffer. The @tt blob_len parameter indicates the size
    of the buffer and is updated with the actual size of the blob.

    If the @tt blob parameter is @tt NULL, the function updates the
    @tt blob_len parmeter with a size value which is greater or equal
    to what is needed to hold the blob.

    This function may only support the @ref
    ASSH_KEY_FMT_PUB_RFC4253_6_6 format.
*/
#define ASSH_KEY_OUTPUT_FCN(n) assh_error_t (n)(struct assh_context_s *c, \
                                                const struct assh_key_s *key, \
                                                uint8_t *blob, size_t *blob_len, \
                                                enum assh_key_format_e format)
typedef ASSH_KEY_OUTPUT_FCN(assh_key_output_t);


/** This function compares two keys and returns a positive value if
    the keys are equals. If the @tt pub parameter is set, only the
    public part of the keys are compared. */
#define ASSH_KEY_CMP_FCN(n) assh_bool_t (n)(struct assh_key_s *key,     \
                                            struct assh_key_s *b, assh_bool_t pub)
typedef ASSH_KEY_CMP_FCN(assh_key_cmp_t);


/** @internal This function must release the resources used by the key. */
#define ASSH_KEY_CLEANUP_FCN(n) void (n)(struct assh_context_s *c, \
                                         struct assh_key_s *key)
typedef ASSH_KEY_CLEANUP_FCN(assh_key_cleanup_t);

/** SSH key structure */
struct assh_key_s
{
  const struct assh_algo_s *algo;
  struct assh_key_s *next;
  assh_key_output_t *f_output;
  assh_key_validate_t *f_validate;
  assh_key_cmp_t *f_cmp;
  assh_key_cleanup_t *f_cleanup;
};

/** @internal This function loads a key using the specified algorithm. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_key_load3(struct assh_context_s *c, struct assh_key_s **key,
               const struct assh_algo_s *algo,
               const uint8_t *blob, size_t blob_len,
               enum assh_key_format_e format);

/** This function loads a key using the specified algorithm name.

    The @tt algo_name parameter may be @tt NULL provided that the
    requested key format allows guessing the algorithm associated to
    the key. @see assh_key_load */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_key_load2(struct assh_context_s *c, struct assh_key_s **key,
               const char *algo_name, size_t algo_name_len,
               const uint8_t *blob, size_t blob_len,
               enum assh_key_format_e format);

/** This function is similar to @ref assh_key_load2. The @tt algo_name
    parameter is a @tt NUL terminated string. */
static inline ASSH_WARN_UNUSED_RESULT assh_error_t
assh_key_load(struct assh_context_s *c, struct assh_key_s **key,
              const char *algo_name, const uint8_t *blob, size_t blob_len,
              enum assh_key_format_e format)
{
  return assh_key_load2(c, key, algo_name,
                        algo_name != NULL ? strlen(algo_name) : 0,
                        blob, blob_len, format);
}

/** @This function returns true if both keys are equals. If the @tt
    pub parameter is set, only the public part of the key are taken
    into account. */
static inline assh_bool_t
assh_key_cmp(struct assh_key_s *key, struct assh_key_s *b, assh_bool_t pub)
{
  return key->f_cmp(key, b, pub);
}

/** @internal This function releases all the keys on the linked list
    and clears the list. */
void
assh_key_flush(struct assh_context_s *c, struct assh_key_s **head);

/** @internal This function releases the first key on the linked list. */
void
assh_key_drop(struct assh_context_s *c, struct assh_key_s **head);

/** This function checks the key validity. */
static inline ASSH_WARN_UNUSED_RESULT assh_error_t
assh_key_validate(struct assh_context_s *c, const struct assh_key_s *key,
                  assh_bool_t *valid)
{
  return key->f_validate(c, key, valid);
}

#endif

