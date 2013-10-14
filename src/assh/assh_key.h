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

    This function must only support binary key formats; ascii formats
    are handled by helper functions.
*/
#define ASSH_KEY_LOAD_FCN(n) assh_error_t (n)(struct assh_context_s *c, \
                                              const uint8_t *blob, size_t blob_len, \
                                              struct assh_key_s **key, \
                                              enum assh_key_format_e format)
typedef ASSH_KEY_LOAD_FCN(assh_key_load_t);

/** @internal This function must release the resources used by the key. */
#define ASSH_KEY_CLEANUP_FCN(n) void (n)(struct assh_context_s *c, \
                                         struct assh_key_s *key)
typedef ASSH_KEY_CLEANUP_FCN(assh_key_cleanup_t);

/** SSH key structure */
struct assh_key_s
{
  const struct assh_algo_s *algo;
  struct assh_key_s *next;
  assh_key_cleanup_t *f_cleanup;
};

/** @internal This function loads a key and inserts the key in a
    linked list. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_key_add(struct assh_context_s *c, struct assh_key_s **head,
             const char *algo, const uint8_t *blob, size_t blob_len,
             enum assh_key_format_e format);

/** @internal This function releases all the keys on the linked list
    and clears the list. */
void
assh_key_flush(struct assh_context_s *c, struct assh_key_s **head);

#endif

