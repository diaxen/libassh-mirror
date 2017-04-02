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
   @short SSH keys file IO
*/

#ifndef ASSH_HELPER_KEY_H_
#define ASSH_HELPER_KEY_H_

#include "assh_sign.h"

#include <stdio.h>

/** @This loads a key from a file handle and inserts the key
    in the @tt head linked list. Both binary and text key formats are
    supported. This function relies on @ref assh_key_load to load the
    binary key blob.

    Depending on the format, the function may be able to guess the
    type of key when @tt NULL is passed as @tt algo parameter. When the
    type of key is not supported by a registered algorithm, the
    function fails but the position of the file handle is advanced.

    When a binary format is used, the @tt size_hint argument specifies
    the amount of bytes that must be read from the file. When a text
    format is used, the @tt size_hint argument only controls the
    allocation of the temporary buffer used to store the underlying
    binary format. In either cases, a large enough default value is
    used when 0 is passed.
 */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_load_key_file(struct assh_context_s *c,
		   struct assh_key_s **head,
		   const struct assh_key_ops_s *algo,
		   enum assh_algo_class_e role,
		   FILE *file, enum assh_key_format_e format,
		   const char *passphrase, size_t size_hint);

/** @This loads a key from a file name and inserts the key
    in a linked list. This function relies on @ref
    assh_load_key_file. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_load_key_filename(struct assh_context_s *c,
		       struct assh_key_s **head,
		       const struct assh_key_ops_s *algo,
		       enum assh_algo_class_e role,
		       const char *filename,
		       enum assh_key_format_e format,
		       const char *passphrase, size_t size_hint);

/** @This loads a key from a file handler and register the key on the
    library context. @see assh_load_key_file */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_load_hostkey_file(struct assh_context_s *c,
		       const struct assh_key_ops_s *algo,
		       enum assh_algo_class_e role,
		       FILE *file,
		       enum assh_key_format_e format, size_t size_hint);

/** @This loads a key from a file name and register the key on the
    library context. @see assh_load_key_filename */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_load_hostkey_filename(struct assh_context_s *c,
			   const struct assh_key_ops_s *algo,
			   enum assh_algo_class_e role,
			   const char *filename,
			   enum assh_key_format_e format, size_t size_hint);

/** @This saves one or more keys to a file. @see assh_load_key_filename */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_save_key_file(struct assh_context_s *c,
		   const struct assh_key_s *head,
		   FILE *file, enum assh_key_format_e format,
		   const char *passphrase);

/** @This saves one or more keys to a file. @see assh_save_key_file */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_save_key_filename(struct assh_context_s *c,
		       const struct assh_key_s *head,
		       const char *filename,
		       enum assh_key_format_e format,
		       const char *passphrase);

#endif

