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

   This header file provides @hl helper functions designed to load
   and store @hl{SSH keys} on disk.

   @xsee{keysalgos}
   @see{@assh/assh_key.h}
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

    When the @ref ASSH_KEY_FMT_NONE format is specified, multiple
    supported formats are tried.

    When a binary format is used, the @tt size_hint argument specifies
    the amount of bytes that must be read from the file. When a text
    format is used, the @tt size_hint argument only controls the
    allocation of the temporary buffer used to store the underlying
    binary format. In either cases, a large enough default value is
    used when 0 is passed.
 */
ASSH_WARN_UNUSED_RESULT assh_status_t
asshh_load_key_file(struct assh_context_s *c,
		   struct assh_key_s **head,
		   const struct assh_key_algo_s *algo,
		   enum assh_algo_class_e role,
		   FILE *file, enum assh_key_format_e format,
		   const char *passphrase, size_t size_hint);

/** @This loads a key from a file name and inserts the key
    in a linked list. This function relies on @ref
    asshh_load_key_file. */
ASSH_WARN_UNUSED_RESULT assh_status_t
asshh_load_key_filename(struct assh_context_s *c,
		       struct assh_key_s **head,
		       const struct assh_key_algo_s *algo,
		       enum assh_algo_class_e role,
		       const char *filename,
		       enum assh_key_format_e format,
		       const char *passphrase, size_t size_hint);

/** @This loads a key from a file handler and register the key on the
    library context. @see asshh_load_key_file */
ASSH_WARN_UNUSED_RESULT assh_status_t
asshh_load_hostkey_file(struct assh_context_s *c,
		       const struct assh_key_algo_s *algo,
		       enum assh_algo_class_e role,
		       FILE *file,
		       enum assh_key_format_e format, size_t size_hint);

/** @This loads a key from a file name and register the key on the
    library context. @see asshh_load_key_filename */
ASSH_WARN_UNUSED_RESULT assh_status_t
asshh_load_hostkey_filename(struct assh_context_s *c,
			   const struct assh_key_algo_s *algo,
			   enum assh_algo_class_e role,
			   const char *filename,
			   enum assh_key_format_e format, size_t size_hint);

/** @This saves one or more keys to a file. @see asshh_load_key_filename */
ASSH_WARN_UNUSED_RESULT assh_status_t
asshh_save_key_file(struct assh_context_s *c,
		   const struct assh_key_s *head,
		   FILE *file, enum assh_key_format_e format,
		   const char *passphrase);

/** @This saves one or more keys to a file. @see asshh_save_key_file */
ASSH_WARN_UNUSED_RESULT assh_status_t
asshh_save_key_filename(struct assh_context_s *c,
		       const struct assh_key_s *head,
		       const char *filename,
		       enum assh_key_format_e format,
		       const char *passphrase);

/** @This specifies formats of ssh key fingerprint. */
enum asshh_fingerprint_fmt_e
{
  ASSH_FP_RFC4716_MD5,
  ASSH_FP_RFC4255_SHA1,
  ASSH_FP_RFC6594_SHA256,
  ASSH_FP_BASE64_SHA256,
};

/** @This writes a fingerprint string of a key in the provided
    buffer. The value of @tt buf_size is updated with the required
    size when a @tt NULL buffer is passed. The string is null
    terminated.

    The function returns @ref ASSH_NO_DATA when the format is not
    known. All supported format ids are contiguous, starting at 0. */
ASSH_WARN_UNUSED_RESULT assh_status_t
asshh_key_fingerprint(struct assh_context_s *c,
		     const struct assh_key_s *key,
		     enum asshh_fingerprint_fmt_e fmt,
		     char *buf, size_t *buf_size,
                     const char **fmt_name);

#endif

