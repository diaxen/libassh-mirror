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


#ifndef ASSH_HELPER_KEY_H_
#define ASSH_HELPER_KEY_H_

#include "assh_sign.h"

#include <stdio.h>

/** @This loads a key from a file handler and inserts
    the key in a linked list. Both binary and text key formats are
    supported. This function relies on @ref assh_key_load2 to load the
    binary key blob. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_load_key_file(struct assh_context_s *c,
		   struct assh_key_s **head, const char *algo,
		   FILE *file, enum assh_key_format_e format);

/** @This loads a key from a file name and inserts
    the key in a linked list. This function relies on @ref
    assh_key_loads_file. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_load_key_filename(struct assh_context_s *c,
		       struct assh_key_s **head,
		       const char *algo, const char *filename,
		       enum assh_key_format_e format);

/** @This loads a key from a file handler and register the key as an
    host key for the context. @see assh_load_key_file */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_load_hostkey_file(struct assh_context_s *c,
		       const char *algo, FILE *file,
		       enum assh_key_format_e format);

/** @This loads a key from a file name and register the key as an
    host key for the context. @see assh_load_key_filename */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_load_hostkey_filename(struct assh_context_s *c,
			   const char *algo, const char *filename,
			   enum assh_key_format_e format);

#endif

