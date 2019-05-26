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
   @internal
   @short Bcrypt password hashing algorithm
*/

#ifndef ASSH_HELPER_BCRYPT_H_
#define ASSH_HELPER_BCRYPT_H_

assh_error_t
asshh_bcrypt_pbkdf(struct assh_context_s *c,
		  const char *pass, size_t passlen,
		  const uint8_t *salt, size_t saltlen,
		  uint8_t *key, size_t keylen, size_t rounds);

#endif

