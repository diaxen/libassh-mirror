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

/*
  ssh-rsa signature shared declarations
*/

#ifndef ASSH_SIGN_RSA_H_
#define ASSH_SIGN_RSA_H_

enum assh_rsa_digest_e
{
  RSA_DIGEST_MD2,
  RSA_DIGEST_MD5,
  RSA_DIGEST_SHA1,
  RSA_DIGEST_SHA256,
  RSA_DIGEST_SHA384,
  RSA_DIGEST_SHA512,
  RSA_DIGEST_count,
};

struct assh_rsa_digest_s
{
  /* asn1 DER digest algorithm identifier */
  uint_fast8_t oid_len;
  const char *oid;

  const struct assh_hash_algo_s *algo;
};

static const struct assh_rsa_digest_s assh_rsa_digests[RSA_DIGEST_count] =
{
 /* len   DigestInfo header */
  { 18, "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x02\x05\x00\x04\x10",
    NULL /* md2 */ },
  { 18, "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10",
    &assh_hash_md5 },
  { 15, "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14",
    &assh_hash_sha1 },
  { 19, "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20",
    &assh_hash_sha256 },
  { 19, "\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30",
    &assh_hash_sha384 },
  { 19, "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40",
    &assh_hash_sha512 },
};

#define ASSH_RSA_SHA256_ID "\x00\x00\x00\x0crsa-sha2-256"
#define ASSH_RSA_SHA512_ID "\x00\x00\x00\x0crsa-sha2-512"

#endif
