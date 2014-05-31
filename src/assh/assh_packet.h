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


#ifndef ASSH_PACKET_H_
#define ASSH_PACKET_H_

#include "assh.h"

#include <string.h>

/** @internal SSH protocol packet header */
struct assh_packet_head_s
{
  uint8_t   pck_len[4];
  uint8_t   pad_len;
  uint8_t   msg;
  uint8_t   end[0];
};

/** @internal SSH packet object */
struct assh_packet_s
{
  union {
    /** Packet queue entry, valid when packet is allocated. */
    struct assh_queue_entry_s entry;
    /** Spare packet pool entry, valid when packet has been released. */
    struct assh_packet_s *pool_next;
  };

  /** Associated assh context */
  struct assh_context_s *ctx;

  /** Size of the allocated packet data buffer. */
  uint_fast32_t alloc_size;
  /** Amount of valid packet data. This value is increased when adding
      data to the packet and is used when the packet is finally sent out. */
  uint_fast32_t data_size;

  /** Number of references to this packet. */
  uint_fast16_t ref_count;

  union {
    uint8_t                   data[0];
    struct assh_packet_head_s head;
  };
};

/** @internal @This specifies the standard values for ssh message ids. */
enum assh_ssh_msg_e
{
  SSH_MSG_INVALID                   =   0,

  /* SSH-TRANS */
  SSH_MSG_DISCONNECT                =   1,
  SSH_MSG_IGNORE                    =   2,
  SSH_MSG_UNIMPLEMENTED             =   3,
  SSH_MSG_DEBUG                     =   4,
  SSH_MSG_SERVICE_REQUEST           =   5,
  SSH_MSG_SERVICE_ACCEPT            =   6,
  SSH_MSG_KEXINIT                   =  20,
  SSH_MSG_NEWKEYS                   =  21,

  /* SSH-KEX */
  SSH_MSG_KEX_DH_REQUEST            =  30,
  SSH_MSG_KEX_DH_REPLY              =  31,
  SSH_MSG_KEX_ECDH_INIT             =  30,
  SSH_MSG_KEX_ECDH_REPLY            =  31,

  /* SSH-USERAUTH */
  SSH_MSG_USERAUTH_REQUEST          =  50,
  SSH_MSG_USERAUTH_FAILURE          =  51,
  SSH_MSG_USERAUTH_SUCCESS          =  52,
  SSH_MSG_USERAUTH_BANNER           =  53,
  SSH_MSG_USERAUTH_PK_OK            =  60,
  SSH_MSG_USERAUTH_PASSWD_CHANGEREQ =  60,

  /* SSH-CONNECT */
  SSH_MSG_GLOBAL_REQUEST            =  80,
  SSH_MSG_REQUEST_SUCCESS           =  81,
  SSH_MSG_REQUEST_FAILURE           =  82,
  SSH_MSG_CHANNEL_OPEN              =  90,
  SSH_MSG_CHANNEL_OPEN_CONFIRMATION =  91,
  SSH_MSG_CHANNEL_OPEN_FAILURE      =  92,
  SSH_MSG_CHANNEL_WINDOW_ADJUST     =  93,
  SSH_MSG_CHANNEL_DATA              =  94,
  SSH_MSG_CHANNEL_EXTENDED_DATA     =  95,
  SSH_MSG_CHANNEL_EOF               =  96,
  SSH_MSG_CHANNEL_CLOSE             =  97,
  SSH_MSG_CHANNEL_REQUEST           =  98,
  SSH_MSG_CHANNEL_SUCCESS           =  99,
  SSH_MSG_CHANNEL_FAILURE           = 100,
};

/** @internal @This specifies standard ssh disconnect reasons. */
enum assh_ssh_disconnect_e
{
  SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT    =  1,
  SSH_DISCONNECT_PROTOCOL_ERROR                 =  2,
  SSH_DISCONNECT_KEY_EXCHANGE_FAILED            =  3,
  SSH_DISCONNECT_RESERVED                       =  4,
  SSH_DISCONNECT_MAC_ERROR                      =  5,
  SSH_DISCONNECT_COMPRESSION_ERROR              =  6,
  SSH_DISCONNECT_SERVICE_NOT_AVAILABLE          =  7,
  SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED =  8,
  SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE        =  9,
  SSH_DISCONNECT_CONNECTION_LOST                = 10,
  SSH_DISCONNECT_BY_APPLICATION                 = 11,
  SSH_DISCONNECT_TOO_MANY_CONNECTIONS           = 12,
  SSH_DISCONNECT_AUTH_CANCELLED_BY_USER         = 13,
  SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14,
  SSH_DISCONNECT_ILLEGAL_USER_NAME              = 15,
};

/** @internal This function allocates a new packet. The @tt alloc_size
    parameter specifies total allocated size. No range checking is
    performed on the size parameter. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_packet_alloc2(struct assh_context_s *c,
                  uint8_t msg, size_t alloc_size,
                  struct assh_packet_s **p);

/** @internal This function allocates a new packet. The @tt
    payload_size parameter specifies the amount of bytes needed
    between the message id byte and the mac bytes. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_packet_alloc(struct assh_context_s *c,
                  uint8_t msg, size_t payload_size,
                  struct assh_packet_s **result);

/** @internal This function decreases the reference counter of the
    packet and release the packet if the new counter value is
    zero. */
void assh_packet_release(struct assh_packet_s *p);

/** @internal This function increase the reference counter of the packet. */
static inline struct assh_packet_s *
assh_packet_refinc(struct assh_packet_s *p)
{
  p->ref_count++;
  return p;
}

/** @internal This function creates a copy of a packet. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_packet_dup(struct assh_packet_s *p,
                struct assh_packet_s **copy);

/** @internal This function stores a 32 bytes value in network byte
    order into a non-aligned location. */
static inline void assh_store_u32(uint8_t *s, uint32_t x)
{
  s[0] = x >> 24;
  s[1] = x >> 16;
  s[2] = x >> 8;
  s[3] = x;
}

static inline void assh_store_u32le(uint8_t *s, uint32_t x)
{
  s[3] = x >> 24;
  s[2] = x >> 16;
  s[1] = x >> 8;
  s[0] = x;
}

/** @internal This function stores a 64 bytes value in network byte
    order into a non-aligned location. */
static inline void assh_store_u64(uint8_t *s, uint64_t x)
{
  s[0] = x >> 56;
  s[1] = x >> 48;
  s[2] = x >> 40;
  s[3] = x >> 32;
  s[4] = x >> 24;
  s[5] = x >> 16;
  s[6] = x >> 8;
  s[7] = x;
}

static inline void assh_store_u64le(uint8_t *s, uint64_t x)
{
  s[7] = x >> 56;
  s[6] = x >> 48;
  s[5] = x >> 40;
  s[4] = x >> 32;
  s[3] = x >> 24;
  s[2] = x >> 16;
  s[1] = x >> 8;
  s[0] = x;
}

/** @internal This function loads a 32 bytes value in network byte
    order from a non-aligned location. */
static inline uint32_t assh_load_u32(const uint8_t *s)
{
  return s[3] + (s[2] << 8) + (s[1] << 16) + (s[0] << 24);
}

static inline uint32_t assh_load_u32le(const uint8_t *s)
{
  return s[0] + (s[1] << 8) + (s[2] << 16) + (s[3] << 24);
}

/** @internal This function loads a 64 bytes value in network byte
    order from a non-aligned location. */
static inline uint64_t assh_load_u64(const uint8_t *s)
{
  return (uint64_t)s[7]         + ((uint64_t)s[6] << 8) +
         ((uint64_t)s[5] << 16) + ((uint64_t)s[4] << 24) +
         ((uint64_t)s[3] << 32) + ((uint64_t)s[2] << 40) +
         ((uint64_t)s[1] << 48) + ((uint64_t)s[0] << 56);
}

/** @internal This function allocates an array of bytes in a packet
    and returns a pointer to the array. If there is not enough space
    left in the packet, an error is returned. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_packet_add_array(struct assh_packet_s *p, size_t len, uint8_t **result);

static inline ASSH_WARN_UNUSED_RESULT assh_error_t
assh_packet_add_u32(struct assh_packet_s *p, uint32_t value)
{
  uint8_t *be;
  assh_error_t err = assh_packet_add_array(p, 4, &be);
  if (!err)
    assh_store_u32(be, value);
  return err;
}

/** @internal This function allocates a string in a packet and returns
    a pointer to the first char of the string. If there is not enough
    space left in the packet, and error is returned. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_packet_add_string(struct assh_packet_s *p, size_t len, uint8_t **result);

/** @internal This function enlarges a string previously allocated in
    a packet and returns a pointer to the first additional char of the
    string. If there is not enough space left in the packet, an error
    is returned. The string must be the last allocated thing in the
    packet when this function is called. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_packet_enlarge_string(struct assh_packet_s *p, uint8_t *str,
                           size_t len, uint8_t **result);

/** @internal This function reduces the size of a string previously
    allocated in a packet. The string must be the last allocated thing
    in the packet when this function is called. */
void
assh_packet_shrink_string(struct assh_packet_s *p, uint8_t *str,
                          size_t new_len);

/** @internal This function allocates a string in a packet and writes
    the given big number in mpint representation as string
    content. The @ref assh_bignum_mpint_size function can be used to
    find the amount of space needed to store the number. */
assh_error_t ASSH_WARN_UNUSED_RESULT
assh_packet_add_mpint(struct assh_packet_s *p,
                      const struct assh_bignum_s *bn);

/** @internal This function returns the bytes size of the mpint
    representation of a big number of given bits size. The returned
    size may be 1 byte larger than needed depending on the actual
    value of the number. */
static inline size_t assh_packet_mpint_size(size_t bits)
{
  return 4 + 1 + (bits / 8);
}

/** @internal This function checks that an array is well inside a
    buffer. If no error is returned, the @tt next parameter is set to
    point to the first byte following the array in the buffer. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_check_array(const uint8_t *buffer, size_t buffer_len,
                 const uint8_t *array, size_t array_len, uint8_t **next);

/** @internal This function checks that a string is well inside a
    buffer. If no error is returned, the @tt next parameter is set to
    point to the first byte following the string in the buffer. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_check_string(const uint8_t *buffer, size_t buffer_len,
                  const uint8_t *str, uint8_t **next);

/** @internal This function checks that an asn1 DER value is well inside a
    buffer. If no error is returned, the @tt value parameter is set to
    point to the first byte of the value and the @tt next parameter is
    set to point to the first byte in the buffer following the
    value. Any of these two parameters may be @tt NULL. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_check_asn1(const uint8_t *buffer, size_t buffer_len, const uint8_t *str,
                uint8_t **value, uint8_t **next);

/** @internal This function checks that a string is well inside packet
    bounds. @see assh_check_string */
static inline ASSH_WARN_UNUSED_RESULT assh_error_t
assh_packet_check_string(const struct assh_packet_s *p, const uint8_t *str,
                         uint8_t **next)
{
  return assh_check_string(p->data, p->data_size, str, next);
}

/** @internal This function checks that an array is well inside packet
    bounds. @see assh_check_array */
static inline ASSH_WARN_UNUSED_RESULT assh_error_t
assh_packet_check_array(const struct assh_packet_s *p, const uint8_t *array,
                        size_t array_len, uint8_t **next)
{
  return assh_check_array(p->data, p->data_size, array, array_len, next);
}

/** @internal This function checks that a 32 bits integer is well
    inside packet bounds and converts the value from network byte
    order. @see assh_packet_check_array */
static inline ASSH_WARN_UNUSED_RESULT assh_error_t
assh_packet_check_u32(struct assh_packet_s *p, uint32_t *u32,
		      const uint8_t *data, uint8_t **next)
{
  assh_error_t err = assh_packet_check_array(p, data, 4, next);
  if (!err)
    *u32 = assh_load_u32(data);
  return err;
}

/** @internal This function compare two byte buffers. The processing
    time does not depend on the buffer contents. */
static inline ASSH_WARN_UNUSED_RESULT assh_bool_t
assh_memcmp(const uint8_t *nula, const uint8_t *nulb, size_t len)
{
  assh_bool_t r = 0;
  while (len--)
    r |= nula[len] ^ nulb[len];
  return r;  
}

/** @internal This function compares a ssh string with a size header to a @tt
    NUL terminated string. No bound checking is performed. */
static inline ASSH_WARN_UNUSED_RESULT int
assh_ssh_string_compare(const uint8_t *ssh_str, const char *nul_str)
{
  size_t l = assh_load_u32(ssh_str);
  return strncmp((const char*)ssh_str + 4, nul_str, l) || nul_str[l] != '\0';
}

/** @internal This function copies a ssh string to a nul terminated
    string. An error is returned if the size of the buffer is not
    large enough to store the string along with its nul terminating
    byte. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_ssh_string_copy(const uint8_t *ssh_str, char *nul_str, size_t max_len);

static inline ASSH_WARN_UNUSED_RESULT int
assh_buffer_strcmp(const struct assh_buffer_s *buf, const char *nul_str)
{
  uint_fast16_t i;
  for (i = 0; i < buf->len; i++)
    if (!nul_str[i] || buf->str[i] != nul_str[i])
      return 1;
  return nul_str[i];
}

#endif

