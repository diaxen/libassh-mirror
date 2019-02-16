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
   @short SSH packets management

   This header provides functions used to build and parse the packet
   format used the @em ssh2 protocol.

   @see{@assh/assh_buffer.h}
*/

#ifndef ASSH_PACKET_H_
#define ASSH_PACKET_H_

#include "assh.h"
#include "assh_queue.h"

#include <string.h>

/** @internal @em ssh2 protocol packet header */
struct assh_packet_head_s
{
  uint8_t   pck_len[4];
  uint8_t   pad_len;
  uint8_t   msg;
  uint8_t   end[0];
};

/** @internal Specifies the @em ssh2 packet padding size policy */
enum assh_padding_policy_e
{
  /** Minimal padding size */
  ASSH_PADDING_MIN,
  /** Use maximal padding size according to allocated buffer
      size. This allows hiding the size of actual data in the
      enciphered packet. */
  ASSH_PADDING_MAX,
};

/** @internal @em ssh2 packet object */
struct assh_packet_s
{
  union {
    /** Packet queue entry, valid when packet is allocated. */
    struct assh_queue_entry_s entry;
#ifdef CONFIG_ASSH_PACKET_POOL
    /** Spare packet pool entry, valid when packet has been released. */
    struct assh_packet_s *pool_next;
#endif
  };

  /** Associated assh context */
  struct assh_context_s *ctx;

#ifdef CONFIG_ASSH_PACKET_POOL
  /** Size of the pre-allocated packet data buffer. */
  uint32_t buffer_size;
#endif
  /** Size of the allocated packet data buffer. */
  uint32_t alloc_size;
  /** Amount of valid packet data. This value is increased when adding
      data to the packet and is used when the packet is finally sent out. */
  uint32_t data_size;

  /** For output packets, this is the output sequence number, valid
      only after sending. For input packets, this is the input
      sequence number. For input @ref SSH_MSG_UNIMPLEMENTED packets,
      this is changed to the output sequence number of the associated
      packet before dispatch to the service or kex layer. @see sent */
  uint32_t seq;

  /** This is set when the packet has been sent, indicating that the
      @ref seq field is valid. The packet is released when this
      happens, unless the @ref assh_packet_refinc function has been
      used. */
  uint8_t sent:1;

  /** This is set for outgoing @ref SSH_MSG_DISCONNECT packets before
      encryption. */
  uint8_t last:1;

  /** Number of references to this packet. */
  uint8_t ref_count:5;

  /** Padding size policy */
  enum assh_padding_policy_e padding:2;

  union {
    uint8_t                   data[0];
    struct assh_packet_head_s head;
  };
};

ASSH_FIRST_FIELD_ASSERT(assh_packet_s, entry);

/** @internal @This specifies ranges of @em ssh2 message ids. */
enum assh_ssh_msg_ranges_e
{
  /** @multiple Transport layer generic messages */
  SSH_MSG_TRGENERIC_FIRST = 1,
  SSH_MSG_TRGENERIC_LAST  = 19,
  /** @multiple Algorithm negotiation messages */
  SSH_MSG_ALGONEG_FIRST   = 20,
  SSH_MSG_ALGONEG_LAST    = 29,
  /** @multiple Specific key exchange method messages */
  SSH_MSG_KEXSPEC_FIRST   = 30,
  SSH_MSG_KEXSPEC_LAST    = 49,
  /** @multiple Service messages */
  SSH_MSG_SERVICE_FIRST   = 50,
};

/** @This specifies the standard values for @em ssh2 message ids. */
enum assh_ssh_msg_e
{
  SSH_MSG_INVALID                   =   0,

  /** @multiple Transport layer generic messages */
  SSH_MSG_DISCONNECT                =   1,
  SSH_MSG_IGNORE                    =   2,
  SSH_MSG_UNIMPLEMENTED             =   3,
  SSH_MSG_DEBUG                     =   4,
  SSH_MSG_SERVICE_REQUEST           =   5,
  SSH_MSG_SERVICE_ACCEPT            =   6,

  /** @multiple Algorithm negotiation messages */
  SSH_MSG_KEXINIT                   =  20,
  SSH_MSG_NEWKEYS                   =  21,

  /** @multiple Specific key exchange method messages */
  SSH_MSG_KEX_DH_REQUEST            =  30,
  SSH_MSG_KEX_DH_REPLY              =  31,
  SSH_MSG_KEX_ECDH_INIT             =  30,
  SSH_MSG_KEX_ECDH_REPLY            =  31,

  SSH_MSG_KEX_DH_GEX_REQUEST_OLD    =  30,
  SSH_MSG_KEX_DH_GEX_GROUP          =  31,
  SSH_MSG_KEX_DH_GEX_INIT           =  32,
  SSH_MSG_KEX_DH_GEX_REPLY          =  33,
  SSH_MSG_KEX_DH_GEX_REQUEST        =  34,

  SSH_MSG_KEXRSA_PUBKEY             =  30,
  SSH_MSG_KEXRSA_SECRET             =  31,
  SSH_MSG_KEXRSA_DONE               =  32,

  /** @multiple SSH user authentication related messages */
  SSH_MSG_USERAUTH_REQUEST          =  50,
  SSH_MSG_USERAUTH_FAILURE          =  51,
  SSH_MSG_USERAUTH_SUCCESS          =  52,
  SSH_MSG_USERAUTH_BANNER           =  53,
  SSH_MSG_USERAUTH_PK_OK            =  60,
  SSH_MSG_USERAUTH_PASSWD_CHANGEREQ =  60,
  SSH_MSG_USERAUTH_INFO_REQUEST     =  60,
  SSH_MSG_USERAUTH_INFO_RESPONSE    =  61,

  /** @multiple @em ssh2 connection service related messages */
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

/** @This specifies standard @em ssh2 disconnect reasons. */
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
  SSH_DISCONNECT_PRIVATE                        = 0xfe000000
};

/** @internal @This allocates a new packet. The @tt buffer_size
    parameter specifies total allocated size. The size is not limited. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_packet_alloc_raw(struct assh_context_s *c, size_t raw_size,
                   struct assh_packet_s **p);

/** @internal @This allocates a new packet is the specified size can't
    be stored in the current packet. The original packet is not
    released and the data are not copied. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_packet_realloc_raw(struct assh_context_s *c,
                        struct assh_packet_s **p_,
                        size_t raw_size);

/** @internal @This allocates a new packet. The @tt payload_size_m1
    parameter specifies the size of the payload minus one. This is
    amount of bytes between the message id and the padding. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_packet_alloc(struct assh_context_s *c,
                  uint8_t msg, size_t payload_size_m1,
                  struct assh_packet_s **result);

/** @This forces garbage collect of packets. This does nothing when
    @ref #CONFIG_ASSH_PACKET_POOL is not defined. */
void assh_packet_collect(struct assh_context_s *c);

#define ASSH_PACKET_HEADLEN                             \
   (/* pck_len field */ 4 + /* pad_len field */ 1)

#define ASSH_PACKET_MIN_PADDING 4

#define ASSH_PACKET_MAX_PADDING 255

/** @internal @This specifies the difference between the size of the
    packet payload and the size of the whole packet buffer. */
#define ASSH_PACKET_OVERHEAD(pad_len, mac_len)                          \
  (ASSH_PACKET_HEADLEN + pad_len + mac_len)

/** @internal @This specifies the maximum difference between the size
    of the packet payload and the size of the whole packet buffer. */
#define ASSH_PACKET_MAX_OVERHEAD                                        \
  ASSH_PACKET_OVERHEAD(255, ASSH_MAX_MAC_SIZE)

/** @internal @This specifies the maximum difference between the size
    of the packet payload and the size of the whole packet buffer when
    minimal padding policy is used. When the padding len is <= 3, we
    will add at most ASSH_MAX_BLOCK_SIZE bytes. */
#define ASSH_PACKET_MIN_OVERHEAD                                        \
  ASSH_PACKET_OVERHEAD(ASSH_MAX_BLOCK_SIZE + 3, ASSH_MAX_MAC_SIZE)

/** @internal @This decreases the reference counter of the
    packet and release the packet if the new counter value is
    zero. */
void assh_packet_release(struct assh_packet_s *p);

/** @internal @This removes all packets from the queue and calls the
    @ref assh_packet_release function for each packet. */
void assh_packet_queue_cleanup(struct assh_queue_s *q);

/** @internal @This increase the reference counter of the packet. */
ASSH_INLINE struct assh_packet_s *
assh_packet_refinc(struct assh_packet_s *p)
{
  p->ref_count++;
  return p;
}

/** @internal @This creates a copy of a packet. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_packet_dup(struct assh_packet_s *p,
                struct assh_packet_s **copy);

/** @internal @This allocates an array of bytes in a packet
    and returns a pointer to the array. If there is not enough space
    left in the packet, an error is returned. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_packet_add_array(struct assh_packet_s *p, size_t len, uint8_t **result);

/** @internal @This allocates an unsigned 32 bits integer in a packet
    and sets its value. If there is not enough space left in the
    packet, an error is returned. */
ASSH_INLINE ASSH_WARN_UNUSED_RESULT assh_error_t
assh_packet_add_u32(struct assh_packet_s *p, uint32_t value)
{
  uint8_t *be;
  assh_error_t err = assh_packet_add_array(p, 4, &be);
  if (ASSH_ERR_ERROR(err) == ASSH_OK)
    assh_store_u32(be, value);
  return err;
}

/** @internal @This allocates a string in a packet and returns
    a pointer to the first char of the string. If there is not enough
    space left in the packet, and error is returned. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_packet_add_string(struct assh_packet_s *p, size_t len, uint8_t **result);

/** @internal @This enlarges a string previously allocated in
    a packet and returns a pointer to the first additional char of the
    string. If there is not enough space left in the packet, an error
    is returned. The string must be the last allocated thing in the
    packet when this function is called. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_packet_enlarge_string(struct assh_packet_s *p, uint8_t *str,
                           size_t len, uint8_t **result);

/** @internal @This reduces the size of a string previously
    allocated in a packet. The string must be the last allocated thing
    in the packet when this function is called. */
void
assh_packet_shrink_string(struct assh_packet_s *p, uint8_t *str,
                          size_t new_len);

/** @internal @This update the size of the packet using the
    size header of the string. The string must be the last allocated
    thing in the packet when this function is called. */
void assh_packet_string_resized(struct assh_packet_s *p, uint8_t *str);

/** @internal @This allocates a string in a packet and writes
    the given big number in mpint representation as string content. A
    storage size large enough to store the number may be passed to the
    function or 0 if it is not known. */
assh_error_t ASSH_WARN_UNUSED_RESULT
assh_packet_add_mpint(struct assh_context_s *ctx,
                      struct assh_packet_s *p,
                      const struct assh_bignum_s *bn);

/** @internal @This checks that an array is well inside a
    buffer. If no error is returned, the @tt next parameter is set to
    point to the first byte following the array in the buffer. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_check_array(const uint8_t *buffer, size_t buffer_len,
                 const uint8_t *array, size_t array_len, const uint8_t **next);

/** @internal @This checks that a string is well inside a
    buffer. If no error is returned, the @tt next parameter is set to
    point to the first byte following the string in the buffer. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_check_string(const uint8_t *buffer, size_t buffer_len,
                  const uint8_t *str, const uint8_t **next);

/** @internal @This checks that an asn1 DER value is well inside a
    buffer. If no error is returned, the @tt value parameter is set to
    point to the first byte of the value and the @tt next parameter is
    set to point to the first byte in the buffer following the
    value. Any of these two parameters may be @tt NULL. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_check_asn1(const uint8_t *buffer, size_t buffer_len, const uint8_t *str,
                const uint8_t **value, const uint8_t **next, uint8_t id);

/** @internal @This append ASN1 identifier and length bytes to a
    buffer. This will write at most 6 bytes to the buffer. */
void assh_append_asn1(uint8_t **dst, uint8_t id, size_t len);

/** @internal @This computes the size an ASN1 header from the
    specified ASN1 content length. */
ASSH_INLINE size_t
assh_asn1_headlen(size_t len)
{
  return 2 + (len >= 0x80) + (len >= 0x100)
           + (len >= 0x10000) + (len >= 0x1000000);
}

/** @internal @This checks that a string is well inside packet
    bounds. @see assh_check_string */
ASSH_INLINE ASSH_WARN_UNUSED_RESULT assh_error_t
assh_packet_check_string(const struct assh_packet_s *p, const uint8_t *str,
                         const uint8_t **next)
{
  return assh_check_string(p->data, p->data_size, str, next);
}

/** @internal @This checks that an array is well inside packet
    bounds. @see assh_check_array */
ASSH_INLINE ASSH_WARN_UNUSED_RESULT assh_error_t
assh_packet_check_array(const struct assh_packet_s *p, const uint8_t *array,
                        size_t array_len, const uint8_t **next)
{
  return assh_check_array(p->data, p->data_size, array, array_len, next);
}

/** @internal @This checks that a 32 bits integer is well
    inside packet bounds and converts the value from network byte
    order. @see assh_packet_check_array */
ASSH_INLINE ASSH_WARN_UNUSED_RESULT assh_error_t
assh_packet_check_u32(const struct assh_packet_s *p, uint32_t *u32,
		      const uint8_t *data, const uint8_t **next)
{
  assh_error_t err = assh_packet_check_array(p, data, 4, next);
  if (ASSH_ERR_ERROR(err) == ASSH_OK)
    *u32 = assh_load_u32(data);
  return err;
}

/** @internal @This compares an @em ssh2 string with a size header to a @tt
    NUL terminated string. No bound checking is performed. */
ASSH_INLINE ASSH_WARN_UNUSED_RESULT assh_bool_t
assh_ssh_string_compare(const uint8_t *ssh_str, const char *nul_str)
{
  size_t l = assh_load_u32(ssh_str);
  return strncmp((const char*)ssh_str + 4, nul_str, l) || nul_str[l] != '\0';
}

/** @internal @This copies an @em ssh2 string to a nul terminated
    string. An error is returned if the size of the buffer is not
    large enough to store the string along with its nul terminating
    byte. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_ssh_string_copy(const uint8_t *ssh_str, char *nul_str, size_t max_len);

/** @internal @This behaves like the standard @tt strdup function but
    relies on the context registered memory allocator. */
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_strdup(struct assh_context_s *c, char **r,
            const char *str, enum assh_alloc_type_e type);

/** @This scans a blob as a sequence of ASN1 objects and @em ssh2
    strings and numbers. It can extract pointers, lengths and
    perform some checks on the parsed objects.

    The @tt blob and @tt blob_len values are updated when the function
    is successfull.

    The format string may contains the following characters:

    @table 2
     @item @tt s       @item @em ssh2 string or ssh mpint object.
     @item @tt aX      @item ASN1 object of given type in decimal.
     @item @tt lX      @item fixed size LSB byte array object of given byte size.
     @item @tt l       @item fixed size LSB byte array object of byte size passed in arguments.
     @item @tt mX      @item fixed size MSB byte array object of given byte size.
     @item @tt m       @item fixed size MSB byte array object of byte size passed in arguments.

     @item @tt P       @item store pointer to last object.
     @item @tt R       @item store pointer to content of the last object.
     @item @tt N       @item store pointer to the next object.
     @item @tt S       @item store size of the last object in a size_t.
     @item @tt L       @item store size of the content of the last object in a size_t.
     @item @tt B       @item store bits size of the bignum value of the last object as a size_t.

     @item @tt T       @item check that content of last object has content size passed in arguments.
     @item @tt HL      @item check that content of last object has size L in decimal.
     @item @tt Q       @item check that content of last object matches a nul terminated string passed in arguments.
     @item @tt M       @item check that content of last object matches a buffer (ptr, size) passed in arguments.
     @item @tt EO;L;X  @item check that content of last object matches string X of len L at offset O.

     @item @tt (       @item start scanning the content of the last object instead of juming over.
                           5 levels of nesting can be used.
     @item @tt )       @item end nested scanning
     @item @tt SPACE   @item ignored
    @end table
*/
ASSH_WARN_UNUSED_RESULT assh_error_t
assh_scan_blob(const char *format, const uint8_t **blob, size_t *blob_len, ...);

#endif

