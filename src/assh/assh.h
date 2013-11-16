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

#ifndef ASSH_H_
#define ASSH_H_

#include <stddef.h>
#include <stdint.h>
#include <assert.h>

#include <stdio.h>     // DEBUG

#ifdef HAVE_CONFIG_H
# include "assh_config.h"
#endif

#if !defined(CONFIG_ASSH_SERVER) && !defined(CONFIG_ASSH_CLIENT)
# error CONFIG_ASSH_SERVER and CONFIG_ASSH_CLIENT are both undefined
#endif

struct assh_context_s;
struct assh_session_s;
struct assh_packet_s;
struct assh_channel_s;
struct assh_bignum_s;
struct assh_kex_keys_s;
struct assh_algo_kex_s;
struct assh_hash_s;
struct assh_prng_s;
struct assh_algo_cipher_s;
struct assh_algo_mac_s;
struct assh_algo_sign_s;
struct assh_event_s;
struct assh_service_s;

typedef char assh_bool_t;

enum assh_key_format_e;

enum assh_error_e
{
  /** Success error code. */
  ASSH_OK = 0,
  /** No data were available, this is not fatal. */
  ASSH_NO_DATA = 1,
  /** The requested entry was not found, this is not fatal. */
  ASSH_NOT_FOUND = 2,

  /** IO error. */
  ASSH_ERR_IO = 101,
  /** Memory allocation error. */
  ASSH_ERR_MEM,
  /** Buffer overflow or arithmetic overflow. */
  ASSH_ERR_OVERFLOW,
  /** Bad packet size. */
  ASSH_ERR_PACKET_SIZE,
  /** Bad version of the ssh protocol. */
  ASSH_ERR_BAD_VERSION,
  /** Packet contains bad corrupt data. */
  ASSH_ERR_BAD_DATA,
  /** Message authentication code error. */
  ASSH_ERR_MAC,
  /** Packet content doesn't match current state of the protocol. */
  ASSH_ERR_PROTOCOL,
  /** The function can not be called in the current state of the protocol. */
  ASSH_ERR_STATE,
  /** Crypto initialization or pressing error. */
  ASSH_ERR_CRYPTO,
  /** Unsupported parameter value. */
  ASSH_ERR_NOTSUP,
  ASSH_ERR_KEX_FAILED,
  /**  */
  ASSH_ERR_MISSING_KEY,
  ASSH_ERR_MISSING_ALGO,
  ASSH_ERR_MISSMATCH_KEY,
  ASSH_ERR_HOSTKEY_SIGNATURE,
  ASSH_ERR_SERVICE_NA,
  ASSH_ERR_NO_AUTH,
  ASSH_ERR_DISCONNECTED,
};

/** @This associates an @ref assh_ssh_disconnect_e standard disconnect
    reason code to the @ref assh_error_e error code.
    @see #ASSH_ERR_ERROR @see #ASSH_ERR_DISCONNECT */
#define ASSH_ERR_CODE(err, disconnect) ((err) | ((disconnect) << 16))

/** @This extracts the @ref assh_error_e part of an error code
    returned by a function. @see #ASSH_ERR_CODE */
#define ASSH_ERR_ERROR(code) ((err) & 0xffff)
/** @This extracts the @ref assh_ssh_disconnect_e part of an error
    code returned by a function. @see #ASSH_ERR_CODE */
#define ASSH_ERR_DISCONNECT(code) ((err) >> 16)

#define ASSH_ASSERT(expr) do { assh_error_t _e_ = (expr); assert(_e_ == ASSH_OK); } while(0)

typedef int assh_error_t;

/** Maximum size of incoming packet length, including header and mac. */
#define ASSH_MAX_PCK_LEN 35000

/** Log2 of smallest packet size bucket in the packet allocator pool. */
#define ASSH_PCK_POOL_MIN 6
/** Log2 of largest packet size bucket in the packet allocator pool. */
#define ASSH_PCK_POOL_MAX 16
/** Number of buckets in the packet allocator pool */
#define ASSH_PCK_POOL_SIZE (ASSH_PCK_POOL_MAX - ASSH_PCK_POOL_MIN)

/** Size of the context registered algorithms pointer array */
#define ASSH_MAX_ALGORITHMS 40
/** Size of the context registered services pointer array */
#define ASSH_MAX_SERVICES 4

/** Maximum size of hash algorithms output in bytes. */
#define ASSH_MAX_HASH_SIZE 64

/** Maximum size of cipher algorithms keys in bytes. */
#define ASSH_MAX_EKEY_SIZE 64

/** Maximum size of mac algorithms keys in bytes. */
#define ASSH_MAX_IKEY_SIZE 64

/** Maximum cipher block size in bytes. */
#define ASSH_MAX_BLOCK_SIZE 16

/** Maximum size of cipher/mac keys or iv in bytes. */
#define ASSH_MAX_SYMKEY_SIZE 64

#if 0
# define ASSH_ERR_GTO(expr, label) do { if ((err = (expr))) goto label; } while (0)
# define ASSH_ERR_RET(expr) do { if ((err = (expr))) return err; } while (0)
#else

# define ASSH_ERR_GTO(expr, label)               \
do {                                             \
  if ((err = (expr)))                            \
    {                                            \
      fprintf(stderr, "%s:%u:assh ERROR %u in %s, expr:`%s'\n", \
              __FILE__, __LINE__, err, __func__, #expr);              \
      goto label;                                \
    }                                            \
  else {                                              \
    /*    fprintf(stderr, "%s:%u:assh in %s.\n",      \
	  __FILE__, __LINE__, __func__);      */      \
    }                                            \
} while (0)

# define ASSH_ERR_RET(expr)                     \
do {                                            \
  if ((err = (expr)))                           \
    {                                           \
      fprintf(stderr, "%s:%u:assh ERROR %u in %s, expr:`%s'\n", \
              __FILE__, __LINE__, err, __func__, #expr);              \
      return err;                               \
    }                                           \
  else {                                              \
    /*    fprintf(stderr, "%s:%u:assh in %s.\n",      \
	  __FILE__, __LINE__, __func__);        */    \
    }                                            \
} while (0)

#endif

#define ASSH_DEBUG(...) fprintf(stderr, "assh_debug: " __VA_ARGS__)

#include <stdio.h>
static inline void assh_hexdump(const char *name, const void *data, unsigned int len)
{
  int i, j;
  const uint8_t *data_ = data;
  const int width = 32;

  fprintf(stderr, "--- %s (%u bytes) ---\n", name, len);
  for (i = 0; i < len; i += width)
    {
      for (j = 0; j < width && i + j < len; j++)
        fprintf(stderr, "%02x ", data_[i + j]);
      for (; j < width; j++)
        fputs("   ", stderr);
      for (j = 0; j < width && i + j < len; j++)
        fprintf(stderr, "%c", (unsigned)data_[i + j] - 32 < 96 ? data_[i + j] : '.');
      fputc('\n', stderr);
    }
  fputc('\n', stderr);
}

struct assh_queue_entry_s
{
  struct assh_queue_entry_s *next, *prev;
};

struct assh_queue_s
{
  struct assh_queue_entry_s head;
  int count;
};

#define ASSH_HELLO "SSH-2.0-LIBASSH\r\n"

enum assh_alloc_type_e;

/** This macro specifies the prototype of a memory allocator function. */
#define ASSH_ALLOCATOR(n) assh_error_t (n)(struct assh_context_s *c, void **ptr, \
					   size_t size, enum assh_alloc_type_e type)
/** @see #ASSH_ALLOCATOR */
typedef ASSH_ALLOCATOR(assh_allocator_t);

#define ASSH_MAX(a, b) ({ typeof(a) __a = (a); typeof(b) __b = (b); __a > __b ? __a : __b; })
#define ASSH_MIN(a, b) ({ typeof(a) __a = (a); typeof(b) __b = (b); __a < __b ? __a : __b; })
#define ASSH_SWAP(a, b) do { typeof(a) __a = (a); typeof(b) __b = (b); (a) = __b; (b) = __a; } while(0)

#ifdef __GNUC__
#define ASSH_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#else
#define ASSH_WARN_UNUSED_RESULT
#endif

#endif

