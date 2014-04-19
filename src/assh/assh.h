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

/* make event fields written by the library read-only for user. */
#ifndef ASSH_EV_CONST
# define ASSH_EV_CONST const
#endif

struct assh_context_s;
struct assh_session_s;
struct assh_packet_s;
struct assh_channel_s;
struct assh_request_s;
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
struct assh_event_hndl_table_s;
struct assh_event_s;

typedef char assh_bool_t;

enum assh_key_format_e;
enum assh_alloc_type_e;
enum assh_ssh_msg_e;

/** @This specify the error severity and must be used along with error
    code constants (@ref assh_error_e).

    These values indicate how the state of the session has been
    impacted by the error.

    Multiple error severity bits may be ored together; in this case
    the highest bit set prevails. This allows increasing the error
    severity returned by a callee from the caller function. */
enum assh_error_severity_e
{
  /** The error is not critical and the connection may continue. This
      is the default when no severity is specified. */
  ASSH_ERRSV_CONTINUE              = 0x0000,
  /** The error prevent further communication with the remote host but
      a disconnect packet may still be send before closing the connection. */
  ASSH_ERRSV_DISCONNECT            = 0x2000,
  /** The error prevent further communication with the remote host due
      to irrecoverable protocol error. */
  ASSH_ERRSV_FIN                   = 0x4000,
  /** The error is due to an implementation related issue. It's not
      possible to continue, cleanup functions may be called. This
      should never happen. */
  ASSH_ERRSV_FATAL                 = 0x8000,
};

/** @This specify possible return codes returned by @em libassh
    functions. All codes indicating an error must always be ored with
    a severity code (@ref assh_error_severity_e). */
enum assh_error_e
{
  /** Success error code. */
  ASSH_OK                          = 0,
  /** No data were available, this is not fatal. */
  ASSH_NO_DATA                     = 1,
  /** The requested entry was not found, this is not fatal. */
  ASSH_NOT_FOUND                   = 2,

  /** IO error. */
  ASSH_ERR_IO                      = 0x100,
  /** Memory allocation error. */
  ASSH_ERR_MEM                     = 0x101,
  /** Buffer overflow in input data. Input data contains bad or
      corrupt data which would result in memory access outside allowed bounds. */
  ASSH_ERR_INPUT_OVERFLOW          = 0x102,
  /** Output buffer is not large enough to write expected data. */
  ASSH_ERR_OUTPUT_OVERFLOW         = 0x103,
  /** Arithmetic overflow on big number. */
  ASSH_ERR_NUM_OVERFLOW            = 0x104,
  /** Bad version of the ssh protocol. */
  ASSH_ERR_BAD_VERSION             = 0x105,
  /** Packet or buffer contains unexpected or corrupt data. */
  ASSH_ERR_BAD_DATA                = 0x106,
  /** Invalid function arguments */
  ASSH_ERR_BAD_ARG                 = 0x107,
  /** Message authentication code error. */
  ASSH_ERR_MAC                     = 0x108,
  /** Packet content doesn't match current state of the protocol. */
  ASSH_ERR_PROTOCOL                = 0x10a,
  /** The function can not be called in the current state of the protocol. */
  ASSH_ERR_STATE                   = 0x10b,
  /** Crypto initialization or processing error. */
  ASSH_ERR_CRYPTO                  = 0x10c,
  /** Unsupported parameter value. */
  ASSH_ERR_NOTSUP                  = 0x10d,
  /** The key exchange has failed */
  ASSH_ERR_KEX_FAILED              = 0x10f,
  /** The required key is not available. */
  ASSH_ERR_MISSING_KEY             = 0x110,
  /** The required algorithm is not available. */
  ASSH_ERR_MISSING_ALGO            = 0x111,
  /** The host key verification has failed */
  ASSH_ERR_HOSTKEY_SIGNATURE       = 0x113,
  /** The requested service is not available */
  ASSH_ERR_SERVICE_NA              = 0x114,
  /** No more authentication method available. */
  ASSH_ERR_NO_AUTH                 = 0x115,
  /** The remote host sent a disconnect packet. */
  ASSH_ERR_DISCONNECTED            = 0x116,
  /** The client has reached the end of list of services to request. */
  ASSH_ERR_NO_MORE_SERVICE         = 0x117,
  /** The session is closed. */
  ASSH_ERR_CLOSED                  = 0x118,
};

/** @This extracts the @ref assh_error_e part of an error code
    returned by a function. */
#define ASSH_ERR_ERROR(code) ((code) & 0xfff)
/** @This extracts the @ref assh_error_severity_e part of an error
    code returned by a function. This consists of ored flag values. */
#define ASSH_ERR_SEVERITY(code) ((code) & 0xf000)

#define ASSH_ASSERT(expr) do { assh_error_t _e_ = (expr); assert((_e_ & 0xfff) == ASSH_OK); } while(0)

typedef int assh_error_t;

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
#define ASSH_MAX_BLOCK_SIZE 16    /* must be >= 16 */

/** Maximum size of cipher/mac keys or iv in bytes. */
#define ASSH_MAX_SYMKEY_SIZE 64

/** Maximum mac output size in bytes. */
#define ASSH_MAX_MAC_SIZE 32

/** Maximum size of incoming packet length, including header and mac. */
#define ASSH_MAX_PCK_LEN 35000

/** Maximum size of packet payload */
#define ASSH_MAX_PCK_PAYLOAD_SIZE \
  (ASSH_MAX_PCK_LEN - /* sizeof(struct assh_packet_head_s) */ 6 \
   - ASSH_MAX_MAC_SIZE - ASSH_MAX_BLOCK_SIZE)

#if 0
# define ASSH_ERR_GTO(expr, label) do { if ((err = (expr) & 0x100)) goto label; err &= 0xff; } while (0)
# define ASSH_ERR_RET(expr) do { if ((err = (expr) & 0x100)) return err; err &= 0xff; } while (0)
#else

# define ASSH_ERR_GTO(expr, label)					\
  do {									\
    err = (expr);							\
    if (err & 0x100)							\
      {									\
	fprintf(stderr, "%s:%u:assh ERROR %u in %s, expr:`%s'\n",	\
		__FILE__, __LINE__, err, __func__, #expr);              \
	goto label;							\
      }									\
    else {								\
      err &= 0xff;							\
      /*    fprintf(stderr, "%s:%u:assh in %s.\n",			\
	    __FILE__, __LINE__, __func__);      */			\
    }									\
  } while (0)

# define ASSH_ERR_RET(expr)						\
  do {									\
    err = (expr);							\
    if (err & 0x100)							\
      {									\
	fprintf(stderr, "%s:%u:assh ERROR %u in %s, expr:`%s'\n",	\
		__FILE__, __LINE__, err, __func__, #expr);              \
	return err;							\
      }									\
    else {								\
      err &= 0xff;							\
      /*    fprintf(stderr, "%s:%u:assh in %s.\n",			\
	    __FILE__, __LINE__, __func__);        */			\
    }									\
  } while (0)

#endif

# define ASSH_CHK_GTO(cond, err, label) ASSH_ERR_GTO(cond ? err : 0, label) 
# define ASSH_CHK_RET(cond, err) ASSH_ERR_RET(cond ? err : 0) 

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

struct assh_buffer_s
{
  union {
    char *str;
    uint8_t *data;
  };
  union {
    size_t size;
    size_t len;
  };
};

struct assh_queue_entry_s
{
  struct assh_queue_entry_s *next, *prev;
};

struct assh_queue_s
{
  struct assh_queue_entry_s head;
  int count;
};

#define ASSH_IDENT "SSH-2.0-LIBASSH\r\n"

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

