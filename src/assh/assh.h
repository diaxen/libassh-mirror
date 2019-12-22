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

/**
   @file
   @short Constants and forward declarations

   This header contains declarations of types used across the library
   as well as error related enums and macros.
*/

#ifndef ASSH_H_
#define ASSH_H_

#include "assh_platform.h"

#ifdef HAVE_CONFIG_H
# include "assh_config.h"
#endif

#include <assert.h>

#if !defined(CONFIG_ASSH_SERVER) && !defined(CONFIG_ASSH_CLIENT)
# error CONFIG_ASSH_SERVER and CONFIG_ASSH_CLIENT are both undefined
#endif

/* make event fields written by the library read-only for user. */
#ifndef ASSH_EV_CONST
/** @internal */
# define ASSH_EV_CONST const
#endif

struct assh_context_s;
struct assh_session_s;
struct assh_packet_s;
struct assh_channel_s;
struct assh_request_s;
struct assh_bignum_s;
struct assh_key_s;
struct assh_kex_keys_s;
struct assh_algo_s;
struct assh_algo_name_s;
struct assh_algo_kex_s;
struct assh_hash_algo_s;
struct assh_hash_ctx_s;
struct assh_prng_s;
struct assh_algo_cipher_s;
struct assh_algo_mac_s;
struct assh_algo_sign_s;
struct assh_key_algo_s;
struct assh_event_s;
struct assh_service_s;
struct assh_event_s;
struct assh_queue_entry_s;
struct assh_queue_s;
struct assh_buffer_s;
struct assh_cbuffer_s;

struct assh_event_channel_close_s;
struct assh_event_channel_data_s;
struct assh_event_channel_eof_s;
struct assh_event_channel_confirmation_s;
struct assh_event_channel_failure_s;
struct assh_event_channel_open_s;
struct assh_event_channel_window_s;
struct assh_event_connection_start_s;
struct assh_event_kex_done_s;
struct assh_event_kex_hostkey_lookup_s;
struct assh_event_request_success_s;
struct assh_event_request_failure_s;
struct assh_event_request_s;
struct assh_event_transport_read_s;
struct assh_event_transport_write_s;
struct assh_event_transport_disconnect_s;
struct assh_event_transport_debug_s;
struct assh_event_userauth_client_banner_s;
struct assh_event_userauth_client_keyboard_s;
struct assh_event_userauth_client_methods_s;
struct assh_event_userauth_client_pwchange_s;
struct assh_event_userauth_client_sign_s;
struct assh_event_userauth_client_user_s;
struct assh_event_userauth_server_hostbased_s;
struct assh_event_userauth_server_kbinfo_s;
struct assh_event_userauth_server_kbresponse_s;
struct assh_event_userauth_server_methods_s;
struct assh_event_userauth_server_password_s;
struct assh_event_userauth_server_success_s;
struct assh_event_userauth_server_userkey_s;

enum assh_alloc_type_e;
enum assh_key_format_e;
enum assh_alloc_type_e;
enum assh_ssh_msg_e;
enum assh_algo_class_e;
enum assh_userauth_methods_e;

/** A simple boolean type used in @em {assh}. */
typedef uint8_t assh_bool_t;

/** The error code integer type returned by @em assh functions. It is
    composed of two parts specified by the @ref assh_status_e and @ref
    assh_severity_e enums.
    @see #ASSH_STATUS
    @see #ASSH_SEVERITY
*/
typedef int_fast16_t assh_status_t;

/** This is used to estimate algorithms and keys safety. The safety
    factor ranges are defined as this:

   @list
     @item 0-19: broken
     @item 20-25: weak
     @item 26-49: medium
     @item 50-99: strong
   @end list

   @see assh_safety_name
*/
typedef uint8_t assh_safety_t;

/** @This returns the name associated to an
    @hl algorithm safety factor value. */
ASSH_INLINE const char *
assh_safety_name(assh_safety_t safety)
{
  if (safety >= 50)
    return "strong";
  if (safety >= 26)
    return "medium";
  if (safety >= 20)
    return "weak";
  return "broken";
}

/** @This specifies the error severity and must be ored with
    an @ref assh_status_e value.

    These values indicate how the state of the session is
    impacted by the associated error.

    Multiple error severity bits may be ored together; in this case
    the highest bit set prevails. This allows increasing the error
    severity returned by a callee from the caller function. */
enum assh_severity_e
{
  /** The error is not critical and the connection may continue. This
      is the default when no severity is specified. */
  ASSH_ERRSV_CONTINUE              = 0x0000,
  /** The error prevent further communication with the remote host but
      a disconnect packet may still be send before closing the connection. */
  ASSH_ERRSV_DISCONNECT            = 0x2000,
};

/** @This specifies the possible errors returned by the @em libassh
    functions and passed to the @ref assh_event_done function. */
enum assh_status_e
{
  /** Success. */
  ASSH_OK                          = 0,
  /** No data were available, This is not an error. */
  ASSH_NO_DATA                     = 1,
  /** The requested entry was not found, This is not an error. */
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
  /** Compare failed on big number. */
  ASSH_ERR_NUM_COMPARE_FAILED      = 0x105,
  /** Bad version of the ssh protocol. */
  ASSH_ERR_BAD_VERSION             = 0x106,
  /** Packet or buffer contains unexpected or corrupt data. */
  ASSH_ERR_BAD_DATA                = 0x107,
  /** Invalid function arguments */
  ASSH_ERR_BAD_ARG                 = 0x108,
  /** Message authentication code error. */
  ASSH_ERR_MAC                     = 0x109,
  /** Packet content doesn't match current state of the protocol. */
  ASSH_ERR_PROTOCOL                = 0x10a,
  /** Requested operation can not be performed at this time. */
  ASSH_ERR_BUSY                    = 0x10b,
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
  /** The key failed to decipher */
  ASSH_ERR_WRONG_KEY               = 0x112,
  /** The host key verification has failed */
  ASSH_ERR_HOSTKEY_SIGNATURE       = 0x113,
  /** The requested service is not available */
  ASSH_ERR_SERVICE_NA              = 0x114,
  /** No more authentication method available. */
  ASSH_ERR_NO_AUTH                 = 0x115,
  /** The client has reached the end of list of services to request. */
  ASSH_ERR_NO_MORE_SERVICE         = 0x116,
  /** Algorithm or key security level is below defined threshold. */
  ASSH_ERR_WEAK_ALGORITHM          = 0x117,
  /** Protocol timeout. */
  ASSH_ERR_TIMEOUT                 = 0x118,
  /** @internal */
  ASSH_ERR_count,
};

/** @This returns an error string description of the passed error
    code. */
const char * assh_error_str(assh_status_t err);

/** @This extracts the @ref assh_status_e part of an status code
    returned by a function.
    @see assh_status_t @see assh_status_e @see #ASSH_ERR_SUCESS */
#define ASSH_STATUS(code) ((enum assh_status_e)((code) & 0xfff))

/** @This evaluate to true when the status code is not an error.
    @see #ASSH_STATUS */
#define ASSH_SUCCESS(code) (ASSH_STATUS(code) < 0x100)

/** @This extracts the @ref assh_severity_e part of an status
    code returned by a function.
    @see assh_status_t @see assh_severity_e */
#define ASSH_SEVERITY(code) ((enum assh_severity_e)((code) & 0xf000))

/** @internal Log2 of smallest packet size bucket in the packet
    allocator pool. */
#define ASSH_PCK_POOL_MIN 6
/** @internal Log2 of largest packet size bucket in the packet
    allocator pool. */
#define ASSH_PCK_POOL_MAX 16
/** @internal Number of buckets in the packet allocator pool */
#define ASSH_PCK_POOL_SIZE (ASSH_PCK_POOL_MAX - ASSH_PCK_POOL_MIN)

/** @internal Maximum size of hash algorithms output in bytes. */
#define ASSH_MAX_HASH_SIZE 64

/** @internal Maximum size of cipher algorithms keys in bytes. */
#define ASSH_MAX_EKEY_SIZE 64

/** @internal Maximum size of mac algorithms keys in bytes. */
#define ASSH_MAX_IKEY_SIZE 64

/** @internal Minimal cipher block size in bytes. Spec says 8 */
#define ASSH_MIN_BLOCK_SIZE 8

/** @internal Maximum cipher block size in bytes. must be >= 16. */
#define ASSH_MAX_BLOCK_SIZE 16

/** @internal Maximum size of cipher/mac keys or iv in bytes. */
#define ASSH_MAX_SYMKEY_SIZE 64

/** @internal Maximum mac output size in bytes. */
#define ASSH_MAX_MAC_SIZE 64

/** @internal Default key re-echange threshold in bytes */
#define ASSH_REKEX_THRESHOLD (1 << 31)

/** @internal */
void assh_hexdump(const char *name, const void *data, size_t len);

/** @internal @This takes an @ref assh_status_t value returned by a
    function and asserts that the error code is @ref ASSH_OK. */
#define ASSH_ASSERT(expr)                      \
  do {                                         \
    assh_status_t _e_ = (expr);                 \
    (void)_e_;                                 \
    assert((_e_ & 0xfff) == ASSH_OK);          \
  } while(0)

#ifndef CONFIG_ASSH_DEBUG

/** @internal @multiple */
# define ASSH_DEBUG(...)
# define ASSH_DEBUG_(...)
# define ASSH_DEBUG_HEXDUMP(...)

/** @internal @This takes an @ref assh_status_t value returned by a
    function of the library and assigns it to the locally defined @tt
    err variable.

    It jumps to the provided label for any error codes >= 256.  If the
    code is not an error, the execution continues to the next line..

    It can be made verbose by defining the @ref #CONFIG_ASSH_DEBUG and
    @ref CONFIG_ASSH_CALLTRACE macros.

    @see assh_status_e @see assh_status_t
    @see #ASSH_RET_ON_ERR @see ASSH_RETURN */
# define ASSH_JMP_ON_ERR(expr, label)           \
  do {                                          \
    if ((err = (expr)) & 0x100)                 \
      goto label;                               \
  } while (0)

/** @internal @This takes an @ref assh_status_t value returned by a
    function and assigns it to the locally defined @tt err variable.

    It forwards the error to the calling function for any error codes
    >= 256. If the code is not an error, the execution continues to
    the next line.

    It can be made verbose by defining the @ref #CONFIG_ASSH_DEBUG and
    @ref CONFIG_ASSH_CALLTRACE macros.

    @see assh_status_e @see assh_status_t
    @see #ASSH_JMP_ON_ERR @see ASSH_RETURN */
# define ASSH_RET_ON_ERR(expr)                  \
  do {                                          \
    if ((err = (expr)) & 0x100)                 \
      return err;                               \
  } while (0)

/** @internal @This takes an @ref assh_status_t value returned by a
    function and forwards it to the calling function in any case.

    The execution never continues to the next line.

    It can be made verbose by defining the @ref #CONFIG_ASSH_DEBUG and
    @ref CONFIG_ASSH_CALLTRACE macros. In the other case, it only
    performs a function return.

    @see assh_status_t
    @see #ASSH_JMP_ON_ERR @see #ASSH_RET_ON_ERR */
# define ASSH_RETURN(expr)                      \
  do {                                          \
    (void)err;                                  \
    return (expr);                              \
  } while (0)

#else

#include <stdio.h>

/** @internal @multiple */
# define ASSH_DEBUG(...) fprintf(stderr, "assh_debug: " __VA_ARGS__)
# define ASSH_DEBUG_(...) fprintf(stderr, __VA_ARGS__)
# define ASSH_DEBUG_HEXDUMP(...) assh_hexdump(__VA_ARGS__)

# ifndef CONFIG_ASSH_CALLTRACE

/** @hidden */
# define ASSH_JMP_ON_ERR(expr, label)					\
  do {									\
    err = (expr);							\
    if (err & 0x100)							\
      {									\
	fprintf(stderr, "%s:%u:assh ERROR %"PRIiFAST16" in %s, expr:`%s'\n",	\
		__FILE__, __LINE__, err, __func__, #expr);              \
	goto label;							\
      }									\
  } while (0)

/** @hidden */
# define ASSH_RET_ON_ERR(expr)						\
  do {									\
    err = (expr);							\
    if (err & 0x100)							\
      {									\
	fprintf(stderr, "%s:%u:assh ERROR %"PRIiFAST16" in %s, expr:`%s'\n",	\
		__FILE__, __LINE__, err, __func__, #expr);              \
	return err;							\
      }									\
  } while (0)

/** @hidden */
# define ASSH_RETURN(expr)						\
  do {									\
    err = (expr);							\
    if (err & 0x100)							\
      {									\
	fprintf(stderr, "%s:%u:assh ERROR %"PRIiFAST16" in %s, expr:`%s'\n",	\
		__FILE__, __LINE__, err, __func__, #expr);              \
      }									\
    return err;                                                         \
  } while (0)

# else

/** @hidden */
# define ASSH_JMP_ON_ERR(expr, label)					\
  do {									\
    fprintf(stderr, "%s:%u:assh >>> in %s, expr:`%s'\n",                \
            __FILE__, __LINE__, __func__, #expr);                       \
    err = (expr);							\
    if (err & 0x100) {							\
      fprintf(stderr, "%s:%u:assh <<< ERROR %"PRIiFAST16" in %s, expr:`%s'\n",     \
              __FILE__, __LINE__, err, __func__, #expr);                \
      goto label;							\
    } else {								\
      fprintf(stderr, "%s:%u:assh <<< OK in %s, expr:`%s'\n",           \
              __FILE__, __LINE__, __func__, #expr);                     \
    }									\
  } while (0)

/** @hidden */
# define ASSH_RET_ON_ERR(expr)						\
  do {									\
    fprintf(stderr, "%s:%u:assh >>> in %s, expr:`%s'\n",                \
            __FILE__, __LINE__, __func__, #expr);                       \
    err = (expr);							\
    if (err & 0x100) {							\
      fprintf(stderr, "%s:%u:assh <<< ERROR %"PRIiFAST16" in %s, expr:`%s'\n",     \
              __FILE__, __LINE__, err, __func__, #expr);                \
      return err;							\
    } else {								\
      fprintf(stderr, "%s:%u:assh <<< OK in %s, expr:`%s'\n",           \
              __FILE__, __LINE__, __func__, #expr);                     \
    }									\
  } while (0)

/** @hidden */
# define ASSH_RETURN(expr)						\
  do {									\
    fprintf(stderr, "%s:%u:assh >>> in %s, expr:`%s'\n",                \
            __FILE__, __LINE__, __func__, #expr);                       \
    err = (expr);							\
    if (err & 0x100) {							\
      fprintf(stderr, "%s:%u:assh <<< ERROR %"PRIiFAST16" in %s, expr:`%s'\n",     \
              __FILE__, __LINE__, err, __func__, #expr);                \
    } else {								\
      fprintf(stderr, "%s:%u:assh <<< OK in %s, expr:`%s'\n",           \
              __FILE__, __LINE__, __func__, #expr);                     \
    }									\
    return err;                                                         \
  } while (0)


# endif

#endif

# ifdef CONFIG_ASSH_FSMTRACE
/** @internal @This is used to change the state variable of finite
    state machines. It can be made verbose by defining the @ref
    #CONFIG_ASSH_FSMTRACE macro. */
# define ASSH_SET_STATE(obj, field, value)       \
  do {                                           \
    fprintf(stderr, "%s:%u:%s: " #field " update %u -> %u:" #value" \n", \
            __FILE__, __LINE__, __func__, (obj)->field, value);         \
    (obj)->field = value;                        \
  } while (0)
#else
/** @hidden */
# define ASSH_SET_STATE(obj, field, value)       \
  do {                                           \
    (obj)->field = value;                        \
  } while (0)
#endif

/** @internal @This reports on error to the @ref #ASSH_JMP_ON_ERR
    macro if the given expression is @em{true}. */
# define ASSH_JMP_IF_TRUE(cond, err, label)     \
  ASSH_JMP_ON_ERR(cond ? err : 0, label)

/** @internal @This reports on error to the @ref #ASSH_RET_ON_ERR
    macro if the given expression is @em{true}. */
# define ASSH_RET_IF_TRUE(cond, err)            \
  ASSH_RET_ON_ERR(cond ? err : 0)

/** @internal The SSH implementation identification string. Because
    this is involved in the shared secret generation process, Changing
    this breaks the testsuite. */
#define ASSH_IDENT "SSH-2.0-LIBASSH\r\n"

/** @internal This macro specifies the prototype of a memory allocator function.
    @see assh_allocator_t */
#define ASSH_ALLOCATOR(n) assh_status_t (n)(void *alloc_pv, void **ptr, \
					   size_t size, enum assh_alloc_type_e type)

/** This is the memory allocator function type. A pointer to function
    of this type may be passed to the @ref assh_context_create
    function. The same behavior as the standard @tt realloc function is
    expected. @xsee{coremod} */
typedef ASSH_ALLOCATOR(assh_allocator_t);

/** @internal @hidecontent This checks expression at compile time. */
#define ASSH_STATIC_ASSERT(expr, msgid)               \
  typedef int msgid [-(int)!(expr)] ASSH_UNUSED;

/** @internal @hidecontent This checks at compile time that a field is
    at offset 0 in a structure. */
#define ASSH_FIRST_FIELD_ASSERT(struct_name, field)                   \
  /** @hidden */                                                      \
  ASSH_STATIC_ASSERT(offsetof(struct struct_name, field) == 0,        \
                     field##_must_be_the_first_field_in_struct_##struct_name)

/** @internal */
ASSH_INLINE const char ** assh_charptr_cast(char **p)
{
  return (const char **)p;
}

/** @internal */
ASSH_INLINE const uint8_t ** assh_uint8ptr_cast(uint8_t **p)
{
  return (const uint8_t **)p;
}

/** @internal @This generates contant time ctz and clz functions */
#define ASSH_CT_CTLZ_GEN(n, l)                                        \
/** @internal @This computes the number of trailing zero bits of a    \
     n bits value in constant time */                                 \
ASSH_INLINE uint_fast8_t assh_ct_ctz##n(uint##n##_t x)                \
{                                                                     \
  x &= -x;                                                            \
  uint##n##_t c = (x & (uint##n##_t)0x5555555555555555ULL) - 1;       \
  c = (c >> 1) ^ ((x & (uint##n##_t)0x3333333333333333ULL) - 1);      \
  c = (c >> 1) ^ ((x & (uint##n##_t)0x0f0f0f0f0f0f0f0fULL) - 1);      \
  if (n > 8)                                                          \
    c = (c >> 1) ^ ((x & (uint##n##_t)0x00ff00ff00ff00ffULL) - 1);    \
  if (n > 16)                                                         \
    c = (c >> 1) ^ ((x & (uint##n##_t)0x0000ffff0000ffffULL) - 1);    \
  if (n > 32)                                                         \
    c = (c >> 1) ^ ((x & (uint##n##_t)0x00000000ffffffffULL) - 1);    \
  return (c >> (n - l)) ^ (c >> (n - l + 1));                         \
}                                                                     \
                                                                      \
/** @internal @This computes the number of leading zero bits of a     \
    n bits value in constant time */                                  \
ASSH_INLINE uint_fast8_t assh_ct_clz##n(uint##n##_t x)                \
{                                                                     \
  uint##n##_t a0, a1, a2, a3, a4, j = 0;                              \
  a0 = x  | (( x & (uint##n##_t)0xaaaaaaaaaaaaaaaaULL) >> 1);         \
  a1 = a0 | ((a0 & (uint##n##_t)0xccccccccccccccccULL) >> 2);         \
  a2 = a1 | ((a1 & (uint##n##_t)0xf0f0f0f0f0f0f0f0ULL) >> 4);         \
  a3 = a2 | ((a2 & (uint##n##_t)0xff00ff00ff00ff00ULL) >> 8);         \
  a4 = a3 | ((a3 & (uint##n##_t)0xffff0000ffff0000ULL) >> 16);        \
  if (n > 32)                                                         \
    j |= (a4 >> (j + 32-5)) & 32;                                     \
  if (n > 16)                                                         \
    j |= (a3 >> (j + 16-4)) & 16;                                     \
  if (n > 8)                                                          \
    j |= (a2 >> (j + 8-3))  & 8;                                      \
  j |= (a1 >> (j + 4-2))  & 4;                                        \
  j |= (a0 >> (j + 2-1))  & 2;                                        \
  j |= (x  >> (j + 1-0))  & 1;                                        \
  return j ^ (n - 1);                                                 \
}                                                                     \
                                                                      \
/** @internal @This computes the number of one bits of a              \
    n bits value in constant time */                                  \
ASSH_INLINE uint_fast8_t assh_ct_popc##n(uint##n##_t x)               \
{                                                                     \
  x = (x & (uint##n##_t)0x5555555555555555ULL) +                      \
    ((x >> 1) & (uint##n##_t)0x5555555555555555ULL);                  \
  x = (x & (uint##n##_t)0x3333333333333333ULL) +                      \
    ((x >> 2) & (uint##n##_t)0x3333333333333333ULL);                  \
  x = (x & (uint##n##_t)0x0f0f0f0f0f0f0f0fULL) +                      \
    ((x >> 4) & (uint##n##_t)0x0f0f0f0f0f0f0f0fULL);                  \
  if (n > 8)                                                          \
    x = (x & (uint##n##_t)0x00ff00ff00ff00ffULL) +                    \
      ((x >> 8) & (uint##n##_t)0x00ff00ff00ff00ffULL);                \
  if (n > 16)                                                         \
    x = (x & (uint##n##_t)0x0000ffff0000ffffULL) +                    \
      ((x >> 16) & (uint##n##_t)0x0000ffff0000ffffULL);               \
  if (n > 32)                                                         \
    x = (x & 0x00000000ffffffffULL) +                                 \
      (((uint64_t)x >> 32) & 0x00000000ffffffffULL);                  \
  return x;                                                           \
}

ASSH_CT_CTLZ_GEN(8, 3);
ASSH_CT_CTLZ_GEN(16, 4);
ASSH_CT_CTLZ_GEN(32, 5);
ASSH_CT_CTLZ_GEN(64, 6);

#endif

