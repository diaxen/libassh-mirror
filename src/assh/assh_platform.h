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

#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>

/**
   @file
   @short PLatform dependent definitions
   @internal
*/

#ifndef ASSH_PLATFORM_H_
#define ASSH_PLATFORM_H_

#ifdef __GNUC__
# define ASSH_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
# if defined(CONFIG_ASSH_ABI_WARN) && !defined(ASSH_ABI_UNSAFE)
#  define ASSH_ABI_UNSAFE __attribute__((deprecated("ABI")))
# endif
# define ASSH_UNUSED __attribute__((unused))
#endif

#ifndef ASSH_ABI_UNSAFE
# define ASSH_ABI_UNSAFE
#endif

#ifndef ASSH_WARN_UNUSED_RESULT
# define ASSH_WARN_UNUSED_RESULT
#endif

#ifndef ASSH_UNUSED
# define ASSH_UNUSED
#endif

#define ASSH_INLINE static inline

/** @This stores a 32 bits value in network byte
    order into a non-aligned location. */
ASSH_INLINE void assh_store_u32(uint8_t *s, uint32_t x)
{
#if defined(CONFIG_ASSH_NONALIGNED_ACCESS) && defined(__GNUC__)
  uint32_t *u = (uint32_t*)s;
  *u = htonl(x);
  __asm__ ("" : "=m" (*s) : "m" (*u)); /* circumvent strict aliasing */
#else
  s[0] = x >> 24;
  s[1] = x >> 16;
  s[2] = x >> 8;
  s[3] = x;
#endif
}

/** @This stores a 32 bits value in little endian byte
    order into a non-aligned location. */
ASSH_INLINE void assh_store_u32le(uint8_t *s, uint32_t x)
{
  s[3] = x >> 24;
  s[2] = x >> 16;
  s[1] = x >> 8;
  s[0] = x;
}

/** @This stores a 64 bits value in network byte
    order into a non-aligned location. */
ASSH_INLINE void assh_store_u64(uint8_t *s, uint64_t x)
{
  assh_store_u32(s, x >> 32);
  assh_store_u32(s + 4, x);
}

/** @This stores a 64 bits value in little endian byte
    order into a non-aligned location. */
ASSH_INLINE void assh_store_u64le(uint8_t *s, uint64_t x)
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

/** @This loads a 32 bits value in network byte
    order from a non-aligned location. */
ASSH_INLINE uint32_t assh_load_u32(const uint8_t *s)
{
#if defined(CONFIG_ASSH_NONALIGNED_ACCESS) && defined(__GNUC__)
  uint32_t *u = (uint32_t*)s;
  __asm__ ("" : "=m" (*u) : "m" (*s)); /* circumvent strict aliasing */
  return htonl(*u);
#else
  return s[3] | (s[2] << 8) | (s[1] << 16) | (s[0] << 24);
#endif
}

/** @This loads a 32 bits value in little endian
    byte order from a non-aligned location. */
ASSH_INLINE uint32_t assh_load_u32le(const uint8_t *s)
{
  return s[0] | (s[1] << 8) | (s[2] << 16) | (s[3] << 24);
}

/** @This loads a 64 bits value in network byte
    order from a non-aligned location. */
ASSH_INLINE uint64_t assh_load_u64(const uint8_t *s)
{
  return ((uint64_t)s[7] << 0)  | ((uint64_t)s[6] << 8)  |
         ((uint64_t)s[5] << 16) | ((uint64_t)s[4] << 24) |
         ((uint64_t)s[3] << 32) | ((uint64_t)s[2] << 40) |
         ((uint64_t)s[1] << 48) | ((uint64_t)s[0] << 56);
}

/** @This loads a 64 bits value in little endian
    byte order from a non-aligned location. */
ASSH_INLINE uint64_t assh_load_u64le(const uint8_t *s)
{
  return ((uint64_t)s[0] << 0)  | ((uint64_t)s[1] << 8)  |
         ((uint64_t)s[2] << 16) | ((uint64_t)s[3] << 24) |
         ((uint64_t)s[4] << 32) | ((uint64_t)s[5] << 40) |
         ((uint64_t)s[6] << 48) | ((uint64_t)s[7] << 56);
}

/** @This performs a byte swap of a 32 bits value. */
ASSH_INLINE uint32_t assh_swap_u32(uint32_t x)
{
  x = (x << 16) | (x >> 16);
  x = ((x & 0x00ff00ff) << 8) | ((x & 0xff00ff00) >> 8);
  return x;
}

/** @This wipes the content of a memory buffer. */
ASSH_INLINE void assh_clear(void *data, size_t len)
{
#ifdef __GNUC__
  memset(data, 0, len);
  __asm__ volatile ("" ::: "memory");
#else
  volatile uint8_t *d = data;
  while (len--)
    *d++ = 0;
#endif
}

#ifdef __GNUC__
/** @internal */
#define assh_clz8(x)  (__builtin_clz((uint8_t)(x)) + 8 - sizeof(int) * 8)
/** @internal */
#define assh_clz16(x) (__builtin_clz((uint16_t)(x)) + 16 - sizeof(int) * 8)
/** @internal */
#define assh_clz32(x) (__builtin_clzl((uint32_t)(x)) + 32 - sizeof(long) * 8)
/** @internal */
#define assh_clz64(x) (__builtin_clzll((uint64_t)(x)) + 64 - sizeof(long long) * 8)

/** @internal */
#define assh_ctz8(x) __builtin_ctz(x)
/** @internal */
#define assh_ctz16(x) __builtin_ctz(x)
/** @internal */
#define assh_ctz32(x) __builtin_ctzl(x)
/** @internal */
#define assh_ctz64(x) __builtin_ctzll(x)

/** @internal */
#define assh_popc8(x) __builtin_popcount(x)
/** @internal */
#define assh_popc16(x) __builtin_popcount(x)
/** @internal */
#define assh_popc32(x) __builtin_popcountl(x)
/** @internal */
#define assh_popc64(x) __builtin_popcountll(x)

#else

/** @internal */
#define assh_clz8(x)  assh_ct_clz8(x)
/** @internal */
#define assh_clz16(x) assh_ct_clz16(x)
/** @internal */
#define assh_clz32(x) assh_ct_clz32(x)
/** @internal */
#define assh_clz64(x) assh_ct_clz64(x)

/** @internal */
#define assh_ctz8(x)  assh_ct_ctz8(x)
/** @internal */
#define assh_ctz16(x) assh_ct_ctz16(x)
/** @internal */
#define assh_ctz32(x) assh_ct_ctz32(x)
/** @internal */
#define assh_ctz64(x) assh_ct_ctz64(x)

/** @internal */
#define assh_popc8(x)  assh_ct_popc8(x)
/** @internal */
#define assh_popc16(x) assh_ct_popc16(x)
/** @internal */
#define assh_popc32(x) assh_ct_popc32(x)
/** @internal */
#define assh_popc64(x) assh_ct_popc64(x)

#endif

#define ASSH_STRUCT_ALIGN(x) ASSH_ALIGN(16, x)

#if defined(__GNUC__) && defined(NDEBUG)
# define ASSH_UNREACHABLE(msg)  __builtin_unreachable()
#else
# define ASSH_UNREACHABLE(msg)  do { assert(!"not reachable: " msg); abort(); } while (1)
#endif

typedef time_t assh_time_t;

#endif
