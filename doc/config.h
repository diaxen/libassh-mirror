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
  @brief Build configuration macro examples

  This sample header file shows configuration macros which are used in
  the code of @em {libassh}.

  When using the provided @tt configure script, a @tt config.h file is
  generated which takes care of properly defining these macros.

  @xsee {Build configuration}
*/

/** When defined, @this enables warning at compile time for use of
    functions which are not ABI stable. */
#define CONFIG_ASSH_ABI_WARN /**/

/** When defined, @this enables storage of temporary buffers on
    stack. This is not secur on platforms with memory swapping. */
#define CONFIG_ASSH_ALLOCA

/** @This specifies the maximum length of hostname for user authentication. */
#define CONFIG_ASSH_AUTH_HOSTNAME_LEN 128

/** @This specifies the maximum length of password for user authentication. */
#define CONFIG_ASSH_AUTH_PASSWORD_LEN 32

/** @This specifies the maximum length of username for user authentication. */
#define CONFIG_ASSH_AUTH_USERNAME_LEN 32

/** @This specifies the word width used for bignum operations. */
#define CONFIG_ASSH_BIGNUM_WORD 64

/** When defined, @this enables support for the client side of the SSH
    protocol. */
#define CONFIG_ASSH_CLIENT

/** When defined, @this enables support for the @em{host based} user
    authentication method on client side. */
#define CONFIG_ASSH_CLIENT_AUTH_HOSTBASED

/** When defined, @this enables support for the @em{keyboard
    interactive} user authentication method on client side. */
#define CONFIG_ASSH_CLIENT_AUTH_KEYBOARD

/** When defined, @this enables support for the @em{password} user
    authentication method on client side. */
#define CONFIG_ASSH_CLIENT_AUTH_PASSWORD

/** When defined, @this enables support for the @em{public key} user
    authentication method on client side. */
#define CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY

/** When defined, @this enables sending a public key lookup packet
    first instead of sending the signature directly during user
    authentication. The specification allows either behaviors. */
#define CONFIG_ASSH_CLIENT_AUTH_USE_PKOK

/** When defined, @this enables code that relies on the @tt crypt_r function. */
#define CONFIG_ASSH_CRYPT_R

/** When defined, @this enables code that relies on the @tt getpwnam_r function. */
#define CONFIG_ASSH_GETPWNAM_R

/** When defined, @this enables code that relies on the @tt getspnam_r function. */
#define CONFIG_ASSH_GETSPNAM_R

/** When defined, @this enables the MD5 message digest. */
#define CONFIG_ASSH_BUILTIN_MD5

/** When defined, @this enables the RIPE-MD-160 MAC algorithm. */
#define CONFIG_ASSH_BUILTIN_RIPEMD160

/** When defined, @this enables the SHA1 message digest. */
#define CONFIG_ASSH_BUILTIN_SHA1

/** When defined, @this enables the SHA2 message digest. */
#define CONFIG_ASSH_BUILTIN_SHA2

/** When defined, @this enables the SHA3 message digest. */
#define CONFIG_ASSH_BUILTIN_SHA3

/** @This specifies the maximum length of the remote software
    identification string.  rfc4253 section 4.2 requires 255 bytes
    which is almost never seen in practice. Using a lower value on
    embedded targets will reduce the size of the @ref assh_session_s
    structure. */
#define CONFIG_ASSH_IDENT_SIZE 255

/** When defined, @this enables support for SSH key creation. */
#define CONFIG_ASSH_KEY_CREATE

/** When defined, @this enables support for SSH key validation. */
#define CONFIG_ASSH_KEY_VALIDATE

/** When defined, @this enables support for the C library allocator
    which is not able to provides secure memory on many
    platforms. This can be useful on embedded platforms where there is
    no virtual memory implemented. */
#define CONFIG_ASSH_LIBC_REALLOC

/** @This specifies the maximum size of the ssh packet
    payload. rfc4253 section 6.1 requires at least 32768 bytes. Using
    a lower value on embedded targets will reduce the memory usage and
    limit resources exhaustion attacks. */
#define CONFIG_ASSH_MAX_PAYLOAD 32768

/** @This specifies the maximum number of registered services. */
#define CONFIG_ASSH_MAX_SERVICES 4

/** @This specifies the path to @em OpenSSH host key files for use by helpers. */
#define CONFIG_ASSH_OPENSSH_PREFIX "/etc/ssh/"

/** When defined, @this enables the packet pool allocator. */
#define CONFIG_ASSH_PACKET_POOL

/** @This specifies the maximum byte amount of spare packets in the pool. */
#define CONFIG_ASSH_PACKET_POOL_SIZE 1048576

/** When defined, @this enables code which relies on the @tt qsort_r
    function from the C library. */
#define CONFIG_ASSH_GNU_QSORTR

/** When defined, @this enables code which relies on the @tt
    malloc_usable_size function from the C library. */
#define CONFIG_ASSH_MALLOC_USABLE_SIZE

/** When defined, @this enables support for the server side of the SSH protocol. */
#define CONFIG_ASSH_SERVER

/** When defined, @this enables support for the @em{host based} user
    authentication method on server side. */
#define CONFIG_ASSH_SERVER_AUTH_HOSTBASED

/** When defined, @this enables support for the @em{keyboard
    interactive} user authentication method on server side. */
#define CONFIG_ASSH_SERVER_AUTH_KEYBOARD

/** When defined, @this enables support for the @em{none} user
   authentication method on server side. */
#define CONFIG_ASSH_SERVER_AUTH_NONE

/** When defined, @this enables support for the @em{password} user
    authentication method on server side. */
#define CONFIG_ASSH_SERVER_AUTH_PASSWORD

/** When defined, @this enables support for the @em{public key} user
    authentication method on server side. */
#define CONFIG_ASSH_SERVER_AUTH_PUBLICKEY

/** When defined, @this enables support for UNIX @tt {/dev/u?random}
    random generator. */
#define CONFIG_ASSH_USE_DEV_RANDOM

#define CONFIG_ASSH_USE_LIBC_ALLOC

/** When defined, @this enables use of @em Libgcrypt. */
#define CONFIG_ASSH_USE_GCRYPT

/** When defined, @this enables use of the @em Libgcrypt secur memory
    allocator.  This requires @ref #CONFIG_ASSH_USE_GCRYPT. */
#define CONFIG_ASSH_USE_GCRYPT_ALLOC

/** When defined, @this enables use of @em Libgcrypt cipher
    algorithms.  This requires @ref #CONFIG_ASSH_USE_GCRYPT. */
#define CONFIG_ASSH_USE_GCRYPT_CIPHERS

/** When defined, @this enables use of @em Libgcrypt hash algorithms
    implementations.  This requires @ref #CONFIG_ASSH_USE_GCRYPT. */
#define CONFIG_ASSH_USE_GCRYPT_HASH

/** When defined, @this enables use of the @em Libgcrypt random number
    generator.  This requires @ref #CONFIG_ASSH_USE_GCRYPT. */
#define CONFIG_ASSH_USE_GCRYPT_PRNG

#define CONFIG_ASSH_GCRYPT_HAS_SHA3

/** When defined, @this allows use of the @em OpenSSL library. */
#define CONFIG_ASSH_USE_OPENSSL

/** When defined, @this enables use of the @em OpenSSL secur memory
    allocator.  This requires @ref #CONFIG_ASSH_USE_OPENSSL. */
#define CONFIG_ASSH_USE_OPENSSL_ALLOC

#define CONFIG_ASSH_USE_OPENSSL_HEAP_SIZE

/** When defined, @this enables use of the @em OpenSSL cipher
    algorithms.  This requires @ref #CONFIG_ASSH_USE_OPENSSL. */
#define CONFIG_ASSH_USE_OPENSSL_CIPHERS

/** When defined, @this enables use of the @em OpenSSL hash algorithms
    implementations.  This requires @ref #CONFIG_ASSH_USE_OPENSSL. */
#define CONFIG_ASSH_USE_OPENSSL_HASH

/** When defined, @this enables use of the @em OpenSSL random number
    generator.  This requires @ref #CONFIG_ASSH_USE_OPENSSL. */
#define CONFIG_ASSH_USE_OPENSSL_PRNG

/** When defined, @this allows use of the @em zlib library. */
#define CONFIG_ASSH_USE_ZLIB

/** @This specifies the allocator storage type used for the zlib
    context. The default is to use the @ref ASSH_ALLOC_INTERNAL
    policy that does not allocate secur memory. */
#define CONFIG_ASSH_ZLIB_ALLOC ASSH_ALLOC_INTERNAL

/** When defined, @this enables relying on @em valgrind headers files
    for better memory errors reporting. */
#define CONFIG_ASSH_VALGRIND

/** When defined, @this makes the library print debug information on
    error and enables use of other debug configuration macros. This
    must @b not be enabled on production code in order to avoid leaking
    secret material. */
#define CONFIG_ASSH_DEBUG

/** When defined, @this makes the library verbose about reported events.
    This requires @ref #CONFIG_ASSH_DEBUG. */
#define CONFIG_ASSH_DEBUG_EVENT

/** When defined, @this makes the library verbose about signatures.
    This may leak key related material.
    This requires @ref #CONFIG_ASSH_DEBUG. */
#define CONFIG_ASSH_DEBUG_SIGN

/** When defined, @this makes the library dump packets.
    This requires @ref #CONFIG_ASSH_DEBUG. */
#define CONFIG_ASSH_DEBUG_PROTOCOL

/** When defined, @this makes the library verbose about the
    kex-exchange.  This may leak key related material.  This requires
    @ref #CONFIG_ASSH_DEBUG. */
#define CONFIG_ASSH_DEBUG_KEX

/** When defined, @this make the library dump a function call trace.
    This requires @ref #CONFIG_ASSH_DEBUG. */
#define CONFIG_ASSH_CALLTRACE

/** When defined, @this makes the library verbose about FSM state changes.
    This requires @ref #CONFIG_ASSH_DEBUG. */
#define CONFIG_ASSH_FSMTRACE

/** When defined, @this makes the library verbose about big number computations.
    This requires @ref #CONFIG_ASSH_DEBUG. */
#define CONFIG_ASSH_DEBUG_BIGNUM_TRACE

/** When defined, @this embed error reasons strings in the library. */
#define CONFIG_ASSH_VERBOSE_ERROR

/** When defined, @this disallows performing multiple key exchanges
    before user authentication.  This is not required by the
    specification but helps preventing a simple resource exhaustion
    attacks. */
#define CONFIG_ASSH_NO_REKEX_BEFORE_AUTH
