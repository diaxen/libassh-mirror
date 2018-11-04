
/** Enable warning at compile time for use of functions which are not ABI
   stable. */
#define CONFIG_ASSH_ABI_WARN /**/

/** Enable storage of temporary buffers on stack. This is not secur on platforms
   with memory swapping. */
#define CONFIG_ASSH_ALLOCA

/** Specifies maximum length of hostname for user authentication. */
#define CONFIG_ASSH_AUTH_HOSTNAME_LEN 128

/** Specifies maximum length of password for user authentication. */
#define CONFIG_ASSH_AUTH_PASSWORD_LEN 32

/** Specifies maximum length of username for user authentication. */
#define CONFIG_ASSH_AUTH_USERNAME_LEN 32

/** Bignum uses 16 bits words when defined. */
#define CONFIG_ASSH_BIGNUM_WORD 64

/** Enable the AES cipher when defined. */
#define CONFIG_ASSH_CIPHER_AES

/** Enable the Arcfour cipher when defined. */
#define CONFIG_ASSH_CIPHER_ARCFOUR

/** Enable the Blowfish cipher when defined. */
#define CONFIG_ASSH_CIPHER_BLOWFISH

/** Enable the Camellia cipher when defined. */
#define CONFIG_ASSH_CIPHER_CAMELLIA

/** Enable the CAST128 cipher when defined. */
#define CONFIG_ASSH_CIPHER_CAST128

/** Enable the Chacha20-Poly1305 cipher when defined. */
#define CONFIG_ASSH_CIPHER_CHACHAPOLY

/** Enable the IDEA cipher when defined. */
#define CONFIG_ASSH_CIPHER_IDEA

/** Enable the Serpent cipher when defined. */
#define CONFIG_ASSH_CIPHER_SERPENT

/** Enable the Triple-DES cipher when defined. */
#define CONFIG_ASSH_CIPHER_TDES

/** Enable the Twofish cipher when defined. */
#define CONFIG_ASSH_CIPHER_TWOFISH

/** Enable support for the client side of the SSH protocol when defined. */
#define CONFIG_ASSH_CLIENT

/** Enable support for the @em{host based} user authentication method on server
   side when defined. */
#define CONFIG_ASSH_CLIENT_AUTH_HOSTBASED

/** Enable support for the @em{keyboard interactive} user authentication method
   on server side when defined. */
#define CONFIG_ASSH_CLIENT_AUTH_KEYBOARD

/** Enable support for the @em{password support} user authentication method on
   server side when defined. */
#define CONFIG_ASSH_CLIENT_AUTH_PASSWORD

/** Enable support for the @em{public key support} user authentication method
   on server side when defined. */
#define CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY

/** Send a public key lookup packet first before sending the signature during
   user authentication when defined. */
#define CONFIG_ASSH_CLIENT_AUTH_USE_PKOK

/** Use crypt_r when defined. */
#define CONFIG_ASSH_CRYPT_R

/** Use getpwnam_r when defined. */
#define CONFIG_ASSH_GETPWNAM_R

/** Use getspnam_r when defined. */
#define CONFIG_ASSH_GETSPNAM_R

/** Enable the MD5 message digest when defined. */
#define CONFIG_ASSH_HASH_MD5

/** Enable the RIPE-MD-160 MAC algorithm when defined. */
#define CONFIG_ASSH_HASH_RIPEMD160

/** Enable the SHA1 message digest when defined. */
#define CONFIG_ASSH_HASH_SHA1

/** Enable the SHA2 message digest when defined. */
#define CONFIG_ASSH_HASH_SHA2

/** Enable the SHA3 message digest when defined. */
#define CONFIG_ASSH_HASH_SHA3

/** Specifies the maximum length of the remote software identification string.
   rfc4253 section 4.2 requires 255 bytes which is almost never seen in
   practice. Using a lower value on embedded targets will reduce the size of
   the @ref assh_session_s structure. */
#define CONFIG_ASSH_IDENT_SIZE 255

/** Enable support for SSH key creation when defined. */
#define CONFIG_ASSH_KEY_CREATE

/** Enable support for SSH key validation when defined. */
#define CONFIG_ASSH_KEY_VALIDATE

/** Enable support for the C library allocator which is not secur on some
   platforms. */
#define CONFIG_ASSH_LIBC_REALLOC

/** Specifies the maximum size of the ssh packet payload. rfc4253 section 6.1
   requires 32768 bytes. Using a lower value on embedded targets will reduce
   the memory usage and limit resources exhaustion attacks. */
#define CONFIG_ASSH_MAX_PAYLOAD 32768

/** Specifies the maximum number of registered services. */
#define CONFIG_ASSH_MAX_SERVICES 4

/** Enable the Counter cipher mode when defined. */
#define CONFIG_ASSH_MODE_CTR

/** Enable the GCM cipher mode when defined. */
#define CONFIG_ASSH_MODE_GCM

/** Specifies the path to OpenSSH key files for use by helpers. */
#define CONFIG_ASSH_OPENSSH_PREFIX "/etc/ssh/"

/** Enable the packet pool allocator when defined. */
#define CONFIG_ASSH_PACKET_POOL

/** Specifies the maximum byte amount of spare packets in the pool. */
#define CONFIG_ASSH_PACKET_POOL_SIZE 1048576

/** Use posix_openpt when defined. */
#define CONFIG_ASSH_POSIX_OPENPT 1

/** Use qsort_r from C lbirary when defined. */
#define CONFIG_ASSH_QSORTR 1

/** Enable support for the server side of the SSH protocol when defined. */
#define CONFIG_ASSH_SERVER

/** Enable support for the @em{host based} user authentication method on server
   side when defined. */
#define CONFIG_ASSH_SERVER_AUTH_HOSTBASED

/** Enable support for the @em{keyboard interactive} user authentication method
   on server side when defined. */
#define CONFIG_ASSH_SERVER_AUTH_KEYBOARD

/** Enable support for the @em{none} user authentication method on server side
   when defined. */
#define CONFIG_ASSH_SERVER_AUTH_NONE

/** Enable support for the @em{password} user authentication method on server
   side when defined. */
#define CONFIG_ASSH_SERVER_AUTH_PASSWORD

/** Enable support for the @em{public key} user authentication method on server
   side when defined. */
#define CONFIG_ASSH_SERVER_AUTH_PUBLICKEY

/** Enable support for unix @tt {/dev/u?random} random generator when defined.
   */
#define CONFIG_ASSH_USE_DEV_RANDOM

/** Enable the Libgcrypt support when defined. */
#define CONFIG_ASSH_USE_GCRYPT

/** Enable Libgcrypt secur memory allocator when defined. */
#define CONFIG_ASSH_USE_GCRYPT_ALLOC

/** Enable Libgcrypt cipher algorithms when defined. */
#define CONFIG_ASSH_USE_GCRYPT_CIPHERS

/** Use Libgcrypt hash algorithms implementations when defined. */
#define CONFIG_ASSH_USE_GCRYPT_HASH

/** Enable Libgcrypt random number generator when defined. */
#define CONFIG_ASSH_USE_GCRYPT_PRNG

/** Enable the zlib library when defined. */
#define CONFIG_ASSH_USE_ZLIB

/** Use valgrind headers for better checking when defined. */
#define CONFIG_ASSH_VALGRIND

/** Specifies the allocator storage type used for the zlib context. */
#define CONFIG_ASSH_ZLIB_ALLOC ASSH_ALLOC_INTERNAL

/** Makes the library print debug information on error and enable use
    of other debug configuration macros. */
#define CONFIG_ASSH_DEBUG

/** Makes the library verbose about reported events.
    This requires @ref #CONFIG_ASSH_DEBUG. */
#define CONFIG_ASSH_DEBUG_EVENT

/** Makes the library verbose about signatures.
    This may leak key related material.
    This requires @ref #CONFIG_ASSH_DEBUG. */
#define CONFIG_ASSH_DEBUG_SIGN

/** Makes the library dump packets.
    This requires @ref #CONFIG_ASSH_DEBUG. */
#define CONFIG_ASSH_DEBUG_PROTOCOL

/** Makes the library verbose about the kex-exchange.
    This may leak key related material.
    This requires @ref #CONFIG_ASSH_DEBUG. */
#define CONFIG_ASSH_DEBUG_KEX

/** This make the library dump a function call trace.
    This requires @ref #CONFIG_ASSH_DEBUG. */
#define CONFIG_ASSH_CALLTRACE

/** This makes the library verbose about FSM state changes.
    This requires @ref #CONFIG_ASSH_DEBUG. */
#define CONFIG_ASSH_FSMTRACE

/** This makes the library verbose about big number computations.
    This requires @ref #CONFIG_ASSH_DEBUG. */
#define CONFIG_ASSH_DEBUG_BIGNUM_TRACE

/** The disables invocations of the @tt assert macro when defined. */
#define NDEBUG

/** This includes strings for ssh error reasons in the library. */
#define CONFIG_ASSH_VERBOSE_ERROR

/** This disallows performing multiple key exchanges before user authentication. */
#define CONFIG_ASSH_NO_REKEX_BEFORE_AUTH
