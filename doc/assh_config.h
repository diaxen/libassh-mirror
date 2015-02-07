/** SSH authentication max password length */
#define CONFIG_ASSH_AUTH_PASSWORD_LEN 32
/** SSH authentication max username length */
#define CONFIG_ASSH_AUTH_USERNAME_LEN 32
/** SSH client support */
#define CONFIG_ASSH_CLIENT
/** SSH client authentication: password support */
#define CONFIG_ASSH_CLIENT_AUTH_PASSWORD
/** SSH client authentication: public key support */
#define CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY
/** SSH client authentication: public key signature is not sent directly */
#define CONFIG_ASSH_CLIENT_AUTH_USE_PKOK
/** SSH server support */
#define CONFIG_ASSH_SERVER
/** SSH server authentication: password support */
#define CONFIG_ASSH_SERVER_AUTH_PASSWORD
/** SSH server authentication: public key support */
#define CONFIG_ASSH_SERVER_AUTH_PUBLICKEY
/** Libgcrypt support */
#define CONFIG_ASSH_USE_GCRYPT
/** use of gcrypt secur memory allocation */
#define CONFIG_ASSH_USE_GCRYPT_ALLOC
/** use of gcrypt big number functions */
#define CONFIG_ASSH_USE_GCRYPT_BIGNUM
/** use of gcrypt cipherss */
#define CONFIG_ASSH_USE_GCRYPT_CIPHERS
/** use of gcrypt hash algorithms */
#define CONFIG_ASSH_USE_GCRYPT_HASH
/** use of gcrypt random number generation */
#define CONFIG_ASSH_USE_GCRYPT_PRNG
