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

#include <assh/mod_builtin.h>
#include <assh/mod_openssl.h>
#include <assh/mod_gcrypt.h>
#include <assh/mod_sodium.h>
#include <assh/mod_zlib.h>

#ifdef CONFIG_ASSH_USE_GCRYPT
# include <assh/mod_gcrypt.h>
# include <gcrypt.h>
#endif

#ifdef CONFIG_ASSH_USE_OPENSSL_ALLOC
# include <assh/mod_openssl.h>
# include <openssl/crypto.h>
#endif

assh_status_t
assh_deps_init(void)
{
  assh_status_t err;

#ifdef CONFIG_ASSH_USE_GCRYPT
  ASSH_RET_IF_TRUE(!gcry_check_version(GCRYPT_VERSION),
               ASSH_ERR_CRYPTO);

  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
#endif

#ifdef CONFIG_ASSH_USE_OPENSSL_ALLOC
  if (!CRYPTO_secure_malloc_initialized())
    ASSH_RET_IF_TRUE(CRYPTO_secure_malloc_init(
                       CONFIG_ASSH_USE_OPENSSL_HEAP_SIZE, 64) != 1,
                     ASSH_ERR_CRYPTO);
#endif

  return ASSH_OK;
}


#include <assh/assh_alloc.h>

assh_allocator_t *
assh_default_alloc(void)
{
#if defined(CONFIG_ASSH_USE_GCRYPT_ALLOC)
  if (gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P))
    return &assh_gcrypt_allocator;

#elif defined(CONFIG_ASSH_USE_OPENSSL_ALLOC)
  return &assh_openssl_allocator;

#elif defined(CONFIG_ASSH_USE_LIBC_ALLOC)
# warning The default allocator relies on the standard non-secure realloc function
  return &assh_libc_allocator;
#endif

  return NULL;
}


#include <assh/assh_prng.h>

const struct assh_prng_s *
assh_default_prng(void)
{
#if defined(CONFIG_ASSH_USE_DEV_RANDOM)
  return &assh_prng_dev_random;

#elif defined(CONFIG_ASSH_USE_GCRYPT_PRNG)
  return &assh_prng_gcrypt;

#elif defined(CONFIG_ASSH_USE_OPENSSL_PRNG)
  return &assh_prng_openssl;

#elif defined(CONFIG_ASSH_USE_SODIUM_PRNG)
  return &assh_prng_sodium;

#elif defined(CONFIG_ASSH_USE_BUILTIN_PRNG)
  return &assh_prng_xswap;

#endif
  return NULL;
}


#include <assh/assh_algo.h>
#include <assh/assh_kex.h>
#include <assh/assh_cipher.h>
#include <assh/assh_mac.h>
#include <assh/assh_sign.h>
#include <assh/assh_compress.h>

#ifdef __GNUC__
__attribute__((weak))
#endif
const struct assh_algo_s *assh_algo_table[] = {

  /* kex */
  // &assh_kex_none.algo_wk.algo,

#ifdef CONFIG_ASSH_USE_BUILTIN_KEX
  &assh_kex_builtin_curve25519_sha256.algo_wk.algo,
  &assh_kex_builtin_m383_sha384.algo_wk.algo,
  &assh_kex_builtin_m511_sha512.algo_wk.algo,
  &assh_kex_builtin_dh_group1_sha1.algo_wk.algo,
  &assh_kex_builtin_dh_group14_sha1.algo_wk.algo,
  &assh_kex_builtin_dh_group14_sha256.algo_wk.algo,
  &assh_kex_builtin_dh_group15_sha512.algo_wk.algo,
  &assh_kex_builtin_dh_group16_sha512.algo_wk.algo,
  &assh_kex_builtin_dh_group17_sha512.algo_wk.algo,
  &assh_kex_builtin_dh_group18_sha512.algo_wk.algo,
  &assh_kex_builtin_dh_gex_sha1.algo_wk.algo,
  &assh_kex_builtin_dh_gex_sha256_12.algo_wk.algo,
  &assh_kex_builtin_dh_gex_sha256_8.algo_wk.algo,
  &assh_kex_builtin_dh_gex_sha256_4.algo_wk.algo,
  &assh_kex_builtin_rsa1024_sha1.algo_wk.algo,
  &assh_kex_builtin_rsa2048_sha256.algo_wk.algo,
  &assh_kex_builtin_sha2_nistp256.algo_wk.algo,
  &assh_kex_builtin_sha2_nistp384.algo_wk.algo,
  &assh_kex_builtin_sha2_nistp521.algo_wk.algo,
#endif

#ifdef CONFIG_ASSH_USE_SODIUM_KEX
  &assh_kex_sodium_curve25519_sha256.algo_wk.algo,
#endif

#ifdef CONFIG_ASSH_USE_SODIUM_SIGN
  &assh_sign_sodium_ed25519.algo_wk.algo,
#endif

  /* sign */
  // &assh_sign_none.algo_wk.algo,

#ifdef CONFIG_ASSH_USE_BUILTIN_SIGN
  &assh_sign_builtin_dsa768.algo_wk.algo,
  &assh_sign_builtin_dsa1024.algo_wk.algo,
  &assh_sign_builtin_dsa2048_sha224.algo_wk.algo,
  &assh_sign_builtin_dsa2048_sha256.algo_wk.algo,
  &assh_sign_builtin_dsa3072_sha256.algo_wk.algo,
  &assh_sign_builtin_rsa_sha1_md5.algo_wk.algo,
  &assh_sign_builtin_rsa_sha1.algo_wk.algo,
  &assh_sign_builtin_rsa_sha1_2048.algo_wk.algo,
  &assh_sign_builtin_rsa_sha256.algo_wk.algo,
  &assh_sign_builtin_rsa_sha512.algo_wk.algo,
  &assh_sign_builtin_ed25519.algo_wk.algo,
  &assh_sign_builtin_eddsa_e382.algo_wk.algo,
  &assh_sign_builtin_eddsa_e521.algo_wk.algo,
  &assh_sign_builtin_nistp256.algo_wk.algo,
  &assh_sign_builtin_nistp384.algo_wk.algo,
  &assh_sign_builtin_nistp521.algo_wk.algo,
#endif

  /* ciphers */
  // &assh_cipher_none.algo,

#ifdef CONFIG_ASSH_USE_BUILTIN_CIPHERS
  &assh_cipher_builtin_aes128_cbc.algo,
  &assh_cipher_builtin_aes192_cbc.algo,
  &assh_cipher_builtin_aes256_cbc.algo,
  &assh_cipher_builtin_aes128_ctr.algo,
  &assh_cipher_builtin_aes192_ctr.algo,
  &assh_cipher_builtin_aes256_ctr.algo,
  &assh_cipher_builtin_arc4.algo,
  &assh_cipher_builtin_arc4_128.algo,
  &assh_cipher_builtin_arc4_256.algo,
  &assh_cipher_builtin_chachapoly.algo,
#endif

#ifdef CONFIG_ASSH_USE_GCRYPT_CIPHERS
  &assh_cipher_gcrypt_aes128_cbc.algo,
  &assh_cipher_gcrypt_aes192_cbc.algo,
  &assh_cipher_gcrypt_aes256_cbc.algo,
  &assh_cipher_gcrypt_aes128_ctr.algo,
  &assh_cipher_gcrypt_aes192_ctr.algo,
  &assh_cipher_gcrypt_aes256_ctr.algo,
  &assh_cipher_gcrypt_aes128_gcm.algo,
  &assh_cipher_gcrypt_aes256_gcm.algo,
  &assh_cipher_gcrypt_arc4.algo,
  &assh_cipher_gcrypt_arc4_128.algo,
  &assh_cipher_gcrypt_arc4_256.algo,
  &assh_cipher_gcrypt_blowfish_cbc.algo,
  &assh_cipher_gcrypt_blowfish_ctr.algo,
  &assh_cipher_gcrypt_camellia128_cbc.algo,
  &assh_cipher_gcrypt_camellia192_cbc.algo,
  &assh_cipher_gcrypt_camellia256_cbc.algo,
  &assh_cipher_gcrypt_camellia128_ctr.algo,
  &assh_cipher_gcrypt_camellia192_ctr.algo,
  &assh_cipher_gcrypt_camellia256_ctr.algo,
  &assh_cipher_gcrypt_cast128_cbc.algo,
  &assh_cipher_gcrypt_cast128_ctr.algo,
  &assh_cipher_gcrypt_idea_cbc.algo,
  &assh_cipher_gcrypt_idea_ctr.algo,
  &assh_cipher_gcrypt_serpent128_cbc.algo,
  &assh_cipher_gcrypt_serpent192_cbc.algo,
  &assh_cipher_gcrypt_serpent256_cbc.algo,
  &assh_cipher_gcrypt_serpent128_ctr.algo,
  &assh_cipher_gcrypt_serpent192_ctr.algo,
  &assh_cipher_gcrypt_serpent256_ctr.algo,
  &assh_cipher_gcrypt_serpent128_gcm.algo,
  &assh_cipher_gcrypt_serpent256_gcm.algo,
  &assh_cipher_gcrypt_tdes_cbc.algo,
  &assh_cipher_gcrypt_tdes_ctr.algo,
  &assh_cipher_gcrypt_twofish128_cbc.algo,
  &assh_cipher_gcrypt_twofish256_cbc.algo,
  &assh_cipher_gcrypt_twofish128_ctr.algo,
  &assh_cipher_gcrypt_twofish256_ctr.algo,
  &assh_cipher_gcrypt_twofish128_gcm.algo,
  &assh_cipher_gcrypt_twofish256_gcm.algo,
#endif

#ifdef CONFIG_ASSH_USE_OPENSSL_CIPHERS
  &assh_cipher_openssl_aes128_cbc.algo,
  &assh_cipher_openssl_aes192_cbc.algo,
  &assh_cipher_openssl_aes256_cbc.algo,
  &assh_cipher_openssl_aes128_ctr.algo,
  &assh_cipher_openssl_aes192_ctr.algo,
  &assh_cipher_openssl_aes256_ctr.algo,
  &assh_cipher_openssl_aes128_gcm.algo,
  &assh_cipher_openssl_aes256_gcm.algo,
# ifndef OPENSSL_NO_DES
  &assh_cipher_openssl_tdes_cbc.algo,
# endif
# ifndef OPENSSL_NO_RC4
  &assh_cipher_openssl_arc4.algo,
  &assh_cipher_openssl_arc4_128.algo,
  &assh_cipher_openssl_arc4_256.algo,
# endif
# ifndef OPENSSL_NO_BF
  &assh_cipher_openssl_blowfish_cbc.algo,
# endif
# ifndef OPENSSL_NO_CAMELLIA
  &assh_cipher_openssl_camellia128_cbc.algo,
  &assh_cipher_openssl_camellia192_cbc.algo,
  &assh_cipher_openssl_camellia256_cbc.algo,
  &assh_cipher_openssl_camellia128_ctr.algo,
  &assh_cipher_openssl_camellia192_ctr.algo,
  &assh_cipher_openssl_camellia256_ctr.algo,
# endif
# ifndef OPENSSL_NO_CAST
  &assh_cipher_openssl_cast128_cbc.algo,
# endif
# ifndef OPENSSL_NO_IDEA
  &assh_cipher_openssl_idea_cbc.algo,
# endif
#endif

  /* mac */
  // &assh_mac_none.algo,

#ifdef CONFIG_ASSH_USE_BUILTIN_MACS
  &assh_mac_builtin_md5.algo,
  &assh_mac_builtin_md5_96.algo,
  &assh_mac_builtin_md5_etm.algo,
  &assh_mac_builtin_md5_96_etm.algo,
  &assh_mac_builtin_sha1.algo,
  &assh_mac_builtin_sha1_96.algo,
  &assh_mac_builtin_sha1_etm.algo,
  &assh_mac_builtin_sha1_96_etm.algo,
  &assh_mac_builtin_sha256.algo,
  &assh_mac_builtin_sha512.algo,
  &assh_mac_builtin_sha256_etm.algo,
  &assh_mac_builtin_sha512_etm.algo,
#endif

#ifdef CONFIG_ASSH_USE_GCRYPT_MACS
  &assh_mac_gcrypt_md5.algo,
  &assh_mac_gcrypt_md5_96.algo,
  &assh_mac_gcrypt_md5_etm.algo,
  &assh_mac_gcrypt_md5_96_etm.algo,
  &assh_mac_gcrypt_sha1.algo,
  &assh_mac_gcrypt_sha1_96.algo,
  &assh_mac_gcrypt_sha1_etm.algo,
  &assh_mac_gcrypt_sha1_96_etm.algo,
  &assh_mac_gcrypt_sha256.algo,
  &assh_mac_gcrypt_sha512.algo,
  &assh_mac_gcrypt_sha256_etm.algo,
  &assh_mac_gcrypt_sha512_etm.algo,
  &assh_mac_gcrypt_ripemd160.algo,
  &assh_mac_gcrypt_ripemd160_etm.algo,
#endif

#ifdef CONFIG_ASSH_USE_OPENSSL_MACS
#  ifndef OPENSSL_NO_MD5
  &assh_mac_openssl_md5.algo,
  &assh_mac_openssl_md5_96.algo,
  &assh_mac_openssl_md5_etm.algo,
  &assh_mac_openssl_md5_96_etm.algo,
#  endif
  &assh_mac_openssl_sha1.algo,
  &assh_mac_openssl_sha1_96.algo,
  &assh_mac_openssl_sha1_etm.algo,
  &assh_mac_openssl_sha1_96_etm.algo,
  &assh_mac_openssl_sha256.algo,
  &assh_mac_openssl_sha512.algo,
  &assh_mac_openssl_sha256_etm.algo,
  &assh_mac_openssl_sha512_etm.algo,
#  ifndef OPENSSL_NO_RMD160
  &assh_mac_openssl_ripemd160.algo,
  &assh_mac_openssl_ripemd160_etm.algo,
#  endif
#endif

  /* compress */
  &assh_compress_none.algo,

# ifdef CONFIG_ASSH_USE_ZLIB
  &assh_compress_zlib_zlib.algo,
  &assh_compress_zlib_zlib_openssh.algo,
# endif
  NULL
};

