/*

  libassh - asynchronous ssh2 client/server library.

  Copyright (C) 2013-2021 Alexandre Becoulet <alexandre.becoulet@free.fr>

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

#define ASSH_PV

#include <assh/assh_cipher.h>
#include <assh/assh_packet.h>
#include <assh/mod_builtin.h>

#include <wmmintrin.h>
#include <tmmintrin.h>
#include <smmintrin.h>

/************************************************************* AES */

#define AESNI_TARGET_ATTRIBUTES \
  __attribute__ ((target("aes,sse2,ssse3,sse4.1,pclmul")))

typedef __m128i aes128_ni_key_t[11];
typedef __m128i aes192_ni_key_t[13];
typedef __m128i aes256_ni_key_t[15];

AESNI_TARGET_ATTRIBUTES
static inline __m128i
aes128_ni_block_encrypt(__m128i x, const aes128_ni_key_t ek)
{
  x = _mm_xor_si128(x, ek[0]);
  x = _mm_aesenc_si128(x, ek[1]);
  x = _mm_aesenc_si128(x, ek[2]);
  x = _mm_aesenc_si128(x, ek[3]);
  x = _mm_aesenc_si128(x, ek[4]);
  x = _mm_aesenc_si128(x, ek[5]);
  x = _mm_aesenc_si128(x, ek[6]);
  x = _mm_aesenc_si128(x, ek[7]);
  x = _mm_aesenc_si128(x, ek[8]);
  x = _mm_aesenc_si128(x, ek[9]);
  return _mm_aesenclast_si128(x, ek[10]);
}

AESNI_TARGET_ATTRIBUTES
static inline __m128i
aes128_ni_block_decrypt(__m128i x, const aes128_ni_key_t dk)
{
  x = _mm_xor_si128(x,    dk[10]);
  x = _mm_aesdec_si128(x, dk[9]);
  x = _mm_aesdec_si128(x, dk[8]);
  x = _mm_aesdec_si128(x, dk[7]);
  x = _mm_aesdec_si128(x, dk[6]);
  x = _mm_aesdec_si128(x, dk[5]);
  x = _mm_aesdec_si128(x, dk[4]);
  x = _mm_aesdec_si128(x, dk[3]);
  x = _mm_aesdec_si128(x, dk[2]);
  x = _mm_aesdec_si128(x, dk[1]);
  return _mm_aesdeclast_si128(x, dk[0]);
}

AESNI_TARGET_ATTRIBUTES
static inline __m128i
aes192_ni_block_encrypt(__m128i x, const aes192_ni_key_t ek)
{
  x = _mm_xor_si128(x, ek[0]);
  x = _mm_aesenc_si128(x, ek[1]);
  x = _mm_aesenc_si128(x, ek[2]);
  x = _mm_aesenc_si128(x, ek[3]);
  x = _mm_aesenc_si128(x, ek[4]);
  x = _mm_aesenc_si128(x, ek[5]);
  x = _mm_aesenc_si128(x, ek[6]);
  x = _mm_aesenc_si128(x, ek[7]);
  x = _mm_aesenc_si128(x, ek[8]);
  x = _mm_aesenc_si128(x, ek[9]);
  x = _mm_aesenc_si128(x, ek[10]);
  x = _mm_aesenc_si128(x, ek[11]);
  return _mm_aesenclast_si128(x, ek[12]);
}

AESNI_TARGET_ATTRIBUTES
static inline __m128i
aes192_ni_block_decrypt(__m128i x, const aes192_ni_key_t dk)
{
  x = _mm_xor_si128(x, dk[12]);
  x = _mm_aesdec_si128(x, dk[11]);
  x = _mm_aesdec_si128(x, dk[10]);
  x = _mm_aesdec_si128(x, dk[9]);
  x = _mm_aesdec_si128(x, dk[8]);
  x = _mm_aesdec_si128(x, dk[7]);
  x = _mm_aesdec_si128(x, dk[6]);
  x = _mm_aesdec_si128(x, dk[5]);
  x = _mm_aesdec_si128(x, dk[4]);
  x = _mm_aesdec_si128(x, dk[3]);
  x = _mm_aesdec_si128(x, dk[2]);
  x = _mm_aesdec_si128(x, dk[1]);
  return _mm_aesdeclast_si128(x, dk[0]);
}

AESNI_TARGET_ATTRIBUTES
static inline __m128i
aes256_ni_block_encrypt(__m128i x, const aes256_ni_key_t ek)
{
  x = _mm_xor_si128(x, ek[0]);
  x = _mm_aesenc_si128(x, ek[1]);
  x = _mm_aesenc_si128(x, ek[2]);
  x = _mm_aesenc_si128(x, ek[3]);
  x = _mm_aesenc_si128(x, ek[4]);
  x = _mm_aesenc_si128(x, ek[5]);
  x = _mm_aesenc_si128(x, ek[6]);
  x = _mm_aesenc_si128(x, ek[7]);
  x = _mm_aesenc_si128(x, ek[8]);
  x = _mm_aesenc_si128(x, ek[9]);
  x = _mm_aesenc_si128(x, ek[10]);
  x = _mm_aesenc_si128(x, ek[11]);
  x = _mm_aesenc_si128(x, ek[12]);
  x = _mm_aesenc_si128(x, ek[13]);
  return _mm_aesenclast_si128(x, ek[14]);
}

AESNI_TARGET_ATTRIBUTES
static inline __m128i
aes256_ni_block_decrypt(__m128i x, const aes256_ni_key_t dk)
{
  x = _mm_xor_si128(x, dk[14]);
  x = _mm_aesdec_si128(x, dk[13]);
  x = _mm_aesdec_si128(x, dk[12]);
  x = _mm_aesdec_si128(x, dk[11]);
  x = _mm_aesdec_si128(x, dk[10]);
  x = _mm_aesdec_si128(x, dk[9]);
  x = _mm_aesdec_si128(x, dk[8]);
  x = _mm_aesdec_si128(x, dk[7]);
  x = _mm_aesdec_si128(x, dk[6]);
  x = _mm_aesdec_si128(x, dk[5]);
  x = _mm_aesdec_si128(x, dk[4]);
  x = _mm_aesdec_si128(x, dk[3]);
  x = _mm_aesdec_si128(x, dk[2]);
  x = _mm_aesdec_si128(x, dk[1]);
  return _mm_aesdeclast_si128(x, dk[0]);
}

/************************************************************* common */

AESNI_TARGET_ATTRIBUTES
static void assh_aesni_expand_key(uint32_t *b, uint_fast8_t c)
{
  uint_fast8_t r = 7 + c;	/* rounds */
  uint8_t rcon = 1;
  uint_fast8_t i, j;

  for (j = c; j < 4 * r; j += c)
    {
      /* x = RotWord(SubWord(x)) */
      uint32_t x = b[j - 1];
      x = _mm_extract_epi32(
	    _mm_aeskeygenassist_si128(
	      _mm_set_epi32(0, 0, x, 0), 0), 1);

      b[j] = x ^ b[j - c] ^ rcon;

      for (i = 1; i < c; i++)
        {
          if (i + j == 4 * r)
            return;

	  x = b[i + j - 1];

          if (c == 8 && i == 4)
	    /* x = SubWord(x) */
	    x = _mm_extract_epi32(
	            _mm_aeskeygenassist_si128(
	              _mm_set_epi32(0, 0, x, 0), 0), 0);

          b[i + j] = x ^ b[i + j - c];
        }

      rcon = (rcon << 1) | (((int8_t)(rcon & 0x80) >> 7) & 0x1b);
    }
}

AESNI_TARGET_ATTRIBUTES
static void assh_aesni_reverse_key(__m128i *out, const __m128i *in,
				   uint_fast8_t c)
{
  uint_fast8_t i, r = 7 + c;	/* rounds */

  out[0] = in[0];
  for (i = 1; i < r - 1; i++)
    out[i] = _mm_aesimc_si128(in[i]);
  out[i] = in[i];
}

static ASSH_CIPHER_CLEANUP_FCN(assh_aesni_cleanup)
{
}

static ASSH_ALGO_SUPPORTED_FCN(assh_cipher_builtin_aesni_supported)
{
  return !!__builtin_cpu_supports("aes");
}

static ASSH_ALGO_SUPPORTED_FCN(assh_cipher_builtin_pclmul_supported)
{
  return __builtin_cpu_supports("aes") &&
    __builtin_cpu_supports("pclmul");
}

/************************************************************* CBC */

#define ASSH_AESNI_CBC_IMPLEM(kbit, saf_, spd_, names_)			\
									\
struct assh_cipher_aesni##kbit##_cbc_context_s				\
{									\
  union {								\
    aes##kbit##_ni_key_t k;						\
    uint32_t b[(7 + kbit / 32) * 4];					\
  };									\
  __m128i iv;								\
  assh_bool_t encrypt;							\
};									\
									\
AESNI_TARGET_ATTRIBUTES							\
static ASSH_CIPHER_PROCESS_FCN(assh_aesni##kbit##_cbc_process)		\
{									\
  struct assh_cipher_aesni##kbit##_cbc_context_s *ctx = ctx_;		\
									\
  __m128i iv = ctx->iv;							\
									\
  if (ctx->encrypt)							\
    {									\
      for (; len >= 16; len -= 16)					\
	{								\
	  __m128i b = _mm_xor_si128(iv,					\
			_mm_loadu_si128((const __m128i*)data));		\
	  b = aes##kbit##_ni_block_encrypt(b, ctx->k);			\
	  _mm_storeu_si128((__m128i *)data, b);				\
	  iv = b;							\
	  data += 16;							\
	}								\
    }									\
  else									\
    {									\
      for (; len >= 16; len -= 16)					\
	{								\
	  __m128i t = _mm_loadu_si128((const __m128i*)data);		\
	  __m128i b = aes##kbit##_ni_block_decrypt(t, ctx->k);		\
	  _mm_storeu_si128((__m128i *)data, _mm_xor_si128(b, iv));	\
	  iv = t;							\
	  data += 16;							\
	}								\
    }									\
									\
  ctx->iv = iv;								\
									\
  return ASSH_OK;							\
}									\
									\
AESNI_TARGET_ATTRIBUTES							\
static ASSH_CIPHER_INIT_FCN(assh_aesni##kbit##_cbc_init)		\
{									\
  struct assh_cipher_aesni##kbit##_cbc_context_s *ctx = ctx_;		\
									\
  ctx->encrypt = encrypt;						\
  ctx->iv = _mm_loadu_si128((const __m128i*)iv);			\
									\
  memcpy(ctx->k, key, kbit / 8);					\
  assh_aesni_expand_key(ctx->b, kbit / 32);				\
									\
  if (!encrypt)								\
    assh_aesni_reverse_key(ctx->k, ctx->k, kbit / 32);			\
									\
  return ASSH_OK;							\
}									\
									\
const struct assh_algo_cipher_s assh_cipher_builtin_aesni##kbit##_cbc =	\
{									\
  ASSH_ALGO_BASE(CIPHER, "assh-aesni", saf_, spd_, names_,		\
    .f_supported = assh_cipher_builtin_aesni_supported,			\
  ),									\
  .ctx_size = sizeof(struct assh_cipher_aesni##kbit##_cbc_context_s),	\
  .block_size = 16,							\
  .head_size = 16,							\
  .iv_size = 16,							\
  .key_size = kbit / 8,							\
  .f_init = assh_aesni##kbit##_cbc_init,				\
  .f_process = assh_aesni##kbit##_cbc_process,				\
  .f_cleanup = assh_aesni_cleanup,					\
};

ASSH_AESNI_CBC_IMPLEM(128, 40, 100,
      ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
	  "aes128-cbc" })
);

ASSH_AESNI_CBC_IMPLEM(192, 50, 100,
      ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
	  "aes192-cbc" })
);

ASSH_AESNI_CBC_IMPLEM(256, 60, 100,
      ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,
	  "aes256-cbc" },
	{ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_OLDNAME,
	  "rijndael-cbc@lysator.liu.se" })
);

/************************************************************* CTR */

#define ASSH_AESNI_CTR_IMPLEM(kbit, saf_, spd_)				\
									\
struct assh_cipher_aesni##kbit##_ctr_context_s				\
{									\
  union {								\
    aes##kbit##_ni_key_t k;						\
    uint32_t b[(7 + kbit / 32) * 4];					\
  };									\
  __m128i iv;								\
  assh_bool_t encrypt;							\
};									\
									\
AESNI_TARGET_ATTRIBUTES							\
static ASSH_CIPHER_PROCESS_FCN(assh_aesni##kbit##_ctr_process)		\
{									\
  struct assh_cipher_aesni##kbit##_ctr_context_s *ctx = ctx_;		\
									\
  __m128i iv = ctx->iv;							\
									\
  const __m128i s = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7,		\
				 8, 9, 10, 11, 12, 13, 14, 15);		\
									\
  for ( ;len >= 16; len -= 16)						\
    {									\
      __m128i v = _mm_shuffle_epi8(iv, s);				\
      __m128i b = aes##kbit##_ni_block_encrypt(v, ctx->k);		\
      __m128i p = _mm_loadu_si128((const __m128i*)data);		\
      p = _mm_xor_si128(b, p);						\
      _mm_storeu_si128((__m128i *)data, p);				\
									\
      /* 128 bit increment */						\
      __m128i a = _mm_add_epi64(iv, _mm_set_epi64x(0, 1));		\
      __m128i c = _mm_srli_epi64(_mm_bslli_si128(			\
		    _mm_andnot_si128(a, iv), 8), 63);			\
      iv = _mm_add_epi64(a, c);						\
									\
      data += 16;							\
    }									\
									\
  ctx->iv = iv;								\
									\
  return ASSH_OK;							\
}									\
									\
AESNI_TARGET_ATTRIBUTES							\
static ASSH_CIPHER_INIT_FCN(assh_aesni##kbit##_ctr_init)		\
{									\
  struct assh_cipher_aesni##kbit##_ctr_context_s *ctx = ctx_;		\
									\
  ctx->encrypt = encrypt;						\
									\
  const __m128i s = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7,		\
				 8, 9, 10, 11, 12, 13, 14, 15);		\
  ctx->iv = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)iv), s);	\
									\
  memcpy(ctx->k, key, kbit / 8);					\
  assh_aesni_expand_key(ctx->b, kbit / 32);				\
									\
  return ASSH_OK;							\
}									\
									\
const struct assh_algo_cipher_s assh_cipher_builtin_aesni##kbit##_ctr =	\
{									\
  ASSH_ALGO_BASE(CIPHER, "assh-aesni", saf_, spd_,			\
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_IETF | ASSH_ALGO_COMMON,		\
                      "aes" #kbit "-ctr" }),				\
    .f_supported = assh_cipher_builtin_aesni_supported,			\
  ),									\
  .ctx_size = sizeof(struct assh_cipher_aesni##kbit##_ctr_context_s),	\
  .block_size = 16,							\
  .head_size = 16,							\
  .iv_size = 16,							\
  .key_size = kbit / 8,							\
  .f_init = assh_aesni##kbit##_ctr_init,				\
  .f_process = assh_aesni##kbit##_ctr_process,				\
  .f_cleanup = assh_aesni_cleanup,					\
};

ASSH_AESNI_CTR_IMPLEM(128, 0, 0);
ASSH_AESNI_CTR_IMPLEM(192, 0, 0);
ASSH_AESNI_CTR_IMPLEM(256, 0, 0);

/************************************************************* OCB */

#define AES_OCB_LCOUNT 2 + sizeof(int) * 8 -		\
  __builtin_clz((CONFIG_ASSH_MAX_PACKET_LEN + 15) / 16)

#define ASSH_AESNI_OCB_IMPLEM(kbit, saf_, spd_)				\
									\
struct assh_cipher_aesni##kbit##_ocb_context_s				\
{									\
  aes##kbit##_ni_key_t dk;						\
  union {								\
   aes##kbit##_ni_key_t ek;						\
   uint32_t eb[(7 + kbit / 32) * 4];					\
  };									\
  __m128i         l[AES_OCB_LCOUNT];					\
  __m128i         stretch;						\
  __m128i         nonce;						\
  uint_fast8_t    nonce_b;						\
  assh_bool_t     encrypt;						\
};									\
									\
AESNI_TARGET_ATTRIBUTES							\
static ASSH_CIPHER_PROCESS_FCN(assh_aesni##kbit##_ocb_process)		\
{									\
  struct assh_cipher_aesni##kbit##_ocb_context_s *ctx = ctx_;		\
  assh_status_t err;							\
									\
  if (op == ASSH_CIPHER_PCK_HEAD)					\
    return ASSH_OK;							\
									\
  size_t csize = len - 4 - 16;						\
  size_t i, m = csize >> 4;						\
									\
  /* process first 4 bytes as associated data */			\
  __m128i p = _mm_set_epi32(0, 0, 0x80, assh_load_u32le(data));		\
  __m128i c = _mm_xor_si128(p, ctx->l[0]);				\
  __m128i ak = aes##kbit##_ni_block_encrypt(c, ctx->ek);		\
  data += 4;								\
									\
  __m128i a = ctx->stretch;						\
  __m128i l2 = ctx->l[2];						\
  __m128i ck0 = _mm_setzero_si128(), ck1 = ck0;				\
									\
  if (ctx->encrypt)							\
    {									\
      for (i = 0; i + 1 < m; i += 2)					\
	{								\
	  __m128i p0 = _mm_loadu_si128((const __m128i*)data);		\
	  __m128i p1 = _mm_loadu_si128((const __m128i*)(data + 16));	\
									\
	  /* even blocks always use l[2] */				\
	  ck0 = _mm_xor_si128(ck0, p0);					\
	  a = _mm_xor_si128(a, l2);					\
	  __m128i c0 = _mm_xor_si128(p0, a);				\
	  c0 = aes##kbit##_ni_block_encrypt(c0, ctx->ek);		\
	  c0 = _mm_xor_si128(c0, a);					\
									\
	  /* odd blocks */						\
	  __m128i l = ctx->l[2 + assh_ctz32(i + 2)];			\
	  ck1 = _mm_xor_si128(ck1, p1);					\
	  a = _mm_xor_si128(a, l);					\
	  __m128i c1 = _mm_xor_si128(p1, a);				\
	  c1 = aes##kbit##_ni_block_encrypt(c1, ctx->ek);		\
	  c1 = _mm_xor_si128(c1, a);					\
									\
	  _mm_storeu_si128((__m128i *)data, c0);			\
	  _mm_storeu_si128((__m128i *)(data + 16), c1);			\
	  data += 32;							\
	}								\
									\
      __m128i ck = _mm_xor_si128(ck0, ck1);				\
									\
      if (i < m)		/* last block */			\
	{								\
	  p = _mm_loadu_si128((const __m128i*)data);			\
									\
	  ck = _mm_xor_si128(ck, p);					\
	  a = _mm_xor_si128(a, l2);					\
	  c = _mm_xor_si128(p, a);					\
	  c = aes##kbit##_ni_block_encrypt(c, ctx->ek);			\
	  c = _mm_xor_si128(c, a);					\
									\
	  _mm_storeu_si128((__m128i *)data, c);				\
	  data += 16;							\
	}								\
									\
      /* authentication tag */						\
      c = _mm_xor_si128(ck, a);						\
      c = _mm_xor_si128(c, ctx->l[1]);					\
      c = aes##kbit##_ni_block_encrypt(c, ctx->ek);			\
      c = _mm_xor_si128(c, ak);						\
									\
      _mm_storeu_si128((__m128i *)data, c);				\
    }									\
  else				/* decrypt */				\
    {									\
      for (i = 0; i + 1 < m; i += 2)					\
	{								\
	  __m128i p0 = _mm_loadu_si128((const __m128i*)data);		\
	  __m128i p1 = _mm_loadu_si128((const __m128i*)(data + 16));	\
									\
	  /* even blocks */						\
	  a = _mm_xor_si128(a, l2);					\
	  __m128i c0 = _mm_xor_si128(p0, a);				\
	  c0 = aes##kbit##_ni_block_decrypt(c0, ctx->dk);		\
	  c0 = _mm_xor_si128(c0, a);					\
	  ck0 = _mm_xor_si128(ck0, c0);					\
									\
	  /* odd blocks */						\
	  __m128i l = ctx->l[2 + assh_ctz32(i + 2)];			\
	  a = _mm_xor_si128(a, l);					\
	  __m128i c1 = _mm_xor_si128(p1, a);				\
	  c1 = aes##kbit##_ni_block_decrypt(c1, ctx->dk);		\
	  c1 = _mm_xor_si128(c1, a);					\
	  ck1 = _mm_xor_si128(ck1, c1);					\
									\
	  _mm_storeu_si128((__m128i *)data, c0);			\
	  _mm_storeu_si128((__m128i *)(data + 16), c1);			\
	  data += 32;							\
	}								\
									\
      __m128i ck = _mm_xor_si128(ck0, ck1);				\
									\
      if (i < m)		/* last block */			\
	{								\
	  p = _mm_loadu_si128((const __m128i*)data);			\
									\
	  a = _mm_xor_si128(a, l2);					\
	  c = _mm_xor_si128(p, a);					\
	  c = aes##kbit##_ni_block_decrypt(c, ctx->dk);			\
	  c = _mm_xor_si128(c, a);					\
	  ck = _mm_xor_si128(ck, c);					\
									\
	  _mm_storeu_si128((__m128i *)data, c);				\
	  data += 16;							\
	}								\
									\
      /* authentication tag */						\
      c = _mm_xor_si128(ck, a);						\
      c = _mm_xor_si128(c, ctx->l[1]);					\
      c = aes##kbit##_ni_block_encrypt(c, ctx->ek);			\
      c = _mm_xor_si128(c, ak);						\
									\
      c = _mm_xor_si128(c, _mm_loadu_si128((__m128i *)data));		\
									\
      ASSH_RET_IF_TRUE(!_mm_test_all_zeros(c, c),			\
		       ASSH_ERR_CRYPTO);				\
    }									\
									\
  /* increment nonce */							\
  {									\
    const __m128i s = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7,		\
				   8, 9, 10, 11, 12, 13, 14, 15);	\
									\
    uint_fast8_t b = ctx->nonce_b;					\
    b = (b + 1) & 63;							\
    ctx->nonce_b = b;							\
									\
    if (b)		/* bottom doesnt wrap, just shift stretch */	\
      {									\
	__m128i n = _mm_shuffle_epi8(ctx->stretch, s);			\
									\
	/* 1 bit left shift */						\
	__m128i a = _mm_srli_epi64(_mm_bslli_si128(n, 8), 63);		\
	__m128i x = _mm_or_si128(a, _mm_slli_epi64(n, 1));		\
									\
	/* generate 1 bit from stretch upper part */			\
	a = _mm_xor_si128(_mm_bsrli_si128(n, 8), _mm_bsrli_si128(n, 7)); \
	a = _mm_srli_epi64(a, 63);					\
	n = _mm_or_si128(a, x);						\
									\
	ctx->stretch = _mm_shuffle_epi8(n, s);				\
      }									\
    else		/* bottom counter wraps */			\
      {									\
	__m128i n = ctx->nonce;						\
									\
	/* nonce += 64 */						\
	__m128i a = _mm_add_epi64(n, _mm_set_epi64x(0, 64));		\
	__m128i c = _mm_srli_epi64(_mm_bslli_si128(			\
				     _mm_andnot_si128(a, n), 8), 63);	\
	n = _mm_add_epi64(a, c);					\
	ctx->nonce = n;							\
									\
	/* new stretch */						\
	n = _mm_shuffle_epi8(n, s);					\
	ctx->stretch = aes##kbit##_ni_block_encrypt(n, ctx->ek);	\
      }									\
  }									\
									\
  return ASSH_OK;							\
}									\
									\
AESNI_TARGET_ATTRIBUTES							\
static ASSH_CIPHER_INIT_FCN(assh_aesni##kbit##_ocb_init)		\
{									\
  struct assh_cipher_aesni##kbit##_ocb_context_s *ctx = ctx_;		\
									\
  ctx->encrypt = encrypt;						\
									\
  const __m128i s = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7,		\
				 8, 9, 10, 11, 12, 13, 14, 15);		\
									\
  /* setup AES key */							\
  memcpy(ctx->ek, key, kbit / 8);					\
  assh_aesni_expand_key(ctx->eb, kbit / 32);				\
  assh_aesni_reverse_key(ctx->dk, ctx->ek, kbit / 32);			\
									\
  /* setup OCB key */							\
  __m128i l = aes##kbit##_ni_block_encrypt(_mm_setzero_si128(), ctx->ek); \
  ctx->l[0] = l;							\
									\
  l = _mm_shuffle_epi8(l, s);						\
									\
  for (uint_fast8_t i = 1; i < AES_OCB_LCOUNT; i++)			\
    {									\
      /* double */							\
      __m128i a = _mm_srli_epi64(_mm_bslli_si128(l, 8), 63);		\
      __m128i x = _mm_or_si128(a, _mm_slli_epi64(l, 1));		\
      a = _mm_srli_epi64(_mm_bsrli_si128(l, 15), 7);			\
      l = _mm_xor_si128(x, _mm_mul_epu32(a, _mm_set1_epi32(135)));	\
									\
      ctx->l[i] = _mm_shuffle_epi8(l, s);				\
    }									\
									\
  /* set OCB nonce from iv */						\
  int_fast8_t i;							\
  uint8_t n[16];							\
									\
  /* expand to 128 bit nonce */						\
  n[0] = (uint8_t)(/* tag len */ 16 << 4);				\
  n[1] = n[2] = 0;							\
  n[3] = 0x01;								\
  for (i = 4; i < 16; i++)						\
    n[i] = iv[i - 4];							\
									\
  /* bottom */								\
  uint_fast8_t b = n[15] & 63;						\
  ctx->nonce_b = b;							\
									\
  /* top */								\
  n[15] &= 0xc0;							\
									\
  __m128i x = _mm_loadu_si128((const __m128i*)n);			\
  ctx->nonce = _mm_shuffle_epi8(x, s);					\
									\
  x = aes##kbit##_ni_block_encrypt(x, ctx->ek);				\
									\
  /* shift stretch */							\
  if (b)								\
    {									\
      x = _mm_shuffle_epi8(x, s);					\
      uint64_t l = _mm_extract_epi64(x, 1);				\
      uint64_t h = _mm_extract_epi64(x, 0);				\
      uint64_t t = l ^ (l << 8) ^ (h >> 56);				\
      x = _mm_shuffle_epi8(_mm_set_epi64x(				\
	   (l << b) | (h >> (64 - b)),					\
	   (h << b) | (t >> (64 - b))), s);				\
    }									\
									\
  ctx->stretch = x;							\
									\
  return ASSH_OK;							\
}									\
									\
const struct assh_algo_cipher_s assh_cipher_builtin_aesni##kbit##_ocb =	\
{									\
  ASSH_ALGO_BASE(CIPHER, "assh-aesni", saf_, spd_,			\
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE,				\
                      "aes" #kbit "-ocb@libassh.org" }),		\
    .f_supported = assh_cipher_builtin_aesni_supported,			\
  ),									\
  .ctx_size = sizeof(struct assh_cipher_aesni##kbit##_ocb_context_s),	\
  .block_size = 16,							\
  .head_size = 4,							\
  .iv_size = 12,							\
  .key_size = kbit / 8,							\
  .auth_size = 16,							\
  .f_init = assh_aesni##kbit##_ocb_init,				\
  .f_process = assh_aesni##kbit##_ocb_process,				\
  .f_cleanup = assh_aesni_cleanup,					\
};

ASSH_AESNI_OCB_IMPLEM(128, 41, 150);
ASSH_AESNI_OCB_IMPLEM(256, 61, 150);

/************************************************************* GCM */

AESNI_TARGET_ATTRIBUTES
static inline __m128i assh_aesni_gcm_gfmul(__m128i x, __m128i y)
{
  /* see Intel document: Carry-Less Multiplication Instruction and its
     Usage for Computing the GCM Mode. */

  __m128i a, b, c, d;

  a = _mm_clmulepi64_si128(x, y, 0x10);
  b = _mm_clmulepi64_si128(x, y, 0x01);
  a = _mm_xor_si128(a, b);
  b = _mm_slli_si128(a, 8);
  a = _mm_srli_si128(a, 8);
  c = _mm_clmulepi64_si128(x, y, 0x00);
  c = _mm_xor_si128(c, b);
  b = _mm_clmulepi64_si128(x, y, 0x11);
  b = _mm_xor_si128(b, a);
  d = _mm_srli_epi32(c, 31);
  a = _mm_srli_epi32(b, 31);

  c = _mm_or_si128(_mm_slli_epi32(c, 1), _mm_slli_si128(d, 4));

  b = _mm_or_si128(_mm_or_si128(_mm_slli_epi32(b, 1),
				 _mm_slli_si128(a, 4)),
		    _mm_srli_si128(d, 12));

  d = _mm_xor_si128(_mm_xor_si128(_mm_slli_epi32(c, 31),
				   _mm_slli_epi32(c, 30)),
		     _mm_slli_epi32(c, 25));

  c = _mm_xor_si128(c, _mm_slli_si128(d, 12));
  a = _mm_xor_si128(_mm_srli_epi32(c, 1), _mm_srli_epi32(c, 2));
  d = _mm_xor_si128(_mm_srli_si128(d, 4), _mm_srli_epi32(c, 7));

  return _mm_xor_si128(_mm_xor_si128(a, d), _mm_xor_si128(b, c));
}

#define ASSH_AESNI_GCM_IMPLEM(kbit, saf_, spd_)				\
									\
struct assh_cipher_aesni##kbit##_gcm_context_s				\
{									\
  union {								\
    aes##kbit##_ni_key_t k;						\
    uint32_t b[(7 + kbit / 32) * 4];					\
  };									\
  __m128i iv;								\
  assh_bool_t encrypt;							\
};									\
									\
AESNI_TARGET_ATTRIBUTES							\
static ASSH_CIPHER_PROCESS_FCN(assh_aesni##kbit##_gcm_process)		\
{									\
  struct assh_cipher_aesni##kbit##_gcm_context_s *ctx = ctx_;		\
  assh_status_t err;							\
									\
  if (op == ASSH_CIPHER_PCK_HEAD)					\
    return ASSH_OK;							\
									\
  const __m128i one = _mm_set_epi32(1, 0, 0, 0);			\
									\
  const __m128i iv2ctr = _mm_set_epi8(3, 2, 1, 0,			\
			15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4);	\
									\
  const __m128i ctr_s = _mm_set_epi8(12, 13, 14, 15,			\
			       4, 5, 6, 7, 8, 9, 10, 11,		\
			       0, 1, 2, 3);				\
									\
  const __m128i s = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7,		\
			   8, 9, 10, 11, 12, 13, 14, 15);		\
									\
  size_t csize = len - 4 - 16;						\
  size_t i, m = csize >> 4;						\
									\
  __m128i iv = ctx->iv;							\
  __m128i ctr = _mm_shuffle_epi8(iv, iv2ctr);				\
									\
  __m128i h = aes##kbit##_ni_block_encrypt(				\
	        _mm_setzero_si128(), ctx->k);				\
  __m128i t = aes##kbit##_ni_block_encrypt(				\
		_mm_shuffle_epi8(ctr, ctr_s), ctx->k);			\
  h = _mm_shuffle_epi8(h, s);						\
									\
  /* process first 4 bytes as associated data */			\
  __m128i ck = _mm_set_epi32(assh_load_u32(data), 0, 0, 0);		\
  ck = assh_aesni_gcm_gfmul(ck, h);					\
  data += 4;								\
									\
  if (ctx->encrypt)							\
    {									\
      __m128i c = _mm_add_epi32(ctr, one);				\
									\
      for (i = 0; i < m; i++)						\
	{								\
	  __m128i p = _mm_loadu_si128((__m128i*)data);			\
									\
	  __m128i a = aes##kbit##_ni_block_encrypt(			\
		        _mm_shuffle_epi8(c, ctr_s), ctx->k);		\
	  p = _mm_xor_si128(a, p);					\
	  a = _mm_shuffle_epi8(p, s);					\
	  ck = _mm_xor_si128(ck, a);					\
	  ck = assh_aesni_gcm_gfmul(ck, h);				\
									\
	  _mm_storeu_si128((__m128i*)data, p);				\
	  data += 16;							\
									\
	  c = _mm_add_epi32(c, one);					\
	}								\
									\
      __m128i a = _mm_set_epi64x(4 * 8, csize * 8);			\
      ck = _mm_xor_si128(ck, a);					\
      ck = assh_aesni_gcm_gfmul(ck, h);					\
      ck = _mm_shuffle_epi8(ck, s);					\
      ck = _mm_xor_si128(ck, t);					\
									\
      _mm_storeu_si128((__m128i*)data, ck);				\
    }									\
  else									\
    {									\
      __m128i c = _mm_add_epi32(ctr, one);				\
									\
      for (i = 0; i < m; i++)						\
	{								\
	  __m128i p = _mm_loadu_si128((__m128i*)data);			\
									\
	  __m128i a = aes##kbit##_ni_block_encrypt(			\
		        _mm_shuffle_epi8(c, ctr_s), ctx->k);		\
	  ck = _mm_xor_si128(ck, _mm_shuffle_epi8(p, s));		\
	  ck = assh_aesni_gcm_gfmul(ck, h);				\
	  a = _mm_xor_si128(a, p);					\
									\
	  _mm_storeu_si128((__m128i*)data, a);				\
	  data += 16;							\
									\
	  c = _mm_add_epi32(c, one);					\
	}								\
									\
      __m128i a = _mm_set_epi64x(4 * 8, csize * 8);			\
      ck = _mm_xor_si128(ck, a);					\
      ck = assh_aesni_gcm_gfmul(ck, h);					\
      ck = _mm_shuffle_epi8(ck, s);					\
      ck = _mm_xor_si128(ck, t);					\
      ck = _mm_xor_si128(ck, _mm_loadu_si128((__m128i*)data));		\
									\
      ASSH_RET_IF_TRUE(!_mm_test_all_zeros(ck, ck),			\
		       ASSH_ERR_CRYPTO);				\
    }									\
									\
  /* increment invocation counter */					\
  ctx->iv = _mm_add_epi64(iv, _mm_set_epi64x(1, 0));			\
									\
  return ASSH_OK;							\
}									\
									\
AESNI_TARGET_ATTRIBUTES							\
static ASSH_CIPHER_INIT_FCN(assh_aesni##kbit##_gcm_init)		\
{									\
  struct assh_cipher_aesni##kbit##_gcm_context_s *ctx = ctx_;		\
									\
  ctx->encrypt = encrypt;						\
									\
  memcpy(ctx->k, key, kbit / 8);					\
  assh_aesni_expand_key(ctx->b, kbit / 32);				\
									\
  /* according to rfc5647:						\
   32: block_counter, 64: invocation_counter, 32:fixed.			\
									\
   Keep IV left rotated so that invocation_counter is 64 bit aligned */ \
  ctx->iv = _mm_set_epi32(assh_load_u32(iv + 4), assh_load_u32(iv + 8),	\
			  assh_load_u32(iv), 1);			\
									\
  return ASSH_OK;							\
}									\
									\
const struct assh_algo_cipher_s assh_cipher_builtin_aesni##kbit##_gcm =	\
{									\
  ASSH_ALGO_BASE(CIPHER, "assh-aesni", saf_, spd_,			\
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_COMMON,		\
                      "aes" #kbit "-gcm@openssh.com" }),		\
    .f_supported = assh_cipher_builtin_pclmul_supported,		\
  ),									\
  .ctx_size = sizeof(struct assh_cipher_aesni##kbit##_gcm_context_s),	\
  .block_size = 16,							\
  .head_size = 4,							\
  .iv_size = 12,							\
  .key_size = kbit / 8,							\
  .auth_size = 16,							\
  .f_init = assh_aesni##kbit##_gcm_init,				\
  .f_process = assh_aesni##kbit##_gcm_process,				\
  .f_cleanup = assh_aesni_cleanup,					\
};

ASSH_AESNI_GCM_IMPLEM(128, 41, 0);
ASSH_AESNI_GCM_IMPLEM(256, 61, 0);
