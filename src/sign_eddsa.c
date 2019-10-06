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

#include <assh/assh_buffer.h>
#include <assh/assh_bignum.h>
#include <assh/assh_sign.h>
#include <assh/key_eddsa.h>
#include <assh/assh_hash.h>
#include <assh/assh_alloc.h>

#include <string.h>

static ASSH_SIGN_GENERATE_FCN(assh_sign_eddsa_generate)
{
  const struct assh_key_eddsa_s *k = (const void*)key;
  assh_status_t err;

  const struct assh_edward_curve_s *curve = k->curve;
  const struct assh_hash_algo_s *hash = k->hash;

  size_t n = ASSH_ALIGN8(k->curve->bits) / 8;
  size_t tlen = strlen(k->key.algo->name);
  size_t len = 4 + tlen + 4 + 2 * n;

  /* check/return signature length */
  if (sign == NULL)
    {
      *sign_len = len;
      return ASSH_OK;
    }

  /* check availability of the private key */
  ASSH_RET_IF_TRUE(!k->key.private, ASSH_ERR_MISSING_KEY);

  ASSH_RET_IF_TRUE(*sign_len < len, ASSH_ERR_OUTPUT_OVERFLOW);
  *sign_len = len;

  assh_store_u32(sign, tlen);
  memcpy(sign + 4, k->key.algo->name, tlen);
  assh_store_u32(sign + 4 + tlen, 2 * n);
  uint8_t *r_str = sign + 4 + tlen + 4;
  uint8_t *s_str = r_str + n;

  const uint8_t *kp = k->data;
  const uint8_t *ks = k->data + n;

  ASSH_SCRATCH_ALLOC(c, uint8_t, sc,
    hash->ctx_size + /* h */ n * 2 + /* r */ n * 2 +  /* hram */ n * 2 +
    /* az */ n * 2 + /* rx */ n, ASSH_ERRSV_CONTINUE, err_);

  void    *hash_ctx = sc;
  uint8_t *h = sc + hash->ctx_size;
  uint8_t *r = h + 2 * n;
  uint8_t *hram = r + 2 * n;
  uint8_t *az = hram + 2 * n;
  uint8_t *rx = az + 2;

  uint_fast8_t i;

  ASSH_JMP_ON_ERR(assh_hash_init(c, hash_ctx, hash), err_scratch);
  assh_hash_update(hash_ctx, ks, n);
  assh_hash_final(hash_ctx, h, n * 2);
  assh_hash_cleanup(hash_ctx);

#ifdef CONFIG_ASSH_DEBUG_SIGN
  ASSH_DEBUG_HEXDUMP("h", h, 2 * n);
#endif

  /* a is h[0,n-1] */
  assh_edward_adjust(curve, h);

  /* r */
  ASSH_JMP_ON_ERR(assh_hash_init(c, hash_ctx, hash), err_scratch);
  assh_hash_update(hash_ctx, h + n, n);
  for (i = 0; i < data_count; i++)
    assh_hash_update(hash_ctx, data[i].data, data[i].len);
  assh_hash_final(hash_ctx, r, n * 2);
  assh_hash_cleanup(hash_ctx);

#ifdef CONFIG_ASSH_DEBUG_SIGN
  ASSH_DEBUG_HEXDUMP("r", r, 2 * n);
#endif

  {
    enum {
      /* in */
      BX_mpint, BY_mpint, A_mpint, P_mpint, D_mpint,
      P_n, SC_raw, SC_size,
      /* out */
      RX_raw, RY_raw,
      /* temp */
      A, D,
      RX, RY, RZ,  BX, BY, BZ,
      PX, PY, PZ,  QX, QY, QZ, T0, T1, MT, SC
    };

    static const assh_bignum_op_t bytecode1[] = {
      ASSH_BOP_SIZER(   A,      MT,     P_n             ),
      ASSH_BOP_SIZE(    SC,     SC_size                 ),

      /* init */
      ASSH_BOP_MOVES(   SC,     SC_raw                  ),
      ASSH_BOP_MOVE(    T0,     P_mpint                 ),
      ASSH_BOP_MTINIT(	MT,     T0                      ),
      ASSH_BOP_MOVE(    A,      A_mpint                 ),
      ASSH_BOP_MOVE(    D,      D_mpint                 ),

      ASSH_BOP_MTUINT(  RX,     0,      MT              ),
      ASSH_BOP_MTUINT(  RY,     1,      MT              ),
      ASSH_BOP_MTUINT(  RZ,     1,      MT              ),
      ASSH_BOP_MOVE(    BX,     BX_mpint                ),
      ASSH_BOP_MOVE(    BY,     BY_mpint                ),
      ASSH_BOP_MTUINT(  BZ,     1,      MT              ),

      ASSH_BOP_MTTO(	A,      D,     A,      MT       ),
      ASSH_BOP_MTTO(	BX,     BY,    BX,     MT       ),
      ASSH_BOP_LADINIT( SC                              ),

      /* ladder */
      ASSH_BOP_TEDWARD_PDBL( PX, PY, PZ,  RX, RY, RZ,
                             T0, T1, MT                 ),

      ASSH_BOP_TEDWARD_PADD( QX, QY, QZ,  PX, PY, PZ,
                             BX, BY, BZ,  T0, T1, A, D, MT ),

      ASSH_BOP_MOVE(    RX,     PX                      ),
      ASSH_BOP_MOVE(    RY,     PY                      ),
      ASSH_BOP_MOVE(    RZ,     PZ                      ),

      ASSH_BOP_LADTEST(   SC,     0                     ),
      ASSH_BOP_CSWAP(     RX,     QX,     0,      0     ),
      ASSH_BOP_CSWAP(     RY,     QY,     0,      0     ),
      ASSH_BOP_CSWAP(     RZ,     QZ,     0,      0     ),
      ASSH_BOP_LADNEXT(   0                             ),
      ASSH_BOP_CJMP(      -44,    0,      0             ),

      /* projective to affine */
      ASSH_BOP_INV(     T0,     RZ,     MT              ),
      ASSH_BOP_MULM(    RX,     RX,     T0,     MT      ),
      ASSH_BOP_MULM(    RY,     RY,     T0,     MT      ),

      ASSH_BOP_MTFROM(	RX,     RY,     RX,     MT      ),

      ASSH_BOP_MOVE(    RX_raw, RX                      ),
      ASSH_BOP_MOVE(    RY_raw, RY                      ),

      ASSH_BOP_END(),
    };

    ASSH_JMP_ON_ERR(assh_bignum_bytecode(c, 0, bytecode1,
      "MMMMMsdsddTTTTTTTTTTTTTTTTmT", curve->bx, curve->by,
      curve->a, curve->p, curve->d, (size_t)curve->bits,
      r, (size_t)(n * 8 * 2),             /* scalar */
      rx, r_str), err_scratch);
  }

  /* encode point */
  assh_edward_encode(curve, r_str, rx);

#ifdef CONFIG_ASSH_DEBUG_SIGN
  ASSH_DEBUG_HEXDUMP("rxy", r_str, n);
#endif

  /* hram */
  ASSH_JMP_ON_ERR(assh_hash_init(c, hash_ctx, hash), err_scratch);
  assh_hash_update(hash_ctx, r_str, n);
  assh_hash_update(hash_ctx, kp, n);
  for (i = 0; i < data_count; i++)
    assh_hash_update(hash_ctx, data[i].data, data[i].len);
  assh_hash_final(hash_ctx, hram, n * 2);
  assh_hash_cleanup(hash_ctx);

#ifdef CONFIG_ASSH_DEBUG_SIGN
  ASSH_DEBUG_HEXDUMP("hram", hram, 2 * n);
#endif

  ASSH_JMP_ON_ERR(assh_hash_init(c, hash_ctx, hash), err_scratch);
  assh_hash_update(hash_ctx, ks, n);
  assh_hash_final(hash_ctx, az, n * 2);
  assh_hash_cleanup(hash_ctx);

  assh_edward_adjust(curve, az);

#ifdef CONFIG_ASSH_DEBUG_SIGN
  ASSH_DEBUG_HEXDUMP("az", az, 2 * n);
#endif

  {
    enum {
      L_mpint, H_raw, AZ_raw, R_raw, S_raw, P_n,
      L, T0, T1, MT, S
    };

    static const assh_bignum_op_t bytecode2[] = {
      ASSH_BOP_SIZEM(   L,      P_n,    0,      1       ),
      ASSH_BOP_SIZER(   T0,     MT,     L               ),
      ASSH_BOP_SIZE(    S,      P_n                     ),

      ASSH_BOP_MOVE(    L,      L_mpint                 ),
      ASSH_BOP_MTINIT(  MT,     L                       ),

      ASSH_BOP_MOVES(   T1,     H_raw                   ),
      ASSH_BOP_MOVES(   S,      AZ_raw                  ),
      ASSH_BOP_MOVE(    T0,     S                       ),
      ASSH_BOP_MTTO(    T0,     T1,     T0,     MT      ),
      ASSH_BOP_MULM(    T1,     T1,     T0,     MT      ),

      ASSH_BOP_MOVES(   T0,     R_raw                   ),
      ASSH_BOP_MTTO(    T0,     T0,     T0,     MT      ),
      ASSH_BOP_ADDM(    T1,     T1,     T0,     MT      ),

      ASSH_BOP_MTFROM(  T1,     T1,     T1,     MT      ),
      ASSH_BOP_MOVE(    S,      T1                      ),
      ASSH_BOP_MOVE(    S_raw,  S                       ),

      ASSH_BOP_END(),
    };

    ASSH_JMP_ON_ERR(assh_bignum_bytecode(c, 0, bytecode2, "MddddsTTTmT",
      curve->l, hram, az, r, s_str, (size_t)(n * 8)), err_scratch);
  }

  ASSH_SCRATCH_FREE(c, sc);
  return ASSH_OK;

 err_scratch:
  ASSH_SCRATCH_FREE(c, sc);
 err_:
  return err;
}

static ASSH_SIGN_CHECK_FCN(assh_sign_eddsa_check)
{
  const struct assh_key_eddsa_s *k = (const void*)key;
  assh_status_t err;

  const struct assh_edward_curve_s *curve = k->curve;
  const struct assh_hash_algo_s *hash = k->hash;

  size_t n = ASSH_ALIGN8(k->curve->bits) / 8;
  size_t tlen = strlen(k->key.algo->name);

  ASSH_RET_IF_TRUE(sign_len != 4 + tlen + 4 + 2 * n, ASSH_ERR_INPUT_OVERFLOW);

  ASSH_RET_IF_TRUE(tlen != assh_load_u32(sign), ASSH_ERR_BAD_DATA);
  ASSH_RET_IF_TRUE(memcmp(sign + 4, k->key.algo->name, tlen), ASSH_ERR_BAD_DATA);

  uint8_t *rs_str = (uint8_t*)sign + 4 + tlen;
  ASSH_RET_IF_TRUE(assh_load_u32(rs_str) != n * 2, ASSH_ERR_INPUT_OVERFLOW);

  const uint8_t *kp = k->data;

  ASSH_SCRATCH_ALLOC(c, uint8_t, sc,
    hash->ctx_size + /* hram */ n * 2 + /* rx */ n + /* ry */ n,
                     ASSH_ERRSV_CONTINUE, err_);

  void    *hash_ctx = sc;
  uint8_t *hram = sc + hash->ctx_size;
  uint8_t *rx = hram + 2 * n;
  uint8_t *ry = rx + n;

  uint_fast8_t i;

  ASSH_JMP_ON_ERR(assh_hash_init(c, hash_ctx, hash), err_scratch);
  assh_hash_update(hash_ctx, rs_str + 4, n);
  assh_hash_update(hash_ctx, kp, n);
  for (i = 0; i < data_count; i++)
    assh_hash_update(hash_ctx, data[i].data, data[i].len);
  assh_hash_final(hash_ctx, hram, n * 2);
  assh_hash_cleanup(hash_ctx);

#ifdef CONFIG_ASSH_DEBUG_SIGN
  ASSH_DEBUG_HEXDUMP("pub", kp, n);
#endif

  /* key X sign bit as mpint */
  uint8_t kx_sign = kp[n - 1] & 0x80;

  enum {
    /* in */
    BX_mpint, BY_mpint, A_mpint, P_mpint, D_mpint, I_mpint,
    P_n, KY_raw, SC1_raw, SC2_raw, SC2_size,
    /* out */
    RX_raw, RY_raw,
    /* temp */
    P, A, D, T0, T1,
    BX, BY, BZ,  RX, RY, RZ,  PX, PY, PZ,
    QX, QY, QZ, MT, SC1, SC2, U = PY, V = PZ
  };

  static const assh_bignum_op_t bytecode[] = {
    ASSH_BOP_SIZER(     P,      MT,     P_n             ),
    ASSH_BOP_SIZEM(     SC1,    SC2_size, 0, 1          ),
    ASSH_BOP_SIZE(      SC2,    SC2_size                ),

    ASSH_BOP_MOVE(      SC1,    SC1_raw                 ),
    ASSH_BOP_MOVE(      SC2,    SC2_raw                 ),
    ASSH_BOP_MOVE(      P,      P_mpint                 ),
    ASSH_BOP_MOVE(      A,      A_mpint                 ),
    ASSH_BOP_MOVE(      D,      D_mpint                 ),

    ASSH_BOP_MOVE(      BY,     KY_raw                  ),

    /* u = y^2-1, v = d*y^2-a */
    ASSH_BOP_MTINIT(    MT,     P                       ),
    ASSH_BOP_MTTO(      A,      D,      A,      MT      ),
    ASSH_BOP_MTTO(      BY,     BY,     BY,     MT      ),

    ASSH_BOP_MULM(      U,      BY,     BY,     MT      ),
    ASSH_BOP_MULM(      V,      U,      D,      MT      ),
    ASSH_BOP_MTUINT(    T0,     1,              MT      ),
    ASSH_BOP_SUBM(      U,      U,      T0,     MT      ),
    ASSH_BOP_SUBM(      V,      V,      A,      MT      ),

    /* compute x = sqrt(u/v), the method depends on the value of P.
       This is tricky when p%8 == 1 (does not occur in used curves) */

    ASSH_BOP_TEST(      P,      1,      ASSH_BOP_NOREG,      0  ),
    ASSH_BOP_CJMP(      24,     0,      0                       ),

    /*** case p%8 == 5: x = (uv^3)*(uv^7)^((p-5)/8) */

    /* v3 = v^3 */
    ASSH_BOP_MULM(      T0,     V,      V,      MT      ),
    ASSH_BOP_MULM(      T1,     T0,     V,      MT      ),

    /* x = uv^7 */
    ASSH_BOP_MULM(      PX,     T1,     T1,     MT      ),
    ASSH_BOP_MULM(      PX,     PX,     V,      MT      ),
    ASSH_BOP_MULM(      PX,     PX,     U,      MT      ),

    /* x = (uv^7)^((p-5)/8) */
    ASSH_BOP_UINT(      T0,     5                       ),
    ASSH_BOP_SUB(       T0,     P,      T0              ),
    ASSH_BOP_SHR(       T0,     T0,     3,      ASSH_BOP_NOREG  ),
    ASSH_BOP_EXPM(      BX,     PX,     T0,     MT      ),

    /* x = (uv^3)*(uv^7)^((p-5)/8) */
    ASSH_BOP_MULM(      BX,     BX,     T1,     MT      ),
    ASSH_BOP_MULM(      BX,     BX,     U,      MT      ),

    /* check v*x^2 == +/-u */
    ASSH_BOP_MULM(      PX,     BX,     BX,     MT      ),
    ASSH_BOP_MULM(      PX,     PX,     V,      MT      ),

    ASSH_BOP_SUBM(      T0,     PX,     U,      MT      ),
    ASSH_BOP_ADDM(      T1,     PX,     U,      MT      ),

    ASSH_BOP_MTFROM(    T0,     BX,     T0,     MT      ),

    ASSH_BOP_UINT(      PX,     0                       ),
    ASSH_BOP_CMPEQ(     T0,     PX,     0               ),
    ASSH_BOP_CJMP(      21,     0,      0               ),
    ASSH_BOP_CMPEQ(     T1,     PX,     0               ),
    ASSH_BOP_CFAIL(     1,      0                       ),
    ASSH_BOP_MOVE(      T0,     I_mpint                 ),
    ASSH_BOP_MULM(      BX,     BX,     T0,     P       ),
    ASSH_BOP_JMP(       16                              ),

    /*** case p%4 == 3: x = (uv)*(uv^3)^((p-3)/4) */

    /* x = uv^3 */
    ASSH_BOP_MULM(      PX,     V,      V,      MT      ),
    ASSH_BOP_MULM(      PX,     PX,     V,      MT      ),
    ASSH_BOP_MULM(      PX,     PX,     U,      MT      ),

    /* x = (uv^3)^((p-3)/4) */
    ASSH_BOP_UINT(      T0,     3                       ),
    ASSH_BOP_SUB(       T0,     P,      T0              ),
    ASSH_BOP_SHR(       T0,     T0,     2,      ASSH_BOP_NOREG  ),
    ASSH_BOP_EXPM(      BX,     PX,     T0,     MT      ),

    /* x = (uv)*(uv^3)^((p-3)/4) */
    ASSH_BOP_MULM(      BX,     BX,     U,      MT      ),
    ASSH_BOP_MULM(      BX,     BX,     V,      MT      ),

    /* check v*x^2 == u */
    ASSH_BOP_MULM(      PX,     BX,     BX,     MT      ),
    ASSH_BOP_MULM(      PX,     PX,     V,      MT      ),

    ASSH_BOP_SUBM(      T1,     PX,     U,      MT      ),

    ASSH_BOP_MTFROM(    T1,     BX,     T1,     MT      ),
    ASSH_BOP_UINT(      PX,     0                       ),
    ASSH_BOP_CMPEQ(     T1,     PX,     0               ),
    ASSH_BOP_CFAIL(     1,      0                       ),

    /***********/

    /* x = -x if sign of x does not match sign bit in encoded key */
    ASSH_BOP_TEST(      BX,     0,      ASSH_BOP_NOREG,      0  ),
    ASSH_BOP_BOOL(      0,      0,      /* kx sign */ 7,
                        ASSH_BOP_BOOL_XOR               ),
    ASSH_BOP_CJMP(      1,      0,      0               ),
    ASSH_BOP_SUB(       BX,     P,      BX              ),

#ifdef CONFIG_ASSH_DEBUG_SIGN
    ASSH_BOP_PRINT(     BX,     'X'                     ),
    ASSH_BOP_PRINT(     BY,     'Y'                     ),
#endif
    ASSH_BOP_MTUINT(    BZ,     1,      MT              ),

    /* compute H(R,A,M).A */
    ASSH_BOP_MTUINT(    RX,     0,      MT              ),
    ASSH_BOP_MTUINT(    RY,     1,      MT              ),
    ASSH_BOP_MTUINT(    RZ,     1,      MT              ),

    ASSH_BOP_MTTO(      BX,     BX,     BX,     MT      ),
    ASSH_BOP_LADINIT(   SC1                             ),

    ASSH_BOP_TEDWARD_PDBL( PX, PY, PZ,  RX, RY, RZ,
                           T0, T1, MT                   ),
    ASSH_BOP_LADTEST(   SC1,     0                      ),
    ASSH_BOP_CJMP(      4,       0,      0              ),
    ASSH_BOP_MOVE(      RX,     PX                      ),
    ASSH_BOP_MOVE(      RY,     PY                      ),
    ASSH_BOP_MOVE(      RZ,     PZ                      ),
    ASSH_BOP_JMP(       20                              ),
    ASSH_BOP_TEDWARD_PADD( RX, RY, RZ,  PX, PY, PZ,
                           BX, BY, BZ,  T0, T1, A, D, MT ),
    ASSH_BOP_LADNEXT(   0                               ),
    ASSH_BOP_CJMP(      -43,    0,      0               ),

    /* compute S.B */
    ASSH_BOP_MOVE(      BX,     BX_mpint                ),
    ASSH_BOP_MOVE(      BY,     BY_mpint                ),
    ASSH_BOP_MTUINT(    BZ,     1,      MT              ),

    ASSH_BOP_MTUINT(    QX,     0,      MT              ),
    ASSH_BOP_MTUINT(    QY,     1,      MT              ),
    ASSH_BOP_MTUINT(    QZ,     1,      MT              ),

    ASSH_BOP_MTTO(      BX,     BY,     BX,     MT      ),
    ASSH_BOP_LADINIT(   SC2                             ),

    ASSH_BOP_TEDWARD_PDBL( PX, PY, PZ,  QX, QY, QZ,
                           T0, T1, MT                   ),
    ASSH_BOP_LADTEST(   SC2,    0                       ),
    ASSH_BOP_CJMP(      4,      0,      0               ),
    ASSH_BOP_MOVE(      QX,     PX                      ),
    ASSH_BOP_MOVE(      QY,     PY                      ),
    ASSH_BOP_MOVE(      QZ,     PZ                      ),
    ASSH_BOP_JMP(       20                              ),
    ASSH_BOP_TEDWARD_PADD( QX, QY, QZ,  PX, PY, PZ,
                           BX, BY, BZ,  T0, T1, A, D, MT ),
    ASSH_BOP_LADNEXT(   0                               ),
    ASSH_BOP_CJMP(      -43,    0,      0               ),

    /* compute S.B + H(R,A,M).A */
    ASSH_BOP_TEDWARD_PADD( PX, PY, PZ,  RX, RY, RZ,
                           QX, QY, QZ,  T0, T1, A, D, MT ),

    ASSH_BOP_MTFROM(    PX,     PZ,     PX,     MT      ),
    ASSH_BOP_INV(       T0,     PZ,     P               ),
    ASSH_BOP_MULM(      RX,     PX,     T0,     P       ),
    ASSH_BOP_MULM(      RY,     PY,     T0,     P       ),

    ASSH_BOP_MOVE(      RX_raw, RX                      ),
    ASSH_BOP_MOVE(      RY_raw, RY                      ),

    ASSH_BOP_END(),
  };

  ASSH_JMP_ON_ERR(assh_bignum_bytecode(c, kx_sign, bytecode,
          "MMMMMMsdddsddTTTTTTTTTTTTTTTTTmTT", curve->bx, curve->by,
          curve->a, curve->p, curve->d, curve->i,
          (size_t)curve->bits, kp,
          hram, rs_str + 4 + n, (size_t)(n * 8), /* scalars */
          rx, ry), err_scratch);

  /* encode point */
  assh_edward_encode(curve, ry, rx);

#ifdef CONFIG_ASSH_DEBUG_SIGN
  ASSH_DEBUG_HEXDUMP("hram", hram, 2 * n);
  ASSH_DEBUG_HEXDUMP("sign", rs_str + 4, 2 * n);
  ASSH_DEBUG_HEXDUMP("rxy", ry, n);
#endif

  ASSH_JMP_IF_TRUE(assh_memcmp(rs_str + 4, ry, n),
               ASSH_ERR_NUM_COMPARE_FAILED, err_scratch);

  err = ASSH_OK;

 err_scratch:
  ASSH_SCRATCH_FREE(c, sc);
 err_:
  return err;
}


static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_ed25519_suitable_key)
{
  if (key == NULL)
    return c->type == ASSH_SERVER;
  return key->algo == &assh_key_ed25519;
}

const struct assh_algo_sign_s assh_sign_ed25519 =
{
  ASSH_ALGO_BASE(SIGN, "assh-builtin", 50, 90,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_COMMON,
                      "ssh-ed25519" }),
    .f_suitable_key = assh_sign_ed25519_suitable_key,
    .key = &assh_key_ed25519,
    .nondeterministic = 1,
  ),
  .f_generate = assh_sign_eddsa_generate,
  .f_check = assh_sign_eddsa_check,
};


static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_eddsa_e382_suitable_key)
{
  if (key == NULL)
    return c->type == ASSH_SERVER;
  return key->algo == &assh_key_eddsa_e382;
}

const struct assh_algo_sign_s assh_sign_eddsa_e382 =
{
  ASSH_ALGO_BASE(SIGN, "assh-builtin", 70, 80,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_ASSH,
                      "eddsa-e382-shake256@libassh.org" }),
    .f_suitable_key = assh_sign_eddsa_e382_suitable_key,
    .key = &assh_key_eddsa_e382,
    .nondeterministic = 1,
  ),
  .f_generate = assh_sign_eddsa_generate,
  .f_check = assh_sign_eddsa_check,
};


static ASSH_ALGO_SUITABLE_KEY_FCN(assh_sign_eddsa_e521_suitable_key)
{
  if (key == NULL)
    return c->type == ASSH_SERVER;
  return key->algo == &assh_key_eddsa_e521;
}

const struct assh_algo_sign_s assh_sign_eddsa_e521 =
{
  ASSH_ALGO_BASE(SIGN, "assh-builtin", 90, 70,
    ASSH_ALGO_NAMES({ ASSH_ALGO_STD_PRIVATE | ASSH_ALGO_ASSH,
                      "eddsa-e521-shake256@libassh.org" }),
    .f_suitable_key = assh_sign_eddsa_e521_suitable_key,
    .key = &assh_key_eddsa_e521,
    .nondeterministic = 1,
  ),
  .f_generate = assh_sign_eddsa_generate,
  .f_check = assh_sign_eddsa_check,
};
