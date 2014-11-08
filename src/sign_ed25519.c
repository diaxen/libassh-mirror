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

#include <assh/assh_packet.h>
#include <assh/assh_bignum.h>
#include <assh/assh_sign.h>
#include <assh/key_ed25519.h>
#include <assh/assh_hash.h>
#include <assh/assh_prng.h>
#include <assh/assh_alloc.h>

#include "ecc_bop.h"

#include <string.h>

/* a*x^2+y^2=1+d*x^2y^2 */
const struct assh_edward_curve_s assh_ed25519_curve = 
{
  .p =  (const uint8_t *)"\x00\x00\x00\x20"
        "\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xed",
  .l =  (const uint8_t *)"\x00\x00\x00\x20" /* order */
        "\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x14\xde\xf9\xde\xa2\xf7\x9c\xd6\x58\x12\x63\x1a\x5c\xf5\xd3\xed",
  .bx = (const uint8_t *)"\x00\x00\x00\x20" /* basepoint x */
        "\x21\x69\x36\xd3\xcd\x6e\x53\xfe\xc0\xa4\xe2\x31\xfd\xd6\xdc\x5c"
        "\x69\x2c\xc7\x60\x95\x25\xa7\xb2\xc9\x56\x2d\x60\x8f\x25\xd5\x1a",
  .by = (const uint8_t *)"\x00\x00\x00\x20" /* basepoint y */
        "\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66"
        "\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x58",
  .a =  (const uint8_t *)"\x00\x00\x00\x20"
        "\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xec",
  .d =  (const uint8_t *)"\x00\x00\x00\x20"
        "\x52\x03\x6c\xee\x2b\x6f\xfe\x73\x8c\xc7\x40\x79\x77\x79\xe8\x98"
        "\x00\x70\x0a\x4d\x41\x41\xd8\xab\x75\xeb\x4d\xca\x13\x59\x78\xa3",
  .i =  (const uint8_t *)"\x00\x00\x00\x20" /* sqrt(-1) */
        "\x2b\x83\x24\x80\x4f\xc1\xdf\x0b\x2b\x4d\x00\x99\x3d\xfb\xd7\xa7"
        "\x2f\x43\x18\x06\xad\x2f\xe4\x78\xc4\xee\x1b\x27\x4a\x0e\xa0\xb0",
  .bits = 255,
  .cofactor = 8,
};

static ASSH_SIGN_GENERATE_FCN(assh_sign_ed25519_generate)
{
  struct assh_key_ed25519_s *k = (void*)key;
  assh_error_t err;

  const struct assh_edward_curve_s *curve = &assh_ed25519_curve;
  const struct assh_hash_algo_s *algo = &assh_hash_sha512;

  /* check availability of the private key */
  ASSH_CHK_RET(!k->private, ASSH_ERR_MISSING_KEY);

  size_t n = 32;

  /* check/return signature length */
  size_t len = assh_ed25519_id_len + 4 + 2 * n;

  if (sign == NULL)
    {
      *sign_len = len;
      return ASSH_OK;
    }

  ASSH_CHK_RET(*sign_len < len, ASSH_ERR_OUTPUT_OVERFLOW);
  *sign_len = len;

  memcpy(sign, assh_ed25519_id, assh_ed25519_id_len);
  assh_store_u32(sign + assh_ed25519_id_len, 2 * n);
  uint8_t *r_str = sign + assh_ed25519_id_len + 4;
  uint8_t *s_str = r_str + n;

  struct scratch_s
  {
    uint8_t h[64];
    uint8_t r[64];
    uint8_t hram[64];
    uint8_t az[64];
    uint8_t rx[32];
    uint8_t hash_ctx[0];
  };

  ASSH_SCRATCH_ALLOC(c, struct scratch_s, sc,
		     sizeof(struct scratch_s) +
                     algo->ctx_size,
		     ASSH_ERRSV_CONTINUE, err_);

  void *hash_ctx = sc->hash_ctx;
  unsigned int i;

  ASSH_ERR_GTO(assh_hash_init(c, hash_ctx, algo), err_scratch);
  assh_hash_update(hash_ctx, k->s, n);
  assh_hash_final(hash_ctx, sc->h);

#ifdef CONFIG_ASSH_DEBUG_SIGN
  assh_hexdump("h", sc->h, 64);
#endif

  /* a is h[0,31] */
  assh_edward_adjust(curve, sc->h);

  /* r */
  ASSH_ERR_GTO(assh_hash_init(c, hash_ctx, algo), err_scratch);
  assh_hash_update(hash_ctx, sc->h + n, n);
  for (i = 0; i < data_count; i++)
    assh_hash_update(hash_ctx, data[i], data_len[i]);
  assh_hash_final(hash_ctx, sc->r);

#ifdef CONFIG_ASSH_DEBUG_SIGN
  assh_hexdump("r", sc->r, 64);
#endif

  struct assh_bignum_mlad_s mlad = {
    .data = sc->r,
    .count = n * 8 * 2,
    .msbyte_1st = 0,
    .msbit_1st = 1,
  };

  {
    enum {
      BX_mpint, BY_mpint, A_mpint, P_mpint, D_mpint, L, Size, /* in */
      RX_raw, RY_raw,                                      /* out */
      P, A, D, T0, T1,                                     /* temp */
      RX, RY, RZ,  BX, BY, BZ,  PX, PY, PZ,  QX, QY, QZ
    };

    static const assh_bignum_op_t bytecode1[] = {

      ASSH_BOP_SIZER(     P,      QZ,     Size            ),

      /* init */
      ASSH_BOP_MOVE(      P,      P_mpint                 ),
      ASSH_BOP_MOVE(      A,      A_mpint                 ),
      ASSH_BOP_MOVE(      D,      D_mpint                 ),

      ASSH_BOP_UINT(      RX,     0                       ),
      ASSH_BOP_UINT(      RY,     1                       ),
      ASSH_BOP_UINT(      RZ,     1                       ),
      ASSH_BOP_MOVE(      BX,     BX_mpint                ),
      ASSH_BOP_MOVE(      BY,     BY_mpint                ),
      ASSH_BOP_UINT(      BZ,     1                       ),

      /* ladder */
      ASSH_BOP_TEDWARD_PDBL( PX, PY, PZ,  RX, RY, RZ,
                             T0, T1, P                    ),

      ASSH_BOP_TEDWARD_PADD( QX, QY, QZ,  PX, PY, PZ,
                             BX, BY, BZ,  T0, T1, A, D, P ),

      ASSH_BOP_MOVE(      RX,     PX                      ),
      ASSH_BOP_MOVE(      RY,     PY                      ),
      ASSH_BOP_MOVE(      RZ,     PZ                      ),

      ASSH_BOP_MLADSWAP(  RX,     QX,     L               ),
      ASSH_BOP_MLADSWAP(  RY,     QY,     L               ),
      ASSH_BOP_MLADSWAP(  RZ,     QZ,     L               ),

      ASSH_BOP_MLADLOOP(  42,             L               ),

      /* projective to affine */
      ASSH_BOP_INV_C(     T0,     RZ,     P               ),
      ASSH_BOP_MULM(      RX,     RX,     T0,     P       ),
      ASSH_BOP_MULM(      RY,     RY,     T0,     P       ),

      ASSH_BOP_MOVE(      RX_raw, RX                      ),
      ASSH_BOP_MOVE(      RY_raw, RY                      ),

      ASSH_BOP_END(),
    };

    ASSH_ERR_GTO(assh_bignum_bytecode(c, bytecode1,
      "MMMMMLsddTTTTTTTTTTTTTTTTTTTTT", curve->bx, curve->by,
      curve->a, curve->p, curve->d, &mlad, curve->bits, sc->rx, r_str), err_scratch);
  }

  /* encode point */
  assh_edward_encode(curve, r_str, sc->rx);

#ifdef CONFIG_ASSH_DEBUG_SIGN
  assh_hexdump("rxy", r_str, 32);
#endif

  /* hram */
  ASSH_ERR_GTO(assh_hash_init(c, hash_ctx, algo), err_scratch);
  assh_hash_update(hash_ctx, r_str, n);
  assh_hash_update(hash_ctx, k->p, n);
  for (i = 0; i < data_count; i++)
    assh_hash_update(hash_ctx, data[i], data_len[i]);
  assh_hash_final(hash_ctx, sc->hram);

#ifdef CONFIG_ASSH_DEBUG_SIGN
  assh_hexdump("hram", sc->hram, 64);
#endif

  ASSH_ERR_GTO(assh_hash_init(c, hash_ctx, algo), err_scratch);
  assh_hash_update(hash_ctx, k->s, n);
  assh_hash_final(hash_ctx, sc->az);

  assh_edward_adjust(curve, sc->az);

#ifdef CONFIG_ASSH_DEBUG_SIGN
  assh_hexdump("az", sc->az, 64);
#endif

  {
    enum {
      L_mpint, H_raw, AZ_raw, R_raw, S_raw, Size,
      AZ, L, S, H, R
    };

    static const assh_bignum_op_t bytecode2[] = {

      ASSH_BOP_SIZER(     AZ,     S,      Size            ),
      ASSH_BOP_SIZEM(     H,      Size,   0,      1       ),
      ASSH_BOP_SIZE(      R,      H                       ),

      ASSH_BOP_MOVE(      L,      L_mpint                 ),
      ASSH_BOP_MOVE(      H,      H_raw                   ),
      ASSH_BOP_MOVE(      R,      R_raw                   ),
      ASSH_BOP_MOVE(      AZ,     AZ_raw                  ),

      ASSH_BOP_MULM(      S,     H,     AZ,      L        ),
      ASSH_BOP_ADDM(      S,     S,     R,       L        ),

      ASSH_BOP_MOVE(      S_raw,  S                       ),

      ASSH_BOP_END(),
    };

    ASSH_ERR_GTO(assh_bignum_bytecode(c, bytecode2, "MddddsTTTTT",
      curve->l, sc->hram, sc->az, sc->r, s_str, n*8), err_scratch);
  }

  ASSH_SCRATCH_FREE(c, sc);
  return ASSH_OK;

 err_hash:
  assh_hash_final(hash_ctx, NULL);
 err_scratch:
  ASSH_SCRATCH_FREE(c, sc);
 err_:
  return err;
}

static ASSH_SIGN_VERIFY_FCN(assh_sign_ed25519_verify)
{
  struct assh_key_ed25519_s *k = (void*)key;
  assh_error_t err;

  const struct assh_edward_curve_s *curve = &assh_ed25519_curve;
  const struct assh_hash_algo_s *algo = &assh_hash_sha512;

  size_t n = 32;

  ASSH_CHK_RET(sign_len != assh_ed25519_id_len + 4 + 2 * n, ASSH_ERR_INPUT_OVERFLOW);

  ASSH_CHK_RET(memcmp(sign, assh_ed25519_id, assh_ed25519_id_len), ASSH_ERR_BAD_DATA);

  uint8_t *rs_str = (uint8_t*)sign + assh_ed25519_id_len;
  ASSH_CHK_RET(assh_load_u32(rs_str) != n * 2, ASSH_ERR_INPUT_OVERFLOW);

  struct scratch_s
  {
    uint8_t hram[64];
    uint8_t ry[64];
    uint8_t rx[32];
    uint8_t hash_ctx[0];
  };

  ASSH_SCRATCH_ALLOC(c, struct scratch_s, sc,
		     sizeof(struct scratch_s) +
                     algo->ctx_size,
		     ASSH_ERRSV_CONTINUE, err_);

  void *hash_ctx = sc->hash_ctx;
  unsigned int i;

  ASSH_ERR_GTO(assh_hash_init(c, hash_ctx, algo), err_scratch);
  assh_hash_update(hash_ctx, rs_str + 4, n);
  assh_hash_update(hash_ctx, k->p, n);
  for (i = 0; i < data_count; i++)
    assh_hash_update(hash_ctx, data[i], data_len[i]);
  assh_hash_final(hash_ctx, sc->hram);

#ifdef CONFIG_ASSH_DEBUG_SIGN
  assh_hexdump("pub", k->p, n);
#endif

  /* key X sign bit as mpint */
  uint8_t kx[5] = { 0, 0, 0, 1, k->p[n-1] >> 7 };

  struct assh_bignum_mlad_s mlad1 = {
    .data = sc->hram,
    .count = n * 8 * 2,
    .msbyte_1st = 0,
    .msbit_1st = 1,
  };

  struct assh_bignum_mlad_s mlad2 = {
    .data = rs_str + 4 + n,
    .count = n * 8,
    .msbyte_1st = 0,
    .msbit_1st = 1,
  };

  enum {
    /* in */
    BX_mpint, BY_mpint, A_mpint, P_mpint, D_mpint, I_mpint, L1, L2, Size,
    KY_raw, KX_mpint,
    /* out */
    RX_raw, RY_raw,
    /* temp */
    P, A, D, T0, T1,
    RX, RY, RZ,  BX, BY, BZ,  PX, PY, PZ,  QX, QY, QZ, U = PY, V = PZ,
  };

  static const assh_bignum_op_t bytecode[] = {

    ASSH_BOP_SIZER(     P,      QZ,     Size            ),

    ASSH_BOP_MOVE(      P,      P_mpint                 ),
    ASSH_BOP_MOVE(      A,      A_mpint                 ),
    ASSH_BOP_MOVE(      D,      D_mpint                 ),

    ASSH_BOP_MOVE(      BY,     KY_raw                  ),

    /* u = y^2-1, v = dy^2+1 */
    ASSH_BOP_UINT(      T0,     1                       ),
    ASSH_BOP_MULM(      U,      BY,     BY,     P       ),
    ASSH_BOP_MULM(      V,      U,      D,      P       ),
    ASSH_BOP_SUBM(      U,      U,      T0,     P       ),
    ASSH_BOP_ADDM(      V,      V,      T0,     P       ),

    /* compute sqrt(u/v), the method depends on the value of P.
       This is tricky when p%8 == 1 (does not occur in ed curves
       evulated at http://safecurves.cr.yp.to/) */

    ASSH_BOP_TESTS(     P,      1,      ASSH_BOP_NOREG,  12       ),

    /*********** x = (uv^3)*(uv^7)^((p-5)/8) if p%8 == 5 ************/

    /* v3 = v^3 */
    ASSH_BOP_MULM(      T1,     V,      V,      P       ),
    ASSH_BOP_MULM(      T1,     T1,     V,      P       ),

    /* x = uv^7 */
    ASSH_BOP_MULM(      PX,     T1,     T1,     P       ),
    ASSH_BOP_MULM(      PX,     PX,     V,      P       ),
    ASSH_BOP_MULM(      PX,     PX,     U,      P       ),

    /* x = (uv^7)^((p-5)/8) */
    ASSH_BOP_UINT(      T0,     5                       ),
    ASSH_BOP_SUBM(      T0,     P,      T0,     P       ),
    ASSH_BOP_SHR(       T0,     T0,     3,      ASSH_BOP_NOREG  ),
    ASSH_BOP_EXPM(      BX,     PX,     T0,     P       ),

    /* x = (uv^3)*(uv^7)^((p-5)/8) */
    ASSH_BOP_MULM(      BX,     BX,     T1,     P       ),
    ASSH_BOP_MULM(      BX,     BX,     U,      P       ),

    ASSH_BOP_JMP(       9                               ),

    /*********** x = (uv)*(uv^3)^((p-3)/4) if p%4 == 3 ************/

    /* x = uv^3 */
    ASSH_BOP_MULM(      PX,     V,      V,     P        ),
    ASSH_BOP_MULM(      PX,     PX,     V,     P        ),
    ASSH_BOP_MULM(      PX,     PX,     U,     P        ),

    /* x = (uv^3)^((p-3)/4) */
    ASSH_BOP_UINT(      T0,     3                       ),
    ASSH_BOP_SUBM(      T0,     P,      T0,     P       ),
    ASSH_BOP_SHR(       T0,     T0,     2,      ASSH_BOP_NOREG  ),
    ASSH_BOP_EXPM(      BX,     PX,     T0,     P       ),

    /* x = (uv)*(uv^3)^((p-3)/4) */
    ASSH_BOP_MULM(      BX,     BX,     U,     P        ),
    ASSH_BOP_MULM(      BX,     BX,     V,     P        ),

    /***********/

    /* check v*x^2 == +/-u */
#warning XXX *sqrtm1 move in square case above
    ASSH_BOP_MULM(      PX,     BX,     BX,    P        ),
    ASSH_BOP_MULM(      PX,     PX,     V,     P        ),

    ASSH_BOP_SUBM(      T0,     PX,     U,     P        ),
    ASSH_BOP_ADDM(      T1,     PX,     U,     P        ),

    ASSH_BOP_UINT(      PX,     0                       ),
    ASSH_BOP_CMPEQ(     T0,     PX,     3               ),
    ASSH_BOP_CMPEQ(     T1,     PX,     0 /* abort */   ),
    ASSH_BOP_MOVE(      T0,     I_mpint                 ),
    ASSH_BOP_MULM(      BX,     BX,     T0,     P       ),

    /* x = -x if sign of x does not match sign bit in encoded key */
    ASSH_BOP_TESTS(     BX,     0,      ASSH_BOP_NOREG,  1      ),
    ASSH_BOP_SUBM(      BX,     PX,     BX,     P               ),
    ASSH_BOP_MOVE(      T0,     KX_mpint                        ),
    ASSH_BOP_TESTC(     T0,     0,      ASSH_BOP_NOREG,  1      ),
    ASSH_BOP_SUBM(      BX,     PX,     BX,     P               ),

#ifdef CONFIG_ASSH_DEBUG_SIGN
    ASSH_BOP_PRINT(     BX,     'X'                     ),
    ASSH_BOP_PRINT(     BY,     'Y'                     ),
#endif
    ASSH_BOP_UINT(      BZ,     1                       ),

    /* compute H(R,A,M).A */
    ASSH_BOP_UINT(      RX,     0                       ),
    ASSH_BOP_UINT(      RY,     1                       ),
    ASSH_BOP_UINT(      RZ,     1                       ),

    ASSH_BOP_TEDWARD_PDBL( PX, PY, PZ,  RX, RY, RZ,
                           T0, T1, P                    ),
    ASSH_BOP_MLADJMP(   L1,     4                       ),
    ASSH_BOP_MOVE(      RX,     PX                      ),
    ASSH_BOP_MOVE(      RY,     PY                      ),
    ASSH_BOP_MOVE(      RZ,     PZ                      ),
    ASSH_BOP_JMP(       20                              ),
    ASSH_BOP_TEDWARD_PADD( RX, RY, RZ,  PX, PY, PZ,
                           BX, BY, BZ,  T0, T1, A, D, P ),
    ASSH_BOP_MLADLOOP(  41,     L1                      ),

    /* compute S.B */
    ASSH_BOP_MOVE(      BX,     BX_mpint                ),
    ASSH_BOP_MOVE(      BY,     BY_mpint                ),
    ASSH_BOP_UINT(      BZ,     1                       ),

    ASSH_BOP_UINT(      QX,     0                       ),
    ASSH_BOP_UINT(      QY,     1                       ),
    ASSH_BOP_UINT(      QZ,     1                       ),

    ASSH_BOP_TEDWARD_PDBL( PX, PY, PZ,  QX, QY, QZ,
                           T0, T1, P                    ),
    ASSH_BOP_MLADJMP(   L2,     4                       ),
    ASSH_BOP_MOVE(      QX,     PX                      ),
    ASSH_BOP_MOVE(      QY,     PY                      ),
    ASSH_BOP_MOVE(      QZ,     PZ                      ),
    ASSH_BOP_JMP(       20                              ),
    ASSH_BOP_TEDWARD_PADD( QX, QY, QZ,  PX, PY, PZ,
                           BX, BY, BZ,  T0, T1, A, D, P ),
    ASSH_BOP_MLADLOOP(  41,     L2                      ),

    /* compute S.B + H(R,A,M).A */
    ASSH_BOP_TEDWARD_PADD( PX, PY, PZ,  RX, RY, RZ,
                           QX, QY, QZ,  T0, T1, A, D, P ),

    ASSH_BOP_INV(       T0,     PZ,     P               ),
    ASSH_BOP_MULM(      RX,     PX,     T0,     P       ),
    ASSH_BOP_MULM(      RY,     PY,     T0,     P       ),

    ASSH_BOP_MOVE(      RX_raw, RX                      ),
    ASSH_BOP_MOVE(      RY_raw, RY                      ),

    ASSH_BOP_END(),
  };

  ASSH_ERR_GTO(assh_bignum_bytecode(c, bytecode,
          "MMMMMMLLsdMddTTTTTTTTTTTTTTTTT", curve->bx, curve->by,
          curve->a, curve->p, curve->d, curve->i,
          &mlad1, &mlad2, curve->bits, k->p, kx, sc->rx, sc->ry), err_scratch);

  /* encode point */
  assh_edward_encode(curve, sc->ry, sc->rx);

#ifdef CONFIG_ASSH_DEBUG_SIGN
  assh_hexdump("hram", sc->hram, 64);
  assh_hexdump("sign", rs_str + 4, 64);
  assh_hexdump("rxy", sc->ry, 32);
#endif

  ASSH_CHK_GTO(assh_memcmp(rs_str + 4, sc->ry, n),
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
  .algo = {
    .name = "ssh-ed25519", .class_ = ASSH_ALGO_SIGN,
    .safety = 50, .speed = 40,
    .f_suitable_key = assh_sign_ed25519_suitable_key,
    .key = &assh_key_ed25519,
  },
  .f_generate = assh_sign_ed25519_generate,
  .f_verify = assh_sign_ed25519_verify,
};

