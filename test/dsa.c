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


#include <assh/assh_bignum.h>
#include <assh/assh_context.h>

#ifdef CONFIG_ASSH_USE_GCRYPT
# include <gcrypt.h>
#endif

static const unsigned int n = 160, l = 512;

static const char *hex_pn = "d411a4a0e393f6aab0f08b14d18458665b3e4dbdce2544543fe365cf71c8622412db6e7dd02bbe13d88c58d7263e90236af17ac8a9fe5f249cc81f427fc543f7";
static const char *hex_qn = "b20db0b101df0c6624fc1392ba55f77d577481e5";
static const char *hex_gn = "b3085510021f999049a9e7cd3872ce9958186b5007e7adaf25248b58a3dc4f71781d21f2df89b71747bd54b323bbecc443ec1d3e020dadabbf7822578255c104";
static const char *hex_yn = "b32fbec03175791df08c3f861c81df7de7e0cba7f1c4f7269bb12d6c628784fb742e66ed315754dfe38b5984e94d372537f655cb3ea4767c878cbd2d783ee662";
static const char *hex_xn = "6b2cd935d0192d54e2c942b574c80102c8f8ef67";
static const char *hex_kn = "79577ddcaafddc038b865b19f8eb1ada8a2838c6";
static const char *hex_m  =  "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880";

assh_error_t dsa_generate(struct assh_context_s *c,
                          struct assh_bignum_s *rn,
                          struct assh_bignum_s *sn)
{
  assh_error_t err;

  enum bytecode_args_e
  {
    /* input hex strings */
    P_hex, Q_hex, G_hex, Y_hex, X_hex, K_hex, M_hex,
    /* output values */
    R, S,
    /* temporary numbers from input strings */
    P, Q, G, Y, X, K, M,
    /* temporary numbers */
    R1, R2, R3
  };

  assh_bignum_op_t bytecode[] = {
    ASSH_BIGNUM_BC_MOVE(        P,      P_hex           ),
    ASSH_BIGNUM_BC_MOVE(        Q,      Q_hex           ),
    ASSH_BIGNUM_BC_MOVE(        G,      G_hex           ),
    ASSH_BIGNUM_BC_MOVE(        K,      K_hex           ),
    ASSH_BIGNUM_BC_MOVE(        M,      M_hex           ),
    ASSH_BIGNUM_BC_MOVE(        X,      X_hex           ),

    /* g^k mod p */
    ASSH_BIGNUM_BC_SETMOD(      P                       ),
    ASSH_BIGNUM_BC_EXPMOD(      R3,     G,      K       ),

    /* r = (g^k mod p) mod q */
    ASSH_BIGNUM_BC_DIV(         R3,     Q,      Q       ),
    ASSH_BIGNUM_BC_MOVE(        R,      R3              ),

    /* (x * r) mod q */
    ASSH_BIGNUM_BC_SETMOD(      Q                       ),
    ASSH_BIGNUM_BC_MULMOD(      R1,     X,      R       ),

    /* sha(m) + (x * r) */
    ASSH_BIGNUM_BC_ADD(         R2,     M,      R1      ),

    /* k^-1 */
    ASSH_BIGNUM_BC_MODINV(      R1,     K,      Q       ),

    /* s = k^-1 * (sha(m) + (x * r)) mod q */
    ASSH_BIGNUM_BC_MULMOD(      S,      R1,     R2      ),
    ASSH_BIGNUM_BC_END(),
  };

  ASSH_ERR_RET(assh_bignum_bytecode(c, bytecode,
              /* format */  /* hex */ "HHHHHHH" /* r, s */ "NN" /* temps: */ "TTTTTTT" "TTT",
              /* char* */   hex_pn, hex_qn, hex_gn, hex_yn, hex_xn, hex_kn, hex_m ,
              /* bignum* */ rn, sn,
              /* size */    /* p, q, g, y, x, k, m */ l, n, l, l, n, n, n,
              /* size */    /* r1, r2, r3 */ n, n + 1, l));

  return ASSH_OK;
}

assh_error_t dsa_verify(struct assh_context_s *c,
                        struct assh_bignum_s *rn,
                        struct assh_bignum_s *sn,
                        struct assh_bignum_s *vn)
{
  assh_error_t err;

  enum bytecode_args_e
  {
    /* input hex strings */
    P_hex, Q_hex, G_hex, Y_hex, M_hex,
    /* input values */
    R, S,
    /* output values */
    V,
    /* temporary numbers from input strings */
    P, Q, G, Y, M,
    /* temporary numbers */
    W, U1, V1, U2, V2
  };

  assh_bignum_op_t bytecode[] = {
    ASSH_BIGNUM_BC_MOVE(        P,      P_hex           ),
    ASSH_BIGNUM_BC_MOVE(        Q,      Q_hex           ),
    ASSH_BIGNUM_BC_MOVE(        G,      G_hex           ),
    ASSH_BIGNUM_BC_MOVE(        Y,      Y_hex           ),
    ASSH_BIGNUM_BC_MOVE(        M,      M_hex           ),

    ASSH_BIGNUM_BC_MODINV(      W,      S,      Q       ),

    /* (sha(m) * w) mod q */
    ASSH_BIGNUM_BC_SETMOD(      Q                       ),
    ASSH_BIGNUM_BC_MULMOD(      U1,     M,      W       ),

    /* g^u1 */
    ASSH_BIGNUM_BC_SETMOD(      P                       ),
    ASSH_BIGNUM_BC_EXPMOD(      V1,     G,      U1      ),

    /* r * w mod q */
    ASSH_BIGNUM_BC_SETMOD(      Q                       ),
    ASSH_BIGNUM_BC_MULMOD(      U2,     R,      W       ),

    /* y^u2 */
    ASSH_BIGNUM_BC_SETMOD(      P                       ),
    ASSH_BIGNUM_BC_EXPMOD(      V2,     Y,      U2      ),

    /* (g^u1 * y^u2) mod p */
    ASSH_BIGNUM_BC_MULMOD(      Y,      V1,     V2      ),

    /* v = (g^u1 * y^u2) mod p mod q */
    ASSH_BIGNUM_BC_DIV(         Y,      Q,      Q       ),
    ASSH_BIGNUM_BC_MOVE(        V,      Y               ),

    ASSH_BIGNUM_BC_CMPEQ(       V,      R               ),
    ASSH_BIGNUM_BC_END(),
  };

  ASSH_ERR_RET(assh_bignum_bytecode(c, bytecode,
              /* format */  /* hex */ "HHHHH" /* r, s, v */ "NNN" /* temps: */ "TTTTT" "TTTTT",
              /* char* */   hex_pn, hex_qn, hex_gn, hex_yn, hex_m ,
              /* bignum* */ rn, sn, vn,
              /* size */    /* p, q, g, y, m */ l, n, l, l, n,
              /* size */    /* w, u1, v1, u2, v2 */ n, n, l, n, l));

  return ASSH_OK;
}

int main()
{
  assh_error_t err;
  struct assh_context_s context;

#ifdef CONFIG_ASSH_USE_GCRYPT
  if (!gcry_check_version(GCRYPT_VERSION))
    return -1;
#endif

  assh_context_init(&context, ASSH_SERVER);

  ASSH_BIGNUM_ALLOC(&context, rn, n, ASSH_ERRSV_CONTINUE, err_);
  ASSH_BIGNUM_ALLOC(&context, sn, n, ASSH_ERRSV_CONTINUE, err_);

  dsa_generate(&context, rn, sn);

  assh_bignum_print(stderr, "r", rn);
  assh_bignum_print(stderr, "s", sn);

  ASSH_BIGNUM_ALLOC(&context, vn, n, ASSH_ERRSV_CONTINUE, err_);

  dsa_verify(&context, rn, sn, vn);

  assh_bignum_print(stderr, "v", vn);

  ASSH_ERR_RET(assh_bignum_cmp(vn, rn) ? ASSH_ERR_BAD_DATA : 0);

  ASSH_ERR_RET(assh_bignum_from_hex(rn, NULL, "9b77f7054c81531c4e46a4692fbfe0f77f7ebff2", n / 4));
  ASSH_ERR_RET(assh_bignum_cmp(vn, rn) ? ASSH_ERR_BAD_DATA : 0);

 err_:
  return 0;
}

