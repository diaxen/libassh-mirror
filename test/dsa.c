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
static const char *hex_m  = "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880";
static const char *hex_r  = "9b77f7054c81531c4e46a4692fbfe0f77f7ebff2";

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
    R1, R2, R3,
    /* bit size */
    N, L
  };

  assh_bignum_op_t bytecode[] = {

    ASSH_BOP_SIZE(	P,	L			),
    ASSH_BOP_MOVE(      P,      P_hex			),

    ASSH_BOP_SIZE(	Q,	N			),
    ASSH_BOP_MOVE(      Q,      Q_hex			),

    ASSH_BOP_SIZE(	G,	L			),
    ASSH_BOP_MOVE(      G,      G_hex			),

    ASSH_BOP_SIZE(	Y,	L			),
    ASSH_BOP_MOVE(      Y,      Y_hex			),

    ASSH_BOP_SIZE(	X,	N			),
    ASSH_BOP_MOVE(      X,      X_hex			),

    ASSH_BOP_SIZE(	K,	N			),
    ASSH_BOP_MOVE(      K,      K_hex			),

    ASSH_BOP_SIZE(	M,	N			),
    ASSH_BOP_MOVE(      M,      M_hex			),

    ASSH_BOP_SIZE(	R1,	N			),
    ASSH_BOP_SIZE(	R2,	N			),
    ASSH_BOP_SIZE(	R3,	L			),

    ASSH_BOP_SIZE(	R,	N			),
    ASSH_BOP_SIZE(	S,	N			),

    /* g^k mod p */
    ASSH_BOP_EXPM(      R3,     G,      K,	P       ),
    /* r = (g^k mod p) mod q */
    ASSH_BOP_MOD(       R,      R3,      Q		),
    /* (x * r) mod q */
    ASSH_BOP_MULM(      R1,     X,      R,	Q	),
    /* sha(m) + (x * r) */
    ASSH_BOP_ADDM(      R2,     M,      R1,	Q       ),
    /* k^-1 */
    ASSH_BOP_INV(       R1,     K,      Q		),
    /* s = k^-1 * (sha(m) + (x * r)) mod q */
    ASSH_BOP_MULM(      S,      R1,     R2,	Q       ),

    ASSH_BOP_PRINT(	R,	0			),
    ASSH_BOP_PRINT(	S,	1			),

    ASSH_BOP_END(),
  };

  ASSH_ERR_RET(assh_bignum_bytecode(c, bytecode,
	      /* hex */ "HHHHHHH"
	      /* r, s */ "NN" /* temps: */ "TTTTTTTTTT"
	      /* sizes */ "ss",

	      /* char* */   hex_pn, hex_qn, hex_gn, hex_yn, hex_xn, hex_kn, hex_m ,
	      /* bignums */ rn, sn, /* bit sizes */ n, l));

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
    W, U1, V1, U2, V2,
    /* bit size */
    N, L
  };

  assh_bignum_op_t bytecode[] = {
    ASSH_BOP_SIZE(	P,	L			),
    ASSH_BOP_MOVE(      P,      P_hex			),

    ASSH_BOP_SIZE(	Q,	N			),
    ASSH_BOP_MOVE(      Q,      Q_hex			),

    ASSH_BOP_SIZE(	G,	L			),
    ASSH_BOP_MOVE(      G,      G_hex			),

    ASSH_BOP_SIZE(	Y,	L			),
    ASSH_BOP_MOVE(      Y,      Y_hex			),

    ASSH_BOP_SIZE(	M,	N			),
    ASSH_BOP_MOVE(      M,      M_hex			),

    ASSH_BOP_SIZE(	V,	N			),

    ASSH_BOP_SIZE(	W,	N			),
    ASSH_BOP_SIZE(	U1,	N			),
    ASSH_BOP_SIZE(	V1,	L			),
    ASSH_BOP_SIZE(	U2,	N			),
    ASSH_BOP_SIZE(	V2,	L			),

    ASSH_BOP_INV(       W,      S,      Q		),

    /* (sha(m) * w) mod q */
    ASSH_BOP_MULM(      U1,     M,      W,	Q       ),
    /* g^u1 */
    ASSH_BOP_EXPM(      V1,     G,      U1,	P	),
    /* r * w mod q */
    ASSH_BOP_MULM(      U2,     R,      W,	Q       ),
    /* y^u2 */
    ASSH_BOP_EXPM(      V2,     Y,      U2,	P	),
    /* (g^u1 * y^u2) mod p */
    ASSH_BOP_MULM(      Y,      V1,     V2,	P	),
    /* v = (g^u1 * y^u2) mod p mod q */
    ASSH_BOP_MOD(       V,      Y,      Q		),

    ASSH_BOP_PRINT(	R,	2			),
    ASSH_BOP_PRINT(	V,	3			),
    ASSH_BOP_CMPEQ(     V,      R,	0		),

    ASSH_BOP_END(),
  };

  ASSH_ERR_RET(assh_bignum_bytecode(c, bytecode,
	      /* hex */ "HHHHH"
	      /* r, s, v */ "NNN" /* temps: */ "TTTTTTTTTT"
              /* sizes */ "ss",

	      /* char* */   hex_pn, hex_qn, hex_gn, hex_yn, hex_m ,
	      /* bignums */ rn, sn, vn, /* bit sizes */ n, l));

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

  struct assh_bignum_s rn;
  struct assh_bignum_s sn;

  assh_bignum_init(&context, &rn, n);
  assh_bignum_init(&context, &sn, n);

  dsa_generate(&context, &rn, &sn);

  struct assh_bignum_s vn;

  assh_bignum_init(&context, &vn, n);

  dsa_verify(&context, &rn, &sn, &vn);

  /* check V against constant R */
  enum bytecode_args_e
  {
    R_hex, R, V, N
  };

  assh_bignum_op_t bytecode[] = {
    ASSH_BOP_SIZE(	V,	N			),

    ASSH_BOP_SIZE(	R,	N			),
    ASSH_BOP_MOVE(      R,      R_hex			),

    ASSH_BOP_CMPEQ(     V,      R,	0		),

    ASSH_BOP_END(),
  };

  ASSH_ERR_RET(assh_bignum_bytecode(&context, bytecode, "HTNs",
				    hex_r, &vn, n));

  assh_bignum_release(&context, &rn);
  assh_bignum_release(&context, &sn);
  assh_bignum_release(&context, &vn);

 err_:
  return 0;
}
