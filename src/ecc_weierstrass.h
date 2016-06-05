/*

  libassh - asynchronous ssh2 client/server library.

  Copyright (C) 2014 Alexandre Becoulet <alexandre.becoulet@free.fr>

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

#ifndef _ECC_WEIERSTRASS_H_
#define _ECC_WEIERSTRASS_H_

#include <assh/assh.h>

struct assh_weierstrass_curve_s
{
  const char *name;
  const uint8_t *p;
  const uint8_t *n;
  const uint8_t *c;
  const uint8_t *b;
  const uint8_t *gx;
  const uint8_t *gy;
  uint16_t bits;
  uint8_t cofactor;
  assh_safety_t safety;
};

extern const struct assh_weierstrass_curve_s assh_nistp256_curve;
extern const struct assh_weierstrass_curve_s assh_nistp384_curve;
extern const struct assh_weierstrass_curve_s assh_nistp521_curve;

#define ASSH_NISTP256_SAFETY 21
#define ASSH_NISTP384_SAFETY 23
#define ASSH_NISTP521_SAFETY 25

/* weierstrass point doubling,
    from http://www.hyperelliptic.org/EFD dbl-2007-bl-2 */
#define ASSH_BOP_WS_PDBL(X3, Y3, Z3, X1, Y1, Z1, T0, T1, P)	\
								\
  /* A = 3*(X1-Z1)*(X1+Z1) */					\
  ASSH_BOP_ADDM( T0,	X1,	Z1,	P	),		\
  ASSH_BOP_SUBM( T1,	X1,	Z1,	P	),		\
  ASSH_BOP_MULM( T0,	T0,	T1,	P	),		\
  ASSH_BOP_ADDM( T1,	T0,	T0,	P	),		\
  ASSH_BOP_ADDM( Y3,	T1,	T0,	P	),		\
  /* B = 2*Y1*Z1 */						\
  ASSH_BOP_MULM( T0,	Z1,	Y1,	P	),		\
  ASSH_BOP_ADDM( Z3,	T0,	T0,	P	),		\
  /* D = Y1*B */						\
  ASSH_BOP_MULM( T1,	Y1,	Z3,	P	),		\
  /* F = 2*X1*D */						\
  ASSH_BOP_MULM( T0,	X1,	T1,	P	),		\
  ASSH_BOP_ADDM( T0,	T0,	T0,	P	),		\
  /* G = A^2 - 2*F */						\
  ASSH_BOP_MULM( X3,	Y3,	Y3,	P	),		\
  ASSH_BOP_SUBM( X3,	X3,	T0,	P	),		\
  ASSH_BOP_SUBM( X3,	X3,	T0,	P	),		\
  /* E = D*D */							\
  ASSH_BOP_MULM( T1,	T1,	T1,	P	),		\
  /* Y3 = A*(F - G) - 2*E */					\
  ASSH_BOP_SUBM( T0,	T0,	X3,	P	),		\
  ASSH_BOP_MULM( T0,	T0,	Y3,	P	),		\
  ASSH_BOP_SUBM( T0,	T0,	T1,	P	),		\
  ASSH_BOP_SUBM( Y3,	T0,	T1,	P	),		\
  /* X3 = B*G */						\
  ASSH_BOP_MULM( X3,	Z3,	X3,	P	),		\
  /* C = B*B */							\
  ASSH_BOP_MULM( T0,	Z3,	Z3,	P	),		\
  /* Z3 = B*C */						\
  ASSH_BOP_MULM( Z3,	Z3,	T0,	P	)

#define ASSH_BOP_WS_PDBL_OPS 21

/* weierstrass point addition, from Efficient elliptic curve
   exponentiation using mixed coordinates, p51-65 */
#define ASSH_BOP_WS_PADD(X3, Y3, Z3, X2, Y2, Z2, X1, Y1, Z1,	\
			 T0, T1, T2, T3, P)			\
								\
  /* A = Z1*Z2 */						\
  ASSH_BOP_MULM( T2,	Z1,	Z2,	P	),		\
  /* B = X1*Z2 */						\
  ASSH_BOP_MULM( T1,	X1,	Z2,	P	),		\
  /* C = Y1*Z2 */						\
  ASSH_BOP_MULM( T3,	Y1,	Z2,	P	),		\
  /* D = B - Z1*X2 */						\
  ASSH_BOP_MULM( X3,	Z1,	X2,	P	),		\
  ASSH_BOP_SUBM( X3,	T1,	X3,	P	),		\
  /* F = D*D */							\
  ASSH_BOP_MULM( T0,	X3,	X3,	P	),		\
  /* G = F*D */							\
  ASSH_BOP_MULM( Z3,	X3,	T0,	P	),		\
  /* H = F*B */							\
  ASSH_BOP_MULM( T1,	T1,	T0,	P	),		\
  /* E = C - Z1*Y2 */						\
  ASSH_BOP_MULM( Y3,	Z1,	Y2,	P	),		\
  ASSH_BOP_SUBM( Y3,	T3,	Y3,	P	),		\
  /* J = E*E*A + G - 2*H */					\
  ASSH_BOP_MULM( T0,	Y3,	Y3,	P	),		\
  ASSH_BOP_MULM( T0,	T0,	T2,	P	),		\
  ASSH_BOP_ADDM( T0,	T0,	Z3,	P	),		\
  ASSH_BOP_SUBM( T0,	T0,	T1,	P	),		\
  ASSH_BOP_SUBM( T0,	T0,	T1,	P	),		\
  /* X3 = D*J */						\
  ASSH_BOP_MULM( X3,	X3,	T0,	P	),		\
  /* Y3 = E*(H -J) - G*C */					\
  ASSH_BOP_SUBM( T1,	T1,	T0,	P	),		\
  ASSH_BOP_MULM( Y3,	T1,	Y3,	P	),		\
  ASSH_BOP_MULM( T0,	Z3,	T3,	P	),		\
  ASSH_BOP_SUBM( Y3,	Y3,	T0,	P	),		\
  /* Z3 = A*G */						\
  ASSH_BOP_MULM( Z3,	Z3,	T2,	P	)

#define ASSH_BOP_WS_PADD_OPS 21

/* check that a point is on the weierstrass curve */
#define ASSH_BOP_WS_POINTONCURVE(X1, Y1, T0, T1, B, P)          \
    ASSH_BOP_MULM(      T0,     Y1,     Y1,     P       ),      \
    ASSH_BOP_MULM(      T1,     X1,     X1,     P       ),      \
    ASSH_BOP_MULM(      T1,     T1,     X1,     P       ),      \
    ASSH_BOP_SUBM(      T1,     T0,     T1,     P       ),      \
    ASSH_BOP_ADDM(      T1,     T1,     X1,     P       ),      \
    ASSH_BOP_ADDM(      T1,     T1,     X1,     P       ),      \
    ASSH_BOP_ADDM(      T1,     T1,     X1,     P       ),      \
    ASSH_BOP_MTFROM(	T1,     T1,     T1,     P       ),      \
    ASSH_BOP_CMPEQ(     T1,     B,      0               ),      \
    ASSH_BOP_CFAIL(     1,      0                       )

/* constant time scalar mul with most significant bit set */
#define ASSH_BOP_WS_SCMUL(X3, Y3, Z3, X2, Y2, Z2, X1, Y1, Z1,           \
			  T0, T1, T2, T3, SC, P)                        \
                                                                        \
    ASSH_BOP_MTUINT(    Z1,     1,      P               ),              \
    ASSH_BOP_MOVE(      X2,     X1                      ),              \
    ASSH_BOP_MOVE(      Y2,     Y1                      ),              \
    ASSH_BOP_MOVE(      Z2,     Z1                      ),              \
                                                                        \
    ASSH_BOP_LADINIT(   SC                              ),              \
    ASSH_BOP_LADNEXT(   1                               ),              \
                                                                        \
    /* ladder */                                                        \
    ASSH_BOP_WS_PDBL(X3, Y3, Z3, X2, Y2, Z2, T0, T1, P  ),              \
    ASSH_BOP_MOVE(      X2,     X3                      ),              \
    ASSH_BOP_MOVE(      Y2,     Y3                      ),              \
    ASSH_BOP_MOVE(      Z2,     Z3                      ),              \
                                                                        \
    ASSH_BOP_WS_PADD(X3, Y3, Z3, X1, Y1, Z1, X2, Y2, Z2,                \
                     T0, T1, T2, T3, P),                                \
                                                                        \
    ASSH_BOP_LADTEST(   SC,      0                      ),              \
    ASSH_BOP_CSWAP(     X2,     X3,     0,      0       ),              \
    ASSH_BOP_CSWAP(     Y2,     Y3,     0,      0       ),              \
    ASSH_BOP_CSWAP(     Z2,     Z3,     0,      0       ),              \
    ASSH_BOP_LADNEXT(   0                               ),              \
    ASSH_BOP_CJMP(      -ASSH_BOP_WS_PDBL_OPS - 3                       \
                        -ASSH_BOP_WS_PADD_OPS - 6,                      \
                        0,      0    ),                                 \
                                                                        \
    ASSH_BOP_MTFROM(	T0,     T0,     Z2,     P       ),              \
    ASSH_BOP_UINT(      T1,     0                       ),              \
    ASSH_BOP_CMPEQ(     T1,     T0,     0               ),              \
    ASSH_BOP_CFAIL(     0,      0                       ),              \
                                                                        \
    ASSH_BOP_INV(       T0,     Z2,             P      ),               \
    ASSH_BOP_MULM(      X2,     X2,     T0,     P      ),               \
    ASSH_BOP_MULM(      Y2,     Y2,     T0,     P      )

/* constant time scalar mul */
#define ASSH_BOP_WS_SCMUL2(X3, Y3, Z3, X2, Y2, Z2, X1, Y1, Z1,          \
                           T0, T1, T2, T3, SC, P)                       \
                                                                        \
    ASSH_BOP_LADINIT(   SC                              ),              \
                                                                        \
    ASSH_BOP_MTUINT(    Z1,     1,      P               ),              \
    ASSH_BOP_MOVE(      X2,     X1                      ),              \
    ASSH_BOP_MOVE(      Y2,     Y1                      ),              \
    ASSH_BOP_MOVE(      Z2,     Z1                      ),              \
                                                                        \
    ASSH_BOP_BOOL(      1,      0,      0,      ASSH_BOP_BOOL_NXOR  ),  \
    ASSH_BOP_LADTEST(   SC,     0                       ),              \
    ASSH_BOP_LADNEXT(   2                               ),              \
                                                                        \
    /* ladder */                                                        \
    ASSH_BOP_BOOL(      1,      1,      0,      ASSH_BOP_BOOL_ANDN  ),  \
                                                                        \
    ASSH_BOP_WS_PDBL(X3, Y3, Z3, X2, Y2, Z2, T0, T1, P  ),              \
    ASSH_BOP_MOVE(      X2,     X3                      ),              \
    ASSH_BOP_MOVE(      Y2,     Y3                      ),              \
    ASSH_BOP_MOVE(      Z2,     Z3                      ),              \
                                                                        \
    ASSH_BOP_WS_PADD(X3, Y3, Z3, X1, Y1, Z1, X2, Y2, Z2,                \
                     T0, T1, T2, T3, P),                                \
                                                                        \
    ASSH_BOP_LADTEST(   SC,      0                      ),              \
    ASSH_BOP_CMOVE(     X2,     X3,     0,      0       ),              \
    ASSH_BOP_CMOVE(     Y2,     Y3,     0,      0       ),              \
    ASSH_BOP_CMOVE(     Z2,     Z3,     0,      0       ),              \
                                                                        \
    ASSH_BOP_CMOVE(     X2,     X1,     0,      1       ),              \
    ASSH_BOP_CMOVE(     Y2,     Y1,     0,      1       ),              \
    ASSH_BOP_CMOVE(     Z2,     Z1,     0,      1       ),              \
                                                                        \
    ASSH_BOP_LADNEXT(   2                               ),              \
    ASSH_BOP_CJMP(      -ASSH_BOP_WS_PADD_OPS                           \
                        -ASSH_BOP_WS_PDBL_OPS - 13,                     \
                        0,      2    ),                                 \
                                                                        \
    ASSH_BOP_MTFROM(	T0,     T0,     Z2,     P       ),              \
    ASSH_BOP_UINT(      T1,     0                       ),              \
    ASSH_BOP_CMPEQ(     T1,     T0,     0               ),              \
    ASSH_BOP_CFAIL(     0,      0                       ),              \
                                                                        \
    ASSH_BOP_INV(       T0,     Z2,             P      ),               \
    ASSH_BOP_MULM(      X2,     X2,     T0,     P      ),               \
    ASSH_BOP_MULM(      Y2,     Y2,     T0,     P      )

/* variable time scalar mul */
#define ASSH_BOP_WS_SCMUL3(X3, Y3, Z3, X2, Y2, Z2, X1, Y1, Z1,          \
                           T0, T1, T2, T3, SC, P)                       \
                                                                        \
    ASSH_BOP_LADINIT(   SC                              ),              \
                                                                        \
    ASSH_BOP_MTUINT(    Z1,     1,      P               ),              \
    ASSH_BOP_MOVE(      X2,     X1                      ),              \
    ASSH_BOP_MOVE(      Y2,     Y1                      ),              \
    ASSH_BOP_MOVE(      Z2,     Z1                      ),              \
                                                                        \
    /* skip zeros */                                                    \
    ASSH_BOP_LADTEST(   SC,     0                       ),              \
    ASSH_BOP_LADNEXT(   1                               ),              \
    ASSH_BOP_BOOL(      2,      1,      0,      ASSH_BOP_BOOL_ANDN  ),  \
    ASSH_BOP_CJMP(      -4,     0,      2               ),              \
    ASSH_BOP_CFAIL(     1,      1                       ),              \
                                                                        \
    /* ladder */                                                        \
    ASSH_BOP_WS_PDBL(X3, Y3, Z3, X2, Y2, Z2, T0, T1, P  ),              \
    ASSH_BOP_MOVE(      X2,     X3                      ),              \
    ASSH_BOP_MOVE(      Y2,     Y3                      ),              \
    ASSH_BOP_MOVE(      Z2,     Z3                      ),              \
                                                                        \
    ASSH_BOP_LADTEST(   SC,      0                      ),              \
    ASSH_BOP_CJMP(      ASSH_BOP_WS_PADD_OPS + 3, 1, 0  ),              \
    ASSH_BOP_WS_PADD(X3, Y3, Z3, X1, Y1, Z1, X2, Y2, Z2,                \
                     T0, T1, T2, T3, P),                                \
    ASSH_BOP_MOVE(      X2,     X3                      ),              \
    ASSH_BOP_MOVE(      Y2,     Y3                      ),              \
    ASSH_BOP_MOVE(      Z2,     Z3                      ),              \
                                                                        \
    ASSH_BOP_LADNEXT(   0                               ),              \
    ASSH_BOP_CJMP(      -ASSH_BOP_WS_PADD_OPS                           \
                        -ASSH_BOP_WS_PDBL_OPS - 10,                     \
                        0,      0    )

#endif

