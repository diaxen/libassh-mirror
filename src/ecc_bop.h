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

/* addition on montgomery curve, single coordinate. 18ops */
#define ASSH_BOP_MONTGOMERY_SADD(X1, X2, X3, Z2, Z3,		\
				  T0, T1, A24, P)		\
    /* D = X3 - Z3        */					\
    ASSH_BOP_SUBM(	T0,	X3,	Z3,	P	),	\
    /* B = X2 - Z2        */					\
    ASSH_BOP_SUBM(	T1,	X2,	Z2,	P	),	\
    /* A = X2 + Z2        */					\
    ASSH_BOP_ADDM(	X2,	X2,	Z2,	P	),	\
    /* C = X3 + Z3        */					\
    ASSH_BOP_ADDM(	Z2,	X3,	Z3,	P	),	\
    /* DA = D*A           */					\
    ASSH_BOP_MULM(	Z3,	T0,	X2,	P	),	\
    /* CB = C*B           */					\
    ASSH_BOP_MULM(	Z2,	Z2,	T1,	P	),	\
    /* BB = B^2           */					\
    ASSH_BOP_MULM( 	T0,	T1,	T1,	P	),	\
    /* AA = A^2           */					\
    ASSH_BOP_MULM( 	T1,	X2,	X2,	P	),	\
    /* X5 = Z1*(DA+CB)^2  */					\
    ASSH_BOP_ADDM(	X3,	Z3,	Z2,	P	),	\
    ASSH_BOP_MULM( 	X3,	X3,	X3,	P	),	\
    /* Z5 = X1*(DA-CB)^2  */					\
    ASSH_BOP_SUBM(	Z2,	Z3,	Z2,	P	),	\
    ASSH_BOP_MULM( 	Z2,	Z2,	Z2,	P	),	\
    /* X4 = AA*BB         */					\
    ASSH_BOP_MULM(	X2,	T1,	T0,	P	),	\
    /* E = AA - BB        */					\
    ASSH_BOP_SUBM(      T1,	T1,	T0,	P	),	\
    /* Z4 = E*(BB+a24*E)  */					\
    ASSH_BOP_MULM(	Z3,	T1,	A24,    P	),	\
    ASSH_BOP_ADDM(	T0,	T0,	Z3,	P	),	\
    ASSH_BOP_MULM(	Z3,	X1,	Z2,	P	),	\
    ASSH_BOP_MULM(	Z2,	T1,	T0,	P	)

/* addition on twisted edward curve, projective coordinate. 20 ops */
#define ASSH_BOP_TEDWARD_PADD(X3, Y3, Z3, X1, Y1, Z1,		\
			      X2, Y2, Z2, T0, T1, A, D, P)	\
    /* A = Z1*Z2 */						\
    ASSH_BOP_MULM(	Z3,	Z1,	Z2,	P	),	\
    /* I = (X1+Y1)*(X2+Y2) */					\
    ASSH_BOP_ADDM(	T0,	X1,	Y1,	P	),	\
    ASSH_BOP_ADDM(	T1,	X2,	Y2,	P	),	\
    ASSH_BOP_MULM(	T0,	T0,	T1,	P	),	\
    /* C = X1*X2 */						\
    ASSH_BOP_MULM(	X3,	X1,	X2,	P	),	\
    /* D = Y1*Y2 */						\
    ASSH_BOP_MULM(	Y3,	Y1,	Y2,	P	),	\
    /* E = d*C*D */						\
    ASSH_BOP_MULM(	T1,	X3,	Y3,	P	),	\
    ASSH_BOP_MULM(	T1,	T1,	D ,	P	),	\
    /* H = A*(I-C-D) */						\
    ASSH_BOP_SUBM(	T0,	T0,	X3,	P	),	\
    ASSH_BOP_SUBM(	T0,	T0,	Y3,	P	),	\
    ASSH_BOP_MULM(	T0,	T0,	Z3,	P	),	\
    /* J = (D-a*C)*A */						\
    ASSH_BOP_MULM(	X3,	X3,	A,	P	),	\
    ASSH_BOP_SUBM(	Y3,	Y3,	X3,	P	),	\
    ASSH_BOP_MULM(	Y3,	Y3,	Z3,	P	),	\
    /* F = A*A - E */						\
    ASSH_BOP_MULM(	Z3,	Z3,	Z3,	P	),	\
    ASSH_BOP_SUBM(	X3,	Z3,	T1,	P	),	\
    /* G = A*A + E */						\
    ASSH_BOP_ADDM(	Z3,	Z3,	T1,	P	),	\
    /* Y3 = G*J */						\
    ASSH_BOP_MULM(	Y3,	Y3,	Z3,	P	),	\
    /* Z3 = F*G */						\
    ASSH_BOP_MULM(	Z3,	Z3,	X3,	P	),	\
    /* X3 = F*H */						\
    ASSH_BOP_MULM(	X3,	X3,	T0,	P	)


/* doubling on twisted edward curve, projective coordinate. 15 ops */
#define ASSH_BOP_TEDWARD_PDBL(X3, Y3, Z3, X1, Y1, Z1, T0, T1, P)\
    /* C = X1^2 */						\
    ASSH_BOP_MULM(	X3,	X1,	X1,	P	),	\
    /* D = Y1^2 */						\
    ASSH_BOP_MULM(	Y3,	Y1,	Y1,	P	),	\
    /* B = (X1+Y1)^2-C-D */					\
    ASSH_BOP_ADDM(	T0,	X1,	Y1,	P	),	\
    ASSH_BOP_MULM(	T0,	T0,	T0,	P	),	\
    ASSH_BOP_SUBM(	T0,	T0,	X3,	P	),	\
    ASSH_BOP_SUBM(	T0,	T0,	Y3,	P	),	\
    /* E = a*C */						\
    ASSH_BOP_MULM(	X3,	X3,	A,	P	),	\
    /* F = E+D */						\
    ASSH_BOP_ADDM(	Z3,	X3,	Y3,	P	),	\
    /* Y3 = F*(E-D) */						\
    ASSH_BOP_SUBM(	Y3,	X3,	Y3,	P	),	\
    ASSH_BOP_MULM(	Y3,	Z3,	Y3,	P	),	\
    /* J = F-2*Z1^2 */						\
    ASSH_BOP_MULM(	T1,	Z1,	Z1,	P	),	\
    ASSH_BOP_ADDM(	T1,	T1,	T1,	P	),	\
    ASSH_BOP_SUBM(	T1,	Z3,	T1,	P	),	\
    /* X3 = B*J */						\
    ASSH_BOP_MULM(	X3,	T0,	T1,	P	),	\
    /* Z3 = F*J */						\
    ASSH_BOP_MULM(	Z3,	Z3,	T1,	P	)

