
#include <stdint.h>

struct assh_weierstrass_curve_s
{
  const uint8_t *p;
  const uint8_t *n;
  const uint8_t *c;
  const uint8_t *b;
  const uint8_t *gx;
  const uint8_t *gy;
  uint_fast16_t bits;
  uint_fast8_t cofactor;
};

/** http://www.hyperelliptic.org/EFD dbl-2007-bl-2 */
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

/* Efficient elliptic curve exponentiation using mixed coordinates, p51-65 */
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


