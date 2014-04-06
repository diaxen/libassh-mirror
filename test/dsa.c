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

int main()
{
  assh_error_t err;
  struct assh_context_s context;

#ifdef CONFIG_ASSH_USE_GCRYPT
  if (!gcry_check_version(GCRYPT_VERSION))
    return -1;
#endif

  assh_context_init(&context, ASSH_SERVER);

  unsigned int n = 160, l = 512;

  ASSH_BIGNUM_ALLOC(&context, pn, l, ASSH_ERRSV_CONTINUE, err_);
  ASSH_ERR_RET(assh_bignum_from_hex(pn, NULL, "d411a4a0e393f6aab0f08b14d18458665b3e4dbdce2544543fe365cf71c8622412db6e7dd02bbe13d88c58d7263e90236af17ac8a9fe5f249cc81f427fc543f7", l / 4));
  assh_bignum_print(stderr, "pn", pn);

  ASSH_BIGNUM_ALLOC(&context, qn, n, ASSH_ERRSV_CONTINUE, err_);
  ASSH_ERR_RET(assh_bignum_from_hex(qn, NULL, "b20db0b101df0c6624fc1392ba55f77d577481e5", n / 4));
  assh_bignum_print(stderr, "qn", qn);

  ASSH_BIGNUM_ALLOC(&context, gn, l, ASSH_ERRSV_CONTINUE, err_);
  ASSH_ERR_RET(assh_bignum_from_hex(gn, NULL, "b3085510021f999049a9e7cd3872ce9958186b5007e7adaf25248b58a3dc4f71781d21f2df89b71747bd54b323bbecc443ec1d3e020dadabbf7822578255c104", l / 4));
  assh_bignum_print(stderr, "gn", gn);

  ASSH_BIGNUM_ALLOC(&context, yn, l, ASSH_ERRSV_CONTINUE, err_);
  ASSH_ERR_RET(assh_bignum_from_hex(yn, NULL, "b32fbec03175791df08c3f861c81df7de7e0cba7f1c4f7269bb12d6c628784fb742e66ed315754dfe38b5984e94d372537f655cb3ea4767c878cbd2d783ee662", l / 4));
  assh_bignum_print(stderr, "yn", yn);

  ASSH_BIGNUM_ALLOC(&context, xn, n, ASSH_ERRSV_CONTINUE, err_);
  ASSH_ERR_RET(assh_bignum_from_hex(xn, NULL, "6b2cd935d0192d54e2c942b574c80102c8f8ef67", n / 4));
  assh_bignum_print(stderr, "xn", xn);

  ASSH_BIGNUM_ALLOC(&context, kn, n, ASSH_ERRSV_CONTINUE, err_);
  ASSH_ERR_RET(assh_bignum_from_hex(kn, NULL, "79577ddcaafddc038b865b19f8eb1ada8a2838c6", n / 4));
  assh_bignum_print(stderr, "kn", kn);

  /* compute R */
  ASSH_BIGNUM_ALLOC(&context, rn, l, ASSH_ERRSV_CONTINUE, err_);
  ASSH_ERR_RET(assh_bignum_expmod(rn, gn, kn, pn));
  assh_bignum_print(stderr, "g^k mod p", rn);

  ASSH_ERR_RET(assh_bignum_div(rn, NULL, rn, qn));
  assh_bignum_print(stderr, "(g^k mod p) mod q", rn);

  ASSH_ERR_RET(assh_bignum_shrink(rn, n));
  assh_bignum_print(stderr, "r = (g^k mod p) mod q", rn);

  /* compute S */
  ASSH_BIGNUM_ALLOC(&context, sn, n, ASSH_ERRSV_CONTINUE, err_);

  ASSH_BIGNUM_ALLOC(&context, mn, n, ASSH_ERRSV_CONTINUE, err_);
  ASSH_ERR_RET(assh_bignum_from_hex(mn, NULL, "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880", n / 4));
  assh_bignum_print(stderr, "mn", mn);

  ASSH_BIGNUM_ALLOC(&context, r1, n, ASSH_ERRSV_CONTINUE, err_);

  ASSH_ERR_RET(assh_bignum_mulmod(r1, xn, rn, qn));
  assh_bignum_print(stderr, "(x * r) mod q", r1);

  ASSH_BIGNUM_ALLOC(&context, r2, n + 1, ASSH_ERRSV_CONTINUE, err_);
  ASSH_ERR_RET(assh_bignum_add(r2, mn, r1));
  assh_bignum_print(stderr, "sha(m) + (x * r)", r2);

  ASSH_ERR_RET(assh_bignum_modinv(r1, kn, qn));
  assh_bignum_print(stderr, "k^-1", r1);

  ASSH_ERR_RET(assh_bignum_mulmod(sn, r1, r2, qn));
  assh_bignum_print(stderr, "s = k^-1 * (sha(m) + (x * r)) mod q", sn);

  /* compute w */
  ASSH_BIGNUM_ALLOC(&context, wn, n, ASSH_ERRSV_CONTINUE, err_);
  ASSH_ERR_RET(assh_bignum_modinv(wn, sn, qn));
  assh_bignum_print(stderr, "w", wn);
  assh_bignum_print(stderr, "m", mn);

  /* compute v */
  ASSH_BIGNUM_ALLOC(&context, u1n, n, ASSH_ERRSV_CONTINUE, err_);
  ASSH_ERR_RET(assh_bignum_mulmod(u1n, mn, wn, qn));
  assh_bignum_print(stderr, "(sha(m) * w) mod q", u1n);

  ASSH_BIGNUM_ALLOC(&context, v1n, l, ASSH_ERRSV_CONTINUE, err_);
  ASSH_ERR_RET(assh_bignum_expmod(v1n, gn, u1n, pn));
  assh_bignum_print(stderr, "g^u1", v1n);

  ASSH_BIGNUM_ALLOC(&context, u2n, n, ASSH_ERRSV_CONTINUE, err_);
  ASSH_ERR_RET(assh_bignum_mulmod(u2n, rn, wn, qn));
  assh_bignum_print(stderr, "r * w mod q", u2n);

  ASSH_BIGNUM_ALLOC(&context, v2n, l, ASSH_ERRSV_CONTINUE, err_);
  ASSH_ERR_RET(assh_bignum_expmod(v2n, yn, u2n, pn));
  assh_bignum_print(stderr, "y^u2", v2n);

  ASSH_BIGNUM_ALLOC(&context, vn, l, ASSH_ERRSV_CONTINUE, err_);
  ASSH_ERR_RET(assh_bignum_mulmod(vn, v1n, v2n, pn));
  assh_bignum_print(stderr, "(g^u1 * y^u2) mod p", vn);

  ASSH_ERR_RET(assh_bignum_div(vn, NULL, vn, qn));

  assh_bignum_print(stderr, "v = (g^u1 * y^u2) mod p mod q", vn);

  ASSH_ERR_RET(assh_bignum_cmp(vn, rn) ? ASSH_ERR_BAD_DATA : 0);

  ASSH_ERR_RET(assh_bignum_from_hex(rn, NULL, "9b77f7054c81531c4e46a4692fbfe0f77f7ebff2", n / 4));
  ASSH_ERR_RET(assh_bignum_cmp(vn, rn) ? ASSH_ERR_BAD_DATA : 0);

 err_:
  return 0;
}

