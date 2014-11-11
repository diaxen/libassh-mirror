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

#include <assh/key_ed25519.h>
#include <assh/assh_bignum.h>
#include <assh/assh_packet.h>
#include <assh/assh_alloc.h>
#include <assh/assh_prng.h>
#include <assh/assh_hash.h>

#include "ecc_bop.h"

#include <string.h>

static ASSH_KEY_OUTPUT_FCN(assh_key_ed25519_output)
{
  struct assh_key_ed25519_s *k = (void*)key;
  assh_error_t err;

  assert(key->algo == &assh_key_ed25519);

  switch (format)
    {
    case ASSH_KEY_FMT_PUB_RFC4253_6_6: {
      /* add algo identifier */
      size_t l = assh_ed25519_id_len;
      if (blob != NULL)
        {
          ASSH_CHK_RET(assh_ed25519_id_len > *blob_len, ASSH_ERR_OUTPUT_OVERFLOW);
          memcpy(blob, assh_ed25519_id, assh_ed25519_id_len);
          *blob_len -= assh_ed25519_id_len;
          blob += assh_ed25519_id_len;
        }

      /* add public key blob */
      size_t s = 32;
      if (blob != NULL)
        {
          ASSH_CHK_RET(4 + s > *blob_len, ASSH_ERR_OUTPUT_OVERFLOW);
          assh_store_u32(blob, s);
          memcpy(blob + 4, k->p, 32);
        }
      l += 4 + s;
      *blob_len = l;
      return ASSH_OK;
    }

#if 0
    case ASSH_KEY_FMT_PV_PEM_ASN1: {
      ASSH_CHK_RET(!k->private, ASSH_ERR_NOTSUP);
      return ASSH_OK;
    }
#endif

    default:
      ASSH_ERR_RET(ASSH_ERR_NOTSUP);
    }

  return ASSH_OK;
}

static ASSH_KEY_CMP_FCN(assh_key_ed25519_cmp)
{
  assert(key->algo == &assh_key_ed25519);

  if (key->algo != b->algo)
    return 0;

  struct assh_key_ed25519_s *k = (void*)key;
  struct assh_key_ed25519_s *l = (void*)b;

  if (!pub && (!k->private || !l->private ||
       (k->private && assh_memcmp(k->s, l->s, 32))))
    return 0;

  return !assh_memcmp(k->p, l->p, 32);
}

static ASSH_KEY_CREATE_FCN(assh_key_ed25519_create)
{
  assh_error_t err;
  struct assh_key_ed25519_s *k;

  size_t n = 32;

  const struct assh_hash_algo_s *algo = &assh_hash_sha512;
  const struct assh_edward_curve_s *curve = &assh_ed25519_curve;

  struct scratch_s
  {
    uint8_t h[64];
    uint8_t rx[32];
    uint8_t hash_ctx[0];
  };

  ASSH_ERR_RET(assh_alloc(c, sizeof(struct assh_key_ed25519_s),
                          ASSH_ALLOC_KEY, (void**)&k));

  k->key.algo = &assh_key_ed25519;

  ASSH_ERR_GTO(c->prng->f_get(c, k->s, n,
                 ASSH_PRNG_QUALITY_LONGTERM_KEY), err_key);

  ASSH_SCRATCH_ALLOC(c, struct scratch_s, sc,
		     sizeof(struct scratch_s) +
                     algo->ctx_size,
		     ASSH_ERRSV_CONTINUE, err_key);

  void *hash_ctx = sc->hash_ctx;
  unsigned int i;

  ASSH_ERR_GTO(assh_hash_init(c, hash_ctx, algo), err_scratch);
  assh_hash_update(hash_ctx, k->s, n);
  assh_hash_final(hash_ctx, sc->h + n, n * 2);
  assh_hash_cleanup(hash_ctx);

  assh_edward_adjust(curve, sc->h + n);

  struct assh_bignum_mlad_s mlad = {
    .data = sc->h + n,
    .count = n * 8,
    .msbyte_1st = 0,
    .msbit_1st = 1,
  };

  enum {
    BX_mpint, BY_mpint, A_mpint, P_mpint, D_mpint, L, Size, /* in */
    RX_raw, RY_raw,                                      /* out */
    P, A, D, T0, T1,                                     /* temp */
    RX, RY, RZ,  BX, BY, BZ,  PX, PY, PZ,  QX, QY, QZ
  };

  static const assh_bignum_op_t bytecode[] = {

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

#ifdef CONFIG_ASSH_DEBUG_SIGN
    ASSH_BOP_PRINT(     RX,     'x'                     ),
    ASSH_BOP_PRINT(     RY,     'y'                     ),
#endif

    ASSH_BOP_END(),
  };

  ASSH_ERR_GTO(assh_bignum_bytecode(c, bytecode,
      "MMMMMLsddTTTTTTTTTTTTTTTTTTTTT", curve->bx, curve->by,
      curve->a, curve->p, curve->d, &mlad, curve->bits, sc->rx, k->p), err_scratch);

  assh_edward_encode(curve, k->p, sc->rx);

  k->private = 1;
  *key = &k->key;

  ASSH_SCRATCH_FREE(c, sc);
  return ASSH_OK;

 err_scratch:
  ASSH_SCRATCH_FREE(c, sc);
 err_key:
  assh_free(c, k, ASSH_ALLOC_KEY);
  return err;
}

static ASSH_KEY_VALIDATE_FCN(assh_key_ed25519_validate)
{
  assh_error_t err;
  struct assh_key_ed25519_s *k = (void*)key;

  if (!k->private)
    return ASSH_OK;

  uint8_t pub[32];

#warning ed key validate
#if 0
  ASSH_ERR_RET(assh_ed25519_twed_mul(c, pup, k->s,
                                &assh_ed25519_base));

  ASSH_CHK_RET(memcmp(pub, k->p, 32), ASSH_ERR_BAD_DATA);
#endif

  return ASSH_OK;
}

static ASSH_KEY_LOAD_FCN(assh_key_ed25519_load)
{
  assh_error_t err;

  unsigned int l, n;

  /* allocate key structure */
  struct assh_key_ed25519_s *k = (void*)*key;

  ASSH_ERR_RET(assh_alloc(c, sizeof(struct assh_key_ed25519_s),
                          ASSH_ALLOC_KEY, (void**)&k));

  k->key.algo = &assh_key_ed25519;

  /* parse the key blob */
  switch (format)
    {
    case ASSH_KEY_FMT_PUB_RFC4253_6_6: {
      k->private = 0;
      ASSH_CHK_GTO(blob_len != assh_ed25519_id_len + 4 + 32, ASSH_ERR_INPUT_OVERFLOW, err_key);
      ASSH_CHK_GTO(memcmp(assh_ed25519_id, blob, assh_ed25519_id_len), ASSH_ERR_BAD_DATA, err_key);
      const uint8_t *p_str = (uint8_t*)blob + assh_ed25519_id_len;
      ASSH_CHK_GTO(assh_load_u32(p_str) != 32, ASSH_ERR_BAD_DATA, err_key);
      memcpy(k->p, p_str + 4, 32);
      break;
    }

    case ASSH_KEY_FMT_PV_OPENSSH_V1_KEY: {
      k->private = 1;
      ASSH_CHK_GTO(blob_len != assh_ed25519_id_len + 4 + 32 + 4 + 64,
                   ASSH_ERR_INPUT_OVERFLOW, err_key);
      ASSH_CHK_GTO(memcmp(assh_ed25519_id, blob, assh_ed25519_id_len), ASSH_ERR_BAD_DATA, err_key);
      const uint8_t *p_str = (uint8_t*)blob + assh_ed25519_id_len;
      ASSH_CHK_GTO(assh_load_u32(p_str) != 32, ASSH_ERR_BAD_DATA, err_key);
      memcpy(k->p, p_str + 4, 32);
      const uint8_t *s_str = p_str + 4 + 32;
      ASSH_CHK_GTO(assh_load_u32(s_str) != 64, ASSH_ERR_BAD_DATA, err_key);
      memcpy(k->s, s_str + 4, 32);
      ASSH_CHK_GTO(memcmp(k->p, s_str + 4 + 32, 32), ASSH_ERR_BAD_DATA, err_key);
      break;
    }

    default:
      ASSH_ERR_RET(ASSH_ERR_NOTSUP);
    }

  *key = &k->key;
  return ASSH_OK;

 err_key:
  assh_free(c, k, ASSH_ALLOC_KEY);
  return err;
}

static ASSH_KEY_CLEANUP_FCN(assh_key_ed25519_cleanup)
{
  struct assh_key_ed25519_s *k = (void*)key;

  assh_free(c, k, ASSH_ALLOC_KEY);
}

const struct assh_algo_key_s assh_key_ed25519 =
{
  .type = "ssh-ed25519",
  .f_output = assh_key_ed25519_output,
  .f_create = assh_key_ed25519_create,
  .f_validate = assh_key_ed25519_validate,
  .f_cmp = assh_key_ed25519_cmp,
  .f_load = assh_key_ed25519_load,
  .f_cleanup = assh_key_ed25519_cleanup,
};

