/*

  libassh - asynchronous ssh2 client/server library.

  Copyright (C) 2013-2020 Alexandre Becoulet <alexandre.becoulet@free.fr>

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

#include "key_builtin_eddsa.h"

#include <assh/mod_builtin.h>
#include <assh/assh_bignum.h>
#include <assh/assh_packet.h>
#include <assh/assh_buffer.h>
#include <assh/assh_alloc.h>
#include <assh/assh_prng.h>
#include <assh/assh_hash.h>

#include <string.h>

static ASSH_KEY_CMP_FCN(assh_key_eddsa_cmp)
{
  assert(key->algo == &assh_key_builtin_ed25519 ||
         key->algo == &assh_key_builtin_eddsa_e382 ||
         key->algo == &assh_key_builtin_eddsa_e521);

  if (key->algo != b->algo)
    return 0;

  struct assh_key_eddsa_s *k = (void*)key;
  struct assh_key_eddsa_s *l = (void*)b;

  size_t n = ASSH_ALIGN8(k->curve->bits) / 8;

  if (!pub && (!k->key.private || !l->key.private ||
       (k->key.private && assh_memcmp(k->data + n, l->data + n, n))))
    return 0;

  return !assh_memcmp(k->data, l->data, n);
}

#ifdef CONFIG_ASSH_KEY_CREATE
static assh_status_t
assh_key_eddsa_create(struct assh_context_s *c,
                      const struct assh_key_algo_s *algo,
                      struct assh_key_s **key,
                      const struct assh_edward_curve_s *curve,
                      const struct assh_hash_algo_s *hash)
{
  assh_status_t err;
  struct assh_key_eddsa_s *k;

  size_t n = ASSH_ALIGN8(curve->bits) / 8;

  ASSH_RET_ON_ERR(assh_alloc(c, sizeof(struct assh_key_eddsa_s) + 2 * n,
                          ASSH_ALLOC_SECUR, (void**)&k));

  k->key.algo = algo;
  k->key.type = algo->name;
  k->key.safety = curve->safety;
  k->key.bits = curve->bits;
  k->key.private = 1;
  k->curve = curve;
  k->hash = hash;

  uint8_t *kp = k->data;
  uint8_t *ks = k->data + n;

  ASSH_JMP_ON_ERR(assh_prng_get(c, ks, n,
                 ASSH_PRNG_QUALITY_LONGTERM_KEY), err_key);

  ASSH_SCRATCH_ALLOC(c, uint8_t, sc,
                     hash->ctx_size + /* h */ n * 2 + /* rx */ n,
                     ASSH_ERRSV_CONTINUE, err_key);

  void    *hash_ctx = sc;
  uint8_t *h = sc + hash->ctx_size;
  uint8_t *rx = h + 2 * n;

  ASSH_JMP_ON_ERR(assh_hash_init(c, hash_ctx, hash), err_scratch);
  assh_hash_update(hash_ctx, ks, n);
  assh_hash_final(hash_ctx, h + n, n * 2);
  assh_hash_cleanup(hash_ctx);

  assh_edward_adjust(curve, h + n);

  enum {
    BX_mpint, BY_mpint, A_mpint, P_mpint,
    D_mpint, Size, SC_raw, SC_size,                      /* in */
    RX_raw, RY_raw,                                      /* out */
    P, A, D, T0, T1,                                     /* temp */
    RX, RY, RZ,  BX, BY, BZ,  PX, PY, PZ,  QX, QY, QZ, MT,
    SC
  };

  static const assh_bignum_op_t bytecode[] = {

    ASSH_BOP_SIZER(     P,      MT,     Size            ),
    ASSH_BOP_SIZE(      SC,     SC_size                 ),

    /* init */
    ASSH_BOP_MOVES(     SC,     SC_raw                  ),
    ASSH_BOP_MOVE(      P,      P_mpint                 ),
    ASSH_BOP_MOVE(      A,      A_mpint                 ),
    ASSH_BOP_MOVE(      D,      D_mpint                 ),

    ASSH_BOP_MTINIT(    MT,     P                       ),

    ASSH_BOP_MTUINT(    RX,     0,      MT              ),
    ASSH_BOP_MTUINT(    RY,     1,      MT              ),
    ASSH_BOP_MTUINT(    RZ,     1,      MT              ),
    ASSH_BOP_MOVE(      BX,     BX_mpint                ),
    ASSH_BOP_MOVE(      BY,     BY_mpint                ),
    ASSH_BOP_MTUINT(    BZ,     1,      MT              ),

    ASSH_BOP_MTTO(      A,      D,      A,      MT      ),
    ASSH_BOP_MTTO(      BX,     BY,     BX,     MT      ),
    ASSH_BOP_LADINIT(   SC                              ),

    /* ladder */
    ASSH_BOP_TEDWARD_PDBL( PX, PY, PZ,  RX, RY, RZ,
                             T0, T1, MT                 ),

    ASSH_BOP_TEDWARD_PADD( QX, QY, QZ,  PX, PY, PZ,
                           BX, BY, BZ,  T0, T1, A, D, MT ),

    ASSH_BOP_MOVE(      RX,     PX                      ),
    ASSH_BOP_MOVE(      RY,     PY                      ),
    ASSH_BOP_MOVE(      RZ,     PZ                      ),

    ASSH_BOP_LADTEST(   SC,      0                      ),
    ASSH_BOP_CSWAP(     RX,     QX,     0,      0       ),
    ASSH_BOP_CSWAP(     RY,     QY,     0,      0       ),
    ASSH_BOP_CSWAP(     RZ,     QZ,     0,      0       ),
    ASSH_BOP_LADNEXT(   0                               ),
    ASSH_BOP_CJMP(      -44,    0,      0               ),

    /* projective to affine */
    ASSH_BOP_INV(       T0,     RZ,     MT              ),
    ASSH_BOP_MULM(      RX,     RX,     T0,     MT      ),
    ASSH_BOP_MULM(      RY,     RY,     T0,     MT      ),

    ASSH_BOP_MTFROM(    RX,     RY,     RX,     MT      ),    

    ASSH_BOP_MOVE(      RX_raw, RX                      ),
    ASSH_BOP_MOVE(      RY_raw, RY                      ),

#ifdef CONFIG_ASSH_DEBUG_SIGN
    ASSH_BOP_PRINT(     RX,     'x'                     ),
    ASSH_BOP_PRINT(     RY,     'y'                     ),
#endif

    ASSH_BOP_END(),
  };

  ASSH_JMP_ON_ERR(assh_bignum_bytecode(c, 0, bytecode,
      "MMMMMsdsddTTTTTTTTTTTTTTTTTmT", curve->bx, curve->by,
      curve->a, curve->p, curve->d, curve->bits,
      h + n, n * 8,             /* scalar */
      rx, kp), err_scratch);

  assh_edward_encode(curve, kp, rx);

  *key = &k->key;

  ASSH_SCRATCH_FREE(c, sc);
  return ASSH_OK;

 err_scratch:
  ASSH_SCRATCH_FREE(c, sc);
 err_key:
  assh_free(c, k);
  return err;
}
#endif

#ifdef CONFIG_ASSH_KEY_VALIDATE
static ASSH_KEY_VALIDATE_FCN(assh_key_eddsa_validate)
{
  *result = ASSH_KEY_NOT_CHECKED;
  return ASSH_OK;
}
#endif

static ASSH_KEY_CLEANUP_FCN(assh_key_eddsa_cleanup)
{
  struct assh_key_eddsa_s *k = (void*)key;

  assh_free(c, k);
}

static ASSH_KEY_OUTPUT_FCN(assh_key_eddsa_output)
{
  struct assh_key_eddsa_s *k = (void*)key;
  assh_status_t err;

  size_t n = ASSH_ALIGN8(k->curve->bits) / 8;

  const uint8_t *kp = k->data;
  const uint8_t *ks = k->data + n;
  const char *algo_name = k->key.algo->name;

  assert(key->algo == &assh_key_builtin_ed25519 ||
         key->algo == &assh_key_builtin_eddsa_e382 ||
         key->algo == &assh_key_builtin_eddsa_e521);

  switch (format)
    {
    case ASSH_KEY_FMT_PUB_RFC4253:
      ASSH_RETURN(assh_blob_write("Zs Ds", blob, blob_len,
                                  algo_name, kp, n));

    case ASSH_KEY_FMT_PV_OPENSSH_V1_KEY:
      ASSH_RET_IF_TRUE(!k->key.private, ASSH_ERR_MISSING_KEY);

      ASSH_RETURN(assh_blob_write("Zs Ds (Db Db)s", blob, blob_len,
                                  algo_name, kp, n, ks, n, kp, n));

    default:
      ASSH_RETURN(ASSH_ERR_NOTSUP);
    }
}

static assh_status_t
assh_key_eddsa_load(struct assh_context_s *c,
                    const struct assh_key_algo_s *algo,
                    const uint8_t **blob_, size_t blob_len,
                    struct assh_key_s **key,
                    enum assh_key_format_e format,
                    const struct assh_edward_curve_s *curve,
                    const struct assh_hash_algo_s *hash)
{
  const uint8_t *blob = *blob_;
  assh_status_t err;

  /* allocate key structure */
  struct assh_key_eddsa_s *k = (void*)*key;

  size_t n = ASSH_ALIGN8(curve->bits) / 8;

  if (k == NULL)
    {
      ASSH_RET_ON_ERR(assh_alloc(c, sizeof(struct assh_key_eddsa_s) + 2 * n,
                                 ASSH_ALLOC_SECUR, (void**)&k));

      k->key.algo = algo;
      k->key.type = algo->name;
      k->key.safety = curve->safety;
      k->key.bits = curve->bits;
      k->key.private = 0;
      k->curve = curve;
      k->hash = hash;
    }

  uint8_t *pub_key = k->data;
  uint8_t *pv_key = k->data + n;

  /* parse the key blob */
  switch (format)
    {
    case ASSH_KEY_FMT_PUB_RFC4253:

      ASSH_JMP_ON_ERR(assh_blob_scan(c,
                                /*  name pub */
                                     "sz stD $",
                                     &blob, &blob_len,
                                     algo->name, n, pub_key), err_);
      break;

    case ASSH_KEY_FMT_PV_OPENSSH_V1_KEY:
      k->key.private = 1;

      ASSH_JMP_ON_ERR(assh_blob_scan(c,
                                 /* name pub  (pv pub) */
                                     "sz st st(bD bD $)",
                                     &blob, &blob_len,
                                     algo->name, n, 2 * n,
                                     n, pv_key, n, pub_key), err_);
      break;

    default:
      ASSH_JMP_ON_ERR(ASSH_ERR_NOTSUP, err_);
    }

  *key = &k->key;
  *blob_ = blob;
  return ASSH_OK;

 err_:
  assh_key_eddsa_cleanup(c, &k->key);
  return err;
}

const struct assh_edward_curve_s assh_ed25519_curve = 
{
  .p =  (const uint8_t *)"\x00\x00\x00\x20"
        "\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xed",
  .l =  (const uint8_t *)"\x00\x00\x00\x20"
        "\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x14\xde\xf9\xde\xa2\xf7\x9c\xd6\x58\x12\x63\x1a\x5c\xf5\xd3\xed",
  .bx = (const uint8_t *)"\x00\x00\x00\x20"
        "\x21\x69\x36\xd3\xcd\x6e\x53\xfe\xc0\xa4\xe2\x31\xfd\xd6\xdc\x5c"
        "\x69\x2c\xc7\x60\x95\x25\xa7\xb2\xc9\x56\x2d\x60\x8f\x25\xd5\x1a",
  .by = (const uint8_t *)"\x00\x00\x00\x20"
        "\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66"
        "\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x58",
  .a =  (const uint8_t *)"\x00\x00\x00\x20"
        "\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xec",
  .d =  (const uint8_t *)"\x00\x00\x00\x20"
        "\x52\x03\x6c\xee\x2b\x6f\xfe\x73\x8c\xc7\x40\x79\x77\x79\xe8\x98"
        "\x00\x70\x0a\x4d\x41\x41\xd8\xab\x75\xeb\x4d\xca\x13\x59\x78\xa3",
  .i =  (const uint8_t *)"\x00\x00\x00\x20"
        "\x2b\x83\x24\x80\x4f\xc1\xdf\x0b\x2b\x4d\x00\x99\x3d\xfb\xd7\xa7"
        "\x2f\x43\x18\x06\xad\x2f\xe4\x78\xc4\xee\x1b\x27\x4a\x0e\xa0\xb0",
  .bits = 255,
  .cofactor = 8,
  .safety = 50
};

static ASSH_KEY_LOAD_FCN(assh_key_ed25519_load)
{
  return assh_key_eddsa_load(c, algo, blob_, blob_len, key, format,
                              &assh_ed25519_curve, &assh_hash_sha512);
}

#ifdef CONFIG_ASSH_KEY_CREATE
static ASSH_KEY_CREATE_FCN(assh_key_ed25519_create)
{
  return assh_key_eddsa_create(c, algo, key, &assh_ed25519_curve, &assh_hash_sha512);
}
#endif

const struct assh_key_algo_s assh_key_builtin_ed25519 =
{
  .name = "ssh-ed25519",
  .implem = "assh-builtin",
  .min_bits = 255,
  .bits = 255,
  .max_bits = 255,
  .priority = 1,

  .formats = (enum assh_key_format_e[]){
    ASSH_KEY_FMT_PV_OPENSSH_V1,
    ASSH_KEY_FMT_PUB_RFC4716,
    ASSH_KEY_FMT_PUB_RFC4253,
    ASSH_KEY_FMT_PUB_OPENSSH,
    ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB,
    ASSH_KEY_FMT_PV_OPENSSH_V1_KEY,
    0,
  },

  .f_output = assh_key_eddsa_output,
#ifdef CONFIG_ASSH_KEY_CREATE
  .f_create = assh_key_ed25519_create,
#endif
  .f_load = assh_key_ed25519_load,
#ifdef CONFIG_ASSH_KEY_VALIDATE
  .f_validate = assh_key_eddsa_validate,
#endif
  .f_cmp = assh_key_eddsa_cmp,
  .f_cleanup = assh_key_eddsa_cleanup,
};


const struct assh_edward_curve_s assh_e382_curve = 
{
  .p =  (const uint8_t *)"\x00\x00\x00\x30"
        "\x3f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x97",
  .l =  (const uint8_t *)"\x00\x00\x00\x30"
        "\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xd5\xfb\x21\xf2\x1e\x95\xee\xe1"
        "\x7c\x5e\x69\x28\x1b\x10\x2d\x27\x73\xe2\x7e\x13\xfd\x3c\x97\x19",
  .bx = (const uint8_t *)"\x00\x00\x00\x30"
        "\x19\x6f\x8d\xd0\xea\xb2\x03\x91\xe5\xf0\x5b\xe9\x6e\x8d\x20\xae"
        "\x68\xf8\x40\x03\x2b\x0b\x64\x35\x29\x23\xba\xb8\x53\x64\x84\x11"
        "\x93\x51\x7d\xbc\xe8\x10\x53\x98\xeb\xc0\xcc\x94\x70\xf7\x96\x03",
  .by = (const uint8_t *)"\x00\x00\x00\x01" "\x11",
  .a =  (const uint8_t *)"\x00\x00\x00\x01" "\x01",
  .d =  (const uint8_t *)"\x00\x00\x00\x30"
        "\x3f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xf8\xe1",
  .bits = 382,
  .cofactor = 4,
  .safety = 70
};

static ASSH_KEY_LOAD_FCN(assh_key_eddsa_e382_load)
{
  return assh_key_eddsa_load(c, algo, blob_, blob_len, key, format,
                             &assh_e382_curve, &assh_hash_shake_256);
}

#ifdef CONFIG_ASSH_KEY_CREATE
static ASSH_KEY_CREATE_FCN(assh_key_eddsa_e382_create)
{
  return assh_key_eddsa_create(c, algo, key,
                               &assh_e382_curve, &assh_hash_shake_256);
}
#endif

const struct assh_key_algo_s assh_key_builtin_eddsa_e382 =
{
  .name = "eddsa-e382-shake256",
  .implem = "assh-builtin",
  .min_bits = 382,
  .bits = 382,
  .max_bits = 382,
  .priority = 1,

  .formats = (enum assh_key_format_e[]){
    ASSH_KEY_FMT_PV_OPENSSH_V1,
    ASSH_KEY_FMT_PUB_RFC4716,
    ASSH_KEY_FMT_PUB_RFC4253,
    ASSH_KEY_FMT_PUB_OPENSSH,
    ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB,
    ASSH_KEY_FMT_PV_OPENSSH_V1_KEY,
    0,
  },

  .f_output = assh_key_eddsa_output,
#ifdef CONFIG_ASSH_KEY_CREATE
  .f_create = assh_key_eddsa_e382_create,
#endif
  .f_load = assh_key_eddsa_e382_load,
#ifdef CONFIG_ASSH_KEY_VALIDATE
  .f_validate = assh_key_eddsa_validate,
#endif
  .f_cmp = assh_key_eddsa_cmp,
  .f_cleanup = assh_key_eddsa_cleanup,
};


const struct assh_edward_curve_s assh_e521_curve = 
{
  .p =  (const uint8_t *)"\x00\x00\x00\x42"
        "\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff",
  .l =  (const uint8_t *)"\x00\x00\x00\x41"
        "\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xfd\x15\xb6\xc6\x47\x46\xfc\x85\xf7\x36\xb8\xaf\x5e\x7e\xc5\x3f"
        "\x04\xfb\xd8\xc4\x56\x9a\x8f\x1f\x45\x40\xea\x24\x35\xf5\x18\x0d"
        "\x6b",
  .bx = (const uint8_t *)"\x00\x00\x00\x41"
        "\x75\x2c\xb4\x5c\x48\x64\x8b\x18\x9d\xf9\x0c\xb2\x29\x6b\x28\x78"
        "\xa3\xbf\xd9\xf4\x2f\xc6\xc8\x18\xec\x8b\xf3\xc9\xc0\xc6\x20\x39"
        "\x13\xf6\xec\xc5\xcc\xc7\x24\x34\xb1\xae\x94\x9d\x56\x8f\xc9\x9c"
        "\x60\x59\xd0\xfb\x13\x36\x48\x38\xaa\x30\x2a\x94\x0a\x2f\x19\xba"
        "\x6c",
  .by = (const uint8_t *)"\x00\x00\x00\x01" "\x0c",
  .a =  (const uint8_t *)"\x00\x00\x00\x01" "\x01",
  .d =  (const uint8_t *)"\x00\x00\x00\x42"
        "\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfa"
        "\x43\x31",
  .bits = 521,
  .cofactor = 4,
  .safety = 90
};

static ASSH_KEY_LOAD_FCN(assh_key_eddsa_e521_load)
{
  return assh_key_eddsa_load(c, algo, blob_, blob_len, key, format,
                             &assh_e521_curve, &assh_hash_shake_256);
}

#ifdef CONFIG_ASSH_KEY_CREATE
static ASSH_KEY_CREATE_FCN(assh_key_eddsa_e521_create)
{
  return assh_key_eddsa_create(c, algo, key,
                               &assh_e521_curve, &assh_hash_shake_256);
}
#endif

const struct assh_key_algo_s assh_key_builtin_eddsa_e521 =
{
  .name = "eddsa-e521-shake256",
  .implem = "assh-builtin",
  .min_bits = 521,
  .bits = 521,
  .max_bits = 521,
  .priority = 1,

  .formats = (enum assh_key_format_e[]){
    ASSH_KEY_FMT_PV_OPENSSH_V1,
    ASSH_KEY_FMT_PUB_RFC4716,
    ASSH_KEY_FMT_PUB_RFC4253,
    ASSH_KEY_FMT_PUB_OPENSSH,
    ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB,
    ASSH_KEY_FMT_PV_OPENSSH_V1_KEY,
    0,
  },

  .f_output = assh_key_eddsa_output,
#ifdef CONFIG_ASSH_KEY_CREATE
  .f_create = assh_key_eddsa_e521_create,
#endif
  .f_load = assh_key_eddsa_e521_load,
#ifdef CONFIG_ASSH_KEY_VALIDATE
  .f_validate = assh_key_eddsa_validate,
#endif
  .f_cmp = assh_key_eddsa_cmp,
  .f_cleanup = assh_key_eddsa_cleanup,
};

