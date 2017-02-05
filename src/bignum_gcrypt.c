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
#include <assh/assh_packet.h>
#include <assh/assh_prng.h>
#include <assh/assh_alloc.h>

#include <gcrypt.h>
#define gcry_mpi_snew gcry_mpi_new

static void assh_bignum_gcrypt_lsb(uint8_t *data, size_t size)
{
  size_t i;
  for (i = 0; i < size / 2; i++)
    ASSH_SWAP(data[i], data[size - i - 1]);
}

static enum gcry_random_level
assh_gcrypt_bignum_randlevel(enum assh_prng_quality_e quality)
{
#if defined(CONFIG_ASSH_DEBUG)
  ASSH_DEBUG("CONFIG_ASSH_DEBUG: using weak random\n");
  return GCRY_WEAK_RANDOM;
#else
  switch (quality)
    {
    case ASSH_PRNG_QUALITY_WEAK:
    case ASSH_PRNG_QUALITY_PUBLIC:
      return GCRY_WEAK_RANDOM;
      break;
    case ASSH_PRNG_QUALITY_NONCE:
    case ASSH_PRNG_QUALITY_EPHEMERAL_KEY:
      return GCRY_STRONG_RANDOM;
      break;
    case ASSH_PRNG_QUALITY_LONGTERM_KEY:
    default:
      return GCRY_VERY_STRONG_RANDOM;
      break;
    }
#endif
}

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_gcrypt_bignum_rand(struct assh_context_s *c,
                        struct assh_bignum_s *bn,
                        const struct assh_bignum_s *min,
                        const struct assh_bignum_s *max,
                        enum assh_prng_quality_e quality)
{
  assh_error_t err;

  ASSH_RET_IF_TRUE(c->prng == NULL, ASSH_ERR_MISSING_ALGO);

  size_t bits = bn->bits;

  bn->secret = quality > ASSH_PRNG_QUALITY_PUBLIC;

  if (max != NULL)
    bits = ASSH_MIN(bits, gcry_mpi_get_nbits(max->n));

#ifdef CONFIG_ASSH_USE_GCRYPT_PRNG
  if (c->prng == &assh_prng_gcrypt)
    {
      enum gcry_random_level level = assh_gcrypt_bignum_randlevel(quality);
      size_t n = ASSH_ALIGN8(bits);

      if (bn->n == NULL)
        bn->n = gcry_mpi_snew(n);

      gcry_mpi_randomize(bn->n, n, level);
      gcry_mpi_rshift(bn->n, bn->n, n - bits);

      gcry_mpi_t t = NULL;

      while ((min != NULL && gcry_mpi_cmp(bn->n, min->n) <= 0) ||
             (max != NULL && gcry_mpi_cmp(bn->n, max->n) >= 0))
        {
          if (t == NULL)
            t = gcry_mpi_snew(8);

          gcry_mpi_rshift(bn->n, bn->n, 8);
          gcry_mpi_randomize(t, 8, level);
          if (bits >= 8)
            gcry_mpi_lshift(t, t, bits - 8);
          else
            gcry_mpi_rshift(t, t, 8 - bits);
          gcry_mpi_add(bn->n, bn->n, t);
        }

      gcry_mpi_release(t);

      err = ASSH_OK;
    }
  else
#endif
    {
      const size_t wsize = 32;
      size_t n = ((bits - 1) | (wsize - 1)) + 1;

      ASSH_SCRATCH_ALLOC(c, uint8_t, rnd, n / 8, ASSH_ERRSV_CONTINUE, err_);

      ASSH_JMP_ON_ERR(c->prng->f_get(c, rnd, n / 8, quality), err_sc);
#ifdef CONFIG_ASSH_DEBUG
      /* give same result as bignum_builtin.c on little-endian platforms */
      assh_bignum_gcrypt_lsb(rnd, n / 8);
#endif

      while (1)
        {
          gcry_mpi_release(bn->n);
          bn->n = NULL;
          ASSH_JMP_IF_TRUE(gcry_mpi_scan((gcry_mpi_t*)&bn->n,
                 GCRYMPI_FMT_USG, rnd, n / 8, NULL), ASSH_ERR_CRYPTO, err_sc);
          gcry_mpi_clear_highbit(bn->n, bits);

          if ((min == NULL || gcry_mpi_cmp(bn->n, min->n) > 0) &&
              (max == NULL || gcry_mpi_cmp(bn->n, max->n) < 0))
            break;

          memmove(rnd, rnd + wsize / 8, (n - wsize) / 8);
          ASSH_JMP_ON_ERR(c->prng->f_get(c, rnd + (n - wsize) / 8, wsize / 8, quality), err_sc);
#ifdef CONFIG_ASSH_DEBUG
          assh_bignum_gcrypt_lsb(rnd, wsize / 8);
#endif
        }

      err = ASSH_OK;
    err_sc:
      ASSH_SCRATCH_FREE(c, rnd);
    err_:;
    }

  return err;
}

static ASSH_BIGNUM_CONVERT_FCN(assh_bignum_gcrypt_convert)
{
  assh_error_t err;

  const struct assh_bignum_s *srcn = src;
  struct assh_bignum_s *dstn = dst;

  if (srcfmt == ASSH_BIGNUM_NATIVE ||
      srcfmt == ASSH_BIGNUM_TEMP)
    {
      size_t s = ASSH_ALIGN8(srcn->bits) / 8;
      size_t z = s;

      switch (dstfmt)
        {
        case ASSH_BIGNUM_NATIVE:
        case ASSH_BIGNUM_TEMP:
          ASSH_RET_IF_TRUE(dstn->bits < gcry_mpi_get_nbits(srcn->n), ASSH_ERR_NUM_OVERFLOW);
          gcry_mpi_release(dstn->n);
          dstn->n = gcry_mpi_copy(srcn->n);
          ASSH_RET_IF_TRUE(dstn->n == NULL, ASSH_ERR_MEM);
          dstn->mt_num = srcn->mt_num;
          dstn->secret = srcn->secret | secret;
          return ASSH_OK;
        case ASSH_BIGNUM_STRING:
          assert(!srcn->mt_num);
          assh_store_u32(dst, s);
          dst += 4;
          ASSH_RET_IF_TRUE(gcry_mpi_print(GCRYMPI_FMT_USG, dst, s, &z, srcn->n),
                       ASSH_ERR_NUM_OVERFLOW);
          break;
        case ASSH_BIGNUM_MPINT:
          assert(!srcn->mt_num);
          ASSH_RET_IF_TRUE(gcry_mpi_print(GCRYMPI_FMT_SSH, dst, s + 5, NULL, srcn->n),
                       ASSH_ERR_NUM_OVERFLOW);
          s = 4 + assh_load_u32(dst);
          goto no_pad;
        case ASSH_BIGNUM_LSB_RAW:
        case ASSH_BIGNUM_MSB_RAW:
          assert(!srcn->mt_num);
          ASSH_RET_IF_TRUE(gcry_mpi_print(GCRYMPI_FMT_USG, dst, s, &z, srcn->n),
                       ASSH_ERR_NUM_OVERFLOW);
          break;
        case ASSH_BIGNUM_ASN1: {
          size_t hl = assh_asn1_headlen(s);
          uint8_t *d = dst;
          uint8_t *e = (uint8_t*)dst + hl;
          ASSH_RET_IF_TRUE(gcry_mpi_print(GCRYMPI_FMT_STD, e, s, &z, srcn->n),
                       ASSH_ERR_NUM_OVERFLOW);
          if (!z)
            {
              *d++ = 0x02;
              *d++ = 0x01;
              *d++ = 0x00;
            }
          else
            {
              assh_append_asn1(&d, 0x02, z);
              if (d < e)
                memmove(d, e, z);
            }
          if (next)
            *next = d + z;
          return ASSH_OK;
        }
        default:
          ASSH_RETURN(ASSH_ERR_NOTSUP);
        }

      /* shift and zero pad */
      if (z < s)
        {
          size_t d = s - z;
          memmove(dst + d, dst, z);
          memset(dst, 0, d);
        }

      /* reverse byte order */
      if (dstfmt == ASSH_BIGNUM_LSB_RAW)
        assh_bignum_gcrypt_lsb(dst, s);

    no_pad:
      if (next)
        *next = dst + s;
    }
  else
    {
      assert(dstfmt == ASSH_BIGNUM_NATIVE ||
             dstfmt == ASSH_BIGNUM_TEMP);
      dstn->mt_num = 0;
      size_t s, n, b;

      if (srcfmt == ASSH_BIGNUM_MSB_RAW ||
          srcfmt == ASSH_BIGNUM_LSB_RAW)
        {
          b = dstn->bits;
          n = s = ASSH_ALIGN8(b) / 8;
        }
      else
        {
          ASSH_RET_ON_ERR(assh_bignum_size_of_data(srcfmt, src, &s, &n, &b));
          ASSH_RET_IF_TRUE(dstn->bits < b, ASSH_ERR_NUM_OVERFLOW);
        }

      gcry_mpi_release(dstn->n);
      dstn->n = NULL;

      switch (srcfmt)
        {
        case ASSH_BIGNUM_STRING:
        case ASSH_BIGNUM_MPINT: {
          const uint8_t *mpint = src;
          ASSH_RET_IF_TRUE(gcry_mpi_scan((gcry_mpi_t*)&dstn->n, GCRYMPI_FMT_USG,
                                     mpint + 4, s - 4, NULL),
                       ASSH_ERR_NUM_OVERFLOW);
          break;
        }

        case ASSH_BIGNUM_ASN1: {
          const uint8_t *asn1 = src;
          ASSH_RET_IF_TRUE(gcry_mpi_scan((gcry_mpi_t*)&dstn->n, GCRYMPI_FMT_USG,
                                     asn1 + s - n, n, NULL),
                       ASSH_ERR_NUM_OVERFLOW);
          break;
        }

        case ASSH_BIGNUM_LSB_RAW: {
          ASSH_SCRATCH_ALLOC(c, uint8_t, lsb, s,
                             ASSH_ERRSV_CONTINUE, err_lsb);
          memcpy(lsb, src, s);
          assh_bignum_gcrypt_lsb(lsb, s);
          ASSH_JMP_IF_TRUE(gcry_mpi_scan((gcry_mpi_t*)&dstn->n, GCRYMPI_FMT_USG,
                                     lsb, s, NULL),
                       ASSH_ERR_NUM_OVERFLOW, err_lsb_scan);          
          gcry_mpi_clear_highbit((gcry_mpi_t)dstn->n, b);

          ASSH_SCRATCH_FREE(c, lsb);
          break;

         err_lsb_scan:
          ASSH_SCRATCH_FREE(c, lsb);
         err_lsb:
          return err;
        }

        case ASSH_BIGNUM_MSB_RAW: {
          ASSH_RET_IF_TRUE(gcry_mpi_scan((gcry_mpi_t*)&dstn->n, GCRYMPI_FMT_USG,
                                     src, s, NULL),
                       ASSH_ERR_NUM_OVERFLOW);
          gcry_mpi_clear_highbit((gcry_mpi_t)dstn->n, b);
          break;
        }

        case ASSH_BIGNUM_HEX: {
          ASSH_RET_IF_TRUE(gcry_mpi_scan((gcry_mpi_t*)&dstn->n, GCRYMPI_FMT_HEX,
                                     src, 0, NULL),
                       ASSH_ERR_NUM_OVERFLOW);
          break;
        }

        case ASSH_BIGNUM_INT: {
          ASSH_RET_IF_TRUE(dstn->bits < sizeof(intptr_t) * 8, ASSH_ERR_NUM_OVERFLOW);
          dstn->n = gcry_mpi_set_ui(dstn->n, (uintptr_t)src);
          break;
        }

        case ASSH_BIGNUM_SIZE: {
          dstn->bits = b;
          break;
        }

        default:
          ASSH_RETURN(ASSH_ERR_NOTSUP);
        }

      ASSH_RET_IF_TRUE(dstn->n == NULL, ASSH_ERR_MEM);
      ASSH_RET_IF_TRUE(gcry_mpi_is_neg(dstn->n), ASSH_ERR_NUM_OVERFLOW);
      ASSH_RET_IF_TRUE(gcry_mpi_get_nbits(dstn->n) > dstn->bits, ASSH_ERR_NUM_OVERFLOW);
      dstn->secret = secret;
      dstn->storage = secret | dstn->secure;
#warning memory leak when enabled
#if 0
      if (dstn->storage)
        gcry_mpi_set_flag(dstn->n, GCRYMPI_FLAG_SECURE);
#endif
    }

  return ASSH_OK;
}

struct assh_gcrypt_prime_s
{
  gcry_mpi_t min;
  gcry_mpi_t max;
};

static int assh_gcrypt_prime_chk(void *arg, int mode,
                                 gcry_mpi_t candidate)
{
  struct assh_gcrypt_prime_s *p = arg;

  if (p->min != NULL && gcry_mpi_cmp(candidate, p->min) <= 0)
    return 0;
  if (p->max != NULL && gcry_mpi_cmp(candidate, p->max) >= 0)
    return 0;
  return 1;
}

static void
assh_bignum_gcrypt_print(void *arg, enum assh_bignum_fmt_e fmt,
                         uint32_t id, uint_fast16_t pc)
{
#ifdef CONFIG_ASSH_DEBUG
  struct assh_bignum_s *src = arg;
  char idstr[5];
  idstr[4] = 0;
  assh_store_u32le((uint8_t*)idstr, id);
  fprintf(stderr, "[pc=%u, id=%s, type=%c] ", pc, idstr, fmt);
  switch (fmt)
    {
    case ASSH_BIGNUM_NATIVE:
    case ASSH_BIGNUM_TEMP:
      fprintf(stderr, "[bits=%zu] ", src->bits);
      if (src->secret)
        fprintf(stderr, "secret ");
      if (src->n == NULL)
        {
          fprintf(stderr, "NULL");
          break;
        }
      size_t n = gcry_mpi_get_nbits(src->n);
      n = n ? ((n - 1) | 7) + 1 : 8;
      size_t b = ((src->bits - 1) | 7) + 1;
      fputs("0x", stderr);
      while (n < b)
        {
          fputc('0', stderr);
          n += 4;
        }
      gcry_mpi_dump(src->n);
      break;
    case ASSH_BIGNUM_SIZE:
      fprintf(stderr, "%u", (unsigned)(uintptr_t)arg);
      break;
    }
  fprintf(stderr, "\n");
#endif
}

assh_error_t assh_bignum_gcrypt_realloc(struct assh_bignum_s *bn, assh_bool_t secret)
{
  assh_error_t err;

  bn->secret = secret;
  secret |= bn->secure;

  if (bn->n == NULL)
    {
      bn->n = secret ? gcry_mpi_snew(bn->bits) : gcry_mpi_new(bn->bits);
    }
  else if (bn->storage != secret)
    {
#warning memory leak when enabled
#if 0
      if (secret)
        {
          gcry_mpi_set_flag(bn->n, GCRYMPI_FLAG_SECURE);
        }
      else
        {
          gcry_mpi_clear_flag(bn->n, GCRYMPI_FLAG_SECURE);
        }
#endif
    }

  ASSH_RET_IF_TRUE(bn->n == NULL, ASSH_ERR_MEM);
  bn->storage = secret;

  return ASSH_OK;
}

static ASSH_BIGNUM_BYTECODE_FCN(assh_bignum_gcrypt_bytecode)
{
  uint_fast8_t flen, tlen = 0;
  assh_error_t err;
  uint_fast8_t i, j;
  uint_fast16_t pc = 0;
  uint_fast16_t lad_index;
  uint8_t cond_secret = 0;
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
  uint8_t trace = 0;
#endif

  /* find number of arguments and temporaries */
  for (tlen = flen = 0; format[flen]; flen++)
    if (format[flen] == 'T' ||
        format[flen] == 'X' ||
        format[flen] == 'm')
      tlen++;

  void *args[flen];
  struct assh_bignum_s tmp[tlen];
  memset(tmp, 0, sizeof(tmp));

  for (j = i = 0; i < flen; i++)
    switch (format[i])
      {
      case ASSH_BIGNUM_TEMP:
      case ASSH_BIGNUM_MT:
        args[i] = &tmp[j];
        j++;
        break;
      case ASSH_BIGNUM_SIZE:
        args[i] = (void*)va_arg(ap, size_t);
        break;
      default:
        args[i] = va_arg(ap, void *);
      }

  while (1)
    {
      uint32_t opc = ops[pc];
      enum assh_bignum_opcode_e op = opc >> 26;
      uint_fast8_t oa = (opc >> 20) & 0x3f;
      uint_fast8_t ob = (opc >> 14) & 0x3f;
      uint_fast8_t oc = (opc >> 6) & 0xff;
      uint_fast8_t od = opc & 0x3f;

#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
      if (trace & 1)
        {
          const char *opnames[] = ASSH_BIGNUM_OP_NAMES;
          ASSH_DEBUG("pc=%u, op=%s, a=%u, b=%u, c=%u, d=%u cond=0x%02x\n",
                     pc, opnames[op], oa, ob, oc, od, cond);
        }
#endif

      pc++;
      switch (op)
        {
        case ASSH_BIGNUM_OP_END:
          goto end;

        case ASSH_BIGNUM_OP_MOVE: {
          void *dst = args[oc];
          uint8_t *next;
          ASSH_JMP_ON_ERR(assh_bignum_gcrypt_convert(c, format[od], format[oc],
                         args[od], dst, &next, ob), err_sc);

          /* deduce pointer of next buffer arg */
          if (oc + 1 < flen && args[oc + 1] == NULL)
            args[oc + 1] = next;

#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          switch (format[oc])
            {
            case ASSH_BIGNUM_NATIVE:
            case ASSH_BIGNUM_TEMP:
              if (trace & 2)
                assh_bignum_gcrypt_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc);
            }
#endif
          break;
        }

        case ASSH_BIGNUM_OP_SIZE: {
          size_t b, i;
          ASSH_JMP_ON_ERR(assh_bignum_size_of_data(format[ob], args[ob],
                                                NULL, NULL, &b), err_sc);
          struct assh_bignum_s *dst = args[oa];
          dst->bits = ((od >= 32) ? (b << (od - 32))
                       : (b >> (32 - od))) + (intptr_t)(int8_t)oc;
          break;
        }

        case ASSH_BIGNUM_OP_SIZER: {
          size_t b, i;
          ASSH_JMP_ON_ERR(assh_bignum_size_of_data(format[ob], args[ob],
                                                NULL, NULL, &b), err_sc);
          for (i = oa; i <= oc; i++) 
            {
              struct assh_bignum_s *dst = args[i];
              dst->bits = b;
            }
          break;
        }

        case ASSH_BIGNUM_OP_MTINIT: {
          struct assh_bignum_s *src = args[od];
          struct assh_bignum_s *dst = args[oc];
          assert(!src->mt_num);
          assert(!src->secret);
          gcry_mpi_release(dst->n);
          dst->n = gcry_mpi_copy(src->n);
          ASSH_JMP_IF_TRUE(dst->n == NULL, ASSH_ERR_MEM, err_sc);
          dst->bits = src->bits;
          dst->mt_mod = 1;
          dst->mt_num = 0;
          dst->secret = 0;
          break;
        }

        case ASSH_BIGNUM_OP_MTFROM:
        case ASSH_BIGNUM_OP_MTTO: {
          uint_fast8_t i;
          for (i = 0; i < oa; i++)
            {
              struct assh_bignum_s *src = args[oc + i];
              struct assh_bignum_s *dst = args[ob + i];
              assert(src->mt_num != (op == ASSH_BIGNUM_OP_MTTO));
              dst->mt_num = (op == ASSH_BIGNUM_OP_MTTO);
              if (oc == ob)
                continue;
              gcry_mpi_release(dst->n);
              dst->n = gcry_mpi_copy(src->n);
              dst->secret = src->secret;
            }
          break;
        }

        case ASSH_BIGNUM_OP_EXPM: {
          assert(format[od] == ASSH_BIGNUM_MT);
        case ASSH_BIGNUM_OP_ADD:
        case ASSH_BIGNUM_OP_SUB:
        case ASSH_BIGNUM_OP_MUL:;
          struct assh_bignum_s *src1 = args[ob];
          struct assh_bignum_s *src2 = args[oc];
          struct assh_bignum_s *dst = args[oa];

          ASSH_JMP_ON_ERR(assh_bignum_gcrypt_realloc(dst, src1->secret | src2->secret), err_sc);

          if (od == ASSH_BOP_NOREG)
            {
              assert(!src1->mt_num && !src2->mt_num);
              assert(dst->bits >= src1->bits &&
                     dst->bits >= src2->bits);
              switch (op)
                {
                case ASSH_BIGNUM_OP_ADD:
                  gcry_mpi_add(dst->n, src1->n, src2->n);
                  ASSH_JMP_IF_TRUE(gcry_mpi_get_nbits(dst->n) > dst->bits,
                               ASSH_ERR_NUM_OVERFLOW, err_sc);
                  break;
                case ASSH_BIGNUM_OP_SUB:
                  gcry_mpi_sub(dst->n, src1->n, src2->n);
                  ASSH_JMP_IF_TRUE(gcry_mpi_get_nbits(dst->n) > dst->bits,
                               ASSH_ERR_NUM_OVERFLOW, err_sc);
                  ASSH_JMP_IF_TRUE(gcry_mpi_is_neg(dst->n),
                               ASSH_ERR_NUM_OVERFLOW, err_sc);
                  break;
                case ASSH_BIGNUM_OP_MUL:
                  assert(dst->bits >= src1->bits + src2->bits);
                  gcry_mpi_mul(dst->n, src1->n, src2->n);
                  break;
                default:
                  ASSH_UNREACHABLE();
                }
            }
          else
            {
              struct assh_bignum_s *mod = args[od];
              switch (op)
                {
                case ASSH_BIGNUM_OP_ADD:
                  assert(mod->mt_mod && src1->mt_num && src2->mt_num);
                  gcry_mpi_addm(dst->n, src1->n, src2->n, mod->n);
                  break;
                case ASSH_BIGNUM_OP_SUB:
                  assert(mod->mt_mod && src1->mt_num && src2->mt_num);
                  gcry_mpi_subm(dst->n, src1->n, src2->n, mod->n);
                  ASSH_JMP_IF_TRUE(gcry_mpi_is_neg(dst->n),
                               ASSH_ERR_NUM_OVERFLOW, err_sc);
                  break;
                case ASSH_BIGNUM_OP_MUL:
                  assert(mod->mt_mod == src1->mt_num);
                  assert(mod->mt_mod == src2->mt_num);
                  assert((!src1->secret && !src2->secret) || mod->mt_mod);
                  gcry_mpi_mulm(dst->n, src1->n, src2->n, mod->n);
                  break;
                case ASSH_BIGNUM_OP_EXPM:
                  assert(mod->mt_mod);
                  assert(src1->mt_num);
                  assert(!src2->mt_num);
                  gcry_mpi_powm(dst->n, src1->n, src2->n, mod->n);
                  break;
                default:
                  ASSH_UNREACHABLE();
                }
            }
          dst->mt_num = src1->mt_num;
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_gcrypt_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_DIV: {
          gcry_mpi_t q = NULL, r = NULL;
          struct assh_bignum_s *dsta = NULL, *dstb = NULL;
          struct assh_bignum_s *src1 = args[oc];
          struct assh_bignum_s *src2 = args[od];
          assert(!src2->mt_num);
          assert(src1->mt_num == src2->mt_mod);
          assert(src2->mt_mod || (!src1->secret && !src2->secret));
          if (oa != ASSH_BOP_NOREG)
            {
              assert(!src2->mt_mod);
              dsta = args[oa];
              dsta->mt_num = 0;
              dsta->secret = 0;
              ASSH_JMP_ON_ERR(assh_bignum_gcrypt_realloc(dsta, 0), err_sc);
              q = dsta->n;
            }
          if (ob != ASSH_BOP_NOREG)
            {
              dstb = args[ob];
              dstb->mt_num = src2->mt_mod;
              dstb->secret = 0;
              ASSH_JMP_ON_ERR(assh_bignum_gcrypt_realloc(dstb, src1->secret), err_sc);
              r = dstb->n;
            }
          ASSH_RET_IF_TRUE(!gcry_mpi_cmp_ui(src2->n, 0), ASSH_ERR_NUM_OVERFLOW);
          gcry_mpi_div(q, r, src1->n, src2->n, 0);
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            {
              if (dsta)
                assh_bignum_gcrypt_print(dsta, ASSH_BIGNUM_NATIVE, 'A', pc);
              if (dstb)
                assh_bignum_gcrypt_print(dstb, ASSH_BIGNUM_NATIVE, 'B', pc);
            }
#endif
          break;
        }

        case ASSH_BIGNUM_OP_INV:
        case ASSH_BIGNUM_OP_GCD: {
          struct assh_bignum_s *dst = args[ob];
          struct assh_bignum_s *src1 = args[oc];
          struct assh_bignum_s *src2 = args[od];
          ASSH_JMP_ON_ERR(assh_bignum_gcrypt_realloc(dst, src1->secret | src2->secret), err_sc);
          switch (op)
            {
            case ASSH_BIGNUM_OP_GCD:
              assert(!src1->secret && !src2->secret);
              assert(!src1->mt_num && !src2->mt_num);
              gcry_mpi_gcd(dst->n, src1->n, src2->n);
              dst->mt_num = 0;
              break;
            case ASSH_BIGNUM_OP_INV:
              assert(src2->mt_mod == src1->mt_num);
              assert(!src1->secret || src2->mt_mod);
              gcry_mpi_invm(dst->n, src1->n, src2->n);
              dst->mt_num = src1->mt_num;
              break;
            default:
              ASSH_UNREACHABLE();
            }
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_gcrypt_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_SHR:
        case ASSH_BIGNUM_OP_SHL: {
          struct assh_bignum_s *dst = args[oa];
          struct assh_bignum_s *src = args[ob];
          assert(!src->mt_num);
          size_t b = 0;
          ASSH_RET_IF_TRUE(dst->bits != src->bits, ASSH_ERR_OUTPUT_OVERFLOW);
          if (od != ASSH_BOP_NOREG)
            {
              ASSH_JMP_ON_ERR(assh_bignum_size_of_data(format[od], args[od],
                                                    NULL, NULL, &b), err_sc);
            }
          ASSH_JMP_ON_ERR(assh_bignum_gcrypt_realloc(dst, src->secret), err_sc);
          switch (op)
            {
            case ASSH_BIGNUM_OP_SHR:
              gcry_mpi_rshift(dst->n, src->n, b + oc - 128);
              break;
            case ASSH_BIGNUM_OP_SHL:
              gcry_mpi_lshift(dst->n, src->n, b + oc - 128);
	      gcry_mpi_clear_highbit(dst->n, dst->bits);
              break;
            default:
              ASSH_UNREACHABLE();
            }
          dst->mt_num = 0;
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_gcrypt_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_RAND: {
          struct assh_bignum_s *dst = args[oa];
          ASSH_JMP_ON_ERR(assh_gcrypt_bignum_rand(c, dst,
                         ob == ASSH_BOP_NOREG ? NULL : args[ob],
                         oc == ASSH_BOP_NOREG ? NULL : args[oc],
                         od), err_sc);
          dst->mt_num = 0;
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_gcrypt_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_CMP: {
          int r = 0;
          struct assh_bignum_s *src1 = args[ob];
          struct assh_bignum_s *src2 = args[oc];
          uint8_t cond_mask = 1 << oa;
          cond &= ~cond_mask;
          cond_secret &= ~cond_mask;
          if (oc == ASSH_BOP_NOREG)
            {
              r = src1->n != NULL;
            }
          else
            {
              cond_secret |= (src1->secret | src2->secret) << oa;
              assert(!src2->mt_num);
              if (oc != ob)
                {
                  assert(!src1->mt_num);
                  r = gcry_mpi_cmp(src1->n, src2->n);
                }
            }
          switch (od)
            {
            case 0:             /* cmpeq */
              r = r == 0;
              break;
            case 1:             /* cmplt */
              r = r < 0;
              break;
            case 2:             /* cmplteq */
              r = r <= 0;
              break;
            }
          cond |= r << oa;
          break;
        }

        case ASSH_BIGNUM_OP_TEST: {
          struct assh_bignum_s *src1 = args[ob];
          uint8_t cond_mask = (1 << oa);
          cond &= ~cond_mask;
          size_t b = oc;
          assert(!src1->mt_num);
          if (od != ASSH_BOP_NOREG)
            {
              ASSH_JMP_ON_ERR(assh_bignum_size_of_data(format[od], args[od],
                                                    NULL, NULL, &b), err_sc);
              b -= oc;
            }
          assert(b < src1->bits);
          cond |= !!gcry_mpi_test_bit(src1->n, b) << oa;
          cond_secret &= ~cond_mask;
          cond_secret |= src1->secret << oa;
          break;
        }

        case ASSH_BIGNUM_OP_MTUINT: {
          uint_fast32_t value = (opc >> 14) & 0xfff;
          struct assh_bignum_s *dst = args[od];
          struct assh_bignum_s *mt = args[oc];
          assert(dst->bits == mt->bits);
          dst->mt_num = 1;
          dst->mt_id = oc;
          dst->n = gcry_mpi_set_ui(dst->n, value);
          dst->secret = 0;
          ASSH_JMP_IF_TRUE(dst->n == NULL, ASSH_ERR_MEM, err_sc);
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_gcrypt_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_UINT: {
          uint_fast32_t value = (opc >> 6) & 0xfffff;
          struct assh_bignum_s *dst = args[od];
          dst->mt_num = 0;
          dst->n = gcry_mpi_set_ui(dst->n, value);
          dst->secret = 0;
          ASSH_JMP_IF_TRUE(dst->n == NULL, ASSH_ERR_MEM, err_sc);
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_gcrypt_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_JMP:
          assert(!((cond_secret >> oa) & 1));
          if (ob | (((cond >> oa) ^ od) & 1))
            pc += oc - 128;
          break;

        case ASSH_BIGNUM_OP_CSWAP: {
          struct assh_bignum_s *a = args[ob];
          struct assh_bignum_s *b = args[oc];

          a->secret = b->secret = a->secret |
            b->secret | ((cond_secret >> oa) & 1);
          if (((cond >> oa) ^ od) & 1)
            gcry_mpi_swap(a->n, b->n);
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            {
              assh_bignum_gcrypt_print(a, ASSH_BIGNUM_NATIVE, 'A', pc);
              assh_bignum_gcrypt_print(b, ASSH_BIGNUM_NATIVE, 'B', pc);
            }
#endif
          break;
        }

        case ASSH_BIGNUM_OP_CMOVE: {
          struct assh_bignum_s *dst = args[ob];
          struct assh_bignum_s *src = args[oc];

          dst->secret |= src->secret | ((cond_secret >> oa) & 1);
          if (((cond >> oa) ^ od) & 1)
            gcry_mpi_set(dst->n, src->n);
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_gcrypt_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_CFAIL:
          ASSH_JMP_IF_TRUE(((cond >> oc) ^ od) & 1, ASSH_ERR_NUM_COMPARE_FAILED, err_sc);
          break;

        case ASSH_BIGNUM_OP_LADINIT: {
          struct assh_bignum_s *src = args[od];
          lad_index = src->bits - 1;
          ASSH_JMP_IF_TRUE(lad_index == 0, ASSH_ERR_NUM_OVERFLOW, err_sc);
          break;
        }

        case ASSH_BIGNUM_OP_LADTEST: {
          struct assh_bignum_s *src = args[od];
          uint8_t cond_mask = (1 << oc);
          assert(!src->mt_num);
          cond &= ~cond_mask;
          cond |= !!gcry_mpi_test_bit(src->n, lad_index) << oc;
          cond_secret &= cond_mask;
          cond_secret |= src->secret << oc;
          break;
        }

        case ASSH_BIGNUM_OP_LADNEXT: {
          uint8_t cond_mask = (1 << od);
          cond &= ~cond_mask;
          if (lad_index--)
            cond |= cond_mask;
          cond_secret &= ~cond_mask;
          break;
        }

        case ASSH_BIGNUM_OP_BOOL: {
          uint8_t src1 = (cond >> ob) & 1;
          uint8_t src2 = (cond >> oc) & 1;
          uint8_t dst_mask = (1 << oa);
          cond &= ~dst_mask;
          /* shift lookup table:
              op:       3     2     1     0
                       ANDN  XOR    OR   AND
            src1 src2  -------- dst --------
             0    0     0     0     0     0
             0    1     0     1     1     0
             1    0     1     1     1     0
             1    1     0     0     1     1
            --------------------------------
              hex:      4     6     E     8
             ~hex:      B     9     1     7
           */
          cond |= ((0xb91746e8 >> ((od << 2) | (src1 << 1) | src2)) & 1) << oa;
          cond_secret &= ~dst_mask;
          uint8_t src1_secret = (cond_secret >> ob) & 1;
          uint8_t src2_secret = (cond_secret >> oc) & 1;
          cond_secret |= (src1_secret | src1_secret) << oa;
          break;
        }

        case ASSH_BIGNUM_OP_PRIME: {
          struct assh_bignum_s *dst = args[oa];
          struct assh_gcrypt_prime_s pchk = { NULL, NULL };
          size_t bits = dst->bits;
          if (ob != ASSH_BOP_NOREG)
            {
              struct assh_bignum_s *min = args[ob];
              pchk.min = min->n;
              assert(min->bits == dst->bits);
            }
          if (oc != ASSH_BOP_NOREG)
            {
              struct assh_bignum_s *max = args[oc];
              pchk.max = max->n;
              assert(max->bits == dst->bits);
              bits = gcry_mpi_get_nbits(pchk.max);
            }
          if (dst->n)
            gcry_mpi_release(dst->n);

          /* FIXME call gcry_random_add_bytes here */
          ASSH_JMP_IF_TRUE(gcry_prime_generate((struct gcry_mpi **)&dst->n,
                         bits, 0, NULL, assh_gcrypt_prime_chk,
                         &pchk, assh_gcrypt_bignum_randlevel(od), 0),
                       ASSH_ERR_CRYPTO, err_sc);
          dst->mt_num = 0;
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_gcrypt_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_ISPRIME: {
          struct assh_bignum_s *src = args[od];
          assert(!src->mt_num);
          assert(!src->secret);
          assert(oc >= 7);
          uint8_t cond_mask = (1 << ob);
          cond &= ~cond_mask;
          cond |= (gcry_mpi_cmp_ui(src->n, 2) > 0 &&
                   !gcry_prime_check(src->n, 0)) << ob;
          cond_secret &= ~cond_mask;
        }

        case ASSH_BIGNUM_OP_PRIVACY: {
          struct assh_bignum_s *src = args[od];
          src->secure = oc;
          src->secret = ob;
          src->storage = oc | ob;
#warning memory leak when enabled
#if 0
          if (src->storage)
            gcry_mpi_set_flag(src->n, GCRYMPI_FLAG_SECURE);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_NEXTPRIME: {
          struct assh_bignum_s *dst = args[oc];
          assert(!dst->mt_num);
          gcry_mpi_t t = gcry_mpi_snew(dst->bits);
          ASSH_JMP_IF_TRUE(t == NULL, ASSH_ERR_MEM, err_sc);

          if (od != ASSH_BOP_NOREG)
            {
              struct assh_bignum_s *step = args[od];
              gcry_mpi_set(t, step->n);
              assert(gcry_mpi_test_bit(t, 0));
              assert(step->bits <= dst->bits);
              assert(!step->mt_num);
              assert(!step->secret);
              assert(!dst->secret);
            }
          else
            {
              gcry_mpi_set_ui(t, 1);
            }

          if (!gcry_mpi_test_bit(dst->n, 0))
            gcry_mpi_add(dst->n, dst->n, t);
          gcry_mpi_add(t, t, t);

          while (gcry_prime_check(dst->n, 0))
            gcry_mpi_add(dst->n, dst->n, t);
          gcry_mpi_release(t);

#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_gcrypt_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_PRINT: {
          assh_bignum_gcrypt_print(args[od], format[od], oc, pc);
          break;
        }

        case ASSH_BIGNUM_OP_TRACE:
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          trace = od;
#endif
          break;
        }
    }

 end:
  err = ASSH_OK;
 err_sc:;
  for (i = 0; i < tlen; i++)
    if (tmp[i].n != NULL)
      gcry_mpi_release(tmp[i].n);
  return err;
}

static ASSH_BIGNUM_RELEASE_FCN(assh_bignum_gcrypt_release)
{
  gcry_mpi_release(bn->n);
  bn->n = NULL;
}

const struct assh_bignum_algo_s assh_bignum_gcrypt =
{
  .name = "gcrypt",
  .f_bytecode = assh_bignum_gcrypt_bytecode,
  .f_convert = assh_bignum_gcrypt_convert,
  .f_release = assh_bignum_gcrypt_release,
};

