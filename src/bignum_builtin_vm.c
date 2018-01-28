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

#include "bignum_builtin.h"

#include <assh/assh_alloc.h>

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_bignum_realloc(struct assh_context_s *c,
                    struct assh_bignum_s *bn,
                    assh_bool_t secret, assh_bool_t perserve)
{
  assh_error_t err;

  bn->secret = secret;
  secret |= bn->secure;

  if (!bn->tmp)
    {
      enum assh_alloc_type_e type = secret
        ? ASSH_ALLOC_SECUR : ASSH_ALLOC_INTERNAL;
      size_t size = assh_bignum_words(bn->bits) * sizeof(assh_bnword_t);

      if (bn->n != NULL && bn->storage != secret)
        {
          void *new;
          ASSH_RET_ON_ERR(assh_alloc(c, size, type, &new));
          if (perserve)
            memcpy(new, bn->n, size);
          assh_free(c, bn->n);
          bn->n = new;
        }
      else if (bn->n == NULL)
        {
          ASSH_RET_ON_ERR(assh_realloc(c, &bn->n, size, type));
        }
    }

  bn->storage = secret;
  return ASSH_OK;
}

static ASSH_BIGNUM_CONVERT_FCN(assh_bignum_builtin_convert)
{
  assh_error_t err;

  const struct assh_bignum_s *srcn = src;
  struct assh_bignum_s *dstn = dst;

  if (srcfmt == ASSH_BIGNUM_NATIVE ||
      srcfmt == ASSH_BIGNUM_TEMP)
    {
      switch (dstfmt)
        {
        case ASSH_BIGNUM_NATIVE:
        case ASSH_BIGNUM_TEMP:
          ASSH_RET_ON_ERR(assh_bignum_realloc(c, dstn, srcn->secret | secret, 0));
          ASSH_RET_ON_ERR(assh_bignum_copy(dstn, srcn));
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
          dstn->mt_num = srcn->mt_num;
          dstn->mt_id = srcn->mt_id;
#endif
          break;
        case ASSH_BIGNUM_MPINT:
        case ASSH_BIGNUM_STRING:
        case ASSH_BIGNUM_MSB_RAW:
        case ASSH_BIGNUM_LSB_RAW:
        case ASSH_BIGNUM_ASN1:
          assert(!srcn->mt_num);
          assh_bignum_to_buffer(srcn, dst, next, dstfmt);
          break;

        default:
          ASSH_RETURN(ASSH_ERR_NOTSUP);
        }
    }
  else
    {
      size_t l, n, b;

      assert(dstfmt == ASSH_BIGNUM_NATIVE ||
             dstfmt == ASSH_BIGNUM_TEMP);
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
      dstn->mt_num = 0;
#endif

      if (srcfmt == ASSH_BIGNUM_MSB_RAW ||
          srcfmt == ASSH_BIGNUM_LSB_RAW)
        {
          b = dstn->bits;
          n = l = ASSH_ALIGN8(b) / 8;
        }
      else
        {
          ASSH_RET_ON_ERR(assh_bignum_size_of_data(srcfmt, src, &l, &n, &b));
          ASSH_RET_IF_TRUE(dstn->bits < b, ASSH_ERR_NUM_OVERFLOW);
        }

      switch (srcfmt)
        {
        case ASSH_BIGNUM_STRING:
        case ASSH_BIGNUM_MPINT:
        case ASSH_BIGNUM_ASN1:
          ASSH_RET_ON_ERR(assh_bignum_realloc(c, dstn, secret, 0));
          ASSH_RET_ON_ERR(assh_bignum_from_buffer(dstn, src + l - n, n, srcfmt));
          break;

        case ASSH_BIGNUM_MSB_RAW:
        case ASSH_BIGNUM_LSB_RAW:
          ASSH_RET_ON_ERR(assh_bignum_realloc(c, dstn, secret, 0));
          ASSH_ASSERT(assh_bignum_from_buffer(dstn, src, n, srcfmt));
          break;

        case ASSH_BIGNUM_INT:
          ASSH_RET_IF_TRUE(dstn->bits < sizeof(uintptr_t) * 8, ASSH_ERR_NUM_OVERFLOW);
          ASSH_RET_ON_ERR(assh_bignum_realloc(c, dstn, secret, 0));
          ASSH_RET_ON_ERR(assh_bignum_from_uint(dstn, (uintptr_t)src));
          break;

        default:
          ASSH_RETURN(ASSH_ERR_NOTSUP);
        }
    }

  return ASSH_OK;
}

static void
assh_bignum_builtin_print(void *arg, enum assh_bignum_fmt_e fmt,
                          uint32_t id, uint_fast16_t pc,
                          const struct assh_bignum_mt_s mt[])
{
#ifdef CONFIG_ASSH_DEBUG
  struct assh_bignum_s *src = arg;
  char idstr[5];
  size_t i;

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
          fprintf(stderr, "NULL\n");
          break;
        }
      size_t l = assh_bignum_words(src->bits);
      if (src->mt_num)
        {
          assh_bnword_t t[l];
          assh_bignum_mt_reduce(mt + src->mt_id, t, src->n);
          assh_bignum_dump(t, l);
        }
      else
        {
          assh_bignum_dump(src->n, l);
        }
      break;
    case ASSH_BIGNUM_SIZE:
      fprintf(stderr, "%u\n", (unsigned)(uintptr_t)arg);
      break;
    }
#endif
}

static ASSH_BIGNUM_BYTECODE_FCN(assh_bignum_builtin_bytecode)
{
  uint_fast8_t flen, tlen, mlen;
  assh_error_t err;
  uint_fast8_t i, j, k;
  uint_fast16_t pc = 0;
  uint_fast32_t lad_index = 0;
  uint8_t cond_secret = 0;
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
  uint8_t trace = 0;
#endif

  struct assh_bignum_scratch_s sc
    = { .words = 0, .words_s = 0, .n = NULL, .n_s = NULL };

  /* find number of arguments and temporaries */
  for (mlen = tlen = flen = 0; format[flen]; flen++)
    {
      switch (format[flen])
        {
        case ASSH_BIGNUM_TEMP:
          tlen++;
          break;
        case ASSH_BIGNUM_MT:
          mlen++;
          break;
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
        case ASSH_BIGNUM_NATIVE:
        case ASSH_BIGNUM_MPINT:
        case ASSH_BIGNUM_ASN1:
        case ASSH_BIGNUM_STRING:
        case ASSH_BIGNUM_MSB_RAW:
        case ASSH_BIGNUM_LSB_RAW:
        case ASSH_BIGNUM_HEX:
        case ASSH_BIGNUM_INT:
        case ASSH_BIGNUM_SIZE:
          break;
        default:
          ASSH_UNREACHABLE();
#endif
        }
    }

  void *args[flen];
  struct assh_bignum_s tmp[tlen];
  struct assh_bignum_mt_s mt[mlen];

  for (i = j = k = 0; i < flen; i++)
    switch (format[i])
      {
      case ASSH_BIGNUM_TEMP:
        assh_bignum_init(c, &tmp[j], 0);
        args[i] = &tmp[j];
        j++;
        break;
      case ASSH_BIGNUM_MT:
        assh_bignum_init(c, &mt[k].mod, 0);
        args[i] = &mt[k];
        k++;
        break;
      case ASSH_BIGNUM_SIZE:
        args[i] = (void*)va_arg(ap, size_t);
        break;
      case ASSH_BIGNUM_NATIVE: {
        struct assh_bignum_s *bn = va_arg(ap, void *);
        args[i] = bn;
        break;
      }
      default:
        args[i] = va_arg(ap, void *);
      }

  size_t scratch_size = 0;

  while (1)
    {
      uint32_t opc = ops[pc];
      enum assh_bignum_opcode_e op = opc >> 26;
      uint_fast8_t oa = (opc >> 20) & 0x3f;
      uint_fast8_t ob = (opc >> 14) & 0x3f;
      uint_fast8_t oc = (opc >> 6) & 0xff;
      uint_fast8_t od = opc & 0x3f;

      switch (op)
        {
          size_t b, i, j;

        case ASSH_BIGNUM_OP_SIZE:
          j = oa;
          goto op_size;
        case ASSH_BIGNUM_OP_SIZER:
          j = oc;
        op_size:
          pc++;

          ASSH_RET_ON_ERR(assh_bignum_size_of_data(format[ob], args[ob],
                                                NULL, NULL, &b));

          if (op == ASSH_BIGNUM_OP_SIZE)
            b = ((od >= 32) ? (b << (od - 32))
                 : (b >> (32 - od))) + (intptr_t)(int8_t)oc;

          for (i = oa; i <= j; i++)
            {
              struct assh_bignum_s *dst = args[i];
              struct assh_bignum_mt_s *mt = args[i];

              switch (format[i])
                {
                case ASSH_BIGNUM_TEMP:
                  dst->bits = b;
                  dst->n = (void*)(scratch_size * sizeof(assh_bnword_t));
                  scratch_size += assh_bignum_words(b);
                  dst->tmp = 1;
                  break;

                case ASSH_BIGNUM_MT:
                  mt->max_bits = b;
                  dst->n = (void*)(scratch_size * sizeof(assh_bnword_t));
                  scratch_size += 3 * assh_bignum_words(b) + 1;
                  dst->tmp = 1;
                  break;

                case ASSH_BIGNUM_NATIVE:
                  dst->bits = b;
                  if (dst->n != NULL)
                    {
                      assh_free(c, dst->n);
                      dst->n = NULL;
                    }
                  break;

                default:
                  ASSH_UNREACHABLE();
                }
            }

          break;

        default:
          goto size_done;
        }
    }
 size_done:;

  ASSH_SCRATCH_ALLOC(c, assh_bnword_t, sc_,
		     scratch_size,
		     ASSH_ERRSV_CONTINUE, err_);

  for (i = 0; i < flen; i++)
    switch (format[i])
      {
      case ASSH_BIGNUM_TEMP:
      case ASSH_BIGNUM_MT:;
        struct assh_bignum_s *dst = args[i];
        dst->n += (uintptr_t)sc_;
        break;
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
          ASSH_JMP_ON_ERR(assh_bignum_builtin_convert(c,
                    format[od], format[oc], args[od], dst, &next, ob), err_sc);

          /* deduce pointer of next buffer arg */
          if (oc + 1 < flen && args[oc + 1] == NULL)
            args[oc + 1] = next;

#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          switch (format[oc])
            {
            case ASSH_BIGNUM_NATIVE:
            case ASSH_BIGNUM_TEMP:
              if (trace & 2)
                assh_bignum_builtin_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc, mt);
            }
#endif
          break;
        }

        case ASSH_BIGNUM_OP_SIZE:
        case ASSH_BIGNUM_OP_SIZER:
          ASSH_UNREACHABLE();

        case ASSH_BIGNUM_OP_SUB:
        case ASSH_BIGNUM_OP_ADD: {
          struct assh_bignum_s *dst = args[oa];
          struct assh_bignum_s *src1 = args[ob];
          struct assh_bignum_s *src2 = args[oc];
          ASSH_JMP_ON_ERR(assh_bignum_realloc(c, dst, src1->secret | src2->secret, 1), err_sc);
          if (od != ASSH_BOP_NOREG)
            {
              struct assh_bignum_s *mod = args[od];
              assert(mod->mt_mod && src1->mt_num && src2->mt_num);
              if (op == ASSH_BIGNUM_OP_ADD)
                assh_bignum_mt_add(dst, src1, src2, mod);
              else
                assh_bignum_mt_sub(dst, src1, src2, mod);
            }
          else
            {
              assert(!src1->mt_num && !src2->mt_num);
              assh_bnword_t mask = (assh_bnword_t)(op == ASSH_BIGNUM_OP_ADD) - 1;
              ASSH_JMP_ON_ERR(assh_bignum_addsub(dst, src1, src2, mask), err_sc);
            }
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
          dst->mt_num = src1->mt_num;
          dst->mt_id = src1->mt_id;
#endif
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_builtin_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc, mt);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_MUL: {
          struct assh_bignum_s *dst = args[oa];
          struct assh_bignum_s *src1 = args[ob];
          struct assh_bignum_s *src2 = args[oc];
          ASSH_JMP_ON_ERR(assh_bignum_realloc(c, dst, src1->secret | src2->secret, 0), err_sc);
          if (od == ASSH_BOP_NOREG)
            {
              assert(!src1->mt_num && !src2->mt_num);
              ASSH_JMP_ON_ERR(assh_bignum_mul(c, &sc, dst, src1, src2), err_sc);
            }
          else
            {
              struct assh_bignum_mt_s *mod = args[od];
              if (format[od] == ASSH_BIGNUM_MT)
                {
                  assert(mod->mod.mt_mod && src1->mt_num);
                  ASSH_JMP_ON_ERR(assh_bignum_mul_mod_mt(c, &sc, dst, src1, src2, args[od]), err_sc);
                }
              else
                {
                  assert(!mod->mod.mt_mod && !src1->mt_num);
                  ASSH_JMP_ON_ERR(assh_bignum_mul_mod(c, &sc, dst, src1, src2, args[od]), err_sc);
                }
            }
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
          dst->mt_num = src1->mt_num;
          dst->mt_id = src1->mt_id;
#endif
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_builtin_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc, mt);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_EXPM: {
          struct assh_bignum_s *dst = args[oa];
          struct assh_bignum_s *src1 = args[ob];
          struct assh_bignum_s *src2 = args[oc];
          struct assh_bignum_mt_s *mod = args[od]; 
          assert(format[od] == ASSH_BIGNUM_MT);
          assert(mod->mod.mt_mod);
          assert(src1->mt_num);
          assert(!src2->mt_num);
          ASSH_JMP_ON_ERR(assh_bignum_realloc(c, dst, src1->secret | src2->secret, 1), err_sc);
          ASSH_JMP_ON_ERR(assh_bignum_expmod_mt(c, &sc, dst, src1, src2, mod), err_sc);
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
          dst->mt_num = src1->mt_num;
          dst->mt_id = src1->mt_id;
#endif
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_builtin_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc, mt);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_MTINIT: {
          struct assh_bignum_s *mod = args[od];
          struct assh_bignum_mt_s *dst = args[oc];
          assert(!mod->mt_num);
          assert(format[oc] == ASSH_BIGNUM_MT);
          ASSH_JMP_ON_ERR(assh_bignum_mt_init(c, dst, mod), err_sc);
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
          dst->mod.mt_mod = 1;
          dst->mod.mt_num = 0;
#endif
          break;
        }

        case ASSH_BIGNUM_OP_MTFROM:
        case ASSH_BIGNUM_OP_MTTO: {
          uint_fast8_t i;
          for (i = 0; i < oa; i++)
            {
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
              if (ob == oc)
                ASSH_DEBUG("MT convert: may optimize with src != dst\n");
#endif
              struct assh_bignum_s *dst = args[ob + i];
              struct assh_bignum_s *src = args[oc + i];
              assert(src->mt_num != (op == ASSH_BIGNUM_OP_MTTO));
              ASSH_JMP_ON_ERR(assh_bignum_realloc(c, dst, src->secret, 1), err_sc);
              ASSH_JMP_ON_ERR(assh_bignum_mt_convert(c, &sc, op == ASSH_BIGNUM_OP_MTTO,
                                                  args[od], dst, src), err_sc);
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
              dst->mt_num = (op == ASSH_BIGNUM_OP_MTTO);
              dst->mt_id = (struct assh_bignum_mt_s*)args[od] - mt;
#endif
            }
          break;
        }

        case ASSH_BIGNUM_OP_DIV: {
          struct assh_bignum_s *dsta = NULL, *dstb = NULL;
          struct assh_bignum_s *src1 = args[oc], *src2 = args[od];
          assert(!src2->mt_num);
          assert(src1->mt_num == src2->mt_mod);
          assert(src2->mt_mod || (!src1->secret && !src2->secret));
          if (oa != ASSH_BOP_NOREG)
            {
              assert(!src2->mt_mod);
              dsta = args[oa];
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
              dsta->mt_num = 0;
#endif
              ASSH_JMP_ON_ERR(assh_bignum_realloc(c, dsta, 0, 0), err_sc);
            }
          if (ob != ASSH_BOP_NOREG)
            {
              dstb = args[ob];
              if (dstb != src1)
                {
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
                  dstb->mt_num = src2->mt_mod;
                  dstb->mt_id = src2->mt_id;
#endif
                  ASSH_JMP_ON_ERR(assh_bignum_realloc(c, dstb, src1->secret, 1), err_sc);
                }
              if (src2->mt_mod)
                {
                  if (dstb != src1)
                    ASSH_JMP_ON_ERR(assh_bignum_copy(dstb, src1), err_sc);
                  goto div_done;
                }
            }
          ASSH_JMP_ON_ERR(assh_bignum_div(c, &sc, dstb, dsta, src1, src2), err_sc);
          div_done:
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            {
              if (dsta)
                assh_bignum_builtin_print(dsta, ASSH_BIGNUM_NATIVE, 'A', pc, mt);
              if (dstb)
                assh_bignum_builtin_print(dstb, ASSH_BIGNUM_NATIVE, 'B', pc, mt);
            }
#endif
          break;
        }

        case ASSH_BIGNUM_OP_INV: {
          struct assh_bignum_s *dst = args[ob];
          struct assh_bignum_s *src1 = args[oc];
          ASSH_JMP_ON_ERR(assh_bignum_realloc(c, dst, src1->secret, 0), err_sc);
          if (format[od] == ASSH_BIGNUM_MT)
            {
              assert(src1->mt_num);
              ASSH_JMP_ON_ERR(assh_bignum_modinv_mt(c, &sc, dst, src1, args[od]), err_sc);
            }
          else
            {
              assert(!src1->mt_num);
              ASSH_JMP_ON_ERR(assh_bignum_modinv(c, &sc, dst, src1, args[od]), err_sc);
            }
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
          dst->mt_num = src1->mt_num;
          dst->mt_id = src1->mt_id;
#endif
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_builtin_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc, mt);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_GCD: {
          struct assh_bignum_s *dst = args[ob];
          struct assh_bignum_s *src1 = args[oc], *src2 = args[od];
          assert(!src1->mt_num && !src2->mt_num);
          ASSH_JMP_ON_ERR(assh_bignum_realloc(c, dst, src1->secret, 0), err_sc);
          ASSH_JMP_ON_ERR(assh_bignum_gcd(c, &sc, dst, src1, src2), err_sc);
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
          dst->mt_num = 0;
#endif
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_builtin_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc, mt);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_SHR:
        case ASSH_BIGNUM_OP_SHL: {
          struct assh_bignum_s *dst = args[oa];
          struct assh_bignum_s *src = args[ob];
          assert(!src->mt_num);
          size_t b = 0;
          ASSH_JMP_IF_TRUE(dst->bits != src->bits, ASSH_ERR_OUTPUT_OVERFLOW, err_sc);
          if (od != ASSH_BOP_NOREG)
            ASSH_JMP_ON_ERR(assh_bignum_size_of_data(format[od], args[od],
                                                  NULL, NULL, &b), err_sc);
          ASSH_JMP_ON_ERR(assh_bignum_realloc(c, dst, src->secret, 1), err_sc);
          switch (op)
            {
            case ASSH_BIGNUM_OP_SHR:
              ASSH_JMP_ON_ERR(assh_bignum_rshift(dst, src, b + oc - 128), err_sc);
              break;
            case ASSH_BIGNUM_OP_SHL:
              ASSH_JMP_ON_ERR(assh_bignum_lshift(dst, src, b + oc - 128), err_sc);
              break;
            default:
              ASSH_UNREACHABLE();
            }
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
          dst->mt_num = 0;
#endif
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_builtin_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc, mt);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_RAND: {
          struct assh_bignum_s *dst = args[oa];
          ASSH_JMP_ON_ERR(assh_bignum_realloc(c, dst, od > ASSH_PRNG_QUALITY_PUBLIC, 0), err_sc);
          ASSH_JMP_ON_ERR(assh_bignum_rand(c, dst,
                         ob == ASSH_BOP_NOREG ? NULL : args[ob],
                         oc == ASSH_BOP_NOREG ? NULL : args[oc],
                         od), err_sc);
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
          dst->mt_num = 0;
#endif
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_builtin_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc, mt);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_CMP: {
          uint8_t r = 0;
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
                  r = assh_bignum_cmp(src1, src2);
                }
            }
          /* shift lookup table for assh_bignum_cmp result against
             CMPEQ, CMPLT and CMPLTEQ opcodes

                  r
                 0  0    ==
                 0  1    >
                 1  0    <

                 cmplteq  cmplt    cmpeq
                 0101     0100     0001
                 5        4        1
          */
          r = (0x541 >> (od * 4 + r)) & 1;
          cond |= r << oa;
          break;
        }

        case ASSH_BIGNUM_OP_JMP:
          assert(!((cond_secret >> oa) & 1));
          if (ob | (((cond >> oa) ^ od) & 1))
            pc += oc - 128;
          break;

        case ASSH_BIGNUM_OP_CSWAP: {
          struct assh_bignum_s *a = args[ob], *b = args[oc];
          assert(a->bits == b->bits);
          a->secret = b->secret = a->secret |
            b->secret | ((cond_secret >> oa) & 1);
          assh_bignum_cswap(a->n, b->n, assh_bignum_words(a->bits),
                            ((cond >> oa) ^ od) & 1);
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            {
              assh_bignum_builtin_print(a, ASSH_BIGNUM_NATIVE, 'A', pc, mt);
              assh_bignum_builtin_print(b, ASSH_BIGNUM_NATIVE, 'B', pc, mt);
            }
#endif
          break;
        }

        case ASSH_BIGNUM_OP_CMOVE: {
          struct assh_bignum_s *dst = args[ob], *src = args[oc];
          assert(dst->bits == src->bits);
          dst->secret |= src->secret | ((cond_secret >> oa) & 1);
          assh_bignum_cmove(dst->n, src->n, assh_bignum_words(dst->bits),
                            ((cond >> oa) ^ od) & 1);
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_builtin_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc, mt);
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
          assh_bnword_t *n = src->n;
          cond |= ((n[lad_index / ASSH_BIGNUM_W]
                    >> (lad_index % ASSH_BIGNUM_W)) & 1) << oc;
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

        case ASSH_BIGNUM_OP_TEST:
        case ASSH_BIGNUM_OP_SET: {
          struct assh_bignum_s *src1 = args[ob];
          size_t b = oc;
          assert(!src1->mt_num);
          if (od != ASSH_BOP_NOREG)
            {
              ASSH_JMP_ON_ERR(assh_bignum_size_of_data(format[od], args[od],
                                                    NULL, NULL, &b), err_sc);
              b -= oc;
            }
          assert(b < src1->bits);
          assh_bnword_t *n = (assh_bnword_t*)src1->n + b / ASSH_BIGNUM_W;

          if (op == ASSH_BIGNUM_OP_SET)
            {
              assh_bnword_t s = (assh_bnword_t)((cond >> oa) & 1) << (b % ASSH_BIGNUM_W);
              assh_bnword_t m = (assh_bnword_t)1 << (b % ASSH_BIGNUM_W);
              *n = (*n & ~m) | (s & m);
              src1->secret |= (cond_secret >> oa) & 1;
            }
          else
            {
              uint8_t s = ((*n >> (b % ASSH_BIGNUM_W)) & 1) << oa;
              uint8_t m = 1 << oa;
              cond = (cond & ~m) | (cond & s);
              cond_secret = (cond_secret & ~m) | (src1->secret << oa);
            }
          break;
        }

        case ASSH_BIGNUM_OP_MTUINT: {
          uint_fast32_t value = (opc >> 14) & 0xfff;
          struct assh_bignum_s *dst = args[od];
          struct assh_bignum_mt_s *mt = args[oc];
          assert(dst->bits == mt->mod.bits);
          size_t ml = assh_bignum_words(mt->mod.bits);
          ASSH_JMP_ON_ERR(assh_bignum_realloc(c, dst, 0, 0), err_sc);
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
          dst->mt_num = 1;
          dst->mt_id = (struct assh_bignum_mt_s*)args[oc] - mt;
#endif
          switch (value)
            {
            case 0:
              memset(dst->n, 0, ml * sizeof(assh_bnword_t));
              break;
            case 1:
              memcpy(dst->n, (assh_bnword_t*)mt->mod.n + 2 * ml, ml * sizeof(assh_bnword_t));
              break;
            default:
              ASSH_JMP_ON_ERR(assh_bignum_from_uint(dst, value), err_sc);
              ASSH_JMP_ON_ERR(assh_bignum_mt_convert(c, &sc, 1, mt, dst, dst), err_sc);
              break;
            }
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_builtin_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc, mt);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_UINT: {
          uint_fast32_t value = (opc >> 6) & 0xfffff;
          struct assh_bignum_s *dst = args[od];
          ASSH_JMP_ON_ERR(assh_bignum_realloc(c, dst, 0, 0), err_sc);
          ASSH_JMP_ON_ERR(assh_bignum_from_uint(dst, value), err_sc);
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
          dst->mt_num = 0;
#endif
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_builtin_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc, mt);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_ISPRIME: {
          struct assh_bignum_s *src = args[od];
          assert(!src->mt_num);
          assert(!src->secret);
          assert(oc > 0);
          uint8_t cond_mask = (1 << ob);
          assh_bool_t r;
          ASSH_JMP_ON_ERR(assh_bignum_check_prime(c, &sc, src, oc, &r), err_sc);
          cond &= ~cond_mask;
          cond |= r << ob;
          cond_secret &= ~cond_mask;
          break;
        }

        case ASSH_BIGNUM_OP_PRIME: {
          struct assh_bignum_s *dst = args[oa];
          ASSH_JMP_ON_ERR(assh_bignum_realloc(c, dst, od > ASSH_PRNG_QUALITY_PUBLIC, 0), err_sc);
          ASSH_JMP_ON_ERR(assh_bignum_gen_prime(c, &sc, dst,
                         ob == ASSH_BOP_NOREG ? NULL : args[ob],
                         oc == ASSH_BOP_NOREG ? NULL : args[oc],
                         od), err_sc);
#if !defined(NDEBUG) || defined(CONFIG_ASSH_DEBUG) 
          dst->mt_num = 0;
#endif
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_builtin_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc, mt);
#endif
          break;
        }

        case ASSH_BIGNUM_OP_NEXTPRIME: {
          struct assh_bignum_s *dst = args[oc];
          assert(!dst->mt_num);
          struct assh_bignum_s *step = NULL;
          if (od != ASSH_BOP_NOREG)
            {
              step = args[od];
              assert(step->bits <= dst->bits);
              assert(!step->mt_num);
              assert(!step->secret);
              assert(!dst->secret);
            }
          ASSH_JMP_ON_ERR(assh_bignum_next_prime(c, &sc, dst, step), err_sc);
#if defined(CONFIG_ASSH_DEBUG_BIGNUM_TRACE)
          if (trace & 2)
            assh_bignum_builtin_print(dst, ASSH_BIGNUM_NATIVE, 'R', pc, mt);
#endif
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
          cond_secret |= (src1_secret | src2_secret) << oa;
          break;
        }

        case ASSH_BIGNUM_OP_PRIVACY: {
          struct assh_bignum_s *dst = args[od];
          dst->secure = oc;
          ASSH_JMP_ON_ERR(assh_bignum_realloc(c, dst, ob, 1), err_sc);
          break;
        }

        case ASSH_BIGNUM_OP_PRINT: {
          assh_bignum_builtin_print(args[od], format[od], oc, pc, mt);
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

  if (sc.n != NULL)
    assh_free(c, sc.n);
  if (sc.n_s != NULL)
    assh_free(c, sc.n_s);

  /* release numbers */
  ASSH_SCRATCH_FREE(c, sc_);
 err_:

  return err;
}

static ASSH_BIGNUM_RELEASE_FCN(assh_bignum_builtin_release)
{
  assh_free(ctx, bn->n);
}

const struct assh_bignum_algo_s assh_bignum_builtin =
{
  .name = "builtin",
  .f_bytecode = assh_bignum_builtin_bytecode,
  .f_convert = assh_bignum_builtin_convert,
  .f_release = assh_bignum_builtin_release,
};

