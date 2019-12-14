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

#define ASSH_EV_CONST /* write access to event const fields */

#include <assh/assh_context.h>
#include <assh/assh_kex.h>
#include <assh/assh_packet.h>
#include <assh/assh_transport.h>
#include <assh/assh_session.h>
#include <assh/assh_cipher.h>
#include <assh/assh_mac.h>
#include <assh/assh_hash.h>
#include <assh/assh_sign.h>
#include <assh/assh_key.h>
#include <assh/assh_prng.h>
#include <assh/assh_compress.h>
#include <assh/assh_alloc.h>
#include <assh/assh_event.h>

#include <string.h>
#include <stdlib.h>

static const enum assh_algo_class_e assh_kex_algos_classes[8] = {
  ASSH_ALGO_KEX, ASSH_ALGO_SIGN,
  ASSH_ALGO_CIPHER, ASSH_ALGO_CIPHER,
  ASSH_ALGO_MAC, ASSH_ALGO_MAC,
  ASSH_ALGO_COMPRESS, ASSH_ALGO_COMPRESS
};

static assh_status_t
assh_kex_list(struct assh_session_s *s, struct assh_packet_s *p,
              uint_fast16_t *algoidx, enum assh_algo_class_e class_,
              assh_bool_t out)
{
  assh_status_t err;
  struct assh_context_s *c = s->ctx;
  assh_bool_t first = 0;
  uint8_t *list;

  ASSH_RET_ON_ERR(assh_packet_add_string(p, 0, &list));

#ifdef CONFIG_ASSH_DEBUG_KEX
  ASSH_DEBUG("kex send: ");
#endif

  for (; *algoidx < c->algo_cnt; (*algoidx)++)
    {
      const struct assh_algo_s *a = c->algos[*algoidx];
      if (a->class_ != class_)
        break;

      /* check host key availability for this algorithm */
      if (assh_algo_suitable_key(c, a, NULL) &&
          assh_key_lookup(c, NULL, a) != ASSH_OK)
        continue;

      const struct assh_algo_name_s *name;
      for (name = a->names; name->spec; name++)
        {
          if (!s->kex_filter(s, a, name, out))
            continue;

          /* append name to the list */
          uint8_t *tail;
          size_t l = strlen(name->name);
          ASSH_RET_ON_ERR(assh_packet_enlarge_string(p, list, first + l, &tail));
          memcpy(tail + first, name->name, l);
          if (first)
            tail[0] = ',';
          else if (class_ < 2)
            s->kex_preferred[class_] = a; /* keep prefered algorithm */

          first = 1;
#ifdef CONFIG_ASSH_DEBUG_KEX
          ASSH_DEBUG_("%s ", name->name);
#endif
        }
    }

#ifdef CONFIG_ASSH_DEBUG_KEX
  ASSH_DEBUG_("\n");
#endif

  ASSH_RET_IF_TRUE(!first, ASSH_ERR_MISSING_ALGO);

  return ASSH_OK;
}

assh_status_t assh_kex_send_init(struct assh_session_s *s)
{
  assh_status_t err;
  struct assh_context_s *c = s->ctx;

  struct assh_packet_s *p;
  ASSH_RET_ON_ERR(assh_packet_alloc(c, SSH_MSG_KEXINIT,
                 c->kex_init_size, &p));

  uint8_t *cookie;
  ASSH_JMP_ON_ERR(assh_packet_add_array(p, 16, &cookie), err_pck);
  ASSH_JMP_ON_ERR(assh_prng_get(c, cookie,
		  16, ASSH_PRNG_QUALITY_NONCE), err_pck);

  /* lists of algorithms */
  uint_fast16_t i = 0, j;
  for (j = ASSH_ALGO_KEX; j <= ASSH_ALGO_COMPRESS; j++)
    {
      uint_fast16_t k = i;
      ASSH_JMP_ON_ERR(assh_kex_list(s, p, &i, j, c->type == ASSH_CLIENT), err_pck);

      if (j >= ASSH_ALGO_CIPHER) /* other direction */
        ASSH_JMP_ON_ERR(assh_kex_list(s, p, &k, j, c->type == ASSH_SERVER), err_pck);
    }

  uint8_t *x;

  /* empty languages */
  ASSH_JMP_ON_ERR(assh_packet_add_string(p, 0, &x), err_pck);
  ASSH_JMP_ON_ERR(assh_packet_add_string(p, 0, &x), err_pck);

  ASSH_JMP_ON_ERR(assh_packet_add_array(p, 5, &x), err_pck);

  /* fkpf + reserved */
  memset(x, 0, 5);

  /* keep a copy of our KEX_INIT packet, will be needed for hashing */
  assert(s->kex_init_local == NULL);

  struct assh_packet_s *pc;
  ASSH_JMP_ON_ERR(assh_packet_dup(p, &pc), err_pck);
  s->kex_init_local = pc;

  /* setup packet len and padding fields of the copy */
  assh_store_u32(pc->data, pc->data_size - 4);
  pc->head.pad_len = 0;

  assh_transport_push(s, p);
  return ASSH_OK;

 err_pck:
  assh_packet_release(p);
  return err;
}

#ifdef CONFIG_ASSH_SERVER
/* select server side algorithms based on KEX init lists from client */
static assh_status_t
assh_kex_server_algos(struct assh_session_s *s, const uint8_t *lists[9],
                      const struct assh_algo_s *algos[8])
{
  struct assh_context_s *c = s->ctx;
  assh_status_t err;
  uint_fast8_t i;

  for (i = 0; i < 8; i++)
    {
      switch (i)
        {
        case 1: {
          struct assh_algo_kex_s *kex = (void*)algos[i - 1];
          if (kex->implicit_auth)
            {
              /* ignore host key algorithm */
              s->kex_preferred[i] = algos[i] = &assh_sign_none.algo;
              continue;
            }
          break;
        }
        case 4:
        case 5: {
          struct assh_algo_cipher_s *cipher = (void*)algos[i - 2];
          if (cipher->auth_size)
            {
              /* ignore MAC algorithm */
              algos[i] = &assh_hmac_none.algo;
              continue;
            }
          break;
        }
        }

      const char *start = (char*)(lists[i] + 4);
      const char *end = (char*)lists[i+1];
      const char *n;

      /* iterate over name-list */
      for (; start < end; start = n + 1)
        {
          n = start;
          while (*n != ',' && n < end)
            n++;

          /* lookup in registered algorithms */
          const struct assh_algo_s *a;
          const struct assh_algo_name_s *na;
          if (assh_algo_by_name(c, assh_kex_algos_classes[i],
                                start, n - start, &a, &na) != ASSH_OK)
            goto next;

          if (!s->kex_filter(s, a, na, 1 & i))
            goto next;

          /* check algorithm key availability */
          if (assh_algo_suitable_key(c, a, NULL) &&
              assh_key_lookup(c, NULL, a) != ASSH_OK)
            goto next;

          algos[i] = a;
          goto done;

        next:
          if (i < 2)            /* invalidate preferred */
            s->kex_preferred[i] = NULL;
        }

      ASSH_RETURN(ASSH_ERR_MISSING_ALGO);
    done:;
    }

  return ASSH_OK;
}
#endif

#ifdef CONFIG_ASSH_CLIENT
/* select client side algorithms based on KEX init lists from server */
static assh_status_t
assh_kex_client_algos(struct assh_session_s *s, const uint8_t *lists[9],
                      const struct assh_algo_s *algos[8])
{
  struct assh_context_s *c = s->ctx;
  assh_status_t err;
  uint_fast16_t i, j, k;

  for (k = j = i = 0; i < 8; i++)
    {
      switch (i)
        {
        case 2:
        case 6:
          j = k;                /* next algo class */
          break;
        case 1: {
          j = k;
          struct assh_algo_kex_s *kex = (void*)algos[i - 1];
          if (kex->implicit_auth)
            {
              /* ignore host key algorithm */
              s->kex_preferred[i] = algos[i] = &assh_sign_none.algo;
              continue;
            }
          break;
        }
        case 4:
          j = k;
        case 5: {
          struct assh_algo_cipher_s *cipher = (void*)algos[(i ^ 1) - 2];
          if (cipher->auth_size)
            {
              /* ignore MAC algorithm */
              algos[i ^ 1] = &assh_hmac_none.algo;
              continue;
            }
          break;
        }
        }

      /* iterate over available algorithms */
      for (k = j; ; k++)
        {
          ASSH_RET_IF_TRUE(k == c->algo_cnt, ASSH_ERR_MISSING_ALGO);

          const struct assh_algo_s *a = c->algos[k];

          if (a->class_ < assh_kex_algos_classes[i])
            continue;

          ASSH_RET_IF_TRUE(a->class_ > assh_kex_algos_classes[i],
                       ASSH_ERR_MISSING_ALGO);

          const struct assh_algo_name_s *na;
          for (na = a->names; na->spec; na++)
            {
              if (!s->kex_filter(s, a, na, (1 & i) ^ 1))
                continue;

              const char *start = (char*)(lists[i] + 4);
              const char *end = (char*)lists[i+1];
              assh_bool_t inval = 0;

              /* iterate over name-list */
              while (start < end)
                {
                  const char *n = start;
                  while (*n != ',' && n < end)
                    n++;

                  /* check algorithm name match */
                  if (!assh_string_strcmp(start, n - start, na->name))
                    {
                      if (i < 2)
                        {
                          if (inval)            /* invalidate preferred */
                            s->kex_preferred[i] = NULL;
                          algos[i] = a;
                        }
                      else
                        {
                          algos[i ^ 1] = a;
                        }
                      goto done;
                    }

                  inval = 1;
                  start = n + 1;
                }
            }
        }
    done:;
    }

  return ASSH_OK;
}
#endif

assh_status_t assh_kex_got_init(struct assh_session_s *s, struct assh_packet_s *p)
{
  assh_status_t err;

  const uint8_t *lists[11];
  unsigned int i;

  /* get pointers to the 10 name-lists while checking bounds */
  lists[0] = p->head.end /* cookie */ + 16;
  for (i = 0; i < 10; i++)
    ASSH_RET_ON_ERR(assh_packet_check_string(p, lists[i], lists + i + 1));

  ASSH_RET_ON_ERR(assh_packet_check_array(p, lists[10], 1, NULL));

  assh_bool_t guess_follows = *lists[10];

  const struct assh_algo_s *algos[8];

  /* select proper algorithms based on registered algorithms and name-lists */
  switch (s->ctx->type)
    {
#ifdef CONFIG_ASSH_SERVER
    case ASSH_SERVER:
      ASSH_RET_ON_ERR(assh_kex_server_algos(s, lists, algos));
      break;
#endif
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_CLIENT:
      ASSH_RET_ON_ERR(assh_kex_client_algos(s, lists, algos));
      break;
#endif
    default:
      ASSH_UNREACHABLE();
    }

  assh_bool_t good_guess = s->kex_preferred[0] == algos[0] &&
                           s->kex_preferred[1] == algos[1];

  const struct assh_algo_kex_s *kex           = (const void *)algos[0];
  const struct assh_algo_sign_s *sign         = (const void *)algos[1];
  const struct assh_algo_cipher_s *cipher_in  = (const void *)algos[2];
  const struct assh_algo_cipher_s *cipher_out = (const void *)algos[3];
  const struct assh_algo_mac_s *mac_in        = (const void *)algos[4];
  const struct assh_algo_mac_s *mac_out       = (const void *)algos[5];
  const struct assh_algo_compress_s *cmp_in   = (const void *)algos[6];
  const struct assh_algo_compress_s *cmp_out  = (const void *)algos[7];

  assh_safety_t kin_safety = kex->algo.safety;

  if (!kex->implicit_auth)
    kin_safety = ASSH_MIN(kin_safety, (assh_safety_t)sign->algo.safety);

  assh_safety_t kout_safety = kin_safety;

#ifdef CONFIG_ASSH_DEBUG_KEX
  ASSH_DEBUG("kex algorithms:\n"
             "  kex: %s (%s)\n"
             "  sign: %s (%s)\n"
             "  cipher in: %s\n  cipher out: %s\n"
             "  mac in: %s\n  mac out: %s\n  comp in: %s\n  comp out: %s\n"
             "  guess: follows=%x good=%x\n",
             kex->algo.names[0].name, kex->algo.variant,
             sign->algo.names[0].name, sign->algo.variant,
             cipher_in->algo.names[0].name, cipher_out->algo.names[0].name,
             mac_in->algo.names[0].name, mac_out->algo.names[0].name,
             cmp_in->algo.names[0].name, cmp_out->algo.names[0].name,
             guess_follows, good_guess);
#endif

  /* keep the remote KEX_INIT packet, will be needed for hashing */
  assert(s->kex_init_remote == NULL);
  assh_packet_refinc(p);
  s->kex_init_remote = p;

  /* alloacte input and output keys and associated cipher/mac/compress contexts */
  struct assh_kex_keys_s *kin;
  size_t kin_size = sizeof(*kin) + cipher_in->ctx_size + cmp_in->ctx_size
    + mac_in->ctx_size;
  ASSH_RET_ON_ERR(assh_alloc(s->ctx, kin_size, ASSH_ALLOC_SECUR, (void**)&kin));

  kin_safety = ASSH_MIN(kin_safety, (assh_safety_t)cipher_in->algo.safety);
  if (!cipher_in->auth_size)
    kin_safety = ASSH_MIN(kin_safety, (assh_safety_t)mac_in->algo.safety);

  struct assh_kex_keys_s *kout;
  size_t kout_size = sizeof(*kout) + cipher_out->ctx_size + cmp_out->ctx_size
    + mac_out->ctx_size;
  ASSH_JMP_ON_ERR(assh_alloc(s->ctx, kout_size, ASSH_ALLOC_SECUR, (void**)&kout),
	       err_kin);

  kout_safety = ASSH_MIN(kout_safety, (assh_safety_t)cipher_out->algo.safety);
  if (!cipher_out->auth_size)
    kout_safety = ASSH_MIN(kout_safety, (assh_safety_t)mac_out->algo.safety);

  size_t key_size = ASSH_MAX(cipher_in->key_size, cipher_out->key_size) * 8;

  /* initialize input keys structure */
  kin->cmp_ctx = kin->mac_ctx = kin->cipher_ctx = NULL;
  kin->cipher = cipher_in;
  kin->mac = mac_in;
  kin->cmp = cmp_in;
  kin->safety = kin_safety;
  assh_kex_keys_cleanup(s, s->new_keys_in);
  s->new_keys_in = kin;

  /* initialize output keys structure */
  kout->cmp_ctx = kout->mac_ctx = kout->cipher_ctx = NULL;
  kout->cipher = cipher_out;
  kout->mac = mac_out;
  kout->cmp = cmp_out;
  kout->safety = kout_safety;
  assh_kex_keys_cleanup(s, s->new_keys_out);
  s->new_keys_out = kout;

  assert(kin->cipher->block_size >= ASSH_MIN_BLOCK_SIZE);
  assert(kout->cipher->block_size >= ASSH_MIN_BLOCK_SIZE);

  /* initialize key exchange algorithm */
  ASSH_JMP_ON_ERR(kex->f_init(s, key_size), err);

  s->kex = kex;
  s->host_sign_algo = sign;

  /* switch to key exchange running state */
  if (guess_follows && !good_guess)
    ASSH_SET_STATE(s, tr_st, ASSH_TR_KEX_SKIP);
  else
    ASSH_SET_STATE(s, tr_st, ASSH_TR_KEX_RUNNING);

  return ASSH_OK;

 err_kin:
  assh_free(s->ctx, kin);
 err:
  return err;
}

void assh_kex_lower_safety(struct assh_session_s *s, assh_safety_t safety)
{
#ifdef CONFIG_ASSH_DEBUG_KEX
  ASSH_DEBUG("lowering safety to %u\n", safety);
#endif
  s->new_keys_in->safety = ASSH_MIN(safety, s->new_keys_in->safety);
  s->new_keys_out->safety = ASSH_MIN(safety, s->new_keys_out->safety);
}

/* derive cipher/mac/iv key from shared secret */
static assh_status_t assh_kex_new_key(struct assh_session_s *s,
                                     struct assh_hash_ctx_s *hash_ctx,
                                     const struct assh_hash_algo_s *hash_algo,
                                     const uint8_t *ex_hash, const uint8_t *secret_str,
                                     char c, uint8_t *key, size_t key_size)
{
  assh_status_t err;

  ASSH_SCRATCH_ALLOC(s->ctx, uint8_t, buf, ASSH_MAX_SYMKEY_SIZE + ASSH_MAX_HASH_SIZE,
		     ASSH_ERRSV_CONTINUE, err);

  assert(key_size <= ASSH_MAX_SYMKEY_SIZE);

  /* derive key */
  size_t hash_size = hash_algo->hash_size ? hash_algo->hash_size : key_size;
  ASSH_JMP_ON_ERR(assh_hash_init(s->ctx, hash_ctx, hash_algo), err_scratch);

  /* setup session id */
  if (s->session_id_len == 0)
    memcpy(s->session_id, ex_hash, s->session_id_len = hash_size);

  assh_hash_update(hash_ctx, secret_str, assh_load_u32(secret_str) + 4);
  assh_hash_update(hash_ctx, ex_hash, hash_size);
  assh_hash_update(hash_ctx, &c, 1);
  assh_hash_update(hash_ctx, s->session_id, s->session_id_len);

  assh_hash_final(hash_ctx, buf, hash_size);
  assh_hash_cleanup(hash_ctx);

  /* further enlarge derived key if needed */
  size_t size;
  for (size = hash_size; size < key_size; size += hash_size)
    {
      assert(size + hash_size
	     <= ASSH_MAX_SYMKEY_SIZE + ASSH_MAX_HASH_SIZE);

      ASSH_JMP_ON_ERR(assh_hash_init(s->ctx, hash_ctx, hash_algo), err_scratch);
      assh_hash_update(hash_ctx, secret_str, assh_load_u32(secret_str) + 4);
      assh_hash_update(hash_ctx, ex_hash, hash_size);
      assh_hash_update(hash_ctx, buf, size);

      assh_hash_final(hash_ctx, buf + size, hash_size);
      assh_hash_cleanup(hash_ctx);
    }

  memcpy(key, buf, key_size);

  err = ASSH_OK;

 err_scratch:
  ASSH_SCRATCH_FREE(s->ctx, buf);
 err:
  return err;
}

assh_status_t
assh_kex_new_keys(struct assh_session_s *s,
                  const struct assh_hash_algo_s *hash_algo,
                  const uint8_t *ex_hash,
                  const uint8_t *secret_str)
{
  assh_status_t err;
#if defined(CONFIG_ASSH_SERVER) && defined(CONFIG_ASSH_CLIENT)
  const char *c = s->ctx->type == ASSH_SERVER ? "ACBDEF" : "BDACFE";
#elif defined(CONFIG_ASSH_CLIENT)
  const char *c = "BDACFE";
#elif defined(CONFIG_ASSH_SERVER)
  const char *c = "ACBDEF";
#endif

#ifdef CONFIG_ASSH_DEBUG_KEX
  ASSH_DEBUG_HEXDUMP("exchange hash", ex_hash, hash_algo->hash_size);
#endif

  ASSH_SCRATCH_ALLOC(s->ctx, uint8_t, scratch, hash_algo->ctx_size +
           /* iv */  ASSH_MAX_BLOCK_SIZE +
           /* key */ ASSH_MAX(ASSH_MAX_EKEY_SIZE, ASSH_MAX_IKEY_SIZE),
                     ASSH_ERRSV_CONTINUE, err);

  void *hash_ctx = scratch;
  uint8_t *iv = scratch + hash_algo->ctx_size;
  uint8_t *key = iv + ASSH_MAX_BLOCK_SIZE;

  struct assh_kex_keys_s *kin = s->new_keys_in;
  struct assh_kex_keys_s *kout = s->new_keys_out;
  uint8_t *next_in_ctx = (void*)(kin + 1);
  uint8_t *next_out_ctx = (void*)(kout + 1);

  /* get input cipher iv/key and init cipher */
  if (kin->cipher->iv_size)
    ASSH_JMP_ON_ERR(assh_kex_new_key(s, hash_ctx, hash_algo, ex_hash,
                                  secret_str, *c,
                                  iv, kin->cipher->iv_size), err_scratch);
  c++;

  if (kin->cipher->key_size)
    ASSH_JMP_ON_ERR(assh_kex_new_key(s, hash_ctx, hash_algo, ex_hash,
                                  secret_str, *c,
                                  key, kin->cipher->key_size), err_scratch);
  c++;

  kin->cipher_ctx = (void*)next_in_ctx;
  next_in_ctx += kin->cipher->ctx_size;

#ifdef CONFIG_ASSH_DEBUG_KEX
  ASSH_DEBUG_HEXDUMP("in iv", iv, kin->cipher->iv_size);
  ASSH_DEBUG_HEXDUMP("in ekey", key, kin->cipher->key_size);
#endif

  ASSH_JMP_ON_ERR(kin->cipher->f_init(s->ctx, kin->cipher_ctx, key, iv, 0), err_cipher_in);

  /* get output cipher iv/key and init cipher */
  if (kout->cipher->iv_size)
    ASSH_JMP_ON_ERR(assh_kex_new_key(s, hash_ctx, hash_algo, ex_hash,
                                  secret_str, *c,
                                  iv, kout->cipher->iv_size), err_scratch);
  c++;

  if (kout->cipher->key_size)
    ASSH_JMP_ON_ERR(assh_kex_new_key(s, hash_ctx, hash_algo, ex_hash,
                                  secret_str, *c,
                                  key, kout->cipher->key_size), err_cipher_out);
  c++;

  kout->cipher_ctx = (void*)next_out_ctx;
  next_out_ctx += kout->cipher->ctx_size;

#ifdef CONFIG_ASSH_DEBUG_KEX
  ASSH_DEBUG_HEXDUMP("out iv", iv, kout->cipher->iv_size);
  ASSH_DEBUG_HEXDUMP("out ekey", key, kout->cipher->key_size);
#endif

  ASSH_JMP_ON_ERR(kout->cipher->f_init(s->ctx, kout->cipher_ctx, key, iv, 1), err_cipher_out);

  if (kin->mac->key_size)
    {
      /* get input integrity key and init mac */
      ASSH_JMP_ON_ERR(assh_kex_new_key(s, hash_ctx, hash_algo, ex_hash,
                                    secret_str, *c,
                                    key, kin->mac->key_size), err_mac_in);
#ifdef CONFIG_ASSH_DEBUG_KEX
      ASSH_DEBUG_HEXDUMP("in ikey", key, kin->mac->key_size);
#endif
    }
  kin->mac_ctx = (void*)next_in_ctx;
  next_in_ctx += kin->mac->ctx_size;
  ASSH_JMP_ON_ERR(kin->mac->f_init(s->ctx, kin->mac_ctx, key), err_mac_in);
  c++;

  if (kout->mac->key_size)
    {
      /* get output integrity key and init mac */
      ASSH_JMP_ON_ERR(assh_kex_new_key(s, hash_ctx, hash_algo, ex_hash,
                                    secret_str, *c,
                                    key, kout->mac->key_size), err_mac_out);
#ifdef CONFIG_ASSH_DEBUG_KEX
      ASSH_DEBUG_HEXDUMP("out ikey", key, kout->mac->key_size);
#endif
    }
  kout->mac_ctx = (void*)next_out_ctx;
  next_out_ctx += kout->mac->ctx_size;
  ASSH_JMP_ON_ERR(kout->mac->f_init(s->ctx, kout->mac_ctx, key), err_mac_out);
  c++;

  /* init input compression */
  kin->cmp_ctx = (void*)next_in_ctx;
  ASSH_JMP_ON_ERR(kin->cmp->f_init(s->ctx, kin->cmp_ctx, 0), err_cmp_in);

  /* init output compression */
  kout->cmp_ctx = (void*)next_out_ctx;
  ASSH_JMP_ON_ERR(kout->cmp->f_init(s->ctx, kout->cmp_ctx, 1), err_cmp_out);

  ASSH_SCRATCH_FREE(s->ctx, scratch);
  return ASSH_OK;

 err_cmp_out:
  kout->cmp_ctx = NULL;
  kin->cmp->f_cleanup(s->ctx, kin->cmp_ctx);
 err_cmp_in:
  kin->cmp_ctx = NULL;
  kout->mac->f_cleanup(s->ctx, kout->mac_ctx);
 err_mac_out:
  kout->mac_ctx = NULL;
  kin->mac->f_cleanup(s->ctx, kin->mac_ctx);
 err_mac_in:
  kin->mac_ctx = NULL;
  kout->cipher->f_cleanup(s->ctx, kout->cipher_ctx);
 err_cipher_out:
  kout->cipher_ctx = NULL;
  kin->cipher->f_cleanup(s->ctx, kin->cipher_ctx);
 err_cipher_in:
  kin->cipher_ctx = NULL;
 err_scratch:
  ASSH_SCRATCH_FREE(s->ctx, scratch);
 err:
  return err;
}

#ifdef CONFIG_ASSH_CLIENT
assh_status_t
assh_kex_client_get_key(struct assh_session_s *s,
                        const uint8_t *ks_str,
                        struct assh_event_s *e,
                        assh_event_done_t *done, void *pv)
{
  assh_status_t err;

  /* load key */
  const struct assh_algo_sign_s *sign_algo = s->host_sign_algo;
  struct assh_key_s *host_key = NULL;

  const uint8_t *key_blob = ks_str + 4;
  ASSH_RET_ON_ERR(assh_key_load(s->ctx, &host_key, sign_algo->algo.key, ASSH_ALGO_SIGN,
                             ASSH_KEY_FMT_PUB_RFC4253, &key_blob,
                             assh_load_u32(ks_str)));

  /* check if the key can be used by the algorithm */
  ASSH_JMP_IF_TRUE(!assh_algo_suitable_key(s->ctx, &sign_algo->algo, host_key),
               ASSH_ERR_WEAK_ALGORITHM, err_hk);

  /* Return an host key lookup event */
  e->id = ASSH_EVENT_KEX_HOSTKEY_LOOKUP;
  e->f_done = done;
  e->done_pv = pv;
  e->kex.hostkey_lookup.key = host_key;
  e->kex.hostkey_lookup.initial = !s->kex_done;
  e->kex.hostkey_lookup.accept = 0;

  assert(s->kex_host_key == NULL);
  s->kex_host_key = host_key;

  return ASSH_OK;

 err_hk:
  assh_key_drop(s->ctx, &host_key);
  return err;
}

assh_status_t
assh_kex_client_hash1(struct assh_session_s *s,
                      struct assh_hash_ctx_s *hash_ctx,
                      const uint8_t *k_str)
{
  /* compute the exchange hash H */

  assh_hash_bytes_as_string(hash_ctx, (const uint8_t*)ASSH_IDENT,
			    sizeof(ASSH_IDENT) /* \r\n\0 */ - 3);
  assh_hash_bytes_as_string(hash_ctx, s->ident_str, s->ident_len);
  assh_hash_payload_as_string(hash_ctx, s->kex_init_local);
  assh_hash_payload_as_string(hash_ctx, s->kex_init_remote);
  assh_hash_string(hash_ctx, k_str);

  return ASSH_OK;
}

assh_status_t
assh_kex_client_hash2(struct assh_session_s *s,
                      struct assh_hash_ctx_s *hash_ctx,
                      const uint8_t *secret_str,
                      const uint8_t *h_str)
{
  assh_status_t err;
  struct assh_context_s *c = s->ctx;

  assh_hash_string(hash_ctx, secret_str);

  size_t hash_size = hash_ctx->algo->hash_size;
  assert(hash_size);

  uint8_t ex_hash[hash_size];
  assh_hash_final(hash_ctx, ex_hash, hash_size);

  struct assh_cbuffer_s data = {
    .data = ex_hash, .size = hash_size
  };

  const struct assh_algo_sign_s *sign_algo = s->host_sign_algo;
  assh_safety_t sign_safety;

  ASSH_RET_IF_TRUE(assh_sign_check(c, sign_algo, s->kex_host_key, 1, &data,
                h_str + 4, assh_load_u32(h_str), &sign_safety) != ASSH_OK,
               ASSH_ERR_HOSTKEY_SIGNATURE);

  assh_kex_lower_safety(s, sign_safety);

  /* setup new keys */
  ASSH_RETURN(assh_kex_new_keys(s, hash_ctx->algo, ex_hash, secret_str));
}
#endif

#ifdef CONFIG_ASSH_SERVER
assh_status_t
assh_kex_server_hash1(struct assh_session_s *s, size_t kex_len,
                      struct assh_hash_ctx_s *hash_ctx,
                      struct assh_packet_s **pout, size_t *sign_len,
                      struct assh_key_s **host_key,
                      enum assh_ssh_msg_e msg)
{
  assh_status_t err;
  struct assh_context_s *c = s->ctx;

  /* look for an host key pair which can be used with the selected algorithm. */
  const struct assh_algo_sign_s *sign_algo = s->host_sign_algo;

  ASSH_RET_IF_TRUE(assh_key_lookup(c, host_key, &s->host_sign_algo->algo) != ASSH_OK,
               ASSH_ERR_MISSING_KEY);
  struct assh_key_s *hk = *host_key;

  assh_kex_lower_safety(s, hk->safety);

  assert(s->kex_host_key == NULL);
  s->kex_host_key = hk;
  assh_key_refinc(hk);

  /* alloc reply packet */
  size_t ks_len;
  ASSH_RET_ON_ERR(assh_key_output(c, hk, NULL, &ks_len,
	         ASSH_KEY_FMT_PUB_RFC4253));

  ASSH_RET_ON_ERR(assh_sign_generate(c, sign_algo, hk, 0, NULL, NULL, sign_len));

  ASSH_RET_ON_ERR(assh_packet_alloc(c, msg,
		(4 + ks_len) + kex_len + (4 + *sign_len), pout));

  /* append public host key to packet. */
  uint8_t *ks_str;
  ASSH_ASSERT(assh_packet_add_string(*pout, ks_len, &ks_str));
  ASSH_JMP_ON_ERR(assh_key_output(c, hk, ks_str, &ks_len,
		ASSH_KEY_FMT_PUB_RFC4253), err_p);

  assh_packet_shrink_string(*pout, ks_str, ks_len);

  assh_hash_bytes_as_string(hash_ctx, s->ident_str, s->ident_len);
  assh_hash_bytes_as_string(hash_ctx, (const uint8_t*)ASSH_IDENT,
			    sizeof(ASSH_IDENT) /* \r\n\0 */ - 3);
  assh_hash_payload_as_string(hash_ctx, s->kex_init_remote);
  assh_hash_payload_as_string(hash_ctx, s->kex_init_local);
  assh_hash_string(hash_ctx, ks_str - 4);

  return ASSH_OK;
 err_p:
  assh_packet_release(*pout);
  return err;
}

assh_status_t
assh_kex_server_hash2(struct assh_session_s *s,
                      struct assh_hash_ctx_s *hash_ctx,
                      struct assh_packet_s *pout, size_t sign_len,
                      const struct assh_key_s *host_key,
                      const uint8_t *secret_str)
{
  assh_status_t err;
  struct assh_context_s *c = s->ctx;
  const struct assh_algo_sign_s *sign_algo = s->host_sign_algo;

  assh_hash_string(hash_ctx, secret_str);

  size_t hash_size = hash_ctx->algo->hash_size;
  assert(hash_size);

  uint8_t ex_hash[hash_size];
  assh_hash_final(hash_ctx, ex_hash, hash_size);

  /* append the signature */
  struct assh_cbuffer_s data = {
    .data = ex_hash,
    .size = hash_size
  };

  /* append the signature */
  uint8_t *sign;
  ASSH_ASSERT(assh_packet_add_string(pout, sign_len, &sign));

  ASSH_RET_ON_ERR(assh_sign_generate(c, sign_algo, host_key, 1,
		 &data, sign, &sign_len));
  assh_packet_shrink_string(pout, sign, sign_len);

  /* setup new symmetric keys */
  ASSH_RETURN(assh_kex_new_keys(s, hash_ctx->algo, ex_hash, secret_str));
}
#endif

const struct assh_kex_keys_s assh_keys_none =
{
  .cipher = &assh_cipher_none,
  .mac = &assh_hmac_none,
  .cmp = &assh_compress_none,
};

void assh_kex_keys_cleanup(struct assh_session_s *s, struct assh_kex_keys_s *keys)
{
  if (keys == NULL || keys == &assh_keys_none)
    return;

  if (keys->cipher_ctx != NULL)
    keys->cipher->f_cleanup(s->ctx, keys->cipher_ctx);
  if (keys->mac_ctx != NULL)
    keys->mac->f_cleanup(s->ctx, keys->mac_ctx);
  if (keys->cmp_ctx != NULL)
    keys->cmp->f_cleanup(s->ctx, keys->cmp_ctx);

  assh_free(s->ctx, keys);
}

assh_status_t assh_kex_end(struct assh_session_s *s, assh_bool_t accept)
{
  assh_status_t err;

  if (s->kex_pv != NULL)
    s->kex->f_cleanup(s);
  assert(s->kex_pv == NULL);

  /* release KEX init packets */
  assh_packet_release(s->kex_init_local);
  s->kex_init_local = NULL;

  assh_packet_release(s->kex_init_remote);
  s->kex_init_remote = NULL;

  ASSH_RET_IF_TRUE(!accept, ASSH_ERR_KEX_FAILED);

  /* next state is wait for NEWKEY packet */
  ASSH_SET_STATE(s, tr_st, ASSH_TR_NEWKEY);

  /* send a NEWKEY packet */
  struct assh_packet_s *p;
  ASSH_RET_ON_ERR(assh_packet_alloc(s->ctx, SSH_MSG_NEWKEYS, 0, &p));
  assh_transport_push(s, p);

  return ASSH_OK;
}

static ASSH_EVENT_DONE_FCN(assh_event_kex_done_done)
{
  assh_key_drop(s->ctx, &s->kex_host_key);
  s->kex_done = 1;
  return ASSH_OK;
}

void assh_kex_done(struct assh_session_s *s,
                   struct assh_event_s *e)
{
  e->id = ASSH_EVENT_KEX_DONE;
  e->f_done = assh_event_kex_done_done;
  e->kex.done.host_key = s->kex_host_key;

  const struct assh_kex_keys_s *in = s->cur_keys_in;
  const struct assh_kex_keys_s *out = s->new_keys_out != NULL
    ? s->new_keys_out : s->cur_keys_out;

  e->kex.done.ident.data = s->ident_str;
  e->kex.done.ident.size = s->ident_len;
  e->kex.done.safety = ASSH_MIN(in->safety, out->safety);
  e->kex.done.initial = !s->kex_done;
  e->kex.done.algo_kex = s->kex;
  e->kex.done.algos_in = in;
  e->kex.done.algos_out = out;
}

assh_status_t
assh_kex_set_threshold(struct assh_session_s *s, uint32_t bytes)
{
  assh_status_t err;

  ASSH_RET_IF_TRUE(bytes < 1 || bytes > ASSH_REKEX_THRESHOLD,
	       ASSH_ERR_BAD_ARG | ASSH_ERRSV_CONTINUE);

  s->kex_max_bytes = bytes;
  return ASSH_OK;
}

