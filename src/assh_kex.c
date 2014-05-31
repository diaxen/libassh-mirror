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

assh_error_t assh_kex_send_init(struct assh_session_s *s)
{
  assh_error_t err;

  struct assh_packet_s *p;
  ASSH_ERR_RET(assh_packet_alloc(s->ctx, SSH_MSG_KEXINIT, 2048, &p)
	       | ASSH_ERRSV_DISCONNECT);

  uint8_t *cookie;
  ASSH_ERR_GTO(assh_packet_add_array(p, 16, &cookie), err_pck);
  ASSH_ERR_GTO(s->ctx->prng->f_get(s->ctx, cookie,
		  16, ASSH_PRNG_QUALITY_NONCE)
	       | ASSH_ERRSV_DISCONNECT, err_pck);

  unsigned int ac = s->ctx->algos_count;

  /* lists of algorithms */
  unsigned int i = 0, j;
  for (j = ASSH_ALGO_KEX; j <= ASSH_ALGO_COMPRESS; j++)
    {
      assh_bool_t first = 0;
      uint8_t *list;
      ASSH_ERR_GTO(assh_packet_add_string(p, 0, &list)
		   | ASSH_ERRSV_DISCONNECT, err_pck);

      for (; i < ac; i++)
        {
          const struct assh_algo_s *a = s->ctx->algos[i];
          if (a->class_ != j)
            break;

#ifdef CONFIG_ASSH_SERVER
          /* check host key availability for this algorithm */
          if (s->ctx->type == ASSH_SERVER && assh_algo_needs_key(a))
            {
              struct assh_key_s *k = s->ctx->host_keys;
              while (k != NULL && !assh_algo_suitable_key(a, k))
                k = k->next;
              if (k == NULL)
                continue;
            }
#endif

          /* append name to the list */
          uint8_t *tail;
          size_t l = strlen(a->name);
          ASSH_ERR_GTO(assh_packet_enlarge_string(p, list, first + l, &tail)
		       | ASSH_ERRSV_DISCONNECT, err_pck);
          memcpy(tail + first, a->name, l);
          if (first)
            tail[0] = ',';
          first = 1;
        }

      if (j >= ASSH_ALGO_CIPHER)  /* duplicate list */
        {
          size_t len = assh_load_u32(list - 4);
          uint8_t *list2;
          ASSH_ERR_GTO(assh_packet_add_string(p, len, &list2)
		       | ASSH_ERRSV_DISCONNECT, err_pck);
          memcpy(list2, list, len);
        }
    }

  uint8_t *x;

  /* empty languages */
  ASSH_ERR_GTO(assh_packet_add_string(p, 0, &x)
	       | ASSH_ERRSV_DISCONNECT, err_pck);
  ASSH_ERR_GTO(assh_packet_add_string(p, 0, &x)
	       | ASSH_ERRSV_DISCONNECT, err_pck);

  ASSH_ERR_GTO(assh_packet_add_array(p, 5, &x)
	       | ASSH_ERRSV_DISCONNECT, err_pck);
  memset(x, 0, 5);

  /* keep a copy of our KEX_INIT packet, will be needed for hashing */
  assert(s->kex_init_local == NULL);
  struct assh_packet_s *c;
  ASSH_ERR_GTO(assh_packet_dup(p, &c)
	       | ASSH_ERRSV_DISCONNECT, err_pck);
  s->kex_init_local = c;

  /* setup packet len and padding fields of the copy */
  assh_store_u32(c->data, c->data_size - 4);
  c->head.pad_len = 0;

  s->kex_init_sent = 1;
  assh_transport_push(s, p);
  return ASSH_OK;

 err_pck:
  assh_packet_release(p);
  return err;
}

#ifdef CONFIG_ASSH_SERVER
/* select server side algorithms based on KEX init lists from client */
static assh_error_t
assh_kex_server_algos(struct assh_context_s *c, uint8_t *lists[9],
                      const struct assh_algo_s *algos[8], assh_bool_t *guessed)
{
  assh_error_t err;
  unsigned int i;

  *guessed = 1;
  for (i = 0; i < 8; i++)
    {
      char *start = (char*)(lists[i] + 4);
      char *end = (char*)lists[i+1];

      /* iterate over name-list */
      while (start < end)
        {
          char *n = start;
          while (*n != ',' && n < end)
            n++;

          /* lookup in registered algorithms */
          const struct assh_algo_s *a;
          if (assh_algo_by_name(c, assh_kex_algos_classes[i], start, n - start, &a) != ASSH_OK)
            goto next;

          /* check algorithm key availability */
          if (assh_algo_needs_key(a))
            {
              struct assh_key_s *k = c->host_keys;
              while (k != NULL && !assh_algo_suitable_key(a, k))
                k = k->next;
              if (k == NULL)
                goto next;
            }

          algos[i] = a;
          goto done;

        next:
          start = n + 1;
          if (i < 2) /* KEX or HOST KEY algorithm */
            *guessed = 0;
        }

      ASSH_ERR_RET(ASSH_ERR_MISSING_ALGO | ASSH_ERRSV_DISCONNECT);
    done:;
    }

  return ASSH_OK;
}
#endif

#ifdef CONFIG_ASSH_CLIENT
/* select client side algorithms based on KEX init lists from server */
static assh_error_t
assh_kex_client_algos(struct assh_context_s *c, uint8_t *lists[9],
                      const struct assh_algo_s *algos[8], assh_bool_t *guessed)
{
  assh_error_t err;
  unsigned int i, j;

  *guessed = 1;
  for (j = i = 0; i < 8; i++)
    {
      /* iterate over available algorithms */
      for (; ; j++)
        {
          ASSH_CHK_RET(j == c->algos_count,
		       ASSH_ERR_MISSING_ALGO | ASSH_ERRSV_DISCONNECT);

          const struct assh_algo_s *a = c->algos[j];
          if (a->class_ < assh_kex_algos_classes[i])
            continue;
          ASSH_CHK_RET(a->class_ > assh_kex_algos_classes[i],
                       ASSH_ERR_MISSING_ALGO | ASSH_ERRSV_DISCONNECT);

          char *start = (char*)(lists[i] + 4);
          char *end = (char*)lists[i+1];

          /* iterate over name-list */
          while (start < end)
            {
              char *n = start;
              while (*n != ',' && n < end)
                n++;

              /* check algorithm name match */
              if (!strncmp(start, a->name, n - start)
                  && a->name[n - start] == '\0')
                {
                  algos[i] = a;
                  goto done;
                }

              start = n + 1;
              if (i < 2) /* KEX or HOST KEY algorithm */
                *guessed = 0;
            }
        }
    done:;
    }

  return ASSH_OK;
}
#endif

assh_error_t assh_kex_got_init(struct assh_session_s *s, struct assh_packet_s *p)
{
  assh_error_t err;

  uint8_t *lists[11];

  unsigned int i;

  /* get pointers to the 10 name-lists while checking bounds */
  lists[0] = p->head.end /* cookie */ + 16;
  for (i = 0; i < 10; i++)
    ASSH_ERR_RET(assh_packet_check_string(p, lists[i], lists + i + 1)
		 | ASSH_ERRSV_DISCONNECT);

  ASSH_ERR_RET(assh_packet_check_array(p, lists[10], 1, NULL)
               | ASSH_ERRSV_DISCONNECT);

  assh_bool_t guess_follows = *lists[10];
  assh_bool_t good_guess;

  const struct assh_algo_s *algos[8];

  /* select proper algorithms based on registered algorithms and name-lists */
  switch (s->ctx->type)
    {
#ifdef CONFIG_ASSH_SERVER
    case ASSH_SERVER:
      ASSH_ERR_RET(assh_kex_server_algos(s->ctx, lists, algos, &good_guess)
		   | ASSH_ERRSV_DISCONNECT);
      break;
#endif
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_CLIENT:
      ASSH_ERR_RET(assh_kex_client_algos(s->ctx, lists, algos, &good_guess)
		   | ASSH_ERRSV_DISCONNECT);
      break;
#endif
    default:
      abort();
    }

  s->kex_bad_guess = guess_follows && !good_guess;

  const struct assh_algo_kex_s *kex           = (const void *)algos[0];
  const struct assh_algo_sign_s *sign         = (const void *)algos[1];
  const struct assh_algo_cipher_s *cipher_in  = (const void *)algos[2];
  const struct assh_algo_cipher_s *cipher_out = (const void *)algos[3];
  const struct assh_algo_mac_s *mac_in        = (const void *)algos[4];
  const struct assh_algo_mac_s *mac_out       = (const void *)algos[5];
  const struct assh_algo_compress_s *cmp_in   = (const void *)algos[6];
  const struct assh_algo_compress_s *cmp_out  = (const void *)algos[7];

#ifdef CONFIG_ASSH_DEBUG_KEX
  ASSH_DEBUG("kex algorithms:\n"
             "  kex: %s (%s)\n"
             "  sign: %s (%s)\n"
             "  cipher in: %s\n  cipher out: %s\n"
             "  mac in: %s\n  mac out: %s\n  comp in: %s\n  comp out: %s\n"
             "  guess: follows=%x good=%x\n",
             kex->algo.name, kex->algo.variant,
             sign->algo.name, sign->algo.variant,
             cipher_in->algo.name, cipher_out->algo.name,
             mac_in->algo.name, mac_out->algo.name,
             cmp_in->algo.name, cmp_out->algo.name,
             guess_follows, good_guess);
#endif

  /* keep the remote KEX_INIT packet, will be needed for hashing */
  assert(s->kex_init_remote == NULL);
  assh_packet_refinc(p);
  s->kex_init_remote = p;

  /* alloacte input and output keys and associated cipher/mac/compress contexts */
  struct assh_kex_keys_s *kin;
  ASSH_ERR_RET(assh_alloc(s->ctx, sizeof(*kin) + cipher_in->ctx_size
    + mac_in->ctx_size + cmp_in->ctx_size, ASSH_ALLOC_KEY, (void**)&kin)
	       | ASSH_ERRSV_DISCONNECT);

  struct assh_kex_keys_s *kout;
  ASSH_ERR_GTO(assh_alloc(s->ctx, sizeof(*kout) + cipher_out->ctx_size
    + mac_out->ctx_size + cmp_out->ctx_size, ASSH_ALLOC_KEY, (void**)&kout)
	       | ASSH_ERRSV_DISCONNECT, err_kin);

  /* initialize key exchange algorithm */
  ASSH_ERR_GTO(kex->f_init(s) | ASSH_ERRSV_DISCONNECT, err_kout);

  s->kex = kex;
  s->host_sign_algo = sign;

  /* initialize input keys structure */
  kin->cmp_ctx = kin->mac_ctx = kin->cipher_ctx = NULL;
  kin->cipher = cipher_in;
  kin->mac = mac_in;
  kin->cmp = cmp_in;
  assh_kex_keys_cleanup(s, s->new_keys_in);
  s->new_keys_in = kin;

  /* initialize output keys structure */
  kout->cmp_ctx = kout->mac_ctx = kout->cipher_ctx = NULL;
  kout->cipher = cipher_out;
  kout->mac = mac_out;
  kout->cmp = cmp_out;
  assh_kex_keys_cleanup(s, s->new_keys_out);
  s->new_keys_out = kout;

  return ASSH_OK;

 err_kout:
  assh_free(s->ctx, kout, ASSH_ALLOC_KEY);
 err_kin:
  assh_free(s->ctx, kin, ASSH_ALLOC_KEY);
  return err;
}

/* derive cipher/mac/iv key from shared secret */
static assh_error_t assh_kex_new_key(struct assh_session_s *s, void *hash_ctx,
                                     const struct assh_hash_s *hash_algo,
                                     const uint8_t *ex_hash, const uint8_t *secret_str,
                                     char c, uint8_t *key, size_t key_size)
{
  assh_error_t err;

  ASSH_SCRATCH_ALLOC(s->ctx, uint8_t, buf, ASSH_MAX_SYMKEY_SIZE + ASSH_MAX_HASH_SIZE,
		     ASSH_ERRSV_CONTINUE, err);

  assert(key_size <= ASSH_MAX_SYMKEY_SIZE);

  /* setup session id */
  if (s->session_id_len == 0)
    memcpy(s->session_id, ex_hash, s->session_id_len = hash_algo->hash_size);

  /* derive key */
  hash_algo->f_init(hash_ctx);
  hash_algo->f_update(hash_ctx, secret_str, assh_load_u32(secret_str) + 4);
  hash_algo->f_update(hash_ctx, ex_hash, hash_algo->hash_size);
  hash_algo->f_update(hash_ctx, &c, 1);
  hash_algo->f_update(hash_ctx, s->session_id, s->session_id_len);
  hash_algo->f_final(hash_ctx, buf);

  /* further enlarge derived key */
  size_t size;
  for (size = hash_algo->hash_size; size < key_size;
       size += hash_algo->hash_size)
    {
      assert(size + hash_algo->hash_size
	     <= ASSH_MAX_SYMKEY_SIZE + ASSH_MAX_HASH_SIZE);

      hash_algo->f_init(hash_ctx);
      hash_algo->f_update(hash_ctx, secret_str, assh_load_u32(secret_str) + 4);
      hash_algo->f_update(hash_ctx, ex_hash, hash_algo->hash_size);
      hash_algo->f_update(hash_ctx, buf, size);
      hash_algo->f_final(hash_ctx, buf + size);
    }

  memcpy(key, buf, key_size);

  err = ASSH_OK;

  ASSH_SCRATCH_FREE(s->ctx, buf);
 err:
  return err;
}

assh_error_t
assh_kex_new_keys(struct assh_session_s *s,
                  const struct assh_hash_s *hash_algo, const uint8_t *ex_hash,
                  const uint8_t *secret_str)
{
  assh_error_t err;
#if defined(CONFIG_ASSH_SERVER) && defined(CONFIG_ASSH_CLIENT)
  const char *c = s->ctx->type == ASSH_SERVER ? "ABCDEF" : "BADCFE";
#elif defined(CONFIG_ASSH_CLIENT)
  const char *c = "BADCFE";
#elif defined(CONFIG_ASSH_SERVER)
  const char *c = "ABCDEF";
#endif

#ifdef CONFIG_ASSH_DEBUG_KEX
  assh_hexdump("exchange hash", ex_hash, hash_algo->hash_size);
#endif

  ASSH_SCRATCH_ALLOC(s->ctx, uint8_t, scratch, hash_algo->ctx_size +
		     ASSH_MAX(ASSH_MAX_EKEY_SIZE, ASSH_MAX_IKEY_SIZE),
		     ASSH_ERRSV_DISCONNECT, err);

  void *hash_ctx = scratch;
  uint8_t *key = scratch + hash_algo->ctx_size;

  struct assh_kex_keys_s *kin = s->new_keys_in;
  struct assh_kex_keys_s *kout = s->new_keys_out;

  /* get input IV */
  if (!kin->cipher->is_stream)
    ASSH_ERR_GTO(assh_kex_new_key(s, hash_ctx, hash_algo, ex_hash,
                                  secret_str, *c,
                                  kin->iv, kin->cipher->block_size)
		 | ASSH_ERRSV_DISCONNECT, err_scratch);
#ifdef CONFIG_ASSH_DEBUG_KEX
  assh_hexdump("in iv", kin->iv, kin->cipher->block_size);
#endif
  c++;

  /* get output IV */
  if (!kout->cipher->is_stream)
    ASSH_ERR_GTO(assh_kex_new_key(s, hash_ctx, hash_algo, ex_hash,
                                  secret_str, *c,
                                  kout->iv, kout->cipher->block_size)
		 | ASSH_ERRSV_DISCONNECT, err_scratch);
#ifdef CONFIG_ASSH_DEBUG_KEX
  assh_hexdump("out iv", kout->iv, kout->cipher->block_size);
#endif
  c++;

  /* get input cipher key and init cipher */
  ASSH_ERR_GTO(assh_kex_new_key(s, hash_ctx, hash_algo, ex_hash,
                                secret_str, *c++,
                                key, kin->cipher->key_size)
	       | ASSH_ERRSV_DISCONNECT, err_scratch);
  kin->cipher_ctx = (void*)(kin + 1);
  ASSH_ERR_GTO(kin->cipher->f_init(s->ctx, kin->cipher_ctx, key, kin->iv, 0)
	       | ASSH_ERRSV_DISCONNECT, err_cipher_in);
#ifdef CONFIG_ASSH_DEBUG_KEX
  assh_hexdump("in ekey", key, kin->cipher->key_size);
#endif

  /* get output cipher key and init cipher */
  ASSH_ERR_GTO(assh_kex_new_key(s, hash_ctx, hash_algo, ex_hash,
                                secret_str, *c++,
                                key, kout->cipher->key_size)
	       | ASSH_ERRSV_DISCONNECT, err_cipher_out);
  kout->cipher_ctx = (void*)(kout + 1);
  ASSH_ERR_GTO(kout->cipher->f_init(s->ctx, kout->cipher_ctx, key, kout->iv, 1)
	       | ASSH_ERRSV_DISCONNECT, err_cipher_out);
#ifdef CONFIG_ASSH_DEBUG_KEX
  assh_hexdump("out ekey", key, kout->cipher->key_size);
#endif

  /* get input integrity key and init mac */
  ASSH_ERR_GTO(assh_kex_new_key(s, hash_ctx, hash_algo, ex_hash,
                                secret_str, *c++,
                                key, kin->mac->key_size)
	       | ASSH_ERRSV_DISCONNECT, err_mac_in);
  kin->mac_ctx = (void*)((uint8_t*)(kin->cipher_ctx) + kin->cipher->ctx_size);
  ASSH_ERR_GTO(kin->mac->f_init(s->ctx, kin->mac_ctx, key)
	       | ASSH_ERRSV_DISCONNECT, err_mac_in);
#ifdef CONFIG_ASSH_DEBUG_KEX
  assh_hexdump("in ikey", key, kin->mac->key_size);
#endif

  /* get output integrity key and init cipher */
  ASSH_ERR_GTO(assh_kex_new_key(s, hash_ctx, hash_algo, ex_hash,
                                secret_str, *c++,
                                key, kout->mac->key_size)
	       | ASSH_ERRSV_DISCONNECT, err_mac_out);
  kout->mac_ctx = (void*)((uint8_t*)(kout->cipher_ctx) + kout->cipher->ctx_size);
  ASSH_ERR_GTO(kout->mac->f_init(s->ctx, kout->mac_ctx, key)
	       | ASSH_ERRSV_DISCONNECT, err_mac_out);
#ifdef CONFIG_ASSH_DEBUG_KEX
  assh_hexdump("out ikey", key, kout->mac->key_size);
#endif

  /* init input compression */
  kin->cmp_ctx = (void*)((uint8_t*)(kin->mac_ctx) + kin->mac->ctx_size);
  ASSH_ERR_GTO(kin->cmp->f_init(s->ctx, kin->cmp_ctx, 0)
	       | ASSH_ERRSV_DISCONNECT, err_cmp_in);

  /* init output compression */
  kout->cmp_ctx = (void*)((uint8_t*)(kout->mac_ctx) + kout->mac->ctx_size);
  ASSH_ERR_GTO(kout->cmp->f_init(s->ctx, kout->cmp_ctx, 1)
	       | ASSH_ERRSV_DISCONNECT, err_cmp_out);

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
assh_error_t
assh_kex_client_get_key(struct assh_session_s *s, struct assh_key_s **host_key,
                        const uint8_t *ks_str, struct assh_event_s *e,
                        assh_error_t (*done)(struct assh_session_s *s,
                                             struct assh_event_s *e), void *pv)
{
  assh_error_t err;

  /* load key and verify signature */
  const struct assh_algo_sign_s *sign_algo = s->host_sign_algo;

  ASSH_ERR_RET(assh_key_load3(s->ctx, host_key, &sign_algo->algo, ks_str + 4,
                 assh_load_u32(ks_str), ASSH_KEY_FMT_PUB_RFC4253_6_6)
               | ASSH_ERRSV_DISCONNECT);

  /* check if the key can be used by the algorithm */
  ASSH_CHK_GTO(!assh_algo_suitable_key(&sign_algo->algo, *host_key),
               ASSH_ERR_WEAK_ALGORITHM | ASSH_ERRSV_DISCONNECT, err_hk);

  /* Return an host key lookup event */
  e->id = ASSH_EVENT_KEX_HOSTKEY_LOOKUP;
  e->f_done = done;
  e->done_pv = pv;
  e->kex.hostkey_lookup.key = *host_key;
  e->kex.hostkey_lookup.accept = 0;

  return ASSH_OK;

 err_hk:
  assh_key_flush(s->ctx, host_key);
  return err;
}

assh_error_t
assh_kex_client_hash(struct assh_session_s *s, assh_kex_client_hash_t *fcn,
                     const struct assh_hash_s *hash_algo,
                     struct assh_key_s *host_key, const uint8_t *secret_str,
                     const uint8_t *k_str, const uint8_t *h_str)
{
  assh_error_t err;
  struct assh_context_s *c = s->ctx;

  /* compute the exchange hash H */
  ASSH_SCRATCH_ALLOC(c, void, hash_ctx, hash_algo->ctx_size,
		     ASSH_ERRSV_CONTINUE, err_);

  ASSH_ERR_GTO(hash_algo->f_init(hash_ctx), err_scratch);

  assh_hash_bytes_as_string(hash_ctx, hash_algo->f_update, (const uint8_t*)ASSH_IDENT,
			    sizeof(ASSH_IDENT) /* \r\n\0 */ - 3);
  assh_hash_bytes_as_string(hash_ctx, hash_algo->f_update, s->ident_str, s->ident_len);
  assh_hash_payload_as_string(hash_ctx, hash_algo->f_update, s->kex_init_local);
  assh_hash_payload_as_string(hash_ctx, hash_algo->f_update, s->kex_init_remote);
  assh_hash_string(hash_ctx, hash_algo->f_update, k_str);

  ASSH_ERR_GTO(fcn(s, hash_algo, hash_ctx), err_hash);

  assh_hash_string(hash_ctx, hash_algo->f_update, secret_str);

  uint8_t ex_hash[ASSH_MAX_HASH_SIZE];
  hash_algo->f_final(hash_ctx, ex_hash);

  const uint8_t *sign_ptrs[1] = { ex_hash };
  size_t sign_sizes[1] = { hash_algo->hash_size };

  const struct assh_algo_sign_s *sign_algo = s->host_sign_algo;

  ASSH_CHK_GTO(sign_algo->f_verify(c, host_key, 1, sign_ptrs, sign_sizes,
                h_str + 4, assh_load_u32(h_str)) != ASSH_OK,
               ASSH_ERR_HOSTKEY_SIGNATURE | ASSH_ERRSV_DISCONNECT, err_scratch);

  /* setup new keys */
  ASSH_ERR_GTO(assh_kex_new_keys(s, hash_algo, ex_hash, secret_str)
               | ASSH_ERRSV_DISCONNECT, err_scratch);

  ASSH_SCRATCH_FREE(c, hash_ctx);
  return ASSH_OK;

 err_hash:
  hash_algo->f_final(hash_ctx, NULL);
 err_scratch:
  ASSH_SCRATCH_FREE(c, hash_ctx);
 err_:
  return err;
}
#endif

#ifdef CONFIG_ASSH_SERVER
assh_error_t
assh_kex_server_hash(struct assh_session_s *s,
                     assh_kex_server_hash_t *fcn, size_t kex_len,
                     const struct assh_hash_s *hash_algo,
                     const uint8_t *secret_str)
{
  assh_error_t err;
  struct assh_context_s *c = s->ctx;

  /* look for an host key pair which can be used with the selected algorithm. */
  const struct assh_key_s *hk = c->host_keys;
  const struct assh_algo_sign_s *sign_algo = s->host_sign_algo;
  while (hk != NULL && !assh_algo_suitable_key(&sign_algo->algo, hk))
    hk = hk->next;
  ASSH_CHK_RET(hk == NULL, ASSH_ERR_MISSING_KEY | ASSH_ERRSV_DISCONNECT);

  /* alloc reply packet */
  size_t ks_len;
  ASSH_ERR_RET(hk->f_output(c, hk, NULL, &ks_len,
	         ASSH_KEY_FMT_PUB_RFC4253_6_6)
	       | ASSH_ERRSV_DISCONNECT);

  size_t sign_len;
  ASSH_ERR_RET(sign_algo->f_generate(c, hk, 0, NULL, NULL, NULL, &sign_len)
	       | ASSH_ERRSV_DISCONNECT);

  struct assh_packet_s *pout;
  ASSH_ERR_RET(assh_packet_alloc(c, SSH_MSG_KEX_DH_REPLY,
		(4 + ks_len) + kex_len + (4 + sign_len), &pout)
	       | ASSH_ERRSV_DISCONNECT);

  /* append public host key to packet. */
  uint8_t *ks_str;
  ASSH_ASSERT(assh_packet_add_string(pout, ks_len, &ks_str));
  ASSH_ERR_GTO(hk->f_output(c, hk, ks_str, &ks_len,
		ASSH_KEY_FMT_PUB_RFC4253_6_6)
	       | ASSH_ERRSV_DISCONNECT, err_p);

  assh_packet_shrink_string(pout, ks_str, ks_len);

  /* compute the exchange hash H */
  ASSH_SCRATCH_ALLOC(c, void, hash_ctx, hash_algo->ctx_size,
		     ASSH_ERRSV_CONTINUE, err_p);

  hash_algo->f_init(hash_ctx);

  assh_hash_bytes_as_string(hash_ctx, hash_algo->f_update, s->ident_str, s->ident_len);
  assh_hash_bytes_as_string(hash_ctx, hash_algo->f_update, (const uint8_t*)ASSH_IDENT,
			    sizeof(ASSH_IDENT) /* \r\n\0 */ - 3);
  assh_hash_payload_as_string(hash_ctx, hash_algo->f_update, s->kex_init_remote);
  assh_hash_payload_as_string(hash_ctx, hash_algo->f_update, s->kex_init_local);
  assh_hash_string(hash_ctx, hash_algo->f_update, ks_str - 4);

  ASSH_ERR_GTO(fcn(s, hash_algo, hash_ctx, pout), err_scratch);

  assh_hash_string(hash_ctx, hash_algo->f_update, secret_str);

  uint8_t ex_hash[ASSH_MAX_HASH_SIZE];
  hash_algo->f_final(hash_ctx, ex_hash);

  const uint8_t *sign_ptrs[1] = { ex_hash };
  size_t sign_sizes[1] = { hash_algo->hash_size };

  /* append the signature */
  uint8_t *sign;
  ASSH_ASSERT(assh_packet_add_string(pout, sign_len, &sign));

  ASSH_ERR_GTO(sign_algo->f_generate(c, hk, 1,
		 sign_ptrs, sign_sizes, sign, &sign_len)
	       | ASSH_ERRSV_DISCONNECT, err_scratch);
  assh_packet_shrink_string(pout, sign, sign_len);

  /* setup new symmetric keys */
  ASSH_ERR_GTO(assh_kex_new_keys(s, hash_algo, ex_hash, secret_str)
	       | ASSH_ERRSV_DISCONNECT, err_scratch);

  assh_transport_push(s, pout);

  ASSH_SCRATCH_FREE(c, hash_ctx);

  return ASSH_OK;

 err_scratch:
  ASSH_SCRATCH_FREE(c, hash_ctx);
 err_p:
  assh_packet_release(pout);
  return err;
}
#endif

void assh_kex_keys_cleanup(struct assh_session_s *s, struct assh_kex_keys_s *keys)
{
  if (keys == NULL)
    return;

  if (keys->cipher_ctx != NULL)
    keys->cipher->f_cleanup(s->ctx, keys->cipher_ctx);
  if (keys->mac_ctx != NULL)
    keys->mac->f_cleanup(s->ctx, keys->mac_ctx);
  if (keys->cmp_ctx != NULL)
    keys->cmp->f_cleanup(s->ctx, keys->cmp_ctx);

  assh_free(s->ctx, keys, ASSH_ALLOC_KEY);
}

assh_error_t assh_kex_end(struct assh_session_s *s, assh_bool_t accept)
{
  assh_error_t err;

  if (s->kex_pv != NULL)
    s->kex->f_cleanup(s);
  assert(s->kex_pv == NULL);

  /* release KEX init packets */
  assh_packet_release(s->kex_init_local);
  s->kex_init_local = NULL;

  assh_packet_release(s->kex_init_remote);
  s->kex_init_remote = NULL;

  ASSH_CHK_RET(!accept, ASSH_ERR_KEX_FAILED | ASSH_ERRSV_DISCONNECT);

  s->kex_bytes = 0;
  s->kex_init_sent = 0;

  /* next state is wait for NEWKEY packet */
  assh_transport_state(s, ASSH_TR_NEWKEY);

  /* send a NEWKEY packet */
  struct assh_packet_s *p;
  ASSH_ERR_RET(assh_packet_alloc(s->ctx, SSH_MSG_NEWKEYS, 0, &p) | ASSH_ERRSV_DISCONNECT);
  assh_transport_push(s, p);

  return ASSH_OK;
}

assh_error_t
assh_kex_set_threshold(struct assh_session_s *s, uint32_t bytes)
{
  assh_error_t err;

  ASSH_CHK_RET(bytes < 1 || bytes > ASSH_REKEX_THRESHOLD,
	       ASSH_ERR_BAD_ARG | ASSH_ERRSV_CONTINUE);

  s->kex_max_bytes = bytes;
  return ASSH_OK;
}

