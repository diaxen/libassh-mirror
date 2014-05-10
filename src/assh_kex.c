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
          if (s->ctx->type == ASSH_SERVER && a->need_host_key)
            {
              struct assh_key_s *k = s->ctx->host_keys;
              while (k != NULL && k->algo != a)
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
          if (a->need_host_key)
            {
              struct assh_key_s *k = c->host_keys;
              while (k != NULL && k->algo != a)
                k = k->next;
              if (k == NULL)
                goto next;
            }

          algos[i] = a;
          goto done;

        next:
          start = n + 1;
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

              *guessed = 0;
              start = n + 1;
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

  uint8_t *lists[9];

  unsigned int i;

  /* get pointers to the 8 name-lists and check bounds */
  lists[0] = p->head.end /* cookie */ + 16;
  for (i = 0; i < 8; i++)
    ASSH_ERR_RET(assh_packet_check_string(p, lists[i], lists + i + 1)
		 | ASSH_ERRSV_DISCONNECT);

  const struct assh_algo_s *algos[8];
  assh_bool_t guessed;

  /* select proper algorithms based on registered algorithms and name-lists */
  switch (s->ctx->type)
    {
#ifdef CONFIG_ASSH_SERVER
    case ASSH_SERVER:
      ASSH_ERR_RET(assh_kex_server_algos(s->ctx, lists, algos, &guessed)
		   | ASSH_ERRSV_DISCONNECT);
      break;
#endif
#ifdef CONFIG_ASSH_CLIENT
    case ASSH_CLIENT:
      ASSH_ERR_RET(assh_kex_client_algos(s->ctx, lists, algos, &guessed)
		   | ASSH_ERRSV_DISCONNECT);
      break;
#endif
    default:
      abort();
    }

  const struct assh_algo_kex_s *kex           = (const void *)algos[0];
  const struct assh_algo_sign_s *sign         = (const void *)algos[1];
  const struct assh_algo_cipher_s *cipher_in  = (const void *)algos[2];
  const struct assh_algo_cipher_s *cipher_out = (const void *)algos[3];
  const struct assh_algo_mac_s *mac_in        = (const void *)algos[4];
  const struct assh_algo_mac_s *mac_out       = (const void *)algos[5];
  const struct assh_algo_compress_s *cmp_in   = (const void *)algos[6];
  const struct assh_algo_compress_s *cmp_out  = (const void *)algos[7];

#warning handle guess

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
                                     const uint8_t *ex_hash,
                                     struct assh_bignum_s *k, char c,
                                     uint8_t *key, size_t key_size)
{
  assh_error_t err;

  ASSH_SCRATCH_ALLOC(s->ctx, uint8_t, buf, ASSH_MAX_SYMKEY_SIZE,
		     ASSH_ERRSV_CONTINUE, err);

  assert(key_size <= ASSH_MAX_SYMKEY_SIZE);

  /* setup session id */
  if (s->session_id_len == 0)
    memcpy(s->session_id, ex_hash, s->session_id_len = hash_algo->hash_size);

  /* derive key */
  hash_algo->f_init(hash_ctx);
  ASSH_ERR_GTO(assh_hash_bignum(s->ctx, hash_ctx, hash_algo->f_update, k)
	       | ASSH_ERRSV_DISCONNECT, err_buf);
  hash_algo->f_update(hash_ctx, ex_hash, hash_algo->hash_size);
  hash_algo->f_update(hash_ctx, &c, 1);
  hash_algo->f_update(hash_ctx, s->session_id, s->session_id_len);
  hash_algo->f_final(hash_ctx, buf);

  /* further enlarge derived key */
  size_t size;
  for (size = hash_algo->hash_size; size < key_size;
       size += hash_algo->hash_size)
    {
      assert(size + hash_algo->hash_size <= ASSH_MAX_SYMKEY_SIZE);

      hash_algo->f_init(hash_ctx);
      ASSH_ERR_GTO(assh_hash_bignum(s->ctx, hash_ctx, hash_algo->f_update, k)
		   | ASSH_ERRSV_DISCONNECT, err_buf);
      hash_algo->f_update(hash_ctx, ex_hash, hash_algo->hash_size);
      hash_algo->f_update(hash_ctx, buf, size);
      hash_algo->f_final(hash_ctx, buf + size);
    }

  memcpy(key, buf, key_size);

  err = ASSH_OK;

 err_buf:
  ASSH_SCRATCH_FREE(s->ctx, buf);
 err:
  return err;
}

assh_error_t assh_kex_new_keys(struct assh_session_s *s,
                               const struct assh_hash_s *hash_algo,
                               const uint8_t *ex_hash, struct assh_bignum_s *k)
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
    ASSH_ERR_GTO(assh_kex_new_key(s, hash_ctx, hash_algo, ex_hash, k, *c,
                   kin->iv, kin->cipher->block_size)
		 | ASSH_ERRSV_DISCONNECT, err_scratch);
#ifdef CONFIG_ASSH_DEBUG_KEX
  assh_hexdump("in iv", kin->iv, kin->cipher->block_size);
#endif
  c++;

  /* get output IV */
  if (!kout->cipher->is_stream)
    ASSH_ERR_GTO(assh_kex_new_key(s, hash_ctx, hash_algo, ex_hash, k, *c,
                   kout->iv, kout->cipher->block_size)
		 | ASSH_ERRSV_DISCONNECT, err_scratch);
#ifdef CONFIG_ASSH_DEBUG_KEX
  assh_hexdump("out iv", kout->iv, kout->cipher->block_size);
#endif
  c++;

  /* get input cipher key and init cipher */
  ASSH_ERR_GTO(assh_kex_new_key(s, hash_ctx, hash_algo, ex_hash, k, *c++,
                 key, kin->cipher->key_size)
	       | ASSH_ERRSV_DISCONNECT, err_scratch);
  kin->cipher_ctx = (void*)(kin + 1);
  ASSH_ERR_GTO(kin->cipher->f_init(s->ctx, kin->cipher_ctx, key, kin->iv, 0)
	       | ASSH_ERRSV_DISCONNECT, err_cipher_in);
#ifdef CONFIG_ASSH_DEBUG_KEX
  assh_hexdump("in ekey", key, kin->cipher->key_size);
#endif

  /* get output cipher key and init cipher */
  ASSH_ERR_GTO(assh_kex_new_key(s, hash_ctx, hash_algo, ex_hash, k, *c++,
                 key, kout->cipher->key_size)
	       | ASSH_ERRSV_DISCONNECT, err_cipher_out);
  kout->cipher_ctx = (void*)(kout + 1);
  ASSH_ERR_GTO(kout->cipher->f_init(s->ctx, kout->cipher_ctx, key, kout->iv, 1)
	       | ASSH_ERRSV_DISCONNECT, err_cipher_out);
#ifdef CONFIG_ASSH_DEBUG_KEX
  assh_hexdump("out ekey", key, kout->cipher->key_size);
#endif

  /* get input integrity key and init mac */
  ASSH_ERR_GTO(assh_kex_new_key(s, hash_ctx, hash_algo, ex_hash, k, *c++,
                 key, kin->mac->key_size)
	       | ASSH_ERRSV_DISCONNECT, err_mac_in);
  kin->mac_ctx = (void*)((uint8_t*)(kin->cipher_ctx) + kin->cipher->ctx_size);
  ASSH_ERR_GTO(kin->mac->f_init(s->ctx, kin->mac_ctx, key)
	       | ASSH_ERRSV_DISCONNECT, err_mac_in);
#ifdef CONFIG_ASSH_DEBUG_KEX
  assh_hexdump("in ikey", key, kin->mac->key_size);
#endif

  /* get output integrity key and init cipher */
  ASSH_ERR_GTO(assh_kex_new_key(s, hash_ctx, hash_algo, ex_hash, k, *c++,
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

