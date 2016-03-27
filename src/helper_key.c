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

#include <assh/helper_key.h>
#include <assh/helper_base64.h>
#include <assh/helper_bcrypt.h>
#include <assh/assh_context.h>
#include <assh/assh_packet.h>
#include <assh/assh_alloc.h>
#include <assh/assh_prng.h>
#include <assh/assh_cipher.h>
#include <assh/assh_hash.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#define OPENSSH_V1_AUTH_MAGIC "openssh-key-v1"

struct assh_rfc1421_cipher_s
{
  const char *name;
  const struct assh_algo_cipher_s *cipher;
};

static const struct assh_rfc1421_cipher_s
assh_rfc1421_ciphers[] = {
#ifdef CONFIG_ASSH_CIPHER_AES
  { "AES-128-CBC", &assh_cipher_aes128_cbc },
  { "AES-256-CBC", &assh_cipher_aes256_cbc },
#endif
#ifdef CONFIG_ASSH_CIPHER_TDES
  { "DES-EDE3-CBC", &assh_cipher_tdes_cbc },
#endif
  { NULL }
};

/* derive cipher key from passphrase, used for pem enciphered keys */
static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_evp_bytes_to_key(struct assh_context_s *c,
                      const struct assh_hash_algo_s *hash,
                      const char *pass, size_t pass_len,
                      const uint8_t *salt, size_t salt_len,
                      uint8_t *key, size_t key_len, size_t rounds)
{
  assh_error_t err;
  size_t i, j;

  ASSH_SCRATCH_ALLOC(c, uint8_t, sc,
		     hash->ctx_size + hash->hash_size,
		     ASSH_ERRSV_CONTINUE, err_);

  struct assh_hash_ctx_s *hash_ctx = (void*)sc;
  uint8_t *tmp = sc + hash->ctx_size;
  size_t hsize = hash->hash_size;

  for (i = 0; key_len > 0; i++)
    {
      ASSH_ERR_GTO(assh_hash_init(c, hash_ctx, hash), err_sc);
      if (i)
        assh_hash_update(hash_ctx, tmp, hsize);
      assh_hash_update(hash_ctx, pass, pass_len);
      assh_hash_update(hash_ctx, salt, salt_len);
      assh_hash_final(hash_ctx, tmp, hsize);
      assh_hash_cleanup(hash_ctx);

      for (j = 1; j < rounds; j++)
        {
          ASSH_ERR_GTO(assh_hash_init(c, hash_ctx, hash), err_sc);
          assh_hash_update(hash_ctx, tmp, hsize);
          assh_hash_final(hash_ctx, tmp, hsize);
          assh_hash_cleanup(hash_ctx);
        }

      size_t l = ASSH_MIN(hsize, key_len);
      memcpy(key, tmp, l);
      key_len -= l;
      key += l;
    }

  err = ASSH_OK;
 err_sc:
  ASSH_SCRATCH_FREE(c, sc);
 err_:
  return err;
}

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_load_rfc4716_rfc1421(struct assh_context_s *c, FILE *file,
                          uint8_t *kdata, size_t *klen, assh_bool_t enc,
                          const char *passphrase, char **comment)
{
  struct assh_base64_ctx_s ctx;
  assh_error_t err = ASSH_OK;
  char in[80], *l;
  int state = 0;
  const struct assh_algo_cipher_s *cipher = NULL;
  uint8_t iv[16];

  assh_base64_init(&ctx, kdata, *klen);

  while ((l = fgets(in, sizeof(in), file)))
    {
      size_t len = strlen(l);

      /* trim trailing white spaces and skip empty lines */
      while (len && l[len - 1] <= ' ')
	l[--len] = '\0';
      if (!len)
	continue;

      switch (state)
	{
	case 0:                 /* before BEGIN */
	  if (l[0] != '-' || !strstr(l, "BEGIN "))
	    continue;
	  state = 1;
	  continue;

	case 1:                 /* Header line */
	  state = 3;
	  if (!strchr(l, ':'))
            break;

          /* get enciphered keys algorithm and iv */
          if (enc && !strncmp(l, "DEK-Info: ", 10))
            {
              uint_fast8_t i, j;
              char *dek = l + 10;
              ASSH_CHK_GTO(passphrase == NULL, ASSH_ERR_MISSING_KEY, err_);
              /* lookup cipher */
              for (i = 0; ; i++)
                {
                  const char *name = assh_rfc1421_ciphers[i].name;
                  ASSH_CHK_GTO(name == NULL, ASSH_ERR_MISSING_ALGO, err_);
                  j = strlen(name);
                  if (!strncmp(name, dek, j) && dek[j] == ',')
                    break;
                }
              dek += j + 1;
              cipher = assh_rfc1421_ciphers[i].cipher;

              /* get iv */
              assert(cipher->iv_size <= sizeof(iv) * 8);
              for (i = 0; i < cipher->iv_size; i++)
                {
                  char z = dek[2];
                  dek[2] = 0;
                  iv[i] = strtoul(dek, NULL, 16);
                  dek[2] = z;
                  dek += 2;
                }
            }

          /* handle comments */
          else if (!strncmp(l, "Comment: ", 9) && comment != NULL && *comment == NULL)
            {
              /* FIXME comments on multiple lines are not handled */
              ASSH_ERR_RET(assh_strdup(c, comment, l + 9, ASSH_ALLOC_INTERNAL));
            }

	case 2:                 /* Header line continuation */
	  state = 1;
	  if (l[len - 1] == '\\')
	    state = 2;
	  continue;

	case 3:                 /* Base64 content */
	  if (l[0] != '-')
	    break;
	  ASSH_CHK_GTO(!strstr(l, "END "), ASSH_ERR_BAD_DATA, err_);
          goto done;
	}

      ASSH_ERR_GTO(assh_base64_decode_update(&ctx, (const uint8_t*)l, len), err_);
    }

  ASSH_ERR_GTO(ASSH_ERR_BAD_DATA, err_);

 done:
  ASSH_ERR_RET(assh_base64_decode_final(&ctx));
  *klen = assh_base64_outsize(&ctx);

  /* decipher key blob */
  if (cipher != NULL)
    {
      size_t i, len = *klen;

      /* check padding length */
      ASSH_CHK_GTO(len % cipher->block_size || len == 0, ASSH_ERR_BAD_DATA, err_);

      /* compute cipher key from passphrase */
      ASSH_SCRATCH_ALLOC(c, uint8_t, sc, cipher->ctx_size +
                         cipher->key_size,
                         ASSH_ERRSV_CONTINUE, err_);

      uint8_t *cipher_ctx = sc;
      uint8_t *key = sc + cipher->ctx_size;

      ASSH_ERR_GTO(assh_evp_bytes_to_key(c, &assh_hash_md5,
                                         passphrase, strlen(passphrase), iv, 8,
                                         key, cipher->key_size, 1), err_sc);

      /* decipher */
      ASSH_ERR_GTO(cipher->f_init(c, cipher_ctx, key, iv, 0), err_sc);
      ASSH_ERR_GTO(cipher->f_process(cipher_ctx, kdata, len, ASSH_CIPHER_KEY, 0), err_cipher);

      /* check padding content */
      uint8_t j = kdata[len - 1];
      ASSH_CHK_GTO(j < 1 || j > cipher->block_size, ASSH_ERR_BAD_DATA, err_cipher);
      for (i = len - j; i < len; i++)
        ASSH_CHK_GTO(kdata[i] != j, ASSH_ERR_BAD_DATA, err_cipher);

    err_cipher:
      cipher->f_cleanup(c, cipher_ctx);
    err_sc:
      ASSH_SCRATCH_FREE(c, sc);
    }

 err_:
  if (err != ASSH_OK && comment != NULL && *comment != NULL)
    assh_free(c, (void*)*comment);

  return err;
}

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_load_pub_openssh(struct assh_context_s *c, FILE *file,
                      uint8_t *kdata, size_t *klen,
                      char **comment)
{
  struct assh_base64_ctx_s ctx;
  assh_error_t err;
  int_fast16_t in;
  uint_fast8_t clen = 0, state = 0;
  char cmt[80];

  assh_base64_init(&ctx, kdata, *klen);

  while ((in = fgetc(file)))
    {
      if (in == EOF || in == '\n' || in == '\r')
	break;
      switch (state)
	{
	case 0:                 /* skip algorithm */
	  if (!isspace(in))
	    break;
	  state = 1;
	  break;
	case 1:                 /* skip white space */
	  if (isspace(in))
	    break;
	  state = 2;
	case 2:
	  if (isspace(in))      /* read and decode key */
	    {
	      ASSH_ERR_RET(assh_base64_decode_final(&ctx));
	      *klen = assh_base64_outsize(&ctx);
              state = 3;
              break;
	    }
	  uint8_t in8 = in;
	  ASSH_ERR_RET(assh_base64_decode_update(&ctx, &in8, 1));
	  break;
	case 3:                 /* skip white space */
	  if (isspace(in))
	    break;
	  state = 4;
        case 4:                 /* read comment */
          if (clen + 1 >= sizeof(cmt))
            goto done;
          cmt[clen++] = in;
	}
    }

 done:
  ASSH_CHK_RET(state < 3, ASSH_ERR_BAD_DATA);

  if (comment != NULL && clen)
    {
      cmt[clen] = 0;
      ASSH_ERR_RET(assh_strdup(c, comment, cmt, ASSH_ALLOC_INTERNAL));
    }

  return ASSH_OK;
}

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_load_openssh_v1_blob(struct assh_context_s *c,
			  struct assh_key_s **head,
			  const struct assh_key_ops_s *algo,
			  enum assh_algo_class_e role,
                          uint8_t *blob, size_t blob_len,
			  const char *passphrase)
{
  assh_error_t err = ASSH_OK;

  ASSH_CHK_RET(blob_len < sizeof(OPENSSH_V1_AUTH_MAGIC), ASSH_ERR_INPUT_OVERFLOW);
  ASSH_CHK_RET(memcmp(blob, OPENSSH_V1_AUTH_MAGIC, sizeof(OPENSSH_V1_AUTH_MAGIC)),
	       ASSH_ERR_BAD_DATA);

  const uint8_t *cipher_name = blob + sizeof(OPENSSH_V1_AUTH_MAGIC);
  const uint8_t *kdf_name, *kdf_opts, *k_nums, *pub_str, *enc_str;

  ASSH_ERR_RET(assh_check_string(blob, blob_len, cipher_name, &kdf_name));
  ASSH_ERR_RET(assh_check_string(blob, blob_len, kdf_name, &kdf_opts));
  ASSH_ERR_RET(assh_check_string(blob, blob_len, kdf_opts, &k_nums));
  ASSH_ERR_RET(assh_check_array(blob, blob_len, k_nums, 4, &pub_str));
  ASSH_ERR_RET(assh_check_string(blob, blob_len, pub_str, &enc_str));
  ASSH_ERR_RET(assh_check_string(blob, blob_len, enc_str, NULL));

  size_t nums = assh_load_u32(k_nums);
  ASSH_CHK_RET(nums != 1, ASSH_ERR_NOTSUP);

  size_t pv_len, enc_len = assh_load_u32(enc_str);
  uint8_t *enc = (uint8_t*)enc_str + 4;
  const uint8_t *pv_str, *cmt_str;

  if (assh_ssh_string_compare(cipher_name, "none"))
    {
      ASSH_CHK_RET(assh_ssh_string_compare(kdf_name, "bcrypt"), ASSH_ERR_NOTSUP);

      /* lookup cipher */
      const struct assh_algo_cipher_s *cipher;
      ASSH_CHK_RET(assh_algo_by_name(c, ASSH_ALGO_CIPHER,
                     (const char*)cipher_name + 4, assh_load_u32(cipher_name),
                     (const struct assh_algo_s **)&cipher) != ASSH_OK,
                   ASSH_ERR_MISSING_ALGO);

      /* check padding length */
      ASSH_CHK_RET(enc_len % cipher->block_size, ASSH_ERR_BAD_DATA);

      /* derive key and iv from passphrase */
      ASSH_CHK_RET(passphrase == NULL, ASSH_ERR_MISSING_KEY);

      size_t kdf_opts_len = assh_load_u32(kdf_opts);
      const uint8_t *salt_str = kdf_opts + 4;
      const uint8_t *rounds_u32;

      ASSH_ERR_RET(assh_check_string(salt_str, kdf_opts_len, salt_str, &rounds_u32));
      ASSH_ERR_RET(assh_check_array(salt_str, kdf_opts_len, rounds_u32, 4, NULL));

      ASSH_SCRATCH_ALLOC(c, uint8_t, sc, cipher->ctx_size +
			 cipher->key_size + cipher->iv_size,
			 ASSH_ERRSV_CONTINUE, err_);

      uint8_t *cipher_ctx = sc;
      uint8_t *key = sc + cipher->ctx_size;
      uint8_t *iv = key + cipher->key_size;

      ASSH_ERR_GTO(assh_bcrypt_pbkdf(c, passphrase, strlen(passphrase),
                                     salt_str + 4, assh_load_u32(salt_str),
                                     key, cipher->key_size + cipher->iv_size,
                                     assh_load_u32(rounds_u32)), err_sc);

      /* decipher */
      ASSH_ERR_GTO(cipher->f_init(c, cipher_ctx, key, iv, 0), err_sc);
      ASSH_ERR_GTO(cipher->f_process(cipher_ctx, enc, enc_len, ASSH_CIPHER_KEY, 0), err_cipher);

    err_cipher:
      cipher->f_cleanup(c, cipher_ctx);
    err_sc:
      ASSH_SCRATCH_FREE(c, sc);
      if (err != ASSH_OK)
        return err;
    }

  ASSH_ERR_RET(assh_check_array(enc, enc_len, enc, 8, &pv_str));
  ASSH_CHK_RET(assh_load_u32(enc) != assh_load_u32(enc + 4), ASSH_ERR_BAD_DATA);

#if 0
  /* what is specified in openssh PROTOCOL.key */
  ASSH_ERR_RET(assh_check_string(enc, enc_len, pv_str, &cmt_str));
  pv_len = assh_load_u32(pv_str);
  pv_str += 4;

  const uint8_t *key_blob = pv_str;
  ASSH_ERR_RET(assh_key_load(c, head, algo, role, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY,
                             &key_blob, pv_len));
#else
  /* what is actually implemented in openssh */
  pv_len = blob + blob_len - pv_str;

  const uint8_t *key_blob = pv_str;
  ASSH_ERR_RET(assh_key_load(c, head, algo, role, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY,
                             &key_blob, pv_len));

  cmt_str = key_blob;
#endif

  const uint8_t *cmt_end;
  ASSH_ERR_GTO(assh_check_string(enc, enc_len, cmt_str, &cmt_end), err_key);
  size_t clen = cmt_end - cmt_str - 4;

  if (clen > 0)
    {
      struct assh_key_s *key = *head;
      ASSH_ERR_GTO(assh_alloc(c, clen + 1, ASSH_ALLOC_INTERNAL,
                              (void**)&key->comment), err_key);
      memcpy(key->comment, cmt_str + 4, clen);
      key->comment[clen] = 0;
    }

  err = ASSH_OK;
 err_:
  return err;
 err_key:
  assh_key_drop(c, head);
  return err;
}

assh_error_t assh_load_key_file(struct assh_context_s *c,
				struct assh_key_s **head,
				const struct assh_key_ops_s *algo,
				enum assh_algo_class_e role,
				FILE *file, enum assh_key_format_e format,
				const char *passphrase)
{
  assh_error_t err = ASSH_OK;
  char *comment = NULL;

  ASSH_CHK_RET(fseek(file, 0, SEEK_END), ASSH_ERR_IO);
  size_t blob_len = ftell(file);

  ASSH_CHK_RET(blob_len > 4096, ASSH_ERR_INPUT_OVERFLOW);
  fseek(file, 0, SEEK_SET);

  ASSH_SCRATCH_ALLOC(c, uint8_t, blob, blob_len,
                     ASSH_ERRSV_CONTINUE, err_);

  switch (format)
    {
    case ASSH_KEY_FMT_PUB_RFC4716:
      ASSH_ERR_GTO(assh_load_rfc4716_rfc1421(c, file, blob, &blob_len, 0, NULL, &comment), err_sc);
      format = ASSH_KEY_FMT_PUB_RFC4253;
      break;

    case ASSH_KEY_FMT_PUB_OPENSSH:
      ASSH_ERR_GTO(assh_load_pub_openssh(c, file, blob, &blob_len, &comment), err_sc);
      format = ASSH_KEY_FMT_PUB_RFC4253;
      break;

    case ASSH_KEY_FMT_PV_PEM:
      ASSH_ERR_GTO(assh_load_rfc4716_rfc1421(c, file, blob, &blob_len, 1, passphrase, NULL), err_sc);
      format = ASSH_KEY_FMT_PV_PEM_ASN1;
      break;

    case ASSH_KEY_FMT_PUB_PEM:
      ASSH_ERR_GTO(assh_load_rfc4716_rfc1421(c, file, blob, &blob_len, 0, NULL, NULL), err_sc);
      format = ASSH_KEY_FMT_PUB_PEM_ASN1;
      break;

    case ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB:
      blob_len = fread(blob, 1, blob_len, file);
      goto openssh_v1_blob;

    case ASSH_KEY_FMT_PV_OPENSSH_V1:
      ASSH_ERR_GTO(assh_load_rfc4716_rfc1421(c, file, blob, &blob_len, 0, NULL, NULL), err_sc);
    openssh_v1_blob:
      ASSH_ERR_GTO(assh_load_openssh_v1_blob(c, head, algo, role,
					     blob, blob_len, passphrase), err_sc);
      goto err_sc;

    default:
      blob_len = fread(blob, 1, blob_len, file);
      break;
    }

  const uint8_t *key_blob = blob;
  ASSH_ERR_GTO(assh_key_load(c, head, algo, role, format, &key_blob, blob_len), err_sc);

  if (comment)
    {
      (*head)->comment = comment;
      comment = NULL;
    }

 err_sc:
  ASSH_SCRATCH_FREE(c, blob);
 err_:

  if (comment)
    assh_free(c, comment);

  return err;
}

assh_error_t assh_load_key_filename(struct assh_context_s *c,
				    struct assh_key_s **head,
				    const struct assh_key_ops_s *algo,
				    enum assh_algo_class_e role,
				    const char *filename,
				    enum assh_key_format_e format,
				    const char *passphrase)
{
  assh_error_t err;

  FILE *file = fopen(filename, "rb");
  ASSH_CHK_RET(file == NULL, ASSH_ERR_IO);

  ASSH_ERR_GTO(assh_load_key_file(c, head, algo, role, file, format, passphrase), err_);

 err_:
  fclose(file);
  return err;
}

assh_error_t assh_load_hostkey_file(struct assh_context_s *c,
				    const struct assh_key_ops_s *algo,
				    enum assh_algo_class_e role,
				    FILE *file,
				    enum assh_key_format_e format)
{
#ifdef CONFIG_ASSH_SERVER
  if (c->type == ASSH_SERVER)
    return assh_load_key_file(c, &c->keys, algo, role, file, format, NULL);
#endif
  return ASSH_ERR_NOTSUP;
}

assh_error_t assh_load_hostkey_filename(struct assh_context_s *c,
					const struct assh_key_ops_s *algo,
					enum assh_algo_class_e role,
					const char *filename,
					enum assh_key_format_e format)
{
#ifdef CONFIG_ASSH_SERVER
  if (c->type == ASSH_SERVER)
    return assh_load_key_filename(c, &c->keys, algo, role, filename, format, NULL);
#endif
  return ASSH_ERR_NOTSUP;
}

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_save_openssh_v1_blob(struct assh_context_s *c,
                          const struct assh_key_s *head,
                          const char *passphrase,
                          const struct assh_algo_cipher_s *cipher,
                          uint8_t *blob, size_t *blob_len)
{
  assh_error_t err;
  const char *kdfname = "none";
  const char *ciphername = "none";
  const size_t salt_size = 16;
#ifdef CONFIG_ASSH_DEBUG
  /* speedup testsuite */
  const size_t rounds = 1;
#else
  const size_t rounds = 42;
#endif
  size_t pad_len = 16;
  size_t pub_len, pv_len;

  size_t kdf_opt_len = 0;
  if (passphrase != NULL)
    {
      kdfname = "bcrypt";
      kdf_opt_len = 4 + salt_size + 4;
      ciphername = cipher->algo.name;
    }

  if (blob == NULL)
    {
      ASSH_ERR_RET(assh_key_output(c, head, NULL, &pub_len, ASSH_KEY_FMT_PUB_RFC4253));
      ASSH_ERR_RET(assh_key_output(c, head, NULL, &pv_len, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY));

      size_t enc_len =
	8 +			/* check ints */
	pv_len +
	4 + (head->comment != NULL ? strlen(head->comment) : 0);
      enc_len += pad_len - enc_len % pad_len;

      size_t len = sizeof(OPENSSH_V1_AUTH_MAGIC) +
	4 + strlen(ciphername) +
	4 + strlen(kdfname) +
	4 + kdf_opt_len +
	4 +			/* number of keys */
	4 + pub_len +
	4 + enc_len;		/* pv keys list */

      *blob_len = len;
    }
  else
    {
      uint8_t *b = blob;
      memcpy(b, OPENSSH_V1_AUTH_MAGIC, sizeof(OPENSSH_V1_AUTH_MAGIC));
      b += sizeof(OPENSSH_V1_AUTH_MAGIC);

      size_t l = strlen(ciphername);
      assh_store_u32(b, l);
      memcpy(b + 4, ciphername, l);
      b += 4 + l;

      l = strlen(kdfname);
      assh_store_u32(b, l);
      memcpy(b + 4, kdfname, l);
      b += 4 + l;

      assh_store_u32(b, kdf_opt_len);	/* kdf options */
      b += 4;

      uint8_t *salt = NULL;
      if (passphrase != NULL)
        {
          assh_store_u32(b, salt_size);
          b += 4;

          salt = b;
          ASSH_ERR_RET(assh_prng_get(c, salt, salt_size, ASSH_PRNG_QUALITY_NONCE));
          b += salt_size;

          assh_store_u32(b, rounds);
          b += 4;
        }

      assh_store_u32(b, 1);	/* number of keys */
      b += 4;

      ASSH_ERR_RET(assh_key_output(c, head, b + 4, &pub_len, ASSH_KEY_FMT_PUB_RFC4253));
      assh_store_u32(b, pub_len);
      b += 4 + pub_len;

      uint8_t *enc = b;

      ASSH_ERR_RET(assh_prng_get(c, b + 4, 4, ASSH_PRNG_QUALITY_NONCE));
      memcpy(b + 8, b + 4, 4);
      b += 12;

      /* Each private key should be nested in a string according to
	 the openssh PROTOCOL.key spec. This is not the case in the
	 openssh implementation. */
      ASSH_ERR_RET(assh_key_output(c, head, b, &pv_len, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY));
      b += pv_len;

      if (head->comment != NULL)
        {
          l = strlen(head->comment);
          assh_store_u32(b, l);
          memcpy(b + 4, head->comment, l);
          b += 4 + l;
        }
      else
        {
          assh_store_u32(b, 0);
          b += 4;
        }

      l = 1;
      while ((b - enc - 4) & (pad_len - 1))
	*b++ = l++;
      size_t enc_len = b - enc - 4;
      assh_store_u32(enc, enc_len);

      if (passphrase != NULL)
        {
          ASSH_SCRATCH_ALLOC(c, uint8_t, sc, cipher->ctx_size +
                             cipher->key_size + cipher->iv_size,
                             ASSH_ERRSV_CONTINUE, err_);

          uint8_t *cipher_ctx = sc;
          uint8_t *key = sc + cipher->ctx_size;
          uint8_t *iv = key + cipher->key_size;

          ASSH_ERR_GTO(assh_bcrypt_pbkdf(c, passphrase, strlen(passphrase),
                                         salt, salt_size, key,
                                         cipher->key_size + cipher->iv_size,
                                         rounds), err_sc);

          ASSH_ERR_GTO(cipher->f_init(c, cipher_ctx, key, iv, 1), err_sc);
          ASSH_ERR_GTO(cipher->f_process(cipher_ctx, enc + 4, enc_len, ASSH_CIPHER_KEY, 0), err_cipher);

        err_cipher:
          cipher->f_cleanup(c, cipher_ctx);
        err_sc:
          ASSH_SCRATCH_FREE(c, sc);
          if (err != ASSH_OK)
            return err;
        }

      *blob_len = b - blob;
    }

  err = ASSH_OK;
 err_:
  return err;
}

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_save_pub_openssh(struct assh_context_s *c,
		      const struct assh_key_s *head, FILE *file,
		      const uint8_t *blob, size_t blob_len)
{
  assh_error_t err;
  struct assh_base64_ctx_s b64;
  size_t maxlen = assh_base64_encoded_size(blob_len);
  uint8_t tmp[maxlen];

  assh_base64_init(&b64, tmp, maxlen);
  ASSH_ERR_RET(assh_base64_encode_update(&b64, blob, blob_len));
  ASSH_ERR_RET(assh_base64_encode_final(&b64));

  fputs(head->type, file);
  fputc(' ', file);
  fwrite(tmp, assh_base64_outsize(&b64), 1, file);
  fputc(' ', file);
  if (head->comment != NULL)
    fputs(head->comment, file);
  fputc('\n', file);
  return ASSH_OK;
}


static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_save_rfc4716(struct assh_context_s *c,
		  const struct assh_key_s *head, FILE *file,
		  const uint8_t *blob,
		  size_t blob_len)
{
  assh_error_t err;
  struct assh_base64_ctx_s b64;
  size_t maxlen = assh_base64_encoded_size(blob_len);
  uint8_t tmp[maxlen];

  assh_base64_init(&b64, tmp, maxlen);
  ASSH_ERR_RET(assh_base64_encode_update(&b64, blob, blob_len));
  ASSH_ERR_RET(assh_base64_encode_final(&b64));

  size_t l = assh_base64_outsize(&b64);
  char *s = (char*)tmp;

  fprintf(file, "---- BEGIN SSH2 PUBLIC KEY ----\n");
  if (head->comment != NULL)
    fprintf(file, "Comment: %s\n\n", head->comment);

  while (l)
    {
      size_t r = l > 70 ? 70 : l;
      fwrite(s, r, 1, file);
      fputc('\n', file);
      l -= r;
      s += r;
    }

  fprintf(file, "---- END SSH2 PUBLIC KEY ----\n");

  return ASSH_OK;
}

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_save_rfc1421(struct assh_context_s *c,
		  const struct assh_key_s *head, FILE *file,
		  const char *type, uint8_t *blob,
		  size_t blob_len, const char *passphrase)
{
  assh_error_t err = ASSH_OK;

  fprintf(file, "-----%s %s KEY-----\n", "BEGIN", type);

  if (passphrase != NULL)
    {
      const struct assh_algo_cipher_s *cipher = &assh_cipher_aes128_cbc;
      uint8_t iv[16];
      uint_fast8_t i, j;

      fputs("Proc-Type: 4,ENCRYPTED\n"
            "DEK-Info: AES-128-CBC,", file);

      /* generate iv/salt */
      ASSH_ERR_RET(assh_prng_get(c, iv, cipher->iv_size, ASSH_PRNG_QUALITY_NONCE));

      for (i = 0; i < cipher->iv_size; i++)
        fprintf(file, "%02X", iv[i]);
      fputs("\n\n", file);

      /* append padding bytes */
      j = cipher->block_size - blob_len % cipher->block_size;
      for (i = 0; i < j; i++)
        blob[blob_len + i] = j;
      blob_len += i;

      /* compute cipher key from passphrase */
      ASSH_SCRATCH_ALLOC(c, uint8_t, sc, cipher->ctx_size +
                         cipher->key_size,
                         ASSH_ERRSV_CONTINUE, err_);

      uint8_t *cipher_ctx = sc;
      uint8_t *key = sc + cipher->ctx_size;

      ASSH_ERR_GTO(assh_evp_bytes_to_key(c, &assh_hash_md5,
                     passphrase, strlen(passphrase), iv, 8,
                     key, cipher->key_size, 1), err_sc);

      /* encipher */
      ASSH_ERR_GTO(cipher->f_init(c, cipher_ctx, key, iv, 1), err_sc);
      ASSH_ERR_GTO(cipher->f_process(cipher_ctx, blob, blob_len, ASSH_CIPHER_KEY, 0), err_cipher);
    err_cipher:
      cipher->f_cleanup(c, cipher_ctx);
    err_sc:
      ASSH_SCRATCH_FREE(c, sc);
      if (err != ASSH_OK)
        return err;
    }

  /* base64 encode */
  struct assh_base64_ctx_s b64;
  size_t maxlen = assh_base64_encoded_size(blob_len);
  uint8_t *tmp = alloca(maxlen);

  assh_base64_init(&b64, tmp, maxlen);
  ASSH_ERR_RET(assh_base64_encode_update(&b64, blob, blob_len));
  ASSH_ERR_RET(assh_base64_encode_final(&b64));

  size_t l = assh_base64_outsize(&b64);
  char *s = (char*)tmp;

  /* text output */
  while (l)
    {
      size_t r = l > 64 ? 64 : l;
      fwrite(s, r, 1, file);
      fputc('\n', file);
      l -= r;
      s += r;
    }

  fprintf(file, "-----%s %s KEY-----\n", "END", type);

 err_:
  return err;
}

assh_error_t assh_save_key_file(struct assh_context_s *c,
				const struct assh_key_s *head,
				FILE *file, enum assh_key_format_e format,
				const char *passphrase)
{
  assh_error_t err;
  enum assh_key_format_e subfmt;
  size_t blob_len;

  switch (format)
    {
    case ASSH_KEY_FMT_PUB_OPENSSH:
    case ASSH_KEY_FMT_PUB_RFC4716:
      subfmt = ASSH_KEY_FMT_PUB_RFC4253;
      ASSH_ERR_RET(assh_key_output(c, head, NULL, &blob_len, subfmt));
      break;

    case ASSH_KEY_FMT_PV_PEM:
      subfmt = ASSH_KEY_FMT_PV_PEM_ASN1;
      ASSH_ERR_RET(assh_key_output(c, head, NULL, &blob_len, subfmt));
      break;

    case ASSH_KEY_FMT_PUB_PEM:
      subfmt = ASSH_KEY_FMT_PUB_PEM_ASN1;
      ASSH_ERR_RET(assh_key_output(c, head, NULL, &blob_len, subfmt));
      break;

    case ASSH_KEY_FMT_PV_OPENSSH_V1:
    case ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB:
      subfmt = ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB;
      ASSH_ERR_RET(assh_save_openssh_v1_blob(c, head, passphrase,
                     &assh_cipher_aes256_cbc, NULL, &blob_len));
      break;

    default:
      subfmt = format;
      ASSH_ERR_RET(assh_key_output(c, head, NULL, &blob_len, subfmt));
    }

  ASSH_SCRATCH_ALLOC(c, uint8_t, blob, blob_len + /* cipher padding*/ 16,
                     ASSH_ERRSV_CONTINUE, err_);

  switch (format)
    {
    default:
      ASSH_ERR_GTO(assh_key_output(c, head, blob, &blob_len, subfmt), err_sc);
      break;

    case ASSH_KEY_FMT_PV_OPENSSH_V1:
    case ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB:
      ASSH_ERR_GTO(assh_save_openssh_v1_blob(c, head, passphrase,
                     &assh_cipher_aes256_cbc, blob, &blob_len), err_sc);
      break;
    }

  switch (format)
    {
    case ASSH_KEY_FMT_PUB_RFC4716:
      ASSH_ERR_GTO(assh_save_rfc4716(c, head, file, blob, blob_len), err_sc);
      break;

    case ASSH_KEY_FMT_PUB_OPENSSH:
      ASSH_ERR_GTO(assh_save_pub_openssh(c, head, file, blob, blob_len), err_sc);
      break;

    case ASSH_KEY_FMT_PV_PEM:
    case ASSH_KEY_FMT_PUB_PEM: {
      const char *type = head->algo->type;
      if (!strcmp(type, "ssh-rsa"))
	type = (format == ASSH_KEY_FMT_PV_PEM) ? "RSA PRIVATE" : "RSA PUBLIC";
      else if (!strcmp(type, "ecdsa-sha2-nist") && format == ASSH_KEY_FMT_PV_PEM)
	type = "EC PRIVATE";
      else if (!strcmp(type, "ssh-dss") && format == ASSH_KEY_FMT_PV_PEM)
	type = "DSA PRIVATE";
      else
	ASSH_ERR_GTO(ASSH_ERR_NOTSUP, err_sc);
      ASSH_ERR_GTO(assh_save_rfc1421(c, head, file, type, blob, blob_len, passphrase), err_sc);
      break;
    }

    case ASSH_KEY_FMT_PV_OPENSSH_V1:
      ASSH_ERR_GTO(assh_save_rfc1421(c, head, file, "OPENSSH PRIVATE", blob, blob_len, NULL), err_sc);
      break;

    default:
      ASSH_CHK_GTO(fwrite(blob, blob_len, 1, file) != 1, ASSH_ERR_IO, err_sc);
      break;
    }

 err_sc:
  ASSH_SCRATCH_FREE(c, blob);
 err_:
  return err;
}

assh_error_t assh_save_key_filename(struct assh_context_s *c,
				    const struct assh_key_s *head,
				    const char *filename,
				    enum assh_key_format_e format,
				    const char *passphrase)
{
  assh_error_t err;

  FILE *file = fopen(filename, "wb");
  ASSH_CHK_RET(file == NULL, ASSH_ERR_IO);

  ASSH_ERR_GTO(assh_save_key_file(c, head, file, format, passphrase), err_);

 err_:
  fclose(file);
  return err;
}

