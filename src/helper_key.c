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

#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define OPENSSH_V1_AUTH_MAGIC "openssh-key-v1"

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_load_rfc4716(FILE *file, uint8_t *kdata, size_t *klen)
{
  struct assh_base64_ctx_s ctx;
  assh_error_t err;
  char in[80], *l;
  int state = 0;
  assh_base64_init(&ctx, kdata, *klen);

  while ((l = fgets(in, sizeof(in), file)))
    {
      size_t len = strlen(l);

      while (len && l[len - 1] <= ' ')
	l[--len] = '\0';
      if (!len)
	continue;

      switch (state)
	{
	case 0:
	  if (l[0] != '-' || !strstr(l, "BEGIN "))
	    continue;
	  state = 1;
	  continue;
	case 1:
	  state = 3;
	  if (!strchr(l, ':'))
	    break;
	case 2:
	  state = 1;
	  if (l[len - 1] == '\\')
	    state = 2;
	  continue;
	case 3:
	  if (l[0] != '-')
	    break;
	  ASSH_CHK_RET(!strstr(l, "END "), ASSH_ERR_BAD_DATA);
	  state = 0;
	  ASSH_ERR_RET(assh_base64_decode_final(&ctx));
	  *klen = assh_base64_outsize(&ctx);
	  return ASSH_OK;
	}
      ASSH_ERR_RET(assh_base64_decode_update(&ctx, (const uint8_t*)l, len));
    }

  ASSH_ERR_RET(ASSH_ERR_BAD_DATA);
}

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_load_pub_openssh(FILE *file, uint8_t *kdata, size_t *klen)
{
  struct assh_base64_ctx_s ctx;
  assh_error_t err;
  int in;
  int state = 0;
  assh_base64_init(&ctx, kdata, *klen);

  while (in = fgetc(file))
    {
      if (in == EOF || in == '\n' || in == '\r')
	break;
      switch (state)
	{
	case 0:
	  if (!isspace(in))
	    break;
	  state = 1;
	  break;
	case 1:
	  if (isspace(in))
	    break;
	  state = 2;
	case 2:
	  if (isspace(in))
	    {
	      ASSH_ERR_RET(assh_base64_decode_final(&ctx));
	      *klen = assh_base64_outsize(&ctx);
	      return ASSH_OK;
	    }
	  uint8_t in8 = in;
	  ASSH_ERR_RET(assh_base64_decode_update(&ctx, &in8, 1));
	  break;
	}
    }

  ASSH_ERR_RET(ASSH_ERR_BAD_DATA);
}

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_load_openssh_v1_blob(struct assh_context_s *c,
			  const struct assh_key_s **head,
			  const struct assh_key_ops_s *algo,
			  enum assh_algo_class_e role,
			  const uint8_t *blob, size_t blob_len,
			  const char *passphrase)
{
  assh_error_t err = ASSH_OK;

  ASSH_CHK_RET(blob_len < sizeof(OPENSSH_V1_AUTH_MAGIC), ASSH_ERR_INPUT_OVERFLOW);
  ASSH_CHK_RET(memcmp(blob, OPENSSH_V1_AUTH_MAGIC, sizeof(OPENSSH_V1_AUTH_MAGIC)),
	       ASSH_ERR_BAD_DATA);

  uint8_t *cipher_name = blob + sizeof(OPENSSH_V1_AUTH_MAGIC);
  uint8_t *kdf_name, *kdf_opts, *k_nums, *pub_str, *enc_str;

  ASSH_ERR_RET(assh_check_string(blob, blob_len, cipher_name, &kdf_name));
  ASSH_ERR_RET(assh_check_string(blob, blob_len, kdf_name, &kdf_opts));
  ASSH_ERR_RET(assh_check_string(blob, blob_len, kdf_opts, &k_nums));
  ASSH_ERR_RET(assh_check_array(blob, blob_len, k_nums, 4, &pub_str));
  ASSH_ERR_RET(assh_check_string(blob, blob_len, pub_str, &enc_str));
  ASSH_ERR_RET(assh_check_string(blob, blob_len, enc_str, NULL));

  size_t nums = assh_load_u32(k_nums);
  ASSH_CHK_RET(nums != 1, ASSH_ERR_NOTSUP);

  size_t pv_len, enc_len = assh_load_u32(enc_str);
  uint8_t *enc = enc_str + 4;
  uint8_t *pv_str, *cmt_str;

  if (assh_ssh_string_compare(cipher_name, "none"))
    {
      ASSH_CHK_RET(assh_ssh_string_compare(kdf_name, "bcrypt"), ASSH_ERR_NOTSUP);

      const struct assh_algo_cipher_s *cipher;
      ASSH_ERR_RET(assh_algo_by_name(c, ASSH_ALGO_CIPHER,
		     (const char*)cipher_name + 4, assh_load_u32(cipher_name),
		     (const struct assh_algo_s **)&cipher));

      ASSH_CHK_RET(enc_len % cipher->block_size, ASSH_ERR_BAD_DATA);

      ASSH_CHK_RET(passphrase == NULL, ASSH_ERR_MISSING_KEY);

      size_t kdf_opts_len = assh_load_u32(kdf_opts);
      uint8_t *salt_str = kdf_opts + 4;
      uint8_t *rounds_u32;

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

      assh_hexdump("bcrypt out", key, cipher->key_size + cipher->iv_size);
      assh_hexdump("cipher in", enc, enc_len);
      ASSH_ERR_GTO(cipher->f_init(c, cipher_ctx, key, iv, 0), err_sc);
      ASSH_ERR_GTO(cipher->f_process(cipher_ctx, enc, enc_len, ASSH_CIPHER_PCK_TAIL), err_sc);
      cipher->f_cleanup(c, cipher_ctx);
      assh_hexdump("cipher out", enc, enc_len);

      goto ok;
    err_sc:
      ASSH_SCRATCH_FREE(c, sc);
      return err;
    }
 ok:

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
  ASSH_DEBUG("blob %p\n", key_blob);
  ASSH_ERR_RET(assh_key_load(c, head, algo, role, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY,
			     &key_blob, pv_len));
  ASSH_DEBUG("blob %p\n", key_blob);

  cmt_str = key_blob;
  assh_hexdump("end", cmt_str, 8);
#endif

  ASSH_ERR_RET(assh_check_string(enc, enc_len, cmt_str, NULL));

 err_:
  return ASSH_OK;
}

assh_error_t assh_load_key_file(struct assh_context_s *c,
				const struct assh_key_s **head,
				const struct assh_key_ops_s *algo,
				enum assh_algo_class_e role,
				FILE *file, enum assh_key_format_e format,
				const char *passphrase)
{
  assh_error_t err = ASSH_OK;

  ASSH_CHK_RET(fseek(file, 0, SEEK_END), ASSH_ERR_IO);
  size_t blob_len = ftell(file);

  ASSH_CHK_RET(blob_len > 4096, ASSH_ERR_INPUT_OVERFLOW);
  fseek(file, 0, SEEK_SET);

  ASSH_SCRATCH_ALLOC(c, uint8_t, blob, blob_len,
                     ASSH_ERRSV_CONTINUE, err_);

  switch (format)
    {
    case ASSH_KEY_FMT_PUB_RFC4716:
      ASSH_ERR_GTO(assh_load_rfc4716(file, blob, &blob_len), err_sc);
      format = ASSH_KEY_FMT_PUB_RFC4253;
      break;

    case ASSH_KEY_FMT_PUB_OPENSSH:
      ASSH_ERR_GTO(assh_load_pub_openssh(file, blob, &blob_len), err_sc);
      format = ASSH_KEY_FMT_PUB_RFC4253;
      break;

    case ASSH_KEY_FMT_PV_PEM:
      ASSH_ERR_GTO(assh_load_rfc4716(file, blob, &blob_len), err_sc);
      format = ASSH_KEY_FMT_PV_PEM_ASN1;
      break;

    case ASSH_KEY_FMT_PUB_PEM:
      ASSH_ERR_GTO(assh_load_rfc4716(file, blob, &blob_len), err_sc);
      format = ASSH_KEY_FMT_PUB_PEM_ASN1;
      break;

    case ASSH_KEY_FMT_PV_OPENSSH_V1:
      ASSH_ERR_GTO(assh_load_rfc4716(file, blob, &blob_len), err_sc);
      ASSH_ERR_GTO(assh_load_openssh_v1_blob(c, head, algo, role,
					     blob, blob_len, passphrase), err_sc);
      goto err_sc;

    default:
      blob_len = fread(blob, 1, blob_len, file);
      break;
    }

  const uint8_t *key_blob = blob;
  ASSH_ERR_GTO(assh_key_load(c, head, algo, role, format, &key_blob, blob_len), err_sc);

 err_sc:
  ASSH_SCRATCH_FREE(c, blob);
 err_:
  return err;
}

assh_error_t assh_load_key_filename(struct assh_context_s *c,
				    const struct assh_key_s **head,
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
		     const char *comment,
		     uint8_t *blob, size_t *blob_len)
{
  assh_error_t err;
  const char *kdfname = "none";
  const char *ciphername = "none";
  size_t pad_len = 16;
  size_t len, pub_len, pv_len;

  if (blob == NULL)
    {
      ASSH_ERR_RET(assh_key_output(c, head, NULL, &pub_len, ASSH_KEY_FMT_PUB_RFC4253));
      ASSH_ERR_RET(assh_key_output(c, head, NULL, &pv_len, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY));

      size_t enc_len =
	8 +			/* check ints */
	pv_len +
	4 + strlen(comment);
      enc_len += pad_len - enc_len % pad_len;

      size_t len = sizeof(OPENSSH_V1_AUTH_MAGIC) +
	4 + strlen(ciphername) +
	4 + strlen(kdfname) +
	4 + 0 +			/* kdf options */
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

      assh_store_u32(b, 0);	/* kdf options */
      b += 4;

      assh_store_u32(b, 1);	/* number of keys */
      b += 4;

      ASSH_ERR_RET(assh_key_output(c, head, b + 4, &pub_len, ASSH_KEY_FMT_PUB_RFC4253));
      assh_store_u32(b, pub_len);
      b += 4 + pub_len;

      uint8_t *enc = b;

      ASSH_ERR_RET(assh_prng_get(c, b + 4, 4, ASSH_PRNG_QUALITY_NONCE));
      memcpy(b + 8, b + 4, 4);
      b += 12;

      /* Each private key should be nested in a string according to the
	 openssh PROTOCOL.key spec. This is not the case in the implementation. */
      ASSH_ERR_RET(assh_key_output(c, head, b, &pv_len, ASSH_KEY_FMT_PV_OPENSSH_V1_KEY));
      b += pv_len;

      l = strlen(comment);
      assh_store_u32(b, l);
      memcpy(b + 4, comment, l);
      b += 4 + l;

      l = 1;
      while ((b - enc - 4) & (pad_len - 1))
	*b++ = l++;
      assh_store_u32(enc, b - enc - 4);

      *blob_len = b - blob;
    }

  return ASSH_OK;
}

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_save_pub_openssh(struct assh_context_s *c,
		      const struct assh_key_s *head, FILE *file,
		      const uint8_t *blob, size_t blob_len, const char *comment)
{
  struct assh_base64_ctx_s b64;
  size_t maxlen = assh_base64_encoded_size(blob_len);
  char tmp[maxlen];

  assh_base64_init(&b64, tmp, maxlen);
  assh_base64_encode_update(&b64, blob, blob_len);
  assh_base64_encode_final(&b64);

  fputs(head->type, file);
  fputc(' ', file);
  fwrite(tmp, assh_base64_outsize(&b64), 1, file);
  fputc(' ', file);
  fputs(comment, file);
  fputc('\n', file);
  return ASSH_OK;
}

static ASSH_WARN_UNUSED_RESULT assh_error_t
assh_save_rfc4716(struct assh_context_s *c,
		  const struct assh_key_s *head, FILE *file,
		  const char *type, const uint8_t *blob,
		  size_t blob_len, const char *comment)
{
  struct assh_base64_ctx_s b64;
  size_t maxlen = assh_base64_encoded_size(blob_len);
  char tmp[maxlen];

  assh_base64_init(&b64, tmp, maxlen);
  assh_base64_encode_update(&b64, blob, blob_len);
  assh_base64_encode_final(&b64);

  size_t l = assh_base64_outsize(&b64);
  char *s = tmp;

  fprintf(file, "-----BEGIN %s KEY-----\n", type);
  if (comment)
    fprintf(file, "Comment: %s\n", comment);

  while (l)
    {
      size_t r = l > 70 ? 70 : l;
      fwrite(s, r, 1, file);
      fputc('\n', file);
      l -= r;
      s += r;
    }

  fprintf(file, "-----END %s KEY-----\n", type);

  return ASSH_OK;
}

assh_error_t assh_save_key_file(struct assh_context_s *c,
				const struct assh_key_s *head,
				FILE *file, enum assh_key_format_e format,
				const char *comment)
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
      ASSH_ERR_RET(assh_save_openssh_v1_blob(c, head, comment, NULL, &blob_len));
      break;

    default:
      subfmt = format;
      ASSH_ERR_RET(assh_key_output(c, head, NULL, &blob_len, subfmt));
    }

  ASSH_SCRATCH_ALLOC(c, uint8_t, blob, blob_len, ASSH_ERRSV_CONTINUE, err_);

  switch (format)
    {
    default:
      ASSH_ERR_GTO(assh_key_output(c, head, blob, &blob_len, subfmt), err_sc);
      break;

    case ASSH_KEY_FMT_PV_OPENSSH_V1:
    case ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB:
      ASSH_ERR_GTO(assh_save_openssh_v1_blob(c, head, comment, blob, &blob_len), err_sc);
      break;
    }

  switch (format)
    {
    case ASSH_KEY_FMT_PUB_RFC4716:
      ASSH_ERR_GTO(assh_save_rfc4716(c, head, file, "SSH2 PUBLIC", blob, blob_len, comment), err_sc);
      break;

    case ASSH_KEY_FMT_PUB_OPENSSH:
      ASSH_ERR_GTO(assh_save_pub_openssh(c, head, file, blob, blob_len, comment), err_sc);
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
      ASSH_ERR_GTO(assh_save_rfc4716(c, head, file, type, blob, blob_len, comment), err_sc);
      break;
    }

    case ASSH_KEY_FMT_PV_OPENSSH_V1:
      ASSH_ERR_GTO(assh_save_rfc4716(c, head, file, "OPENSSH PRIVATE", blob, blob_len, NULL), err_sc);
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
				    const char *comment)
{
  assh_error_t err;

  FILE *file = fopen(filename, "wb");
  ASSH_CHK_RET(file == NULL, ASSH_ERR_IO);

  ASSH_ERR_GTO(assh_save_key_file(c, head, file, format, comment), err_);

 err_:
  fclose(file);
  return err;
}

