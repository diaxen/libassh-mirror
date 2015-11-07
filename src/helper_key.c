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
#include <assh/assh_context.h>
#include <assh/assh_packet.h>
#include <assh/assh_alloc.h>

#include <string.h>
#include <stdio.h>
#include <ctype.h>


static assh_error_t assh_load_rfc4716(FILE *file, uint8_t *kdata, size_t *klen)
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

static assh_error_t assh_load_pub_openssh(FILE *file, uint8_t *kdata, size_t *klen)
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

assh_error_t assh_load_key_file(struct assh_context_s *c,
				const struct assh_key_s **head,
				const struct assh_key_ops_s *algo,
				enum assh_algo_class_e role,
				FILE *file, enum assh_key_format_e format)
{
  assh_error_t err;
  size_t blob_len = 4096;

  ASSH_SCRATCH_ALLOC(c, uint8_t, blob, blob_len,
                     ASSH_ERRSV_CONTINUE, err_);

  switch (format)
    {
    case ASSH_KEY_FMT_PUB_RFC4716:
      assh_load_rfc4716(file, blob, &blob_len);
      format = ASSH_KEY_FMT_PUB_RFC4253;
      break;

    case ASSH_KEY_FMT_PUB_OPENSSH:
      assh_load_pub_openssh(file, blob, &blob_len);
      format = ASSH_KEY_FMT_PUB_RFC4253;
      break;

    case ASSH_KEY_FMT_PV_PEM:
      assh_load_rfc4716(file, blob, &blob_len);
      format = ASSH_KEY_FMT_PV_PEM_ASN1;
      break;

    case ASSH_KEY_FMT_PUB_PEM:
      assh_load_rfc4716(file, blob, &blob_len);
      format = ASSH_KEY_FMT_PUB_PEM_ASN1;
      break;

    case ASSH_KEY_FMT_PV_OPENSSH_V1:
      assh_load_rfc4716(file, blob, &blob_len);
      format = ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB;
      break;

    default:
      blob_len = fread(blob, 1, blob_len, file);
      break;
    }

  ASSH_ERR_GTO(assh_key_load(c, head, algo, role, format, blob, blob_len), err_sc);

  err = ASSH_OK;

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
				    enum assh_key_format_e format)
{
  assh_error_t err;

  FILE *file = fopen(filename, "r");
  ASSH_CHK_RET(file == NULL, ASSH_ERR_IO);

  ASSH_ERR_GTO(assh_load_key_file(c, head, algo, role, file, format), err_);

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
    return assh_load_key_file(c, &c->keys, algo, role, file, format);
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
    return assh_load_key_filename(c, &c->keys, algo, role, filename, format);
#endif
  return ASSH_ERR_NOTSUP;
}

