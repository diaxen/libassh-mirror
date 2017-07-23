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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <assh/assh_context.h>
#include <assh/assh_cipher.h>
#include <assh/assh_alloc.h>

#include <assh/key_rsa.h>
#include <assh/key_dsa.h>
#include <assh/key_eddsa.h>
#include <assh/key_ecdsa.h>
#include <assh/helper_key.h>
#include <assh/helper_fd.h>

#ifdef CONFIG_ASSH_USE_GCRYPT
# include <gcrypt.h>
#endif

struct assh_keygen_format_s
{
  const char *name;
  const char *desc;
  enum assh_key_format_e format;
  assh_bool_t public, internal;
};

static const struct assh_keygen_format_s formats[] = {
  { "openssh_v1", "openssh v1 ASCII private keys",
    ASSH_KEY_FMT_PV_OPENSSH_V1, 0, 0 },
  { "openssh_v1_bin", "openssh_v1 underlying binary",
    ASSH_KEY_FMT_PV_OPENSSH_V1_BLOB, 0, 1 },
  { "openssh_v1_pv", "openssh_v1_bin underlying single private key",
    ASSH_KEY_FMT_PV_OPENSSH_V1_KEY, 0, 1 },
  { "pem_pv", "PEM ASCII private key",
    ASSH_KEY_FMT_PV_PEM, 0, 0 },
  { "pem_pv_bin", "PEM private key underlying binary",
    ASSH_KEY_FMT_PV_PEM_ASN1, 0, 1 },
  { "rfc4716", "ssh standard ASCII public key",
    ASSH_KEY_FMT_PUB_RFC4716, 1, 0 },
  { "rfc4253", "ssh standard binary public key",
    ASSH_KEY_FMT_PUB_RFC4253, 1, 1 },
  { "openssh_pub", "openssh legacy ASCII public key",
    ASSH_KEY_FMT_PUB_OPENSSH, 1, 0 },
  { "pem_pub", "PEM ASCII public key",
    ASSH_KEY_FMT_PUB_PEM, 0, 0 },
  { "pem_pub_bin", "PEM public key underlying binary",
    ASSH_KEY_FMT_PUB_PEM_ASN1, 0, 1 },
  { NULL }
};

struct assh_keygen_type_s
{
  const struct assh_key_ops_s *ops;
  enum assh_key_format_e format;
  size_t bits;
};

static const struct assh_keygen_type_s types[] = {
  { &assh_key_dsa, ASSH_KEY_FMT_PV_PEM, 1024 },
  { &assh_key_rsa, ASSH_KEY_FMT_PV_PEM, 2048 },
  { &assh_key_ed25519, ASSH_KEY_FMT_PV_OPENSSH_V1, 255 },
  { &assh_key_eddsa_e382, ASSH_KEY_FMT_PV_OPENSSH_V1, 382 },
  { &assh_key_eddsa_e521, ASSH_KEY_FMT_PV_OPENSSH_V1, 521 },
  { &assh_key_ecdsa_nistp, ASSH_KEY_FMT_PV_PEM, 256 },
  { NULL }
};

enum assh_keygen_action_e
{
  ASSH_KEYGEN_LOAD     = 1,
  ASSH_KEYGEN_CREATE   = 2,
  ASSH_KEYGEN_VALIDATE = 4,
  ASSH_KEYGEN_SAVE     = 8,
};

#define ERROR(...) do { fprintf(stderr, __VA_ARGS__); exit(1); } while (0)

static const struct assh_keygen_format_s * get_format(const char *fmt)
{
  unsigned i;
  if (fmt)
    for (i = 0; formats[i].name != NULL; i++)
      if (!strcmp(formats[i].name, fmt))
        return formats + i;
  fprintf(stderr, "Supported key formats:\n");
  for (i = 0; formats[i].name != NULL; i++)
#ifndef CONFIG_ASSH_DEBUG
    if (!formats[i].internal)
#endif
      fprintf(stderr, "  %-15s : %s\n", formats[i].name, formats[i].desc);
  if (fmt)
    exit(1);
  return NULL;
}

static const struct assh_keygen_format_s * lookup_format(enum assh_key_format_e e)
{
  unsigned i;
  for (i = 0; formats[i].name != NULL; i++)
    if (formats[i].format == e)
      return formats + i;
  return NULL;
}

static FILE * get_file(const char *file, const char *mode)
{
  FILE *r = fopen(file, mode);
  if (r != NULL)
    return r;
  fprintf(stderr, "Can not open `%s' key file.\n", file);
  exit(1);
}

static const struct assh_keygen_type_s * get_type(const char *type)
{
  unsigned i;
  if (type)
    for (i = 0; types[i].ops != NULL; i++)
      if (!strcmp(types[i].ops->type, type))
        return types + i;
  fprintf(stderr, "Supported key types:\n");
  for (i = 0; types[i].ops != NULL; i++)
    fprintf(stderr, "  %s\n", types[i].ops->type);
  if (type)
    exit(1);
  return NULL;
}

static const char *
get_passphrase(const char *prompt, struct assh_context_s *context)
{
  fprintf(stderr, prompt);

  const char *p;
  if (assh_fd_get_password(context, &p, 80, 0, 0))
    ERROR("Unable to read passphrase expected\n");

  putc('\n', stderr);

  return p;
}

static void usage(const char *program, assh_bool_t opts)
{
  fprintf(stderr, "usage: %s [-h | options] create|validate|convert|list\n", program);

  if (opts)
    fprintf(stderr, "List of available options:\n\n"
          "    -t algo    specify the type of the key\n"
          "    -b bits    specify the size of the key\n\n"
          "    -o file    specify the output file name\n"
          "    -i file    specify the input file name\n\n"
          "    -g format  specify the input key format\n"
          "    -f format  specify the output key format\n\n"
          "    -p pass    specify key encryption passphrase\n"
          "    -P         don't use passphrase for the output\n\n"
          "    -c comment specify key comment string\n"
          "    -h         show help\n");

  exit(1);
}

int main(int argc, char *argv[])
{
#ifdef CONFIG_ASSH_USE_GCRYPT
  if (!gcry_check_version(GCRYPT_VERSION))
    return -1;
  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
#endif

  int opt;
  size_t bits = 0;
  assh_bool_t no_outpass = 0;
  const struct assh_keygen_format_s *ifmt = NULL;
  const struct assh_keygen_format_s *ofmt = NULL;
  const struct assh_keygen_type_s *type = NULL;
  const char *passphrase = NULL;
  const char *comment = NULL;
  FILE *ifile = NULL;
  FILE *ofile = NULL;

  while ((opt = getopt(argc, argv, "hb:f:g:o:i:t:r:p:Pc:")) != -1)
    {
      switch (opt)
        {
        case 'b':
          bits = atoi(optarg);
          break;
        case 'f':
          ofmt = get_format(optarg);
          break;
        case 'g':
          ifmt = get_format(optarg);
          break;
        case 'o':
          ofile = get_file(optarg, "wb");
          break;
        case 'i':
          ifile = get_file(optarg, "rb");
          break;
        case 't':
          type = get_type(optarg);
          if (ofmt == NULL)
            ofmt = lookup_format(type->format);
          if (bits == 0)
            bits = type->bits;
          break;
        case 'p':
          passphrase = optarg;
          break;
        case 'P':
          no_outpass = 1;
          break;
        case 'c':
          comment = optarg;
          break;
        default:
          usage(argv[0], 0);
        case 'h':
          usage(argv[0], 1);
        }
    }

  if (optind + 1 != argc)
    usage(argv[0], 0);

  struct assh_context_s *context;

  if (assh_context_create(&context, ASSH_CLIENT_SERVER, CONFIG_ASSH_MAX_ALGORITHMS,
                          NULL, NULL, NULL, NULL))
    ERROR("Unable to create context.\n");

  if (assh_algo_register_default(context, 0, 0, 0))
    ERROR("Unable to register algorithms.\n");

  const char *action = argv[optind];
  unsigned action_mask = 0;

  if (!strcmp(action, "create"))
    action_mask = ASSH_KEYGEN_CREATE | ASSH_KEYGEN_SAVE;
  else if (!strcmp(action, "validate"))
    action_mask = ASSH_KEYGEN_LOAD | ASSH_KEYGEN_VALIDATE;
  else if (!strcmp(action, "convert"))
    action_mask = ASSH_KEYGEN_LOAD | ASSH_KEYGEN_SAVE;
  else if (!strcmp(action, "list"))
    {
      get_type(NULL);
      get_format(NULL);
      return 0;
    }
  else
    {
      usage(argv[0], 0);
    }

  struct assh_key_s *key;

  if (action_mask & ASSH_KEYGEN_CREATE)
    {
      if (type == NULL)
        ERROR("Missing -t option\n");

      if (ofmt->public)
        ERROR("Won't save new key in public only format.\n");
      if (bits == 0)
        ERROR("Missing -b option\n");
      if (ofile == NULL)
        ERROR("Missing -o option\n");

      fprintf(stderr, "Generating key...\n");
      if (assh_key_create(context, &key, bits, type->ops, ASSH_ALGO_ANY))
        ERROR("unable to create %zu bits key of type %s\n", bits, type->ops->type);

      fprintf(stderr, "Key algorithmic safety: %s (%u%%)\n",
              assh_key_safety_name(key), assh_key_safety(key));
    }

  if (action_mask & ASSH_KEYGEN_LOAD)
    {
      const char *p = passphrase;
      if (ifile == NULL)
        ERROR("Missing -i option\n");

      fprintf(stderr, "Loading key...\n");

      const struct assh_key_ops_s *ops = type != NULL ? type->ops : NULL;

    retry:
      if (ifmt == NULL)
        {
          const struct assh_keygen_format_s *f = formats;
          for (f = formats; f->name != NULL; f++)
            {
              fseek(ifile, 0, SEEK_SET);
              switch (ASSH_ERR_ERROR(assh_load_key_file(context, &key, ops,
                                       ASSH_ALGO_ANY, ifile, f->format, p, 0)))
                {
                case ASSH_OK:
                  goto done;
                case ASSH_ERR_MISSING_KEY:
                  if (p == NULL)
                    {
                      fprintf(stderr, "Passphrase expected for key format: %s\n", f->name);
                      p = get_passphrase("input key passphrase: ", context);
                      goto retry;
                    }
                default:
                  continue;
                }
            }
          ERROR("Unable to guess input key format, use -g\n");
        done:
          fprintf(stderr, "Guessed input key format: %s.\n", f->name);
        }
      else
        {
          switch (ASSH_ERR_ERROR(assh_load_key_file(context, &key, ops,
                                   ASSH_ALGO_ANY, ifile, ifmt->format, p, 0)))
            {
            case ASSH_OK:
              break;
            case ASSH_ERR_MISSING_KEY:
              if (p == NULL)
                {
                  p = get_passphrase("input key passphrase: ", context);
                  goto retry;
                }
              ERROR("Passphrase expected\n");
            default:
              ERROR("Unable to load key\n");
            }
        }

      if (type == NULL)
        fprintf(stderr, "Key type: %s\n", assh_key_type_name(key));

      fprintf(stderr, "Key algorithmic safety: %s (%u%%)\n",
              assh_key_safety_name(key), assh_key_safety(key));

      if (key->comment != NULL)
        fprintf(stderr, "Key comment: %s\n", key->comment);
    }

  if (action_mask & ASSH_KEYGEN_VALIDATE)
    {
      fprintf(stderr, "Validating key...\n");
      if (assh_key_validate(context, key))
        ERROR("Key validation failed\n");
    }

  if (action_mask & ASSH_KEYGEN_SAVE)
    {
      if (ofile == NULL)
        ERROR("Missing -o option\n");
      if (ofmt == NULL)
        ERROR("Missing -f option\n");

      fprintf(stderr, "Saving key in %s format...\n", ofmt->name);

      if (no_outpass || ofmt->public)
        passphrase = NULL;
      else if (passphrase == NULL)
        {
          passphrase = get_passphrase("Output key passphrase: ", context);
          if (!*passphrase)
            passphrase = NULL;
        }

      if (key->comment == NULL)
        {
          char hostname[32], cmt[64];
          if (comment == NULL)
            {
              const char *username = getenv("USER");
              cmt[0] = 0;
              if (username != NULL && !gethostname(hostname, sizeof(hostname)))
                snprintf(cmt, sizeof(cmt), "%s@%s", username, hostname);
              cmt[sizeof(cmt) - 1] = 0;
              comment = cmt;
            }
          if (assh_key_comment(context, key, comment))
            ERROR("Unable to set key comment.\n");
        }

      if (assh_save_key_file(context, key, ofile, ofmt->format, passphrase))
        ERROR("Unable to save key.\n");
    }

  assh_context_release(context);

  if (ifile != NULL)
    fclose(ifile);
  if (ofile != NULL)
    fclose(ofile);

  fprintf(stderr, "Done.\n");

  return 0;
}

