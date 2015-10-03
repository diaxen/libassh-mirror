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

#include <assh/key_rsa.h>
#include <assh/key_dsa.h>
#include <assh/key_eddsa.h>
#include <assh/key_ecdsa.h>
#include <assh/helper_key.h>

#ifdef CONFIG_ASSH_USE_GCRYPT
# include <gcrypt.h>
#endif

struct assh_keygen_format_s
{
  const char *name;
  const char *desc;
  enum assh_key_format_e format;
  assh_bool_t public;
};

static const struct assh_keygen_format_s formats[] = {
  { "rfc4716", "public key in ASCII format",
    ASSH_KEY_FMT_PUB_RFC4716, 1 },
  { "rfc4716_bin", "rfc4716 underlying binary key format",
    ASSH_KEY_FMT_PUB_RFC4253_6_6, 1 },
  { "openssh_v1", "",
    ASSH_KEY_FMT_OPENSSH_V1 },
  { "openssh_v1_bin", "",
    ASSH_KEY_FMT_OPENSSH_V1_BLOB },
  { "pem", "",
    ASSH_KEY_FMT_PV_RFC2440_PEM_ASN1 },
  { "pem_bin", "",
    ASSH_KEY_FMT_PV_PEM_ASN1 },
  { NULL }
};

static const struct assh_key_ops_s *types[] = {
  &assh_key_dsa,
  &assh_key_rsa,
  &assh_key_ed25519,
  &assh_key_eddsa_e382,
  &assh_key_eddsa_e521,
  &assh_key_ecdsa_nistp,
  NULL
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

static const struct assh_key_ops_s * get_type(const char *type)
{
  unsigned i;
  if (type)
    for (i = 0; types[i] != NULL; i++)
      if (!strcmp(types[i]->type, type))
        return types[i];
  fprintf(stderr, "Supported key types:\n");
  for (i = 0; types[i] != NULL; i++)
    fprintf(stderr, "  %s\n", types[i]->type);
  if (type)
    exit(1);
  return NULL;
}

static void usage(const char *program)
{
  fprintf(stderr, "usage: %s [options] create|validate|convert|list\n"
          "    -b bits    specify the size of the key\n"
          "    -o file    specify the output file name\n"
          "    -i file    specify the input file name\n"
          "    -g format  specify the input key format\n"
          "    -f format  specify the output key format\n", program);
  exit(1);
}

const struct assh_key_ops_s *key_ops[] =
{
  &assh_key_dsa,
  &assh_key_rsa,
};

int main(int argc, char *argv[])
{
#ifdef CONFIG_ASSH_USE_GCRYPT
  if (!gcry_check_version(GCRYPT_VERSION))
    return -1;
#endif

  int opt;
  size_t bits = 0;
  const struct assh_keygen_format_s *ifmt = NULL;
  const struct assh_keygen_format_s *ofmt = lookup_format(ASSH_KEY_FMT_OPENSSH_V1);
  const struct assh_key_ops_s *ops = NULL;
  FILE *ifile = NULL;
  FILE *ofile = NULL;

  while ((opt = getopt(argc, argv, "b:f:g:o:i:t:")) != -1)
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
          ops = get_type(optarg);
          break;
        default:
          usage(argv[0]);
        }
    }

  if (optind + 1 != argc)
    usage(argv[0]);

  struct assh_context_s *context;

  if (assh_context_create(&context, ASSH_SERVER, CONFIG_ASSH_MAX_ALGORITHMS, NULL, NULL)
      || context == NULL || assh_context_prng(context, NULL))
    ERROR("Unable to create context.\n");

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
      usage(argv[0]);
    }

  const struct assh_key_s *key;

  if (ops == NULL)
    ERROR("Missing -t option\n");

  if (action_mask & ASSH_KEYGEN_CREATE)
    {
      if (ofmt->public)
        ERROR("Won't save new key in public only format.\n");
      if (bits == 0)
        ERROR("Missing -b option\n");

      fprintf(stderr, "Generating key...\n");
      if (assh_key_create(context, &key, bits, ops, ASSH_ALGO_ANY))
        ERROR("unable to create %zu bits key of type %s\n", bits, ops->type);
    }

  if (action_mask & ASSH_KEYGEN_LOAD)
    {
      if (ifile == NULL)
        ERROR("Missing -i option\n");

      fprintf(stderr, "Loading key...\n");

      if (ifmt == NULL)
        {
          enum assh_key_format_e f;
          for (f = ASSH_KEY_FMT_NONE + 1; f <= ASSH_KEY_FMT_PV_PEM_ASN1; f++)
            {
              fseek(ifile, 0, SEEK_SET);
              if (!assh_load_key_file(context, &key, ops, ASSH_ALGO_ANY, ifile, f))
                goto done;
            }
          ERROR("Unable to guess input key format\n");
        done:
          fprintf(stderr, "Guessed input key format: %s.\n", lookup_format(f)->name);
        }
      else
        {
          if (assh_load_key_file(context, &key, ops, ASSH_ALGO_ANY, ifile, ifmt->format))
            ERROR("Unable to load key\n");
        }
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

      size_t len;
      if (assh_key_output(context, key, NULL, &len, ofmt->format))
        ERROR("Unable to save key in %s format.\n", ofmt->name);

      fprintf(stderr, "Saving key...\n");
      uint8_t *data = malloc(len);
      if (data == NULL || key->algo->f_output(context, key, data, &len, ofmt->format))
        ERROR("Unable to save key using specified format.\n");

      if (fwrite(data, len, 1, ofile) != 1)
        ERROR("Unable to write file.\n");
    }

  assh_context_release(context);

  if (ifile != NULL)
    fclose(ifile);
  if (ofile != NULL)
    fclose(ofile);

  fprintf(stderr, "Done.\n");

  return 0;
}

