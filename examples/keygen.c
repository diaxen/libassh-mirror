/*

  libassh - asynchronous ssh2 client/server library.

  Copyright (C) 2013-2020 Alexandre Becoulet <alexandre.becoulet@free.fr>

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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <assh/assh_context.h>
#include <assh/assh_cipher.h>
#include <assh/assh_alloc.h>

#include <assh/helper_key.h>
#include <assh/helper_io.h>

enum assh_keygen_action_e
{
  ASSH_KEYGEN_LOAD     = 1,
  ASSH_KEYGEN_CREATE   = 2,
  ASSH_KEYGEN_VALIDATE = 4,
  ASSH_KEYGEN_SAVE     = 8,
  ASSH_KEYGEN_FP       = 16,
};


#define KEY_ALGO_TABLE_MAXSIZE 16
static const struct assh_key_algo_s *key_algo_table[KEY_ALGO_TABLE_MAXSIZE];
static size_t key_algo_table_size;


#define ERROR(...) do { fprintf(stderr, "error: " __VA_ARGS__); exit(1); } while (0)

static void list_formats(assh_bool_t internal)
{
  const struct assh_key_format_desc_s *f;
  unsigned i;

  printf("Supported key formats:\n");
  for (i = 0; i <= ASSH_KEY_FMT_LAST; i++)
    {
      f = assh_key_format_desc(i);
#ifndef CONFIG_ASSH_DEBUG
      if (f->name && (internal || !f->internal))
#endif
        printf("  %-20s (%s)\n", f->name, f->desc);
    }
}

static enum assh_key_format_e get_format(const char *fmt)
{
  const struct assh_key_format_desc_s *f;
  unsigned i;

  if (fmt)
    for (i = 0; i <= ASSH_KEY_FMT_LAST; i++)
      {
        f = assh_key_format_desc(i);
        if (f->name && !strcmp(f->name, fmt))
          return i;
      }

  list_formats(0);

  if (fmt)
    exit(1);
  return ASSH_KEY_FMT_NONE;
}

static FILE * get_file(const char *file, int mode)
{
  int fd = open(file, mode, 0600);
  if (fd < 0)
    ERROR("Can not open `%s' key file.\n", file);
  return fdopen(fd, mode & O_WRONLY ? "wb" : "rb");
}

static void list_types()
{
  const struct assh_key_algo_s **types = key_algo_table;
  unsigned i;

  printf("Supported key types:\n");
  for (i = 0; i < key_algo_table_size; i++)
    printf("  %s\n", types[i]->name);
}

static const struct assh_key_algo_s * get_type(const char *type)
{
  const struct assh_key_algo_s **types = key_algo_table;
  unsigned i;
  if (type)
    for (i = 0; i < key_algo_table_size; i++)
      if (!strcmp(types[i]->name, type))
        return types[i];

  list_types();

  if (type)
    exit(1);
  return NULL;
}

static const char *
get_passphrase(const char *prompt, struct assh_context_s *context)
{
  fputs(prompt, stdout);
  fflush(stdout);

  const char *p;
  if (asshh_fd_get_password(context, &p, 80, 0, 0))
    ERROR("Unable to read passphrase expected\n");

  putc('\n', stdout);

  return p;
}

static void usage(const char *program, assh_bool_t opts)
{
  printf("usage: %s [-h | options] create|validate|convert|fingerprint\n", program);

  if (opts)
    printf("List of available options:\n\n"
          "    -t algo    specify the type of the key\n"
          "    -b bits    specify the size of the key\n\n"
          "    -o file    specify the output file name\n"
          "    -i file    specify the input file name\n\n"
          "    -g format  specify the input key format\n"
          "    -f format  specify the output key format\n\n"
          "    -p pass    specify key encryption passphrase\n"
          "    -P         don't use passphrase for the output\n"
          "    -c comment specify key comment string\n\n"
          "    -l         list supported key types and formats\n"
          "    -L         list internal/raw key formats\n"
          "    -h         show help\n");

  exit(1);
}

int main(int argc, char *argv[])
{
  /* perform initialization of third party libraries */
  if (assh_deps_init())
    ERROR("initialization error\n");

  int opt;
  size_t bits = 0;
  assh_bool_t no_outpass = 0;
  enum assh_key_format_e ifmt = ASSH_KEY_FMT_NONE;
  enum assh_key_format_e ofmt = ASSH_KEY_FMT_NONE;
  const struct assh_key_algo_s *type = NULL;
  const char *passphrase = NULL;
  const char *comment = NULL;
  FILE *ifile = NULL;
  FILE *ofile = NULL;

  /* create a library context */

  struct assh_context_s *context;

  if (assh_context_create(&context, ASSH_CLIENT_SERVER,
                          NULL, NULL, NULL, NULL))
    ERROR("Unable to create context.\n");

  if (assh_algo_register_default(context, 0, 0, 0))
    ERROR("Unable to register algorithms.\n");

  key_algo_table_size = KEY_ALGO_TABLE_MAXSIZE;
  assh_key_algo_enumerate(context, ASSH_ALGO_ANY,
			  &key_algo_table_size, key_algo_table);

  /* parse command list arguments */

  while ((opt = getopt(argc, argv, "hb:f:g:o:i:t:r:p:Pc:lL")) != -1)
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
          ofile = get_file(optarg, O_CREAT | O_WRONLY | O_TRUNC);
          break;
        case 'i':
          ifile = get_file(optarg, O_RDONLY);
          break;
        case 't':
          type = get_type(optarg);
          if (ofmt == ASSH_KEY_FMT_NONE)
            ofmt = type->formats[0];
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
	case 'l':
	  list_types();
	  putc('\n', stdout);
	  list_formats(0);
	  return 0;
	case 'L':
	  list_formats(1);
	  return 0;
        default:
          usage(argv[0], 0);
        case 'h':
          usage(argv[0], 1);
        }
    }

  if (optind + 1 != argc)
    usage(argv[0], 0);

  const char *action = argv[optind];
  unsigned action_mask = 0;

  /* set action flags */

  if (!strcmp(action, "create"))
    action_mask = ASSH_KEYGEN_CREATE | ASSH_KEYGEN_SAVE;
  else if (!strcmp(action, "validate"))
    action_mask = ASSH_KEYGEN_LOAD | ASSH_KEYGEN_VALIDATE;
  else if (!strcmp(action, "convert"))
    action_mask = ASSH_KEYGEN_LOAD | ASSH_KEYGEN_SAVE;
  else if (!strcmp(action, "fingerprint"))
    action_mask = ASSH_KEYGEN_LOAD | ASSH_KEYGEN_FP;
  else
    {
      usage(argv[0], 0);
    }

  /* lookup output format descriptor */

  const struct assh_key_format_desc_s *ofmt_desc
    = assh_key_format_desc(ofmt);

  struct assh_key_s *key = NULL;

  /* handle generation of a new key as needed */

  if (action_mask & ASSH_KEYGEN_CREATE)
    {
      if (type == NULL)
        ERROR("Missing -t option\n");

      if (ofmt_desc->public)
        ERROR("Won't save new key in public only format.\n");
      if (ofile == NULL)
        ERROR("Missing -o option\n");

      printf("Generating key...\n");
      if (assh_key_create(context, &key, bits, type, ASSH_ALGO_ANY))
        ERROR("unable to create %zu bits key of type %s\n", bits, type->name);

      printf("Key algorithmic safety: %s (%u%%)\n",
              assh_key_safety_name(key), assh_key_safety(key));
    }

  /* load an existing key from file as needed */

  if (action_mask & ASSH_KEYGEN_LOAD)
    {
      const char *p = passphrase;
      if (ifile == NULL)
        ERROR("Missing -i option\n");

      printf("Loading key...\n");

      while (1)                 /* retry passphrase prompt */
        {
          switch (ASSH_STATUS(asshh_key_load_file(context, &key,
		   type ? type->name : NULL, ASSH_ALGO_ANY, ifile, ifmt, p, 0)))
            {
            case ASSH_OK:
              break;

            case ASSH_ERR_WRONG_KEY:
              printf("bad passphrase\n");
              if (passphrase != NULL)
                ERROR("Unable to load key\n"); /* do not retry when -p is used */
            case ASSH_ERR_MISSING_KEY:
              p = get_passphrase("Input key passphrase: ", context);
              fseek(ifile, 0, SEEK_SET);
              continue;

            default:
              if (ifmt == ASSH_KEY_FMT_NONE)
                ERROR("Unable to guess input key format, use -g\n");
              ERROR("Unable to load key\n");
            }
          break;
        }

      if (type == NULL)
        printf("Key type: %s (%s)\n", assh_key_type_name(key),
                key->private ? "private" : "public");

      printf("Key algorithmic safety: %s (%u%%)\n",
              assh_key_safety_name(key), assh_key_safety(key));

      if (key->comment != NULL)
        printf("Key comment: %s\n", key->comment);
    }

  /* start key validation as needed */

  if (action_mask & ASSH_KEYGEN_VALIDATE)
    {
#ifdef CONFIG_ASSH_KEY_VALIDATE
      printf("Validating key...\n");

      enum assh_key_validate_result_e r;
      if (assh_key_validate(context, key, &r))
        ERROR("Unexpected error during key validation\n");

        switch (r)
          {
          case ASSH_KEY_BAD:
            ERROR("The key is bad.\n");
          case ASSH_KEY_NOT_SUPPORTED:
            ERROR("The key uses some unsupported parameters.\n");

          case ASSH_KEY_NOT_CHECKED:
#endif
            printf("warning: Checking of this key is not supported.\n");
#ifdef CONFIG_ASSH_KEY_VALIDATE
            break;

          case ASSH_KEY_PARTIALLY_CHECKED:
            printf("warning: This key can not be fully validated.\n");
            break;

          case ASSH_KEY_GOOD:
            break;
          }
#endif
    }

  /* save key to file */

  if (action_mask & ASSH_KEYGEN_SAVE)
    {
      if (ofile == NULL)
        ERROR("Missing -o option\n");
      if (ofmt == ASSH_KEY_FMT_NONE)
        ERROR("Missing -f option\n");

      printf("Saving key in %s format...\n", ofmt_desc->name);

      if (no_outpass || !ofmt_desc->encrypted)
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

      if (asshh_key_save_file(context, key, ofile, ofmt, passphrase))
        ERROR("Unable to save key.\n");
    }

  /* display fingerprint in all supported formats as needed */

  if (action_mask & ASSH_KEYGEN_FP)
    {
      enum asshh_fingerprint_fmt_e fpf = 0;

      while (1)
        {
          const char * fpf_name;
          char fp[128];
          size_t fps = sizeof(fp);

          assh_status_t err = asshh_key_fingerprint(context, key,
                                         fpf, fp, &fps, &fpf_name);
          if (err == ASSH_NO_DATA)
            break;

          if (err == ASSH_OK)
            printf("%-16s: %s\n", fpf_name, fp);

          fpf++;
        }
    }

  assh_key_drop(context, &key);
  assh_context_release(context);

  if (ifile != NULL)
    fclose(ifile);
  if (ofile != NULL)
    fclose(ofile);

  printf("Done.\n");

  return 0;
}

