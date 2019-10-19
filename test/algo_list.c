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

#include <assh/assh_session.h>
#include <assh/assh_context.h>
#include <assh/assh_algo.h>

#include <stdio.h>
#include <stdlib.h>

static char std(enum assh_algo_spec_e s)
{
  switch (s & 7)
    {
    case ASSH_ALGO_STD_IETF:
      return 'I';
    case ASSH_ALGO_STD_DRAFT:
      return 'D';
    case ASSH_ALGO_STD_PRIVATE:
      return 'P';
    default:
      return ' ';
    }
}

static const char *class_names[] = ASSH_ALGO_CLASS_NAMES;

static void show_table()
{
  fprintf(stderr, "  Class      Name                                 Implem    Std Speed Safety\n"
	          "----------------------------------------------------------------------------");

  uint_fast16_t i;
  const struct assh_algo_s *a;
  enum assh_algo_class_e cl = ASSH_ALGO_ANY;

  for (i = 0; (a = assh_algo_table[i]) != NULL; i++)
    {
      const struct assh_algo_name_s *n = a->names;

      if (cl != a->class_)
	{
	  fputc('\n', stderr);
	  cl = a->class_;
	}

      fprintf(stderr, "  %-10s %s%-36s%s %-12s %c  %3u   %3u\n",
	      class_names[a->class_], "\x1b[1m",
	      n->name, "\x1b[m", a->implem, std(n->spec), a->speed, a->safety);

      if (a->variant != NULL)
	fprintf(stderr, "    Variant:   %-40s\n", a->variant);

      for (n++; n->spec; n++)
	fprintf(stderr, "    Alias :  %-40s %c\n", n->name, std(n->spec));
    }
}

static void show_order(assh_safety_t safety)
{
  struct assh_context_s *c;

  if (assh_context_create(&c, ASSH_SERVER,
                          NULL, NULL, NULL, NULL))
    return;

  if (assh_algo_register_default(c, safety, 0, 0) != ASSH_OK)
    return;

  fprintf(stderr, "  Spd Saf Score Algorithm                                Variant\n"
	          "------------------------------------------------------------------------------\n");

  uint_fast16_t i;
  const struct assh_algo_s *a;
  enum assh_algo_class_e cl = ASSH_ALGO_ANY;

  for (i = 0; i < c->algo_cnt; i++)
    {
      a = c->algos[i];
      const struct assh_algo_name_s *n = a->names;

      if (cl != a->class_)
	{
	  cl = a->class_;
	  fprintf(stderr, "%s:\n", class_names[cl]);
	}

      fprintf(stderr, "  %3u %3u %5u %-40s %s\n",
              a->speed, a->safety, ASSH_ALGO_SCORE(a, safety),
              n->name, a->variant ? a->variant : "");
    }

  assh_context_release(c);
}

int main(int argc, char **argv)
{
  if (assh_deps_init())
    return -1;

  if (argc < 2)
    show_table();
  else
    show_order(atoi(argv[1]));

  return 0;
}
