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

int main()
{
  struct assh_context_s *c;

  if (assh_context_create(&c, ASSH_SERVER, CONFIG_ASSH_MAX_ALGORITHMS,
                          NULL, NULL, NULL, NULL))
    return 1;

  if (assh_algo_register_default(c, 99, 0, 0) != ASSH_OK)
    return 1;

  const char *class_names[] = ASSH_ALGO_CLASS_NAMES;

  fprintf(stderr, "  Class      Name                                     Std Speed Safety\n"
	          "------------------------------------------------------------------------");

  uint_fast16_t i;
  const struct assh_algo_s *a;
  enum assh_algo_class_e cl = ASSH_ALGO_ANY;

  for (i = 0; a = assh_algo_table[i]; i++)
    {
      const struct assh_algo_name_s *n = a->names;

      if (cl != a->class_)
	{
	  fputc('\n', stderr);
	  cl = a->class_;
	}

      fprintf(stderr, "  %-10s %s%-40s%s %c  %3u   %3u\n",
	      class_names[a->class_], "\x1b[1m",
	      n->name, "\x1b[m", std(n->spec), a->speed, a->safety);

      if (a->variant != NULL)
	fprintf(stderr, "               %-40s\n", a->variant);

      for (n++; n->spec; n++)
	fprintf(stderr, "  ALIAS      %-40s %c\n", n->name, std(n->spec));
    }

  assh_context_release(c);

  return 0;
}
