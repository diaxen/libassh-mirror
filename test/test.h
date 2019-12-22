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

#include <stdlib.h>
#include <stdio.h>

#define TEST_LOC(lnum) __FILE__ ":" #lnum ":"
#define TEST_LOC_(x) TEST_LOC(x)

#define TEST_FAIL(...)				\
  do {						\
    fprintf(stderr, "FAIL " TEST_LOC_(__LINE__) __VA_ARGS__);	\
    exit(1);					\
  } while (0)

#define TEST_ASSERT(c)				\
  do {						\
    if (!(c)) TEST_FAIL( "failed: " #c);	\
  } while (0)

