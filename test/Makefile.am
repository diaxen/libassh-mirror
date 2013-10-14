# Copyright (C) 2013 Alexandre Becoulet
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/>.

AM_CPPFLAGS = -I$(top_builddir)/src/assh

noinst_PROGRAMS = bignum sha1 dsa
TESTS = bignum sha1 dsa

bignum_SOURCES = bignum.c
bignum_LDADD = $(top_builddir)/src/libassh.la
bignum_CFLAGS = -I$(top_srcdir)/src

sha1_SOURCES = sha1.c
sha1_LDADD = $(top_builddir)/src/libassh.la
sha1_CFLAGS = -I$(top_srcdir)/src

dsa_SOURCES = dsa.c
dsa_LDADD = $(top_builddir)/src/libassh.la
dsa_CFLAGS = -I$(top_srcdir)/src

