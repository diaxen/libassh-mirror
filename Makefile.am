# Copyright (C) 2013-2020 Alexandre Becoulet
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

SUBDIRS = src test doc
ACLOCAL_AMFLAGS=-Im4

if COND_examples
SUBDIRS += examples
endif

pkgconfig_DATA = libassh.pc
pkgconfigdir = $(libdir)/pkgconfig

doc: manual internals

manual:
	make -C $(top_srcdir)/doc manual

internals:
	make -C $(top_srcdir)/doc internals
