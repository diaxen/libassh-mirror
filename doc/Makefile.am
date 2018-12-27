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

EXTRA_DIST = Makefile.am assh_config.h fdl-1.3.mkdoc internals.conf	\
	manual.conf template.mkdoc top.mkdoc manual/html/* internals/html/*

%.pdf: %.dot
	dot -Tpdf -Kdot -Emargin=1 -Granksep=1 $< > $@

%.png: %.dot
	dot -Tpng -Kdot -Emargin=1 -Granksep=1 $< > $@
