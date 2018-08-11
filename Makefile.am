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

SUBDIRS = src examples test doc
ACLOCAL_AMFLAGS=-Im4

doc: manual internals

DOTS=doc/connection_channel.dot \
	doc/connection_request.dot \
	doc/service.dot \
	doc/transport.dot \
	doc/transport_in.dot \
	doc/transport_out.dot \
	doc/userauth_client.dot \
	doc/userauth_server.dot

doc/%.png: doc/%.dot
	dot -Tpng -Kdot -Emargin=1 -Granksep=1 $< > $@

manual: $(DOTS:.dot=.png)
	mkdoc -I doc/ -I src/ --conf-file manual.conf

internals: $(DOTS)
	mkdoc -I doc/ -I src/ --conf-file internals.conf
