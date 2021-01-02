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

%.pdf: %.dot
	dot -Tpdf -Kdot -Emargin=1 -Granksep=1 $< > $@

%.png: %.dot
	dot -Tpng -Kdot -Emargin=1 -Granksep=1 $< > $@

DOTS =  connection_channel.dot 	\
	connection_request.dot 	\
	service.dot 		\
	transport.dot 		\
	transport_in.dot 	\
	transport_out.dot 	\
	userauth_client.dot 	\
	userauth_server.dot

DOTS_PNG = $(DOTS:.dot=.png)

MKDOC_SRC = fdl-1.3.mkdoc template.mkdoc top_manual.mkdoc		\
	top_internals.mkdoc algos_methods.mkdoc appendix_state.mkdoc	\
	bib.mkdoc build_config.mkdoc copyright.mkdoc examples.mkdoc	\
	lexicon.mkdoc protocol_arch.mkdoc sales_pitch.mkdoc		\
	software_interfaces.mkdoc source_tree.mkdoc			\
	state_machines.mkdoc tests.mkdoc

manual: manual/html/index.html

manual/html/index.html: $(DOTS_PNG) $(MKDOC_SRC) manual.conf
	( cd $(top_srcdir) ; mkdoc -I doc/ -I src/ --conf-file manual.conf \
		--output-path $(abs_builddir)/manual \
		--image-path $(abs_builddir) )

internals: internals/html/index.html

internals/html/index.html: $(DOTS_PNG) $(MKDOC_SRC) internals.conf
	( cd $(top_srcdir) ; mkdoc -I doc/ -I src/ --conf-file internals.conf \
		--output-path $(abs_builddir)/internals \
		--image-path $(abs_builddir) )

libassh_manual.tar.gz: manual/html/index.html
	tar czf $@ manual/html/*.html manual/html/*.png manual/html/*.woff2 manual/html/*.css

EXTRA_DIST = Makefile.am config.h internals.conf manual.conf html_title.tmpl \
		$(MKDOC_SRC) $(DOTS) libassh_manual.tar.gz soft_arch.png

distclean-local:
	rm -f $(DOTS_PNG) libassh_manual.tar.gz manual/html/* internals/html/*
