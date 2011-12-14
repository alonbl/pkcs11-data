#
# Copyright (c) 2005-2008 Alon Bar-Lev <alon.barlev@gmail.com>
# All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program (see the file COPYING.GPL included with this
# distribution); if not, write to the Free Software Foundation, Inc.,
# 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#

AUTOMAKE_OPTIONS=foreign dist-bzip2 1.10
ACLOCAL_AMFLAGS = -I m4

MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in $(srcdir)/config.h.in~ $(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/aclocal.m4 \
	$(srcdir)/config.guess $(srcdir)/config.sub
CLEANFILES=pkcs11-data.1.html

dist_doc_DATA=README COPYING.GPL COPYING
dist_noinst_SCRIPTS=prompt-prog.sh
bin_PROGRAMS=pkcs11-data

pkcs11_data_SOURCES=pkcs11-data.c
if WIN32
nodist_pkcs11_data_SOURCES=versioninfo.rc
endif
pkcs11_data_CFLAGS=$(AM_CFLAGS) $(PKCS11_HELPER_CFLAGS)
pkcs11_data_LDADD=$(PKCS11_HELPER_LIBS)

if WIN32
dist_noinst_DATA=pkcs11-data.1
nodist_html_DATA=pkcs11-data.1.html

pkcs11-data.1.html: pkcs11-data.1
	$(MAN2HTML) < "$^" > "$@"
else
dist_man_MANS=pkcs11-data.1
endif

RCCOMPILE = $(RC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) \
	$(AM_CPPFLAGS) $(CPPFLAGS)
LTRCCOMPILE = $(LIBTOOL) --mode=compile --tag=RC $(RCCOMPILE)

.rc.lo:
	$(LTRCCOMPILE) -i $< -o $@

.rc.o:
	$(RCCOMPILE) -i $< -o $@

