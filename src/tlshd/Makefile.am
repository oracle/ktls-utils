#
# Copyright (c) 2022 Oracle and/or its affiliates.
#
# ktls-utils is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.
#

dist_sysconf_DATA	= tlshd.conf

man5_MANS		= tlshd.conf.man
man8_MANS		= tlshd.man
EXTRA_DIST		= $(man5_MANS) $(man8_MANS)

sbin_PROGRAMS		= tlshd
tlshd_CFLAGS		= -Werror -Wall -Wextra $(LIBGNUTLS_CFLAGS) \
			  $(LIBKEYUTILS_CFLAGS) $(GLIB_CFLAGS) $(LIBNL3_CFLAGS)
tlshd_SOURCES		= config.c handshake.c keyring.c ktls.c log.c main.c \
			  netlink.c tlshd.h tls13.c
tlshd_LDADD		= $(LIBGNUTLS_LIBS) $(LIBKEYUTILS_LIBS) $(GLIB_LIBS) \
			  $(LIBNL3_LIBS) -lnl-genl-3

MAINTAINERCLEANFILES	= Makefile.in cscope.out
