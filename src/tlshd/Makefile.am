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

sbin_PROGRAMS		= tlshd
tlshd_CFLAGS		= -Werror -Wall -Wextra $(LIBGNUTLS_CFLAGS) \
			  $(LIBKEYUTILS_CFLAGS) $(GLIB_CFLAGS) $(LIBNL3_CFLAGS) \
			  $(LIBNL_GENL3_CFLAGS)
tlshd_SOURCES		= client.c config.c handshake.c keyring.c ktls.c log.c \
			  main.c netlink.c netlink.h server.c tlshd.h quic.c \
			  quic.h
tlshd_LDADD		= $(LIBGNUTLS_LIBS) $(LIBKEYUTILS_LIBS) $(GLIB_LIBS) \
			  $(LIBNL3_LIBS) $(LIBNL_GENL3_LIBS)

MAINTAINERCLEANFILES	= Makefile.in cscope.out
