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

unit_files		= tlshd.service

EXTRA_DIST		= $(unit_files)
MAINTAINERCLEANFILES	= Makefile.in

if INSTALL_SYSTEMD
install-data-hook: $(unit_files)
	mkdir -p $(DESTDIR)/$(unitdir)
	cp $(unit_files) $(DESTDIR)/$(unitdir)
endif
