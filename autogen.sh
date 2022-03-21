#!/bin/sh -e
#
# Reset the state of the autotools infrastructure
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

GEN="compile config.guess config.sub depcomp install-sh \
     missing aclocal.m4 configure config.h.in \
     autom4te.cache"

for FILE in $GEN
do
  rm -rf $FILE
done

rm -f ktls-utils*.tar.gz

aclocal
autoheader
automake --add-missing --copy --gnu
autoconf

exit 0
