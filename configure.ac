dnl Process this file with autoconf to produce a configure script.
dnl
dnl Copyright (c) 2022 Oracle and/or its affiliates.
dnl
dnl ktls-utils is free software; you can redistribute it and/or
dnl modify it under the terms of the GNU General Public License as
dnl published by the Free Software Foundation; version 2.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
dnl General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write to the Free Software
dnl Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
dnl 02110-1301, USA.
dnl

AC_PREREQ([2.69])
AC_INIT([ktls-utils],[0.9],[kernel-tls-handshake@lists.linux.dev])
AM_INIT_AUTOMAKE
AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
AC_PREFIX_DEFAULT(/usr)
AC_USE_SYSTEM_EXTENSIONS

AC_LANG(C)
AC_PROG_CC
AC_PROG_INSTALL

unitdir=/usr/lib/systemd/system
AC_ARG_WITH(systemd,
	[AS_HELP_STRING([--with-systemd@<:@=unit-dir-path@:>@],
			[install systemd unit files @<:@Default: no, and path defaults to /usr/lib/systemd/system if not given@:>@])],
	if test "$withval" != "no" ; then
		use_systemd=1
		if test "$withval" != "yes" ; then
			unitdir=$withval
		fi
	else
		use_systemd=0
	fi
	)
	AM_CONDITIONAL(INSTALL_SYSTEMD, [test "$use_systemd" = 1])
	AC_SUBST(unitdir)

PKG_PROG_PKG_CONFIG([0.9.0])
PKG_CHECK_MODULES([LIBGNUTLS], [gnutls >= 3.3.0])
AC_SUBST([LIBGNUTLS_CFLAGS])
AC_SUBST([LIBGNUTLS_LIBS])
PKG_CHECK_MODULES([LIBKEYUTILS], [libkeyutils])
AC_SUBST([LIBKEYUTILS_CFLAGS])
AC_SUBST([LIBKEYUTILS_LIBS])
PKG_CHECK_MODULES([GLIB], glib-2.0 >= 2.6)
AC_SUBST([GLIB_CFLAGS])
AC_SUBST([GLIB_LIBS])
PKG_CHECK_MODULES([LIBNL3], libnl-3.0 >= 3.1)
AC_SUBST([LIBNL3_CFLAGS])
AC_SUBST([LIBNL3_LIBS])

AC_CHECK_HEADERS([linux/openat2.h])

AC_CHECK_LIB([gnutls], [gnutls_transport_is_ktls_enabled],
             [AC_DEFINE([HAVE_GNUTLS_TRANSPORT_IS_KTLS_ENABLED], [1],
                        [Define to 1 if you have the gnutls_transport_is_ktls_enabled function.])])
AC_CHECK_LIB([gnutls], [gnutls_protocol_set_enabled],
             [AC_DEFINE([HAVE_GNUTLS_PROTOCOL_SET_ENABLED], [1],
                        [Define to 1 if you have the gnutls_protocol_set_enabled function.])])
AC_SUBST([AM_CPPFLAGS])

AC_CONFIG_FILES([Makefile src/Makefile src/tlshd/Makefile systemd/Makefile])
AC_OUTPUT
