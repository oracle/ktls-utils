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
AC_INIT([ktls-utils],[1.2.0],[kernel-tls-handshake@lists.linux.dev])
AM_INIT_AUTOMAKE
AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
AC_PREFIX_DEFAULT(/usr)
AC_USE_SYSTEM_EXTENSIONS

AC_LANG(C)
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MKDIR_P

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
PKG_CHECK_MODULES([LIBNL_GENL3], libnl-genl-3.0 >= 3.1)
AC_SUBST([LIBNL_GENL3_CFLAGS])
AC_SUBST([LIBNL_GENL3_LIBS])

AC_CHECK_PROG(DOXYGEN, doxygen, doxygen, false)
if test "$DOXYGEN" = false; then
   AC_MSG_WARN([Doxygen not found - documentation will not be built])
fi
AM_CONDITIONAL([HAVE_DOXYGEN], [test "$DOXYGEN" != "false"])

AC_CHECK_LIB([gnutls], [gnutls_handshake_set_secret_function],
             [AC_DEFINE([HAVE_GNUTLS_QUIC], [1],
			[Define to 1 if you have the gnutls_handshake_set_secret_function function.])])
AC_CHECK_LIB([gnutls], [gnutls_transport_is_ktls_enabled],
             [AC_DEFINE([HAVE_GNUTLS_TRANSPORT_IS_KTLS_ENABLED], [1],
                        [Define to 1 if you have the gnutls_transport_is_ktls_enabled function.])])
AC_CHECK_LIB([gnutls], [gnutls_protocol_set_enabled],
             [AC_DEFINE([HAVE_GNUTLS_PROTOCOL_SET_ENABLED], [1],
                        [Define to 1 if you have the gnutls_protocol_set_enabled function.])])
AC_CHECK_LIB([gnutls], [gnutls_get_system_config_file],
             [AC_DEFINE([HAVE_GNUTLS_GET_SYSTEM_CONFIG_FILE], [1],
                        [Define to 1 if you have the gnutls_get_system_config_file function.])])
AC_CHECK_LIB([gnutls], [gnutls_psk_allocate_client_credentials2],
             [AC_DEFINE([HAVE_GNUTLS_PSK_ALLOCATE_CREDENTIALS2], [1],
                        [Define to 1 if you have the gnutls_psk_allocate_client_credentials2 function.])])

AC_MSG_CHECKING(for ML-DSA support in gnutls)
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM([[ #include <gnutls/gnutls.h> ]],
		[[ (void) GNUTLS_SIGN_MLDSA65; ]])],
	[ have_mldsa=yes ],
	[ have_mldsa=no ])
AC_MSG_RESULT([$have_mldsa])
if test "x$have_mldsa" = xyes ; then
	AC_DEFINE([HAVE_GNUTLS_MLDSA], [1], [Define to 1 if gnutls supports ML-DSA])
fi

AC_SUBST([AM_CPPFLAGS])

AC_CONFIG_FILES([Makefile \
                 docs/Doxyfile \
                 docs/Makefile \
                 etc/Makefile \
                 etc/tlshd/Makefile \
                 man/Makefile \
                 man/man5/Makefile \
                 man/man8/Makefile \
                 src/Makefile \
                 src/tlshd/Makefile \
                 systemd/Makefile])

AC_OUTPUT
