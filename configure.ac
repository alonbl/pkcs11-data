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

AC_PREREQ([2.60])

define([PACKAGE_VERSION_MAJOR], [0])
define([PACKAGE_VERSION_MINOR], [7])
define([PACKAGE_VERSION_FIX], [4])

AC_INIT([pkcs11-data], [PACKAGE_VERSION_MAJOR.PACKAGE_VERSION_MINOR.PACKAGE_VERSION_FIX])
AM_INIT_AUTOMAKE([${PACKAGE_NAME}], [${PACKAGE_VERSION}])
AM_CONFIG_HEADER([config.h])
AC_CONFIG_SRCDIR([pkcs11-data.c])
AC_CONFIG_MACRO_DIR([m4])

PKCS11_DATA_VERSION_MAJOR="PACKAGE_VERSION_MAJOR"
PKCS11_DATA_VERSION_MINOR="PACKAGE_VERSION_MINOR"
PKCS11_DATA_VERSION_FIX="PACKAGE_VERSION_FIX"

AC_CANONICAL_HOST

AC_ARG_WITH([cygwin-native],
	[AC_HELP_STRING([--with-cygwin-native], [Compile native win32])],
	[CYGWIN_NATIVE="${withval}"],
	[CYGWIN_NATIVE="no"]
)

WIN32="no"
CYGWIN="no"
case "${host}" in
	*-mingw32*)
		WIN32="yes"
	;;
	*-cygwin*)
		AC_MSG_CHECKING([cygwin mode to use])
		CYGWIN="yes"
		if test "${CYGWIN_NATIVE}" = "yes"; then
			AC_MSG_RESULT([Using native win32])
			CFLAGS="${CFLAGS} -mno-cygwin"
			WIN32="yes"
		else
			AC_MSG_RESULT([Using cygwin])
		fi
	;;
	*)
	;;
esac

AC_ARG_ENABLE(
	[strict],
	[AC_HELP_STRING([--enable-strict], [enable strict compiler warnings (debugging option)])],
	,
	[enable_strict="no"]
)

AC_ARG_ENABLE(
	[pedantic],
	[AC_HELP_STRING([--enable-pedantic], [nable pedantic compiler warnings (debugging option)])],
	,
	[enable_pedantic="no"]
)

AC_PROG_CC
AC_PROG_INSTALL
PKG_PROG_PKG_CONFIG

dnl Add libtool support.
ifdef(
	[LT_INIT],
	[
		LT_INIT
		LT_LANG([Windows Resource])
	],
	[
		AC_LIBTOOL_RC
		AC_PROG_LIBTOOL
	]
)

if test "${WIN32}" = "yes"; then
	AC_CHECK_PROGS([MAN2HTML], [man2html])
	test -z "${MAN2HTML}" && AC_MSG_ERROR([man2html is required for win32])
fi

AC_TYPE_SIGNAL
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([ \
	gettimeofday memmove memset socket strchr strdup strerror strrchr \
	snprintf \
])

PKG_CHECK_MODULES([PKCS11_HELPER], [libpkcs11-helper-1 >= 1.02],, [AC_MSG_ERROR([Cannot locate pkcs11-helper])])
PKCS11_HELPER_1_CHECK_FEATURES([data token])

AC_HEADER_STDC
AC_C_CONST
AC_C_VOLATILE
AC_TYPE_SIZE_T

AC_CHECK_HEADERS([ \
	stdio.h \
	errno.h \
	getopt.h \
	signal.h \
	unistd.h \
	sys/wait.h \
])

AC_SUBST([PKCS11_DATA_VERSION_MAJOR])
AC_SUBST([PKCS11_DATA_VERSION_MINOR])
AC_SUBST([PKCS11_DATA_VERSION_FIX])

AM_CONDITIONAL([WIN32], [test "${WIN32}" = yes])

if test "${enable_pedantic}" = "yes"; then
	enable_strict="yes";
	CFLAGS="${CFLAGS} -pedantic"
fi
if test "${enable_strict}" = "yes"; then
	CFLAGS="${CFLAGS} -Wall -Wextra"
fi

AC_OUTPUT([
	Makefile
	versioninfo.rc
])
