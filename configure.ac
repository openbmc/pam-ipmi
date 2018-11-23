# Initialization
AC_PREREQ([2.69])
AC_INIT([pam_ipmi], [0.1], [https://github.com/openbmc/pam-ipmi/issues])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([subdir-objects -Wall foreign dist-xz])
AM_SILENT_RULES([yes])

AC_SUBST(PACKAGE)
AC_SUBST(VERSION)

# Checks for programs
AM_PROG_AR
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

AX_CHECK_OPENSSL([], [AC_MSG_ERROR(["openssl required and not found"])])
PKG_CHECK_MODULES([LIBCRYPTO], [libcrypto], [], AC_MSG_ERROR(["Requires libcrypto"]))

# Note: The following macro should work but doesn't fill out CRYPTO_LIBS as it should.
#AX_LIB_CRYPTO(auto)

# Checks for library functions.
LT_INIT # Removes 'unrecognized options: --with-libtool-sysroot

# Create configured output
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
