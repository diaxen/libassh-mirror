# Copyright (C) 2013 Alexandre Becoulet
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

AC_INIT(libassh, 0.1)
AC_PREREQ(2.50)

AC_CONFIG_AUX_DIR(build)
AM_INIT_AUTOMAKE(libassh, 0.1)
AC_CONFIG_HEADERS(config.h)
AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CC

AM_PROG_LIBTOOL 

AC_LANG(C)

AC_STDC_HEADERS
AC_CHECK_HEADERS(assert.h, AC_DEFINE([HAVE_ASSERT_H]))

AC_C_CONST
AC_C_INLINE

AC_ARG_ENABLE(gcrypt, AC_HELP_STRING(--enable-gcrypt, [Gcrypt support]),
		       enable_gcrypt=$enableval, enable_gcrypt=no)

if test x$enable_gcrypt = xyes ; then
  AC_CHECK_LIB(gcrypt, gcry_cipher_open, [
    AC_CHECK_HEADERS(gcrypt.h, [
      AC_DEFINE([CONFIG_ASSH_USE_GCRYPT], [], [Libgcrypt support])
      enable_gcrypt=found
      LIBS="$LIBS -lgcrypt"
    ])
  ])
fi

AM_CONDITIONAL(COND_gcrypt, [test x$enable_gcrypt = xfound])

AC_DEFINE([CONFIG_ASSH_SERVER], [], [SSH server support])
AC_DEFINE([CONFIG_ASSH_SERVER_AUTH_PUBLICKEY], [], [SSH server authentication: public key support])
AC_DEFINE([CONFIG_ASSH_SERVER_AUTH_PASSWORD], [], [SSH server authentication: password support])
#AC_DEFINE([CONFIG_ASSH_SERVER_AUTH_NONE], [], [SSH server authentication: bypassed, grant access directly])

AC_DEFINE([CONFIG_ASSH_CLIENT], [], [SSH client support])
AC_DEFINE([CONFIG_ASSH_CLIENT_AUTH_PUBLICKEY], [], [SSH client authentication: public key support])
AC_DEFINE([CONFIG_ASSH_CLIENT_AUTH_PASSWORD], [], [SSH client authentication: password support])
AC_DEFINE([CONFIG_ASSH_CLIENT_AUTH_USE_PKOK], [], [SSH client authentication: public key signature is not sent directly])

AC_DEFINE([CONFIG_ASSH_AUTH_USERNAME_LEN], [32], [SSH authentication max username length])
AC_DEFINE([CONFIG_ASSH_AUTH_PASSWORD_LEN], [32], [SSH authentication max password length])

#AC_DEFINE([CONFIG_ASSH_ALLOCA], [32], [Enable storing key related material on stack])

if test "$GCC" = "yes" ; then
    CFLAGS="-Wall $CFLAGS"
fi

AC_OUTPUT([
  Makefile
  src/Makefile
  src/assh/Makefile
  examples/Makefile
  test/Makefile
])

