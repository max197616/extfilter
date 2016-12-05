#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(extFilter, 0.2, max1976@mail.ru)

PPP_HOME=./PcapPlusPlus
DPDK_HOME=
DPDK_TARGET=

NDPI_HOME=./nDPI
NDPI_GIT_VERSION=dev

AM_INIT_AUTOMAKE()

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES(no)])

AC_CONFIG_SRCDIR([src/main.cpp])
AC_CONFIG_HEADERS([include/config.h])

AC_LANG([C++])
AC_LANG_PUSH([C++])

# store current user given compiler flags to avoid default setup via AC_PROG_CXX
OLD_CXXFLAGS=$CXXFLAGS
OLD_CFLAGS=$CFLAGS

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

CXXFLAGS=$OLD_CXXFLAGS
CFLAGS=$OLD_CFLAGS

CFLAGS="$CFLAGS --pedantic -Wall -O2"

AC_ARG_ENABLE(debug,
  AS_HELP_STRING(
    [--enable-debug],
    [enable debugging, default: no]),
    [case "${enableval}" in
      yes) debug=true ;;
      no)  debug=false ;;
      *)   AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
    esac],
    [debug=false])

AC_MSG_CHECKING([for debug enabled])


if test x"$debug" = x"true"; then
    CXXFLAGS="$CXXFLAGS -std=c++11 -O0 -g -Wall -pthread -msse -msse2 -msse3 -mssse3"
else
    CXXFLAGS="$CXXFLAGS -std=c++11 -O2 -Wall -pthread -msse -msse2 -msse3 -mssse3"
fi

AC_COMPILE_IFELSE([AC_LANG_SOURCE(
  [[template <typename T>
    struct check
    {
      static_assert(sizeof(int) <= sizeof(T), "not big enough");
    };

    typedef check<check<bool>> right_angle_brackets;

    int a;
    decltype(a) b;

    typedef check<int> check_type;
    check_type c;
    check_type&& cr = static_cast<check_type&&>(c);]])],,
  AC_MSG_FAILURE(['$CXX $CXXFLAGS' does not accept ISO C++11]))




# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([netinet/in.h stdint.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_CHECK_FUNCS([strerror])

# Check for methods in library and check for header files
AC_CHECK_HEADERS([Poco/Foundation.h Poco/Net/HTTPCookie.h Poco/Util/Timer.h],
   [],
   AC_MSG_ERROR([Poco include files not found.])
)

AC_CHECK_LIB([PocoFoundation],[main],[HAVE_POCOFOUNDATION=1],AC_MSG_ERROR([PocoFoundation library not found.]))
if test "$HAVE_POCOFOUNDATION"; then
     save_libs="${LIBS}"
     LIBS="-lPocoFoundation"
     AC_LINK_IFELSE(
         [AC_LANG_PROGRAM(
             [#include "Poco/UnicodeConverter.h"],
             [std::wstring wstr; Poco::UnicodeConverter::toUTF16("hello", wstr);]
         )],
         [LIBS="$LIBS $save_libs"],
         [AC_MSG_ERROR([linking with PocoFoundation failed.])]
     )
fi

AC_CHECK_LIB([PocoUtil],[main],[HAVE_POCOUTIL=1],AC_MSG_ERROR([PocoUtil library not found.]))
 if test "$HAVE_POCOUTIL"; then
     save_libs="${LIBS}"
     LIBS="-lPocoUtil"
     AC_LINK_IFELSE(
         [AC_LANG_PROGRAM(
             [#include "Poco/Util/Option.h"],
             [Poco::Util::Option();]
         )],
         [LIBS="$LIBS $save_libs"],
         [AC_MSG_ERROR([linking with PocoUtil failed.])]
     )
fi

AC_CHECK_LIB([PocoNet],[main],[HAVE_POCONET=1],AC_MSG_ERROR([PocoNet library not found.]))
if test "$HAVE_POCONET"; then
     save_libs="${LIBS}"
     LIBS="-lPocoNet"
     AC_LINK_IFELSE(
         [AC_LANG_PROGRAM(
             [#include "Poco/Net/HTTPClientSession.h"],
             [Poco::Net::HTTPClientSession();]
         )],
         [LIBS="$LIBS $save_libs"],
         [AC_MSG_ERROR([linking with PocoNET failed.])]
     )
fi

AC_ARG_WITH(
    [ppp_home],
    AS_HELP_STRING(
    	[--with-ppp_home=DIR],
    	    [Path to PcapPlusPlus library]
    ),
    [PPP_HOME="$withval"]
)

AC_ARG_WITH(
    [dpdk_home],
    AS_HELP_STRING(
    	[--with-dpdk_home=DIR],
    	    [Path to DPDK library]
    ),
    [DPDK_HOME="$withval"]
)

AC_ARG_WITH(
    [dpdk_target],
    AS_HELP_STRING(
    	[--with-dpdk_target=target],
    	    [DPDK target]
    ),
    [DPDK_TARGET="$withval"]
)

if test -z "$DPDK_TARGET"; then
    AC_MSG_ERROR([dpdk_target must be set])
fi

if test -z "$DPDK_HOME"; then
    AC_MSG_ERROR([dpdk_home must be set])
fi

dnl PcapPlusPlus checks...
AC_MSG_CHECKING(for PcapPlusPlus $PPP_HOME)
if test -d "$PPP_HOME" ; then :
    AC_MSG_RESULT(found in $PPP_HOME)
else
    AC_MSG_RESULT(not found)
    AC_MSG_NOTICE(Getting PPP from git)
#    git clone -b master https://github.com/max197616/PcapPlusPlus.git $PPP_HOME; cd $PPP_HOME; cd -
    git clone -b master https://github.com/seladb/PcapPlusPlus.git $PPP_HOME; cd $PPP_HOME; patch -p1 < ../ppp.patch; cd -
    AC_MSG_CHECKING(for PPP $PPP_HOME)
    if test -d "$PPP_HOME" ; then :
	AC_MSG_RESULT(found in $PPP_HOME)
    else
	AC_MSG_ERROR(Install PcapPlusPlus manually!)
    fi
fi

PPP_LIB=$PPP_HOME/Dist/libCommon++.a
AC_MSG_CHECKING(for $PPP_LIB)
if test -f "$PPP_LIB" ; then :
    AC_MSG_RESULT(yes)
else
    AC_MSG_RESULT([not found, compiling...])
    cd $PPP_HOME; ./configure-linux.sh --dpdk --dpdk-home $DPDK_HOME --dpdk-target $DPDK_TARGET; make; cd -
fi


AC_SUBST(DPDK_LIB,$DPDK_HOME/$DPDK_TARGET/lib)
AC_SUBST(DPDK_INCLUDE,$DPDK_HOME/$DPDK_TARGET/include)
AC_SUBST(PPP_LIB,$PPP_HOME/Dist)
AC_SUBST(PPP_HEADER,$PPP_LIB/header)

dnl nDPI checks...
AC_MSG_CHECKING(for nDPI $NDPI_HOME)
if test -d "$NDPI_HOME" ; then :
    AC_MSG_RESULT(found in $NDPI_HOME)
else
    AC_MSG_RESULT(not found)
    AC_MSG_NOTICE(Getting nDPI from git)
    git clone -b $NDPI_GIT_VERSION https://github.com/ntop/nDPI.git $NDPI_HOME; cd $NDPI_HOME; git checkout f51fef6 ; patch -p1 < ../ndpi-ssl.patch; cd -
    AC_MSG_CHECKING(for nDPI $NDPI_HOME)
    if test -d "$NDPI_HOME" ; then :
	AC_MSG_RESULT(found in $NDPI_HOME)
    else
	AC_MSG_ERROR(Install nDPI dev: git clone -b $NDPI_GIT_VERSION https://github.com/ntop/nDPI.git $NDPI_HOME; cd $NDPI_HOME; git checkout f51fef6 ; patch -p1 < ../ndpi-ssl.patch ; ./autogen.sh; make; cd - )
    fi
fi

NDPI_LIB=$NDPI_HOME/src/lib/.libs/libndpi.a
AC_MSG_CHECKING(for $NDPI_LIB)
if test -f "$NDPI_LIB" ; then :

else
    AC_MSG_RESULT([not found, compiling...])
    cd $NDPI_HOME; ./autogen.sh; make; cd -
fi
AC_MSG_RESULT(yes)

save_flags="${CXXFLAGS}"
CXXFLAGS="${CXXFLAGS} -I${NDPI_HOME}/src/include"
AC_MSG_CHECKING(for compiling with nDPI)
save_libs="${LIBS}"
LIBS="$NDPI_LIB"
AC_LINK_IFELSE(
         [AC_LANG_PROGRAM(
             [#include "ndpi_api.h"],
             [ndpi_revision();]
         )],
         [LIBS="$save_libs"],
         [AC_MSG_ERROR([Linking with nDPI failed!])]
)
AC_MSG_RESULT(yes)
CXXFLAGS="$save_flags"


AC_OUTPUT(Makefile src/Makefile include/Makefile)
