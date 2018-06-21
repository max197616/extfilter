#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(extFilter, 0.99a, max1976@mail.ru)

DPDK_HOME=
DPDK_TARGET=

PEAFOWL_HOME=./peafowl
PEAFOWL_BRANCH="-b exp"

MARISA_HOME=./marisa

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
    CXXFLAGS="$CXXFLAGS -std=c++11 -O0 -g -Wall -pthread"
else
    CXXFLAGS="$CXXFLAGS -std=c++11 -O3 -Wall -fno-stack-protector -pthread"
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


# Macros for SSE availability check.
AC_DEFUN([EXTFILTER_ENABLE_SSE2],
          [AC_EGREP_CPP([yes], [
#ifdef __SSE2__
yes
#endif
          ], [enable_sse2="yes"], [enable_sse2="no"])])
AC_DEFUN([EXTFILTER_ENABLE_SSE3],
          [AC_EGREP_CPP([yes], [
#ifdef __SSE3__
yes
#endif
          ], [enable_sse3="yes"], [enable_sse3="no"])])
AC_DEFUN([EXTFILTER_ENABLE_SSSE3],
         [AC_EGREP_CPP([yes], [
#ifdef __SSSE3__
yes
#endif
         ], [enable_ssse3="yes"], [enable_ssse3="no"])])
AC_DEFUN([EXTFILTER_ENABLE_SSE4_1],
         [AC_EGREP_CPP([yes], [
#ifdef __SSE4_1__
yes
#endif
         ], [enable_sse4_1="yes"], [enable_sse4_1="no"])])
AC_DEFUN([EXTFILTER_ENABLE_SSE4_2],
         [AC_EGREP_CPP([yes], [
#ifdef __SSE4_2__
yes
#endif
         ], [enable_sse4_2="yes"], [enable_sse4_2="no"])])
AC_DEFUN([EXTFILTER_ENABLE_SSE4],
         [AC_EGREP_CPP([yes], [
#if defined(__POPCNT__) && defined(__SSE4_2__)
yes
#endif
         ], [enable_sse4="yes"], [enable_sse4="no"])])
AC_DEFUN([EXTFILTER_ENABLE_SSE4A],
         [AC_EGREP_CPP([yes], [
#ifdef __SSE4A__
yes
#endif
         ], [enable_sse4a="yes"], [enable_sse4a="no"])])
AC_DEFUN([EXTFILTER_ENABLE_AVX],
         [AC_EGREP_CPP([yes], [
#ifdef __AVX__
yes
#endif
         ], [enable_avx="yes"], [enable_avx="no"])])
AC_DEFUN([EXTFILTER_ENABLE_AVX2],
         [AC_EGREP_CPP([yes], [
#ifdef __AVX2__
yes
#endif
         ], [enable_avx2="yes"], [enable_avx2="no"])])


AC_DEFUN([EXTFILTER_ENABLE_POPCNT],
         [AC_EGREP_CPP([yes], [
#ifdef __POPCNT__
yes
#endif
         ], [enable_popcnt="yes"], [enable_popcnt="no"])])

# Enable native cpu instructions.
AC_MSG_CHECKING([whether to enable optimization for native cpu])
AC_ARG_ENABLE([native-code],
              [AS_HELP_STRING([--enable-native-code],
                              [generate instructions for native cpu [default=no]])],
              [],
              [enable_native_code="no"])
AS_IF([test "x${enable_native_code}" != "xno"], [
  CFLAGS="$CPPFLAGS -march=native -mtune=native"
  CPPFLAGS="$CPPFLAGS -march=native -mtune=native"
  CXXFLAGS="$CXXFLAGS -march=native -mtune=native"
  EXTFILTER_ENABLE_SSE2
  EXTFILTER_ENABLE_SSE3
  EXTFILTER_ENABLE_SSE4_1
  EXTFILTER_ENABLE_SSE4_2
  EXTFILTER_ENABLE_SSE4
  EXTFILTER_ENABLE_SSE4A
  EXTFILTER_ENABLE_AVX
  EXTFILTER_ENABLE_AVX2
  EXTFILTER_ENABLE_POPCNT
])
AC_MSG_RESULT([${enable_native_code}])

# Checks for SSE availability.
AC_MSG_CHECKING([whether to use SSE2])
AC_ARG_ENABLE([sse2],
              [AS_HELP_STRING([--enable-sse2],
                              [use SSE2 [default=no]])],
              [],
              [enable_sse2="no"])
AS_IF([test "x${enable_sse2}" != "xno"], [EXTFILTER_ENABLE_SSE2])
AC_MSG_RESULT([${enable_sse2}])

AC_MSG_CHECKING([whether to use SSE3])
AC_ARG_ENABLE([sse3],
              [AS_HELP_STRING([--enable-sse3],
                              [use SSE3 [default=no]])],
              [],
              [enable_sse3="no"])
AS_IF([test "x${enable_sse3}" != "xno"], [EXTFILTER_ENABLE_SSE3])
AC_MSG_RESULT([${enable_sse3}])

AC_MSG_CHECKING([whether to use SSSE3])
AC_ARG_ENABLE([ssse3],
              [AS_HELP_STRING([--enable-ssse3],
                              [use SSSE3 [default=no]])],
              [],
              [enable_ssse3="no"])
AS_IF([test "x${enable_ssse3}" != "xno"], [EXTFILTER_ENABLE_SSSE3])
AC_MSG_RESULT([${enable_ssse3}])

AC_MSG_CHECKING([whether to use SSE4.1])
AC_ARG_ENABLE([sse4.1],
              [AS_HELP_STRING([--enable-sse4.1],
                              [use SSE4.1 [default=no]])],
              [],
              [enable_sse4_1="no"])
AS_IF([test "x${enable_sse4_1}" != "xno"], [EXTFILTER_ENABLE_SSE4_1])
AC_MSG_RESULT([${enable_sse4_1}])

AC_MSG_CHECKING([whether to use SSE4.2])
AC_ARG_ENABLE([sse4.2],
              [AS_HELP_STRING([--enable-sse4.2],
                              [use SSE4.2 [default=no]])],
              [],
              [enable_sse4_2="no"])
AS_IF([test "x${enable_sse4_2}" != "xno"], [EXTFILTER_ENABLE_SSE4_2])
AC_MSG_RESULT([${enable_sse4_2}])

AC_MSG_CHECKING([whether to use SSE4])
AC_ARG_ENABLE([sse4],
              [AS_HELP_STRING([--enable-sse4],
                              [use SSE4 [default=no]])],
              [],
              [enable_sse4="no"])
AS_IF([test "x${enable_sse4}" != "xno"], [EXTFILTER_ENABLE_SSE4])
AC_MSG_RESULT([${enable_sse4}])

AC_MSG_CHECKING([whether to use SSE4a])
AC_ARG_ENABLE([sse4a],
              [AS_HELP_STRING([--enable-sse4a],
                              [use SSE4a [default=no]])],
              [],
              [enable_sse4a="no"])
AS_IF([test "x${enable_sse4a}" != "xno"], [EXTFILTER_ENABLE_SSE4A])
AC_MSG_RESULT([${enable_sse4a}])

AC_MSG_CHECKING([whether to use AVX])
AC_ARG_ENABLE([avx],
              [AS_HELP_STRING([--enable-avx],
                              [use AVX [default=no]])],
              [],
              [enable_avx="no"])
AS_IF([test "x${enable_avx}" != "xno"], [EXTFILTER_ENABLE_AVX])
AC_MSG_RESULT([${enable_avx}])

AC_MSG_CHECKING([whether to use AVX2])
AC_ARG_ENABLE([avx2],
              [AS_HELP_STRING([--enable-avx2],
                              [use AVX2 [default=no]])],
              [],
              [enable_avx2="no"])
AS_IF([test "x${enable_avx2}" != "xno"], [EXTFILTER_ENABLE_AVX2])
AC_MSG_RESULT([${enable_avx2}])

AC_MSG_CHECKING([whether to use popcnt])
AC_ARG_ENABLE([popcnt],
              [AS_HELP_STRING([--enable-popcnt],
                              [use POPCNT [default=no]])],
              [],
              [enable_popcnt="no"])
AS_IF([test "x${enable_popcnt}" != "xno"], [EXTFILTER_ENABLE_POPCNT])
AC_MSG_RESULT([${enable_popcnt}])



AS_IF([test "x${enable_popcnt}" != "xno"], [
  enable_sse3="yes"
])

AS_IF([test "x${enable_avx2}" != "xno"], [
  enable_popcnt="yes"
  enable_avx2="yes"
])
AS_IF([test "x${enable_avx}" != "xno"], [
  enable_popcnt="yes"
  enable_avx="yes"
])
AS_IF([test "x${enable_sse4a}" != "xno"], [
  enable_popcnt="yes"
  enable_sse3="yes"
])
AS_IF([test "x${enable_sse4}" != "xno"], [
  enable_popcnt="yes"
  enable_sse4_2="yes"
])
AS_IF([test "x${enable_sse4_2}" != "xno"], [
  enable_popcnt="yes"
  enable_sse4_1="yes"
])
AS_IF([test "x${enable_sse4_1}" != "xno"], [
  enable_ssse3="yes"
])
AS_IF([test "x${enable_ssse3}" != "xno"], [
  enable_sse3="yes"
])
AS_IF([test "x${enable_sse3}" != "xno"], [
  enable_sse2="yes"
])

AS_IF([test "x${enable_popcnt}" != "xno"], [
  CXXFLAGS="$CXXFLAGS -mpopcnt"
])

if test "x${enable_avx2}" != "xno"; then
  CXXFLAGS="$CXXFLAGS -mavx2"
elif test "x${enable_avx}" != "xno"; then
  CXXFLAGS="$CXXFLAGS -mavx"
elif test "x${enable_sse4a}" != "xno"; then
  CXXFLAGS="$CXXFLAGS -msse4a"
elif test "x${enable_sse4}" != "xno"; then
  CXXFLAGS="$CXXFLAGS -msse4"
elif test "x${enable_sse4_2}" != "xno"; then
  CXXFLAGS="$CXXFLAGS -msse4.2"
elif test "x${enable_sse4_1}" != "xno"; then
  CXXFLAGS="$CXXFLAGS -msse4.1"
elif test "x${enable_ssse3}" != "xno"; then
  CXXFLAGS="$CXXFLAGS -mssse3"
elif test "x${enable_sse3}" != "xno"; then
  CXXFLAGS="$CXXFLAGS -msse3"
elif test "x${enable_sse2}" != "xno"; then
  CXXFLAGS="$CXXFLAGS -msse2"
fi


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


AC_SUBST(DPDK_LIB,$DPDK_HOME/$DPDK_TARGET/lib)
AC_SUBST(DPDK_INCLUDE,$DPDK_HOME/$DPDK_TARGET/include)

dnl peafowl checks...
AC_MSG_CHECKING(for peafowl $PEAFOWL_HOME)
if test -d "$PEAFOWL_HOME" ; then :
    AC_MSG_RESULT(found in $PEAFOWL_HOME)
else
    AC_MSG_RESULT(not found)
    AC_MSG_NOTICE(Getting peafowl from git)
    git clone $PEAFOWL_BRANCH https://github.com/max197616/Peafowl.git $PEAFOWL_HOME
    AC_MSG_CHECKING(for peafowl $PEAFOWL_HOME)
    if test -d "$PEAFOWL_HOME" ; then :
	AC_MSG_RESULT(found in $PEAFOWL_HOME)
    else
	AC_MSG_ERROR(Install peafowl manually)
    fi
fi

PEAFOWL_LIB=$PEAFOWL_HOME/lib/libdpi.a
AC_MSG_CHECKING(for $PEAFOWL_LIB)
if test -f "$PEAFOWL_LIB" ; then :

else
    AC_MSG_RESULT([not found, compiling...])
    cd $PEAFOWL_HOME; make; cd -
    if test -f "$PEAFOWL_LIB" ; then :
	
    else
	AC_MSG_ERROR([Peafowl library not found!])
    fi
fi
AC_MSG_RESULT(yes)

AC_SUBST(PEAFOWL_INCLUDE, $PEAFOWL_HOME/src)
AC_SUBST(PEAFOWL_LIB, $PEAFOWL_LIB)

dnl marisa-trie checks...
AC_MSG_CHECKING(for marisa-trie $MARISA_HOME)
if test -d "$MARISA_HOME" ; then :
    AC_MSG_RESULT(found in $MARISA_HOME)
else
    AC_MSG_RESULT(not found)
    AC_MSG_NOTICE(Getting marisa-trie from git)
    git clone https://github.com/max197616/marisa-trie.git $MARISA_HOME
    AC_MSG_CHECKING(for marisa-trie $MARISA_HOME)
    if test -d "$MARISA_HOME" ; then :
	AC_MSG_RESULT(found in $MARISA_HOME)
    else
	AC_MSG_ERROR(Install marisa-trie manually)
    fi
fi

MARISA_LIB=$MARISA_HOME/lib/marisa/.libs/libmarisa.a
AC_MSG_CHECKING(for $MARISA_LIB)
if test -f "$MARISA_LIB" ; then :

else
    AC_MSG_RESULT([not found, compiling...])
    cd $MARISA_HOME; autoreconf -i; ./configure --enable-native-code; make; cd -
    if test -f "$MARISA_LIB" ; then :
	
    else
	AC_MSG_ERROR([Marisa-trie library not found!])
    fi
fi
AC_MSG_RESULT(yes)

AC_SUBST(MARISA_INCLUDE, $MARISA_HOME/include)
AC_SUBST(MARISA_LIB, $MARISA_LIB)

AC_OUTPUT(Makefile src/Makefile include/Makefile)

AS_ECHO([])
AS_ECHO(["${PACKAGE_NAME} ${PACKAGE_VERSION} configuration:"])
AS_ECHO(["-------------------------------"])
AS_ECHO(["  HOST:      ${HOST}"])
AS_ECHO(["  CXX:       ${CXX}"])
AS_ECHO(["  CXXFLAGS:  ${CXXFLAGS}"])
AS_ECHO(["  LDFLAGS:   ${LDFLAGS}"])
AS_ECHO(["  PREFIX:    ${prefix}"])
AS_ECHO([])
AS_ECHO(["  NATIVE:    ${enable_native_code}"])
AS_ECHO(["  SSE2:      ${enable_sse2}"])
AS_ECHO(["  SSE3:      ${enable_sse3}"])
AS_ECHO(["  SSSE3:     ${enable_ssse3}"])
AS_ECHO(["  SSE4.1:    ${enable_sse4_1}"])
AS_ECHO(["  SSE4.2:    ${enable_sse4_2}"])
AS_ECHO(["  SSE4a:     ${enable_sse4a}"])
AS_ECHO(["  AVX:       ${enable_avx}"])
AS_ECHO(["  AVX2:      ${enable_avx2}"])
AS_ECHO(["  POPCNT:    ${enable_popcnt}"])
AS_ECHO([])
