# ------------------------------------------------------------------------------
# versions

AC_PREREQ([2.64])
AC_INIT([no.jklm.network],
        [1],
        [http://www.github.com/teg],
        [www.jklm.no],
        [http://www.github.com/teg])

# ------------------------------------------------------------------------------
# autotools

AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_MACRO_DIR([build/m4])
AC_CONFIG_HEADERS([build/config.h])
AC_CONFIG_AUX_DIR([build/build-aux])

# suppress conflicting defaults
CFLAGS=${CFLAGS:-""}
CXXFLAGS=${CXXFLAGS:-""}

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AM_MAINTAINER_MODE([enable])
AM_INIT_AUTOMAKE([foreign 1.11 -Wall -Wno-portability silent-rules tar-pax no-dist-gzip dist-xz subdir-objects parallel-tests])
AM_SILENT_RULES([yes])
AC_CANONICAL_HOST
AC_DEFINE_UNQUOTED([CANONICAL_HOST], "$host", [Canonical host string.])
AC_PROG_CC_C99
AC_PROG_RANLIB

m4_pattern_forbid([^_?PKG_[A-Z_]+$],[*** pkg.m4 missing, please install pkg-config])

AC_CHECK_TOOL([ASTYLE], [astyle], [no])
AM_CONDITIONAL([HAVE_ASTYLE], [test "$ASTYLE" != no])
AC_SUBST(HAVE_ASTYLE)

# ------------------------------------------------------------------------------
# toolchain

OUR_CFLAGS=${OUR_CFLAGS:-$(echo \
        -g \
        -Og \
        -pipe \
        -ftrapv \
        -ffast-math \
        -fno-common \
        -fdiagnostics-show-option \
        -fno-strict-aliasing \
        -fvisibility=hidden \
        -ffunction-sections \
        -fdata-sections \
        -fstack-protector \
        -fstack-protector-strong \
        -fPIC \
        --param=ssp-buffer-size=4 \
        -Wall \
        -Wextra \
        -Wno-inline \
        -Wundef \
        -Wformat=2 \
        -Wformat-security \
        -Wformat-nonliteral \
        -Wsign-compare \
        -Wmissing-include-dirs \
        -Wold-style-definition \
        -Wpointer-arith \
        -Winit-self \
        -Wdeclaration-after-statement \
        -Wfloat-equal \
        -Wmissing-prototypes \
        -Wstrict-prototypes \
        -Wredundant-decls \
        -Wmissing-declarations \
        -Wmissing-noreturn \
        -Wshadow \
        -Wendif-labels \
        -Wstrict-aliasing=2 \
        -Wwrite-strings \
        -Wno-long-long \
        -Wno-overlength-strings \
        -Wno-unused-parameter \
        -Wno-missing-field-initializers \
        -Wno-unused-result \
        -Werror=overflow \
        -Wnested-externs)}

OUR_CPPFLAGS=${OUR_CPPFLAGS:-$(echo \
        -Wp,-D_FORTIFY_SOURCE=2)}

OUR_LDFLAGS=${OUR_LDFLAGS:-$(echo \
        -Wl,--as-needed \
        -Wl,--no-undefined \
        -Wl,--gc-sections \
        -Wl,-z,relro \
        -Wl,-z,now \
        -pie)}

AC_SUBST(OUR_CFLAGS)
AC_SUBST(OUR_CPPFLAGS)
AC_SUBST(OUR_LDFLAGS)

# ------------------------------------------------------------------------------
AS_CASE([$host],
        [x86_64*], [ARCHITECTURE_TUPLE=x86_64-linux-gnu],
        [arm*],    [ARCHITECTURE_TUPLE=arm-linux-gnueabihf],
        [AC_MSG_ERROR([*** unknown architecture])]
)
AC_SUBST(ARCHITECTURE_TUPLE)

# ------------------------------------------------------------------------------
# dependencies

AC_ARG_ENABLE(static, AS_HELP_STRING([--enable-static], [enable temporary static library linking]))
AS_IF([test "$enable_static" = "yes"], [
        VARLINK_CFLAGS="-I${srcdir}/../../varlink/libvarlink/lib"
        VARLINK_LIBS="-L${srcdir}/../../varlink/libvarlink -lvarlink"
        AC_SUBST(VARLINK_CFLAGS)
        AC_SUBST(VARLINK_LIBS)
], [
        PKG_CHECK_MODULES(VARLINK, [libvarlink],
                [AC_DEFINE(HAVE_VARLINK, 1, [Define if libvarlink is available])],
                AC_MSG_ERROR([*** libvarlink not found]))
])

PKG_CHECK_MODULES(NETLINK, [libnl-3.0],
        [AC_DEFINE(HAVE_NETLINK, 1, [Define if netlink is available])],
        AC_MSG_ERROR([*** libnl not found]))

PKG_CHECK_MODULES(RTNETLINK, [libnl-route-3.0],
        [AC_DEFINE(HAVE_RTNETLINK, 1, [Define if rtnl is available])],
        AC_MSG_ERROR([*** libnl-route not found]))

# ------------------------------------------------------------------------------
# report

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
AC_MSG_RESULT([
        $PACKAGE_NAME $VERSION
        prefix:                 ${prefix}
        exec_prefix:            ${exec_prefix}
        includedir:             ${includedir}

        CFLAGS:                 ${OUR_CFLAGS} ${CFLAGS}
        CPPFLAGS:               ${OUR_CPPFLAGS} ${CPPFLAGS}
        LDFLAGS:                ${OUR_LDFLAGS} ${LDFLAGS}

        HOST:                   ${host}
        ARCHITECTURE_TUPLE:     ${ARCHITECTURE_TUPLE}

        ASTYLE:                 ${ASTYLE}
])
