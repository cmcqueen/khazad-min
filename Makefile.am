
#######################################
# The list of libraries we are building separated by spaces.
# The 'lib_' indicates that these build products will be installed
# in the $(libdir) directory. For example /usr/lib
lib_LTLIBRARIES = lib@PACKAGE_NAME@-@PACKAGE_VERSION@.la

#######################################
# Build information for each library


library_include_khazad_mindir=$(includedir)/@PACKAGE_NAME@-@PACKAGE_VERSION@
library_include_khazad_min_HEADERS = khazad.h
lib@PACKAGE_NAME@_@PACKAGE_VERSION@_la_SOURCES = khazad.c  khazad-matrix-mul.c  khazad-sbox.c
lib@PACKAGE_NAME@_@PACKAGE_VERSION@_la_SOURCES += khazad-add-block.h  khazad.h  khazad-matrix-mul.h  khazad-mul2.h  khazad-sbox.h
lib@PACKAGE_NAME@_@PACKAGE_VERSION@_la_LDFLAGS = -version-info @LIB_SO_VERSION@

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = @PACKAGE_NAME@.pc


#######################################
# Tests

TESTS = khazad-test

check_PROGRAMS = khazad-test

khazad_test_SOURCES = tests/khazad-test.c  khazad-print-block.h
khazad_test_LDADD = lib@PACKAGE_NAME@-@PACKAGE_VERSION@.la

