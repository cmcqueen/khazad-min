
#######################################
# The list of libraries we are building separated by spaces.
# The 'lib_' indicates that these build products will be installed
# in the $(libdir) directory. For example /usr/lib
lib_LTLIBRARIES = lib@PACKAGE_NAME@.la

#######################################
# Build information for each library


library_include_khazad_mindir=$(includedir)/@PACKAGE_NAME@
library_include_khazad_min_HEADERS = khazad-min.h
lib@PACKAGE_NAME@_la_SOURCES = khazad-min.c

lib@PACKAGE_NAME@_la_CFLAGS = -DENABLE_LONG_TEST=${ENABLE_LONG_TEST}
if ENABLE_SBOX_SMALL
lib@PACKAGE_NAME@_la_CFLAGS += -DENABLE_SBOX_SMALL
endif

lib@PACKAGE_NAME@_la_LDFLAGS = -version-info @LIB_SO_VERSION@

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = @PACKAGE_NAME@.pc


#######################################
# Tests

TESTS = khazad-test khazad-sbox-test khazad-vectors-test

check_PROGRAMS = khazad-sbox-test khazad-test khazad-vectors-test

khazad_test_SOURCES = tests/khazad-test.c khazad-print-block.h
khazad_test_LDADD = lib@PACKAGE_NAME@.la

khazad_sbox_test_SOURCES = tests/khazad-sbox-test.c khazad-print-block.h
khazad_sbox_test_LDADD = lib@PACKAGE_NAME@.la

khazad_vectors_test_SOURCES = tests/khazad-vectors-test.c tests/khazad-test-vectors.h khazad-print-block.h
khazad_vectors_test_CFLAGS = -DENABLE_LONG_TEST=${ENABLE_LONG_TEST}
khazad_vectors_test_LDADD = lib@PACKAGE_NAME@.la
