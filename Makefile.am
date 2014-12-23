
#######################################
# The list of libraries we are building separated by spaces.
# The 'lib_' indicates that these build products will be installed
# in the $(libdir) directory. For example /usr/lib
lib_LTLIBRARIES = lib@PACKAGE_NAME@-@PACKAGE_VERSION@.la

#######################################
# Build information for each library


library_include_khazad_mindir=$(includedir)/@PACKAGE_NAME@-@PACKAGE_VERSION@
library_include_khazad_min_HEADERS = khazad.h khazad-otfks.h
lib@PACKAGE_NAME@_@PACKAGE_VERSION@_la_SOURCES = khazad-crypt.c khazad-decrypt.c khazad-key-schedule.c khazad-decrypt-key-schedule.c khazad-matrix-mul.c
lib@PACKAGE_NAME@_@PACKAGE_VERSION@_la_SOURCES += khazad-otfks-encrypt.c khazad-otfks-decrypt.c khazad-otfks-key.c
if ENABLE_SBOX_SMALL
lib@PACKAGE_NAME@_@PACKAGE_VERSION@_la_SOURCES += khazad-sbox-small.c
else
lib@PACKAGE_NAME@_@PACKAGE_VERSION@_la_SOURCES += khazad-sbox.c
endif
lib@PACKAGE_NAME@_@PACKAGE_VERSION@_la_SOURCES += khazad-add-block.h khazad.h khazad-matrix-mul.h khazad-mul2.h khazad-sbox.h khazad-round-funcs.h
lib@PACKAGE_NAME@_@PACKAGE_VERSION@_la_LDFLAGS = -version-info @LIB_SO_VERSION@

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = @PACKAGE_NAME@.pc


#######################################
# Tests

TESTS = khazad-test khazad-sbox-test

check_PROGRAMS = khazad-sbox-test khazad-test

khazad_test_SOURCES = tests/khazad-test.c khazad-print-block.h
khazad_test_LDADD = lib@PACKAGE_NAME@-@PACKAGE_VERSION@.la

khazad_sbox_test_SOURCES = tests/khazad-sbox-test.c khazad-print-block.h
khazad_sbox_test_LDADD = lib@PACKAGE_NAME@-@PACKAGE_VERSION@.la
