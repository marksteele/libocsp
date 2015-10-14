lib_LTLIBRARIES = libocsp.la
libocsp_la_SOURCES = ocsp.c
libocsp_la_LIBADD = -lgnutls -lcurl
include_HEADERS = ocsp.h

bin_PROGRAMS = ocsp
ocsp_SOURCES = main.c
ocsp_LDADD = $(top_srcdir)/lib/libgnu.a libocsp.la
