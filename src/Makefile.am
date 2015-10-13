lib_LTLIBRARIES = libocsp.la
libocsp_la_SOURCES = ocsp.c

bin_PROGRAMS = ocsp
ocsp_SOURCES = main.c
ocsp_LDADD = -lgnutls -lcurl $(top_srcdir)/lib/libgnu.a libocsp.la
