bin_PROGRAMS =
BUILT_SOURCES =
EXTRA_DIST =
CLEANFILES =
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

AM_CPPFLAGS = -include $(top_builddir)/config.h
AM_CFLAGS = ${my_CFLAGS}
AM_LDFLAGS =

SUFFIXES = .proto .pb-c.c .pb-c.h

.proto.pb-c.c:
	$(AM_V_GEN)@PROTOC_C@ "--c_out=`pwd`" -I$(top_srcdir) $<

.proto.pb-c.h:
	$(AM_V_GEN)@PROTOC_C@ "--c_out=`pwd`" -I$(top_srcdir) $<

PROTOBUF_SOURCES = dnstap.pb/dnstap.pb-c.c dnstap.pb/dnstap.pb-c.h
BUILT_SOURCES += ${PROTOBUF_SOURCES}
CLEANFILES += ${PROTOBUF_SOURCES}

bin_PROGRAMS += dnstap-ldns
dnstap_ldns_SOURCES = \
	dnstap-ldns.c \
	host2str.c \
	${PROTOBUF_SOURCES}
dnstap_ldns_CFLAGS = \
	${libldns_CFLAGS} \
	${libfstrm_CFLAGS} \
	${libprotobuf_c_CFLAGS}
dnstap_ldns_LDADD = \
	${libldns_LIBS} \
	${libfstrm_LIBS} \
	${libprotobuf_c_LIBS}
