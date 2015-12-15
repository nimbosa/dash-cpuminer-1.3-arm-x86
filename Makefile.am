
if WANT_JANSSON
JANSSON_INCLUDES= -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES=
endif

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST	= example-cfg.json nomacro.pl

SUBDIRS		= compat

INCLUDES	= $(PTHREAD_FLAGS) -fno-strict-aliasing $(JANSSON_INCLUDES)

bin_PROGRAMS	= minerd

minerd_SOURCES	= elist.h miner.h compat.h \
		  cpu-miner.c util.c \
		  x2/sha2.c \
		  x2/scrypt.c \
		  x11/blake.c	x11/echo.c	x11/keccak.c	x11/simd.c \
		  x11/bmw.c	x11/groestl.c	x11/luffa.c	x11/skein.c \
		  x11/cubehash.c	x11/jh.c	x11/shavite.c x11/aes_helper.c \
		  x5/luffa_for_sse2.c x5/shavite.c x5/cubehash_sse2.c x5/vect128/nist.c x5/vect128/vector.c \
		  x5/echo512/ccalik/aesni/hash.c \
		  xcoin.c
minerd_LDFLAGS	= $(PTHREAD_FLAGS)
minerd_LDADD	= @LIBCURL@ @JANSSON_LIBS@ @PTHREAD_LIBS@ @WS2_LIBS@
minerd_CPPFLAGS = @LIBCURL_CPPFLAGS@

