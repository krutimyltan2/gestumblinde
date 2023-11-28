.SUFFIXES: .o .c

TINY_SHA3_PATH=/home/olikru/packages/tiny_sha3

CC=clang
SOURCES=\
fors.c\
hash.c\
ht.c\
slh.c\
utils.c\
wotsp.c\
xmss.c
BENCHSOURCE=bench.c
CLCOMMON=clcommon.c
KEYGENSOURCE=keygen.c
SIGNSOURCE=sign.c
VERIFSOURCE=verif.c
DEPS=\
context.h\
utils.h\
wotsp.h\
hash.h\
address.h\
xmss.h\
ht.h\
fors.h\
slh.h\
clcommon.h
CFLAGS+=-std=c99 -pedantic -Wall -Werror -Wstrict-prototypes
CFLAGS+=-Wmissing-prototypes -Wmissing-declarations -Wshadow
CFLAGS+=-Wpointer-arith -Wcast-qual -Wsign-compare
CFLAGS+=-O2 -g
#CFLAGS+=-O3 -DNDEBUG
CFLAGS+=-fstack-protector-all -Wtype-limits -fno-common
CFLAGS+=-fno-builtin
CFLAGS+=-I$(TINY_SHA3_PATH) -I/usr/local/include
LDFLAGS=-L/usr/local/lib -lcrypto
BUILDDIR=build

all: $(BUILDDIR) keygen sign verif

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

keygen: $(DEPS)
	$(CC) $(CFLAGS) -DSLH_DSA_SHAKE_128S -o $(BUILDDIR)/keygen_shake_128s $(SOURCES) $(TINY_SHA3_PATH)/sha3.c $(CLCOMMON) $(KEYGENSOURCE) $(LDFLAGS)

sign: $(DEPS)
	$(CC) $(CFLAGS) -DSLH_DSA_SHAKE_128S -o $(BUILDDIR)/sign_shake_128s $(SOURCES) $(TINY_SHA3_PATH)/sha3.c $(CLCOMMON) $(SIGNSOURCE) $(LDFLAGS)

verif: $(DEPS)
	$(CC) $(CFLAGS) -DSLH_DSA_SHAKE_128S -o $(BUILDDIR)/verif_shake_128s $(SOURCES) $(TINY_SHA3_PATH)/sha3.c $(CLCOMMON) $(VERIFSOURCE) $(LDFLAGS)

benchmarks: $(DEPS)
	$(CC) $(CFLAGS) -DSLH_DSA_SHAKE_128S -o $(BUILDDIR)/benchmark_shake_128s $(SOURCES) $(TINY_SHA3_PATH)/sha3.c $(BENCHSOURCE) $(LDFLAGS)
	$(CC) $(CFLAGS) -DSLH_DSA_SHAKE_128F -o $(BUILDDIR)/benchmark_shake_128f $(SOURCES) $(TINY_SHA3_PATH)/sha3.c $(BENCHSOURCE) $(LDFLAGS)
	$(CC) $(CFLAGS) -DSLH_DSA_SHAKE_192S -o $(BUILDDIR)/benchmark_shake_192s $(SOURCES) $(TINY_SHA3_PATH)/sha3.c $(BENCHSOURCE) $(LDFLAGS)
	$(CC) $(CFLAGS) -DSLH_DSA_SHAKE_192F -o $(BUILDDIR)/benchmark_shake_192f $(SOURCES) $(TINY_SHA3_PATH)/sha3.c $(BENCHSOURCE) $(LDFLAGS)
	$(CC) $(CFLAGS) -DSLH_DSA_SHAKE_256S -o $(BUILDDIR)/benchmark_shake_256s $(SOURCES) $(TINY_SHA3_PATH)/sha3.c $(BENCHSOURCE) $(LDFLAGS)
	$(CC) $(CFLAGS) -DSLH_DSA_SHAKE_256F -o $(BUILDDIR)/benchmark_shake_256f $(SOURCES) $(TINY_SHA3_PATH)/sha3.c $(BENCHSOURCE) $(LDFLAGS)
	$(CC) $(CFLAGS) -DSLH_DSA_SHA2_128S -o $(BUILDDIR)/benchmark_sha2_128s $(SOURCES) $(TINY_SHA3_PATH)/sha3.c $(BENCHSOURCE) $(LDFLAGS)
	$(CC) $(CFLAGS) -DSLH_DSA_SHA2_128F -o $(BUILDDIR)/benchmark_sha2_128f $(SOURCES) $(TINY_SHA3_PATH)/sha3.c $(BENCHSOURCE) $(LDFLAGS)
	$(CC) $(CFLAGS) -DSLH_DSA_SHA2_192S -o $(BUILDDIR)/benchmark_sha2_192s $(SOURCES) $(TINY_SHA3_PATH)/sha3.c $(BENCHSOURCE) $(LDFLAGS)
	$(CC) $(CFLAGS) -DSLH_DSA_SHA2_192F -o $(BUILDDIR)/benchmark_sha2_192f $(SOURCES) $(TINY_SHA3_PATH)/sha3.c $(BENCHSOURCE) $(LDFLAGS)
	$(CC) $(CFLAGS) -DSLH_DSA_SHA2_256S -o $(BUILDDIR)/benchmark_sha2_256s $(SOURCES) $(TINY_SHA3_PATH)/sha3.c $(BENCHSOURCE) $(LDFLAGS)
	$(CC) $(CFLAGS) -DSLH_DSA_SHA2_256F -o $(BUILDDIR)/benchmark_sha2_256f $(SOURCES) $(TINY_SHA3_PATH)/sha3.c $(BENCHSOURCE) $(LDFLAGS)

clean:
	rm -rf $(BUILDDIR)
