.SUFFIXES: .o .c

# CHANGE THIS:
SPHINCSPLUS_REFERENCE_SOURCE_PATH=../../sphincsplus/ref

SHAKE_REFERENCE_SOURCES=\
$(SPHINCSPLUS_REFERENCE_SOURCE_PATH)/address.c \
$(SPHINCSPLUS_REFERENCE_SOURCE_PATH)/rng.c \
$(SPHINCSPLUS_REFERENCE_SOURCE_PATH)/merkle.c \
$(SPHINCSPLUS_REFERENCE_SOURCE_PATH)/wots.c \
$(SPHINCSPLUS_REFERENCE_SOURCE_PATH)/wotsx1.c \
$(SPHINCSPLUS_REFERENCE_SOURCE_PATH)/utils.c \
$(SPHINCSPLUS_REFERENCE_SOURCE_PATH)/utilsx1.c \
$(SPHINCSPLUS_REFERENCE_SOURCE_PATH)/fors.c \
$(SPHINCSPLUS_REFERENCE_SOURCE_PATH)/sign.c \
$(SPHINCSPLUS_REFERENCE_SOURCE_PATH)/fips202.c \
$(SPHINCSPLUS_REFERENCE_SOURCE_PATH)/hash_shake.c \
$(SPHINCSPLUS_REFERENCE_SOURCE_PATH)/thash_shake_simple.c


SHA2_REFERENCE_SOURCES=\
$(SPHINCSPLUS_REFERENCE_SOURCE_PATH)/address.c \
$(SPHINCSPLUS_REFERENCE_SOURCE_PATH)/rng.c \
$(SPHINCSPLUS_REFERENCE_SOURCE_PATH)/merkle.c \
$(SPHINCSPLUS_REFERENCE_SOURCE_PATH)/wots.c \
$(SPHINCSPLUS_REFERENCE_SOURCE_PATH)/wotsx1.c \
$(SPHINCSPLUS_REFERENCE_SOURCE_PATH)/utils.c \
$(SPHINCSPLUS_REFERENCE_SOURCE_PATH)/utilsx1.c \
$(SPHINCSPLUS_REFERENCE_SOURCE_PATH)/fors.c \
$(SPHINCSPLUS_REFERENCE_SOURCE_PATH)/sign.c \
$(SPHINCSPLUS_REFERENCE_SOURCE_PATH)/fips202.c \
$(SPHINCSPLUS_REFERENCE_SOURCE_PATH)/hash_sha2.c \
$(SPHINCSPLUS_REFERENCE_SOURCE_PATH)/thash_sha2_simple.c \
$(SPHINCSPLUS_REFERENCE_SOURCE_PATH)/sha2.c

CC=clang
CFLAGS+=-g
CFLAGS+=-std=c99 -pedantic -Wall -Werror -Wstrict-prototypes
CFLAGS+=-Wmissing-prototypes -Wmissing-declarations -Wshadow
CFLAGS+=-Wpointer-arith -Wcast-qual -Wsign-compare -O2
CFLAGS+=-fstack-protector-all -Wtype-limits -fno-common
CFLAGS+=-fno-builtin
CFLAGS+=-I$(SPHINCSPLUS_REFERENCE_SOURCE_PATH)/
CFLAGS+=-I/usr/local/include
CFLAGS+=-L/usr/local/lib
LDFLAGS=-lcrypto -ljansson
BUILDDIR=build
EXECS=\
shake_128s_gen\
shake_128f_gen\
shake_192s_gen\
shake_192f_gen\
shake_256s_gen\
shake_256f_gen\
sha2_128s_gen\
sha2_128f_gen\
sha2_192s_gen\
sha2_192f_gen\
sha2_256s_gen\
sha2_256f_gen

all: $(BUILDDIR) $(EXECS)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

shake_128s_gen: $(BUILDDIR) slhdsa_gen.c
	$(CC) $(CFLAGS) -DPARAMS=sphincs-shake-128s -DPFX=SLH-DSA-SHAKE-128s -o $(BUILDDIR)/shake_128s_gen $(SHAKE_REFERENCE_SOURCES) slhdsa_gen.c $(LDFLAGS)

shake_128f_gen: $(BUILDDIR) slhdsa_gen.c
	$(CC) $(CFLAGS) -DPARAMS=sphincs-shake-128f -DPFX=SLH-DSA-SHAKE-128f -o $(BUILDDIR)/shake_128f_gen $(SHAKE_REFERENCE_SOURCES) slhdsa_gen.c $(LDFLAGS)

shake_192s_gen: $(BUILDDIR) slhdsa_gen.c
	$(CC) $(CFLAGS) -DPARAMS=sphincs-shake-192s -DPFX=SLH-DSA-SHAKE-192s -o $(BUILDDIR)/shake_192s_gen $(SHAKE_REFERENCE_SOURCES) slhdsa_gen.c $(LDFLAGS)

shake_192f_gen: $(BUILDDIR) slhdsa_gen.c
	$(CC) $(CFLAGS) -DPARAMS=sphincs-shake-192f -DPFX=SLH-DSA-SHAKE-192f -o $(BUILDDIR)/shake_192f_gen $(SHAKE_REFERENCE_SOURCES) slhdsa_gen.c $(LDFLAGS)

shake_256s_gen: $(BUILDDIR) slhdsa_gen.c
	$(CC) $(CFLAGS) -DPARAMS=sphincs-shake-256s -DPFX=SLH-DSA-SHAKE-256s -o $(BUILDDIR)/shake_256s_gen $(SHAKE_REFERENCE_SOURCES) slhdsa_gen.c $(LDFLAGS)

shake_256f_gen: $(BUILDDIR) slhdsa_gen.c
	$(CC) $(CFLAGS) -DPARAMS=sphincs-shake-256f -DPFX=SLH-DSA-SHAKE-256f -o $(BUILDDIR)/shake_256f_gen $(SHAKE_REFERENCE_SOURCES) slhdsa_gen.c $(LDFLAGS)

sha2_128s_gen: $(BUILDDIR) slhdsa_gen.c
	$(CC) $(CFLAGS) -DPARAMS=sphincs-sha2-128s -DPFX=SLH-DSA-SHA2-128s -o $(BUILDDIR)/sha2_128s_gen $(SHA2_REFERENCE_SOURCES) slhdsa_gen.c $(LDFLAGS)

sha2_128f_gen: $(BUILDDIR) slhdsa_gen.c
	$(CC) $(CFLAGS) -DPARAMS=sphincs-sha2-128f -DPFX=SLH-DSA-SHA2-128f -o $(BUILDDIR)/sha2_128f_gen $(SHA2_REFERENCE_SOURCES) slhdsa_gen.c $(LDFLAGS)

sha2_192s_gen: $(BUILDDIR) slhdsa_gen.c
	$(CC) $(CFLAGS) -DPARAMS=sphincs-sha2-192s -DPFX=SLH-DSA-SHA2-192s -o $(BUILDDIR)/sha2_192s_gen $(SHA2_REFERENCE_SOURCES) slhdsa_gen.c $(LDFLAGS)

sha2_192f_gen: $(BUILDDIR) slhdsa_gen.c
	$(CC) $(CFLAGS) -DPARAMS=sphincs-sha2-192f -DPFX=SLH-DSA-SHA2-192f -o $(BUILDDIR)/sha2_192f_gen $(SHA2_REFERENCE_SOURCES) slhdsa_gen.c $(LDFLAGS)

sha2_256s_gen: $(BUILDDIR) slhdsa_gen.c
	$(CC) $(CFLAGS) -DPARAMS=sphincs-sha2-256s -DPFX=SLH-DSA-SHA2-256s -o $(BUILDDIR)/sha2_256s_gen $(SHA2_REFERENCE_SOURCES) slhdsa_gen.c $(LDFLAGS)

sha2_256f_gen: $(BUILDDIR) slhdsa_gen.c
	$(CC) $(CFLAGS) -DPARAMS=sphincs-sha2-256f -DPFX=SLH-DSA-SHA2-256f -o $(BUILDDIR)/sha2_256f_gen $(SHA2_REFERENCE_SOURCES) slhdsa_gen.c $(LDFLAGS)

clean:
	rm -rf $(BUILDDIR)
