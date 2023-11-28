.SUFFIXES: .o .c

CC=clang
CFLAGS+=-g
CFLAGS+=-std=c99 -pedantic -Wall -Werror -Wstrict-prototypes
CFLAGS+=-Wmissing-prototypes -Wmissing-declarations -Wshadow
CFLAGS+=-Wpointer-arith -Wcast-qual -Wsign-compare -O2
CFLAGS+=-fstack-protector-all -Wtype-limits -fno-common
CFLAGS+=-fno-builtin
CFLAGS+=-DPARAMS=$(SPHINCS_PARAMS)
CFLAGS+=-I$(SPHINCSPLUS_REFERENCE_SOURCE_PATH)/
LDFLAGS=-lcrypto
BUILDDIR=build
EXECS=\
orders

all: $(BUILDDIR) $(EXECS)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

orders: $(BUILDDIR) orders.c
	$(CC) $(CFLAGS) -o $(BUILDDIR)/orders $(SPHINCSPLUS_REFERENCE_SOURCES) orders.c $(LDFLAGS)

clean:
	rm -rf $(BUILDDIR)
