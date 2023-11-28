.SUFFIXES: .o .c

TINY_SHA3_PATH=/home/olikru/packages/tiny_sha3
#TINY_SHA3_OBJ=$(TINY_SHA3_PATH)/sha3.o

CC=clang
BASE_SOURCES=\
../fors.c\
../hash.c\
../ht.c\
../slh.c\
../utils.c\
../wotsp.c\
../xmss.c
TEST_SOURCES=\
test_fors.c\
test_ht.c\
test_slh.c\
test_wotsp.c\
test_xmss.c\
utils.c\
tests.c
utils.cCFLAGS+=-std=c99 -pedantic -Wall -Werror -Wstrict-prototypes
CFLAGS+=-Wmissing-prototypes -Wmissing-declarations -Wshadow
CFLAGS+=-Wpointer-arith -Wcast-qual -Wsign-compare -O2
CFLAGS+=-fstack-protector-all -Wtype-limits -fno-common
CFLAGS+=-fno-builtin
CFLAGS+=-I$(TINY_SHA3_PATH) -I/usr/local/include
LDFLAGS=-L/usr/local/lib -ljansson -lcunit -lcrypto
TESTBIN=tests
BUILDDIR=build

all: $(BUILDDIR) tests

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

tests: $(BUILDDIR)
	${CC} ${CFLAGS} -DSLH_DSA_SHAKE_128S -o $(BUILDDIR)/${TESTBIN}_shake_128s $(BASE_SOURCES) $(TEST_SOURCES) $(TINY_SHA3_PATH)/sha3.c ${LDFLAGS}
	${CC} ${CFLAGS} -DSLH_DSA_SHAKE_128F -o $(BUILDDIR)/${TESTBIN}_shake_128f $(BASE_SOURCES) $(TEST_SOURCES) $(TINY_SHA3_PATH)/sha3.c ${LDFLAGS}
	${CC} ${CFLAGS} -DSLH_DSA_SHAKE_192S -o $(BUILDDIR)/${TESTBIN}_shake_192s $(BASE_SOURCES) $(TEST_SOURCES) $(TINY_SHA3_PATH)/sha3.c ${LDFLAGS}
	${CC} ${CFLAGS} -DSLH_DSA_SHAKE_192F -o $(BUILDDIR)/${TESTBIN}_shake_192f $(BASE_SOURCES) $(TEST_SOURCES) $(TINY_SHA3_PATH)/sha3.c ${LDFLAGS}
	${CC} ${CFLAGS} -DSLH_DSA_SHAKE_256S -o $(BUILDDIR)/${TESTBIN}_shake_256s $(BASE_SOURCES) $(TEST_SOURCES) $(TINY_SHA3_PATH)/sha3.c ${LDFLAGS}
	${CC} ${CFLAGS} -DSLH_DSA_SHAKE_256F -o $(BUILDDIR)/${TESTBIN}_shake_256f $(BASE_SOURCES) $(TEST_SOURCES) $(TINY_SHA3_PATH)/sha3.c ${LDFLAGS}
	${CC} ${CFLAGS} -DSLH_DSA_SHA2_128S -o $(BUILDDIR)/${TESTBIN}_sha2_128s $(BASE_SOURCES) $(TEST_SOURCES) $(TINY_SHA3_PATH)/sha3.c ${LDFLAGS}
	${CC} ${CFLAGS} -DSLH_DSA_SHA2_128F -o $(BUILDDIR)/${TESTBIN}_sha2_128f $(BASE_SOURCES) $(TEST_SOURCES) $(TINY_SHA3_PATH)/sha3.c ${LDFLAGS}
	${CC} ${CFLAGS} -DSLH_DSA_SHA2_192S -o $(BUILDDIR)/${TESTBIN}_sha2_192s $(BASE_SOURCES) $(TEST_SOURCES) $(TINY_SHA3_PATH)/sha3.c ${LDFLAGS}
	${CC} ${CFLAGS} -DSLH_DSA_SHA2_192F -o $(BUILDDIR)/${TESTBIN}_sha2_192f $(BASE_SOURCES) $(TEST_SOURCES) $(TINY_SHA3_PATH)/sha3.c ${LDFLAGS}
	${CC} ${CFLAGS} -DSLH_DSA_SHA2_256S -o $(BUILDDIR)/${TESTBIN}_sha2_256s $(BASE_SOURCES) $(TEST_SOURCES) $(TINY_SHA3_PATH)/sha3.c ${LDFLAGS}
	${CC} ${CFLAGS} -DSLH_DSA_SHA2_256F -o $(BUILDDIR)/${TESTBIN}_sha2_256f $(BASE_SOURCES) $(TEST_SOURCES) $(TINY_SHA3_PATH)/sha3.c ${LDFLAGS}

runtests: tests
	./$(BUILDDIR)/${TESTBIN}_shake_128s
	./$(BUILDDIR)/${TESTBIN}_shake_128f
	./$(BUILDDIR)/${TESTBIN}_shake_192s
	./$(BUILDDIR)/${TESTBIN}_shake_192f
	./$(BUILDDIR)/${TESTBIN}_shake_256s
	./$(BUILDDIR)/${TESTBIN}_shake_256f
	./$(BUILDDIR)/${TESTBIN}_sha2_128s
	./$(BUILDDIR)/${TESTBIN}_sha2_128f
	./$(BUILDDIR)/${TESTBIN}_sha2_192s
	./$(BUILDDIR)/${TESTBIN}_sha2_192f
	./$(BUILDDIR)/${TESTBIN}_sha2_256s
	./$(BUILDDIR)/${TESTBIN}_sha2_256f

clean:
	rm -rf ${BUILDDIR}
