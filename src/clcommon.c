#include "clcommon.h"

int read_message_from_stdin(uint8_t **m, size_t *mlen) {
  size_t tlen = 0;
  size_t allocd = 1024;
  uint8_t *t = malloc(allocd * sizeof(*t));

  int c;
  while ((c = getc(stdin)) != EOF) {
    if (allocd == tlen) {
      allocd <<= 1;
      t = realloc(t, allocd * sizeof(*t));

      if (t == NULL)
        return -1;
    }
    t[tlen] = (uint8_t)(c & 0xff);
    tlen++;
  }

  t = realloc(t, tlen * sizeof(*t));
  *m = t;
  *mlen = tlen;

  return 0;
}
