#include "clcommon.h"
#include "slh.h"
#include <stdio.h>

#define RANDOMIZE 0 // randomisation off

static void print_usage(char *command) {
  printf("usage: %s <sk_file>\n\n", command);
  printf("    sk_file:   secret key input filename\n\n");
  printf("The program will read the data to sign from standard\n");
  printf("input and write the signature to standard output.\n");
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    print_usage(argv[0]);
    return 1;
  }

  uint8_t sk[4 * ENN];

  FILE *sk_file = fopen(argv[1], "r");
  if (sk_file == NULL) {
    fprintf(stderr, "Error! Could not open file %s\n", argv[1]);
    return 1;
  }

  size_t r = fread(sk, sizeof(*sk), 4 * ENN, sk_file);
  if (r < 4 * ENN) {
    fprintf(stderr, "Error! Failed to read secret key from %s\n", argv[1]);
    return 1;
  }

  size_t mlen;
  uint8_t *m;
  if (read_message_from_stdin(&m, &mlen)) {
    fprintf(stderr, "Error! Failed to read message from stdin.\n");
    return 1;
  }

  uint8_t sig[SLH_SIGNATURE_LEN];
  slh_sign(sig, m, mlen, sk, RANDOMIZE);

  free(m);

  r = fwrite(sig, sizeof(*sig), SLH_SIGNATURE_LEN, stdout);

  if (r != SLH_SIGNATURE_LEN) {
    fprintf(stderr, "Error! An error occured on write!\n");
    return 1;
  }

  return 0;
}
