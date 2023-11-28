#include "clcommon.h"
#include "slh.h"
#include <stdio.h>

static void print_usage(char *command) {
  printf("usage: %s <pk_file> <sig_file>\n\n", command);
  printf("    pk_file:   public key input filename\n");
  printf("    sig_file:  signature input filename\n\n");
  printf("The program will read the message from standard\n");
  printf("input and print \"TRUE\" to standard output if\n");
  printf("the verification succeeds, otherwise \"FALSE\"\n");
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    print_usage(argv[0]);
    return 1;
  }

  uint8_t pk[2 * ENN];
  FILE *pk_file = fopen(argv[1], "r");
  if (pk_file == NULL) {
    fprintf(stderr, "Error! Could not open file %s\n", argv[1]);
    return 1;
  }

  size_t r = fread(pk, sizeof(*pk), 2 * ENN, pk_file);
  if (r < 2 * ENN) {
    fprintf(stderr, "Error! Failed to read public key from %s\n", argv[1]);
    return 1;
  }

  uint8_t sig[SLH_SIGNATURE_LEN];
  FILE *sig_file = fopen(argv[2], "r");
  if (sig_file == NULL) {
    fprintf(stderr, "Error! Could not open file %s\n", argv[2]);
    return 1;
  }

  r = fread(sig, sizeof(*sig), SLH_SIGNATURE_LEN, sig_file);

  size_t mlen;
  uint8_t *m;
  if (read_message_from_stdin(&m, &mlen)) {
    fprintf(stderr, "Error! Failed to read message from stdin.\n");
    return 1;
  }

  if (slh_verify(m, mlen, sig, r, pk)) {
    printf("TRUE\n");
  } else {
    printf("FALSE\n");
  }

  return 0;
}
