#include "slh.h"
#include <stdio.h>

static void print_usage(char *command) {
  printf("usage: %s <pk_file> <sk_file>\n\n", command);
  printf("    pk_file:   public key output filename\n");
  printf("    sk_file:   secret key output filename\n");
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    print_usage(argv[0]);
    return 1;
  }

  uint8_t pk[2 * ENN];
  uint8_t sk[4 * ENN];
  slh_keygen(sk, pk);

  FILE *pk_file = fopen(argv[1], "w");
  if (pk_file == NULL) {
    fprintf(stderr, "Error! Could not open file %s\n", argv[1]);
    return 1;
  }

  FILE *sk_file = fopen(argv[2], "w");
  if (sk_file == NULL) {
    fprintf(stderr, "Error! Could not open file %s\n", argv[2]);
    return 1;
  }

  size_t r;
  r = fwrite(pk, sizeof(*pk), 2 * ENN, pk_file);
  if (r < 2 * ENN) {
    fprintf(stderr, "Error! Failed to write to file %s\n", argv[1]);
    return 1;
  }

  r = fwrite(sk, sizeof(*sk), 4 * ENN, sk_file);
  if (r < 4 * ENN) {
    fprintf(stderr, "Error! Failed to write to file %s\n", argv[2]);
    return 1;
  }

  fclose(sk_file);
  fclose(pk_file);

  return 0;
}
