#include <assert.h>
#include <stdio.h>
#include <time.h>

#include "slh.h"

#define BENCH_LEN_MSG 32

#if ENN == 16
uint8_t BENCH_SK[4 * ENN] = {
    103, 101, 115, 116, 117, 109, 98,  108, 105, 110, 100, 101, 103,
    97,  97,  116, 97,  97,  110, 97,  101, 114, 105, 110, 116, 101,
    108, 111, 101, 115, 116, 102, 111, 101, 114, 101, 110, 110, 97,
    103, 111, 110, 107, 111, 109, 109, 101, 114, 104, 47,  111, 154,
    54,  193, 126, 255, 3,   249, 104, 241, 60,  161, 89,  113};
#elif ENN == 24
uint8_t BENCH_SK[4 * ENN] = {
    103, 101, 115, 116, 117, 109, 98,  108, 105, 110, 100, 101, 103, 97,
    97,  116, 189, 177, 231, 9,   173, 59,  194, 4,   97,  97,  110, 97,
    101, 114, 105, 110, 116, 101, 108, 111, 101, 115, 116, 102, 117, 114,
    146, 254, 171, 158, 41,  218, 111, 101, 114, 101, 110, 110, 97,  103,
    111, 110, 107, 111, 109, 109, 101, 114, 80,  103, 254, 5,   104, 255,
    79,  97,  163, 49,  66,  229, 92,  1,   244, 201, 91,  209, 134, 9,
    15,  25,  109, 199, 7,   250, 113, 42,  18,  244, 98,  145};
#elif ENN == 32
uint8_t BENCH_SK[4 * ENN] = {
    103, 101, 115, 116, 117, 109, 98,  108, 105, 110, 100, 101, 103, 97,  97,
    116, 67,  110, 116, 61,  167, 81,  134, 44,  1,   81,  106, 57,  159, 253,
    203, 225, 97,  97,  110, 97,  101, 114, 105, 110, 116, 101, 108, 111, 101,
    115, 116, 102, 6,   30,  202, 160, 84,  17,  65,  28,  55,  165, 134, 75,
    195, 219, 74,  70,  111, 101, 114, 101, 110, 110, 97,  103, 111, 110, 107,
    111, 109, 109, 101, 114, 118, 23,  140, 134, 120, 24,  199, 193, 210, 197,
    170, 232, 44,  207, 173, 175, 145, 109, 178, 174, 228, 202, 205, 199, 214,
    51,  65,  211, 86,  113, 195, 13,  105, 96,  108, 63,  229, 238, 212, 107,
    135, 28,  172, 175, 215, 221, 222, 202};
#else
#error "T'is a bad'ENN"
#endif
const uint8_t BENCH_MSG[BENCH_LEN_MSG] = {
    104, 101, 108, 108, 111, 119, 111, 114, 108, 100, 111,
    114, 115, 111, 109, 101, 115, 117, 99,  104, 109, 101,
    97,  110, 105, 110, 103, 108, 101, 115, 115, 116};

static double time_sign(uint8_t *sig) {
  const uint8_t *sk = BENCH_SK;
  const uint8_t *msg = BENCH_MSG;

  clock_t before, after;

  before = clock();
  slh_sign(sig, msg, BENCH_LEN_MSG, sk, 0);
  after = clock();

  return ((double)(after - before)) / CLOCKS_PER_SEC;
}

static double time_verif(uint8_t *sig) {
  const uint8_t *pk = BENCH_SK + 2 * ENN;
  const uint8_t *msg = BENCH_MSG;

  clock_t before, after;

  before = clock();
  if (slh_verify(msg, BENCH_LEN_MSG, sig, SLH_SIGNATURE_LEN, pk) != 1) {
    printf("This should not happen!\n");
    exit(1);
  }
  after = clock();

  return ((double)(after - before)) / CLOCKS_PER_SEC;
}

static void pk_hack() {
  uint32_t adrs[ADRS_LEN] = {0};
  adrs[ADRS_LAYER_ADDRESS_IDX] = htobe32(D - 1);

  uint8_t pkb[ENN];
  xmss_node(pkb, BENCH_SK, 0, HP, BENCH_SK + 2 * ENN, adrs);

  memcpy(BENCH_SK + 3 * ENN, pkb, ENN);
}

int main() {
  uint8_t sig[SLH_SIGNATURE_LEN];

  pk_hack();

  double sign_time = time_sign(sig);
  double verif_time = time_verif(sig);

  printf("  %.2f %.2f\n", sign_time, verif_time);

  return 0;
}
