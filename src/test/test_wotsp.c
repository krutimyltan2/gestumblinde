#include "test_wotsp.h"

void test_wotsp_pkgen() {
  json_t *tv = json_load_file(TEST_FILENAME_JSON, 0, NULL);

  if (tv == NULL) {
    fprintf(stderr, "Could not open JSON test file\n");
    exit(1);
  }

  uint32_t adrs[ADRS_LEN];
  if (read_key_array(adrs, ADRS_LEN * sizeof(*adrs), KEY_WOTSP_ADDRESS, tv)) {
    fprintf(stderr, "Could not read address from JSON!\n");
    exit(1);
  }

  uint8_t sk_seed[ENN];
  if (read_key_array(sk_seed, ENN, KEY_WOTSP_SK_SEED, tv)) {
    fprintf(stderr, "Could not read the sk_seed from JSON!\n");
    exit(1);
  }

  uint8_t pk_seed[ENN];
  if (read_key_array(pk_seed, ENN, KEY_WOTSP_PK_SEED, tv)) {
    fprintf(stderr, "Could not read the pk_seed from JSON!\n");
    exit(1);
  }

  uint8_t cpk[ENN];
  if (read_key_array(cpk, ENN, KEY_WOTSP_PUBLIC_KEY, tv)) {
    fprintf(stderr, "Could not read the public key from JSON!\n");
    exit(1);
  }

  uint8_t pk[ENN];
  wotsp_pkgen(pk, sk_seed, pk_seed, adrs);

  size_t i;
  for (i = 0; i < ENN; i++) {
    CU_ASSERT_EQUAL(pk[i], cpk[i]);
  }
}

void test_wotsp_sign() {
  json_t *tv = json_load_file(TEST_FILENAME_JSON, 0, NULL);

  if (tv == NULL) {
    fprintf(stderr, "Could not open JSON test file\n");
    exit(1);
  }

  uint32_t adrs[ADRS_LEN];
  if (read_key_array(adrs, ADRS_LEN * sizeof(*adrs), KEY_WOTSP_ADDRESS, tv)) {
    fprintf(stderr, "Could not read address from JSON!\n");
    exit(1);
  }

  uint8_t sk_seed[ENN];
  if (read_key_array(sk_seed, ENN, KEY_WOTSP_SK_SEED, tv)) {
    fprintf(stderr, "Could not read the sk_seed from JSON!\n");
    exit(1);
  }

  uint8_t pk_seed[ENN];
  if (read_key_array(pk_seed, ENN, KEY_WOTSP_PK_SEED, tv)) {
    fprintf(stderr, "Could not read the pk_seed from JSON!\n");
    exit(1);
  }

  uint8_t m[ENN];
  if (read_key_array(m, ENN, KEY_WOTSP_MSG, tv)) {
    fprintf(stderr, "Could not read the message from JSON!\n");
    exit(1);
  }

  uint8_t csig[ENN * WOTSP_LEN];
  if (read_key_array(csig, ENN * WOTSP_LEN, KEY_WOTSP_SIGNATURE, tv)) {
    fprintf(stderr, "Could not read the signature from JSON!\n");
    exit(1);
  }

  uint8_t sig[ENN * WOTSP_LEN];
  wotsp_sign(sig, m, sk_seed, pk_seed, adrs);

  size_t i;
  for (i = 0; i < ENN * WOTSP_LEN; i++) {
    CU_ASSERT_EQUAL(sig[i], csig[i]);
  }
}

void test_wotsp_verify() {
  json_t *tv = json_load_file(TEST_FILENAME_JSON, 0, NULL);

  if (tv == NULL) {
    fprintf(stderr, "Could not open JSON test file\n");
    exit(1);
  }

  uint32_t adrs[ADRS_LEN];
  if (read_key_array(adrs, ADRS_LEN * sizeof(*adrs), KEY_WOTSP_ADDRESS, tv)) {
    fprintf(stderr, "Could not read address from JSON!\n");
    exit(1);
  }

  uint8_t sk_seed[ENN];
  if (read_key_array(sk_seed, ENN, KEY_WOTSP_SK_SEED, tv)) {
    fprintf(stderr, "Could not read the sk_seed from JSON!\n");
    exit(1);
  }

  uint8_t pk_seed[ENN];
  if (read_key_array(pk_seed, ENN, KEY_WOTSP_PK_SEED, tv)) {
    fprintf(stderr, "Could not read the pk_seed from JSON!\n");
    exit(1);
  }

  uint8_t m[ENN];
  if (read_key_array(m, ENN, KEY_WOTSP_MSG, tv)) {
    fprintf(stderr, "Could not read the message from JSON!\n");
    exit(1);
  }

  uint8_t sig[ENN * WOTSP_LEN];
  if (read_key_array(sig, ENN * WOTSP_LEN, KEY_WOTSP_SIGNATURE, tv)) {
    fprintf(stderr, "Could not read the signature from JSON!\n");
    exit(1);
  }

  uint8_t pk[ENN];
  if (read_key_array(pk, ENN, KEY_WOTSP_PUBLIC_KEY, tv)) {
    fprintf(stderr, "Could not read the public key from JSON!\n");
    exit(1);
  }

  uint8_t computed_pk[ENN];

  // compute correct signature
  wotsp_pk_from_sig(computed_pk, sig, m, ENN, pk_seed, adrs);
  CU_ASSERT_EQUAL(memcmp(pk, computed_pk, ENN), 0);

  // verify fails with bitflipped signature
  uint8_t corrupted_sig[ENN * WOTSP_LEN];
  memcpy(corrupted_sig, sig, ENN * WOTSP_LEN);
  corrupted_sig[3] ^= 0x10;
  wotsp_pk_from_sig(computed_pk, corrupted_sig, m, ENN, pk_seed, adrs);
  CU_ASSERT_NOT_EQUAL(memcmp(pk, computed_pk, ENN), 0);

  // verify fails with bitflipped message
  uint8_t corrupted_msg[ENN];
  memcpy(corrupted_msg, m, ENN);
  corrupted_msg[3] ^= 0x04;
  wotsp_pk_from_sig(computed_pk, sig, corrupted_msg, ENN, pk_seed, adrs);
  CU_ASSERT_NOT_EQUAL(memcmp(pk, computed_pk, ENN), 0);
}
