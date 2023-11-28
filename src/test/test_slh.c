#include "test_slh.h"

void test_slh_keygen() {
  // just run it, enough not to crash
  uint8_t sk[4 * ENN];
  uint8_t pk[2 * ENN];

  slh_keygen(sk, pk);
}

void test_slh_sign() {
  json_t *tv = json_load_file(TEST_FILENAME_JSON, 0, NULL);

  if (tv == NULL) {
    fprintf(stderr, "Could not open JSON test file\n");
    exit(1);
  }

  uint8_t sk[4 * ENN];
  if (read_key_aoa(sk, 4 * ENN, KEY_SLH_SK, tv)) {
    fprintf(stderr, "Could not read the secret key from JSON!\n");
    exit(1);
  }

  uint8_t csig[SLH_SIGNATURE_LEN];
  if (read_key_array(csig, SLH_SIGNATURE_LEN, KEY_SLH_SIGNATURE, tv)) {
    fprintf(stderr, "Could not read the signature from JSON!\n");
    exit(1);
  }

  uint8_t msg[32];
  if (read_key_array(msg, 32, KEY_SLH_MSG, tv)) {
    fprintf(stderr, "Could not read the message from JSON!\n");
    exit(1);
  }

  uint8_t sig[SLH_SIGNATURE_LEN];
  slh_sign(sig, msg, 32, sk, 0);

  size_t j;
  for (j = 0; j < SLH_SIGNATURE_LEN; j++) {
    CU_ASSERT_EQUAL(sig[j], csig[j]);
  }
}

void test_slh_verify() {
  json_t *tv = json_load_file(TEST_FILENAME_JSON, 0, NULL);

  if (tv == NULL) {
    fprintf(stderr, "Could not open JSON test file\n");
    exit(1);
  }

  uint8_t pk[2 * ENN];
  if (read_key_aoa(pk, 2 * ENN, KEY_SLH_PK, tv)) {
    fprintf(stderr, "Could not read the public key from JSON!\n");
    exit(1);
  }

  uint8_t sig[SLH_SIGNATURE_LEN];
  if (read_key_array(sig, SLH_SIGNATURE_LEN, KEY_SLH_SIGNATURE, tv)) {
    fprintf(stderr, "Could not read the signature from JSON!\n");
    exit(1);
  }

  uint8_t msg[32];
  if (read_key_array(msg, 32, KEY_SLH_MSG, tv)) {
    fprintf(stderr, "Could not read the message from JSON!\n");
    exit(1);
  }

  CU_ASSERT_EQUAL(slh_verify(msg, 32, sig, SLH_SIGNATURE_LEN, pk), 1);

  msg[3] ^= 0x40;
  CU_ASSERT_EQUAL(slh_verify(msg, 32, sig, SLH_SIGNATURE_LEN, pk), 0);
  msg[3] ^= 0x40;

  sig[1] ^= 0x10;
  CU_ASSERT_EQUAL(slh_verify(msg, 32, sig, SLH_SIGNATURE_LEN, pk), 0);
  sig[1] ^= 0x10;

  CU_ASSERT_EQUAL(slh_verify(msg, 32, sig, SLH_SIGNATURE_LEN - 1, pk), 0);
}

void test_slh_ref_sign() {
  json_t *tv = json_load_file(TEST_FILENAME_REF_JSON, 0, NULL);

  if (tv == NULL) {
    fprintf(stderr, "Could not open JSON test file\n");
    exit(1);
  }

  uint8_t sk[4 * ENN];
  if (read_key_aoa(sk, 4 * ENN, KEY_SLH_SK, tv)) {
    fprintf(stderr, "Could not read the secret key from JSON!\n");
    exit(1);
  }

  uint8_t csig[SLH_SIGNATURE_LEN];
  if (read_key_array(csig, SLH_SIGNATURE_LEN, KEY_SLH_SIGNATURE, tv)) {
    fprintf(stderr, "Could not read the signature from JSON!\n");
    exit(1);
  }

  uint8_t msg[32];
  if (read_key_array(msg, 32, KEY_SLH_MSG, tv)) {
    fprintf(stderr, "Could not read the message from JSON!\n");
    exit(1);
  }

  uint8_t sig[SLH_SIGNATURE_LEN];
  slh_sign(sig, msg, 32, sk, 0);

  size_t j;
  for (j = 0; j < SLH_SIGNATURE_LEN; j++)
    CU_ASSERT_EQUAL(sig[j], csig[j]);
}
