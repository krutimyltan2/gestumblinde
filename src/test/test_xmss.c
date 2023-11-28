#include "test_xmss.h"

void test_xmss_node() {
  json_t *tv = json_load_file(TEST_FILENAME_JSON, 0, NULL);

  if (tv == NULL) {
    fprintf(stderr, "Could not open JSON test file\n");
    exit(1);
  }

  uint32_t adrs[ADRS_LEN];
  if (read_key_array(adrs, ADRS_LEN * sizeof(*adrs), KEY_XMSS_ADDRESS, tv)) {
    fprintf(stderr, "Could not read address from JSON!\n");
    exit(1);
  }

  uint8_t sk_seed[ENN];
  if (read_key_array(sk_seed, ENN, KEY_XMSS_SK_SEED, tv)) {
    fprintf(stderr, "Could not read the sk_seed from JSON!\n");
    exit(1);
  }

  uint8_t pk_seed[ENN];
  if (read_key_array(pk_seed, ENN, KEY_XMSS_PK_SEED, tv)) {
    fprintf(stderr, "Could not read the pk_seed from JSON!\n");
    exit(1);
  }

  uint64_t i = read_key_uint64(KEY_XMSS_NODEI, tv);
  uint64_t z = read_key_uint64(KEY_XMSS_NODEZ, tv);

  uint8_t cnode[ENN];
  if (read_key_array(cnode, ENN, KEY_XMSS_NODE, tv)) {
    fprintf(stderr, "Could not read the node from JSON!\n");
    exit(1);
  }

  uint8_t node[ENN];
  int rv = xmss_node(node, sk_seed, i, z, pk_seed, adrs);

  CU_ASSERT_EQUAL(rv, ENN);

  size_t j;
  for (j = 0; j < ENN; j++) {
    CU_ASSERT_EQUAL(node[j], cnode[j]);
  }
}

void test_xmss_sign() {
  json_t *tv = json_load_file(TEST_FILENAME_JSON, 0, NULL);

  if (tv == NULL) {
    fprintf(stderr, "Could not open JSON test file\n");
    exit(1);
  }

  uint32_t adrs[ADRS_LEN];
  if (read_key_array(adrs, ADRS_LEN * sizeof(*adrs), KEY_XMSS_ADDRESS, tv)) {
    fprintf(stderr, "Could not read address from JSON!\n");
    exit(1);
  }

  uint8_t sk_seed[ENN];
  if (read_key_array(sk_seed, ENN, KEY_XMSS_SK_SEED, tv)) {
    fprintf(stderr, "Could not read the sk_seed from JSON!\n");
    exit(1);
  }

  uint8_t pk_seed[ENN];
  if (read_key_array(pk_seed, ENN, KEY_XMSS_PK_SEED, tv)) {
    fprintf(stderr, "Could not read the pk_seed from JSON!\n");
    exit(1);
  }

  uint64_t idx = read_key_uint64(KEY_XMSS_SIGNIDX, tv);
  uint8_t msg[ENN];
  if (read_key_array(msg, ENN, KEY_XMSS_MSG, tv)) {
    fprintf(stderr, "Could not read the message from JSON!\n");
    exit(1);
  }

  uint8_t csig[(WOTSP_LEN + HP) * ENN];
  if (read_key_array(csig, (WOTSP_LEN + HP) * ENN, KEY_XMSS_SIGNATURE, tv)) {
    fprintf(stderr, "Could not read the signature from JSON!\n");
    exit(1);
  }

  uint8_t sig[(WOTSP_LEN + HP) * ENN];

  xmss_sign(sig, msg, sk_seed, idx, pk_seed, adrs);

  size_t j;
  for (j = 0; j < (WOTSP_LEN + HP) * ENN; j++) {
    CU_ASSERT_EQUAL(sig[j], csig[j]);
  }
}

void test_xmss_verify() {
  json_t *tv = json_load_file(TEST_FILENAME_JSON, 0, NULL);

  if (tv == NULL) {
    fprintf(stderr, "Could not open JSON test file\n");
    exit(1);
  }

  uint32_t adrs[ADRS_LEN];
  if (read_key_array(adrs, ADRS_LEN * sizeof(*adrs), KEY_XMSS_ADDRESS, tv)) {
    fprintf(stderr, "Could not read address from JSON!\n");
    exit(1);
  }

  uint8_t sk_seed[ENN];
  if (read_key_array(sk_seed, ENN, KEY_XMSS_SK_SEED, tv)) {
    fprintf(stderr, "Could not read the sk_seed from JSON!\n");
    exit(1);
  }

  uint8_t pk_seed[ENN];
  if (read_key_array(pk_seed, ENN, KEY_XMSS_PK_SEED, tv)) {
    fprintf(stderr, "Could not read the pk_seed from JSON!\n");
    exit(1);
  }

  uint64_t idx = read_key_uint64(KEY_XMSS_SIGNIDX, tv);
  uint8_t msg[ENN];
  if (read_key_array(msg, ENN, KEY_XMSS_MSG, tv)) {
    fprintf(stderr, "Could not read the message from JSON!\n");
    exit(1);
  }

  uint8_t sig[(WOTSP_LEN + HP) * ENN];
  if (read_key_array(sig, (WOTSP_LEN + HP) * ENN, KEY_XMSS_SIGNATURE, tv)) {
    fprintf(stderr, "Could not read the signature from JSON!\n");
    exit(1);
  }

  uint8_t pk[ENN];
  xmss_node(pk, sk_seed, 0, HP, pk_seed, adrs);

  // verify good (sig,msg) pair
  uint8_t comp_pk[ENN];
  xmss_pk_from_sig(comp_pk, idx, sig, msg, pk_seed, adrs);
  CU_ASSERT_EQUAL(memcmp(pk, comp_pk, ENN), 0);

  // verify fails with bitflipped signature
  uint8_t corr_sig[(WOTSP_LEN + HP) * ENN];
  memcpy(corr_sig, sig, (WOTSP_LEN + HP) * ENN);
  corr_sig[3] ^= 0x10;
  xmss_pk_from_sig(comp_pk, idx, corr_sig, msg, pk_seed, adrs);
  CU_ASSERT_NOT_EQUAL(memcmp(pk, comp_pk, ENN), 0);

  // verify fails with bitflipped message
  uint8_t corr_msg[ENN];
  memcpy(corr_msg, msg, ENN);
  corr_msg[3] ^= 0x04;
  xmss_pk_from_sig(comp_pk, idx, sig, corr_msg, pk_seed, adrs);
  CU_ASSERT_NOT_EQUAL(memcmp(pk, comp_pk, ENN), 0);

  // verify fails with wrong index
  uint64_t badidx = idx ^ 0x01;
  xmss_pk_from_sig(comp_pk, badidx, sig, msg, pk_seed, adrs);
  CU_ASSERT_NOT_EQUAL(memcmp(pk, comp_pk, ENN), 0);
}
