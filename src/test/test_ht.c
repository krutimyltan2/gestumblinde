#include "test_ht.h"

void test_ht_sign() {
  json_t *tv = json_load_file(TEST_FILENAME_JSON, 0, NULL);

  if (tv == NULL) {
    fprintf(stderr, "Could not open JSON test file\n");
    exit(1);
  }

  uint8_t sk_seed[ENN];
  if (read_key_array(sk_seed, ENN, KEY_HT_SK_SEED, tv)) {
    fprintf(stderr, "Could not read the sk_seed from JSON!\n");
    exit(1);
  }

  uint8_t pk_seed[ENN];
  if (read_key_array(pk_seed, ENN, KEY_HT_PK_SEED, tv)) {
    fprintf(stderr, "Could not read the pk_seed from JSON!\n");
    exit(1);
  }

  idx_tree_t idx_tree = read_key_idx_tree(KEY_HT_IDX_TREE, tv);
  uint64_t idx_leaf = read_key_uint64(KEY_HT_IDX_LEAF, tv);

  uint8_t msg[ENN];
  if (read_key_array(msg, ENN, KEY_HT_MSG, tv)) {
    fprintf(stderr, "Could not read the node from JSON!\n");
    exit(1);
  }

  uint8_t csig[(H + D * WOTSP_LEN) * ENN];
  if (read_key_array(csig, (H + D * WOTSP_LEN) * ENN, KEY_HT_SIGNATURE, tv)) {
    fprintf(stderr, "Could not read the node from JSON!\n");
    exit(1);
  }

  uint8_t sig[(H + D * WOTSP_LEN) * ENN];
  ht_sign(sig, msg, sk_seed, pk_seed, idx_tree, idx_leaf);

  size_t j;
  for (j = 0; j < (H + D * WOTSP_LEN) * ENN; j++) {
    CU_ASSERT_EQUAL(sig[j], csig[j]);
  }
}

void test_ht_verify() {
  json_t *tv = json_load_file(TEST_FILENAME_JSON, 0, NULL);

  if (tv == NULL) {
    fprintf(stderr, "Could not open JSON test file\n");
    exit(1);
  }

  uint8_t sk_seed[ENN];
  if (read_key_array(sk_seed, ENN, KEY_HT_SK_SEED, tv)) {
    fprintf(stderr, "Could not read the sk_seed from JSON!\n");
    exit(1);
  }

  uint8_t pk_seed[ENN];
  if (read_key_array(pk_seed, ENN, KEY_HT_PK_SEED, tv)) {
    fprintf(stderr, "Could not read the pk_seed from JSON!\n");
    exit(1);
  }

  idx_tree_t idx_tree = read_key_idx_tree(KEY_HT_IDX_TREE, tv);
  uint64_t idx_leaf = read_key_uint64(KEY_HT_IDX_LEAF, tv);

  uint8_t msg[ENN];
  if (read_key_array(msg, ENN, KEY_HT_MSG, tv)) {
    fprintf(stderr, "Could not read the node from JSON!\n");
    exit(1);
  }

  uint8_t sig[(H + D * WOTSP_LEN) * ENN];
  if (read_key_array(sig, (H + D * WOTSP_LEN) * ENN, KEY_HT_SIGNATURE, tv)) {
    fprintf(stderr, "Could not read the node from JSON!\n");
    exit(1);
  }

  uint8_t pk_root[ENN];
  uint32_t adrs[ADRS_LEN] = {0};
  adrs[ADRS_LAYER_ADDRESS_IDX] = htobe32(D - 1);
  xmss_node(pk_root, sk_seed, 0, HP, pk_seed, adrs);

  // try valid (sig,msg) pair
  int res = ht_verify(msg, sig, pk_seed, idx_tree, idx_leaf, pk_root);
  CU_ASSERT_EQUAL(res, 1);

  // flip a bit in the signature
  uint8_t sigf[(H + D * WOTSP_LEN) * ENN];
  memcpy(sigf, sig, (H + D * WOTSP_LEN) * ENN);
  sigf[3] ^= 0x40;
  res = ht_verify(msg, sigf, pk_seed, idx_tree, idx_leaf, pk_root);
  CU_ASSERT_EQUAL(res, 0);

  // flip a bit in the message
  uint8_t msgf[ENN];
  memcpy(msgf, msg, ENN);
  msgf[4] ^= 0x02;
  res = ht_verify(msgf, sig, pk_seed, idx_tree, idx_leaf, pk_root);
  CU_ASSERT_EQUAL(res, 0);

  // wrong tree index
  idx_tree_t iff = idx_tree;
  iff.vallb ^= 0x10;
  res = ht_verify(msg, sig, pk_seed, iff, idx_leaf, pk_root);
  CU_ASSERT_EQUAL(res, 0);

  // wrong leaf index
  uint64_t lff = idx_leaf;
  lff ^= 0x80;
  res = ht_verify(msg, sig, pk_seed, idx_tree, lff, pk_root);
  CU_ASSERT_EQUAL(res, 0);
}
