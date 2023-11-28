#include "test_fors.h"

void test_fors_skgen() {
  json_t *tv = json_load_file(TEST_FILENAME_JSON, 0, NULL);

  if (tv == NULL) {
    fprintf(stderr, "Could not open JSON test file\n");
    exit(1);
  }

  uint32_t adrs[ADRS_LEN];
  if (read_key_array(adrs, ADRS_LEN * sizeof(*adrs), KEY_FORS_ADDRESS, tv)) {
    fprintf(stderr, "Could not read address from JSON!\n");
    exit(1);
  }

  uint8_t sk_seed[ENN];
  if (read_key_array(sk_seed, ENN, KEY_FORS_SK_SEED, tv)) {
    fprintf(stderr, "Could not read the sk_seed from JSON!\n");
    exit(1);
  }

  uint8_t pk_seed[ENN];
  if (read_key_array(pk_seed, ENN, KEY_FORS_PK_SEED, tv)) {
    fprintf(stderr, "Could not read the pk_seed from JSON!\n");
    exit(1);
  }

  uint64_t idx = read_key_uint64(KEY_FORS_IDX, tv);

  uint8_t csk[ENN];
  if (read_key_array(csk, ENN, KEY_FORS_SK, tv)) {
    fprintf(stderr, "Could not read the node from JSON!\n");
    exit(1);
  }

  uint8_t sk[ENN];
  fors_skgen(sk, sk_seed, pk_seed, adrs, idx);

  size_t j;
  for (j = 0; j < ENN; j++) {
    CU_ASSERT_EQUAL(sk[j], csk[j]);
  }
}

void test_fors_node() {
  json_t *tv = json_load_file(TEST_FILENAME_JSON, 0, NULL);

  if (tv == NULL) {
    fprintf(stderr, "Could not open JSON test file\n");
    exit(1);
  }

  uint32_t adrs[ADRS_LEN];
  if (read_key_array(adrs, ADRS_LEN * sizeof(*adrs), KEY_FORS_ADDRESS, tv)) {
    fprintf(stderr, "Could not read address from JSON!\n");
    exit(1);
  }

  uint8_t sk_seed[ENN];
  if (read_key_array(sk_seed, ENN, KEY_FORS_SK_SEED, tv)) {
    fprintf(stderr, "Could not read the sk_seed from JSON!\n");
    exit(1);
  }

  uint8_t pk_seed[ENN];
  if (read_key_array(pk_seed, ENN, KEY_FORS_PK_SEED, tv)) {
    fprintf(stderr, "Could not read the pk_seed from JSON!\n");
    exit(1);
  }

  uint64_t i = read_key_uint64(KEY_FORS_NODEI, tv);
  uint64_t z = read_key_uint64(KEY_FORS_NODEZ, tv);

  uint8_t cnode[ENN];
  if (read_key_array(cnode, ENN, KEY_FORS_NODE, tv)) {
    fprintf(stderr, "Could not read the node from JSON!\n");
    exit(1);
  }

  uint8_t node[ENN];
  fors_node(node, sk_seed, i, z, pk_seed, adrs);

  size_t j;
  for (j = 0; j < ENN; j++) {
    CU_ASSERT_EQUAL(node[j], cnode[j]);
  }
}

void test_fors_sign() {
  json_t *tv = json_load_file(TEST_FILENAME_JSON, 0, NULL);

  if (tv == NULL) {
    fprintf(stderr, "Could not open JSON test file\n");
    exit(1);
  }

  uint32_t adrs[ADRS_LEN];
  if (read_key_array(adrs, ADRS_LEN * sizeof(*adrs), KEY_FORS_ADDRESS, tv)) {
    fprintf(stderr, "Could not read address from JSON!\n");
    exit(1);
  }

  uint8_t sk_seed[ENN];
  if (read_key_array(sk_seed, ENN, KEY_FORS_SK_SEED, tv)) {
    fprintf(stderr, "Could not read the sk_seed from JSON!\n");
    exit(1);
  }

  uint8_t pk_seed[ENN];
  if (read_key_array(pk_seed, ENN, KEY_FORS_PK_SEED, tv)) {
    fprintf(stderr, "Could not read the pk_seed from JSON!\n");
    exit(1);
  }

  uint8_t csig[FORS_SIG_LEN];
  if (read_key_array(csig, FORS_SIG_LEN, KEY_FORS_SIGNATURE, tv)) {
    fprintf(stderr, "Could not read the signature from JSON!\n");
    exit(1);
  }

  uint8_t md[FORS_MD_LEN];
  if (read_key_array(md, FORS_MD_LEN, KEY_FORS_MD, tv)) {
    fprintf(stderr, "Could not read the message digest from JSON!\n");
    exit(1);
  }

  uint8_t sig[FORS_SIG_LEN];
  fors_sign(sig, md, sk_seed, pk_seed, adrs);

  size_t j;
  for (j = 0; j < ENN; j++) {
    CU_ASSERT_EQUAL(sig[j], csig[j]);
  }
}

void test_fors_pk_from_sig() {
  json_t *tv = json_load_file(TEST_FILENAME_JSON, 0, NULL);

  if (tv == NULL) {
    fprintf(stderr, "Could not open JSON test file\n");
    exit(1);
  }

  uint32_t adrs[ADRS_LEN];
  if (read_key_array(adrs, ADRS_LEN * sizeof(*adrs), KEY_FORS_ADDRESS, tv)) {
    fprintf(stderr, "Could not read address from JSON!\n");
    exit(1);
  }

  uint8_t sk_seed[ENN];
  if (read_key_array(sk_seed, ENN, KEY_FORS_SK_SEED, tv)) {
    fprintf(stderr, "Could not read the sk_seed from JSON!\n");
    exit(1);
  }

  uint8_t pk_seed[ENN];
  if (read_key_array(pk_seed, ENN, KEY_FORS_PK_SEED, tv)) {
    fprintf(stderr, "Could not read the pk_seed from JSON!\n");
    exit(1);
  }

  uint8_t sig[FORS_SIG_LEN];
  if (read_key_array(sig, FORS_SIG_LEN, KEY_FORS_SIGNATURE, tv)) {
    fprintf(stderr, "Could not read the signature from JSON!\n");
    exit(1);
  }

  uint8_t md[FORS_MD_LEN];
  if (read_key_array(md, FORS_MD_LEN, KEY_FORS_MD, tv)) {
    fprintf(stderr, "Could not read the message digest from JSON!\n");
    exit(1);
  }

  uint8_t node[ENN];
  if (read_key_array(node, ENN, KEY_FORS_NODE, tv)) {
    fprintf(stderr, "Could not read the node from JSON!\n");
    exit(1);
  }

  // generate the pk from roots from sk_seed
  uint8_t roots[K * ENN];
  uint8_t *cr = roots;
  size_t j;
  for (j = 0; j < K; j++) {
    fors_node(cr, sk_seed, j, A, pk_seed, adrs);
    cr += ENN;
  }
  uint32_t forspkadrs[ADRS_LEN];
  memcpy(forspkadrs, adrs, ADRS_LEN * sizeof(*adrs));
  forspkadrs[ADRS_TYPE_IDX] = FORS_ROOTS;
  forspkadrs[ADRS_KEYPAIR_IDX] = adrs[ADRS_KEYPAIR_IDX];
  forspkadrs[6] = 0;
  forspkadrs[7] = 0;

  uint8_t cpk[ENN];
  hash_t(cpk, K, pk_seed, forspkadrs, roots);

  uint8_t pk[ENN];
  fors_pk_from_sig(pk, sig, md, pk_seed, adrs);

  for (j = 0; j < ENN; j++) {
    CU_ASSERT_EQUAL(pk[j], cpk[j]);
  }
}
