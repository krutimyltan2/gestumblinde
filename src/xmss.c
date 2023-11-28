#include "xmss.h"

/*
 * Compute the root of a Merkle subtree of WOTS+ public keys.
 *
 * Returns length of written output.
 */
int xmss_node(uint8_t *out, const uint8_t sk_seed[ENN], const uint64_t i,
              const uint64_t z, const uint8_t pk_seed[ENN],
              uint32_t adrs[ADRS_LEN]) {
  if (z > HP || i >= (1 << (HP - z)))
    return 0;

  if (z == 0) {
    adrs[ADRS_TYPE_IDX] = WOTS_HASH;
    adrs[ADRS_KEYPAIR_IDX] = htobe32((uint32_t)i);
    bzero(&adrs[ADRS_CHAIN_ADDRESS_IDX], 2 * sizeof(*adrs));

    wotsp_pkgen(out, sk_seed, pk_seed, adrs);
  } else {
    uint8_t buffer[2 * ENN];
    uint8_t *left = buffer;
    uint8_t *right = buffer + ENN;

#ifndef NDEBUG
    int r = xmss_node(left, sk_seed, 2 * i, z - 1, pk_seed, adrs);
    assert(r == ENN);
    r = xmss_node(right, sk_seed, 2 * i + 1, z - 1, pk_seed, adrs);
    assert(r == ENN);
#else
    xmss_node(left, sk_seed, 2 * i, z - 1, pk_seed, adrs);
    xmss_node(right, sk_seed, 2 * i + 1, z - 1, pk_seed, adrs);
#endif

    adrs[ADRS_TYPE_IDX] = TREE;
    adrs[ADRS_KEYPAIR_IDX] = 0; // padding zero for TREE type
    adrs[ADRS_TREE_HEIGHT_IDX] = htobe32((uint32_t)z);
    adrs[ADRS_TREE_INDEX_IDX] = htobe32((uint32_t)i);

    hash_h(out, pk_seed, adrs, buffer);
  }

  return ENN;
}

/*
 * Generate an XMSS signature
 */
int xmss_sign(uint8_t *out, const uint8_t m[ENN], const uint8_t sk_seed[ENN],
              const uint64_t idx, const uint8_t pk_seed[ENN],
              uint32_t adrs[ADRS_LEN]) {
  assert(idx <= (1 << HP));
  size_t j;

  uint8_t *auth = out + (WOTSP_LEN * ENN);
  uint64_t k;
  for (j = 0; j < HP; j++) {
    k = (idx >> j) ^ 0x01;
    xmss_node(auth, sk_seed, k, j, pk_seed, adrs);
    auth += ENN;
  }

  adrs[ADRS_TYPE_IDX] = WOTS_HASH;
  adrs[ADRS_KEYPAIR_IDX] = htobe32((uint32_t)idx);
  bzero(&adrs[ADRS_CHAIN_ADDRESS_IDX], 2 * sizeof(*adrs));

  wotsp_sign(out, m, sk_seed, pk_seed, adrs);

  return 0;
}

/*
 * Compute an XMSS public key from an XMSS signature
 */
int xmss_pk_from_sig(uint8_t *out, const uint64_t idx, const uint8_t *sig,
                     const uint8_t m[ENN], const uint8_t pk_seed[ENN],
                     uint32_t adrs[ADRS_LEN]) {
  adrs[ADRS_TYPE_IDX] = WOTS_HASH;
  adrs[ADRS_KEYPAIR_IDX] = htobe32((uint32_t)idx);
  bzero(&adrs[ADRS_CHAIN_ADDRESS_IDX], 2 * sizeof(*adrs));

  const uint8_t *auth = sig + (WOTSP_LEN * ENN);
  uint8_t node_data[3 * ENN];

  wotsp_pk_from_sig(node_data + ENN, sig, m, ENN, pk_seed, adrs);

  adrs[ADRS_TYPE_IDX] = TREE;
  adrs[ADRS_KEYPAIR_IDX] = 0; // padding zero for TREE type
  adrs[ADRS_TREE_INDEX_IDX] = htobe32((uint32_t)idx);

  size_t k;
  for (k = 0; k < HP; k++) {
    adrs[ADRS_TREE_HEIGHT_IDX] = htobe32((uint32_t)k + 1);
    uint32_t ti = betoh32(adrs[ADRS_TREE_INDEX_IDX]);
    if ((idx >> k) % 2 == 0) {
      adrs[ADRS_TREE_INDEX_IDX] = htobe32(ti >> 1);
      memcpy(node_data + 2 * ENN, auth + k * ENN, ENN);
      hash_h(node_data + ENN, pk_seed, adrs, node_data + ENN);
    } else {
      adrs[ADRS_TREE_INDEX_IDX] = htobe32((ti - 1) >> 1);
      memcpy(node_data, auth + k * ENN, ENN);
      hash_h(node_data + ENN, pk_seed, adrs, node_data);
    }
  }

  memcpy(out, node_data + ENN, ENN);

  return 0;
}
