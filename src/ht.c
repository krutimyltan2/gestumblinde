#include "ht.h"

static inline void set_tree_address(uint32_t adrs[ADRS_LEN], idx_tree_t idx) {
  idx_tree_t tmp;
  tmp.valhb = htobe32(idx.valhb);
  tmp.vallb = htobe64(idx.vallb);

  memcpy(&adrs[ADRS_TREE_ADDRESS_IDX], &tmp, sizeof(tmp));
}

/*
 * Generate a hypertree signature.
 */
int ht_sign(uint8_t *out, const uint8_t msg[ENN], const uint8_t sk_seed[ENN],
            const uint8_t pk_seed[ENN], idx_tree_t idx_tree,
            uint64_t idx_leaf) {
  uint32_t adrs[ADRS_LEN] = {0};
  set_tree_address(adrs, idx_tree);

  uint8_t *csig = out;
  xmss_sign(csig, msg, sk_seed, idx_leaf, pk_seed, adrs);

  uint8_t root[ENN];
  xmss_pk_from_sig(root, idx_leaf, csig, msg, pk_seed, adrs);

  csig += (WOTSP_LEN + HP) * ENN;
  size_t j;
  for (j = 1; j < D; j++) {
    idx_leaf = idx_tree_mod_2hp(idx_tree);
    idx_tree_shift(&idx_tree, HP);

    adrs[ADRS_LAYER_ADDRESS_IDX] = htobe32(j);
    set_tree_address(adrs, idx_tree);

    xmss_sign(csig, root, sk_seed, idx_leaf, pk_seed, adrs);

    if (j < D - 1) {
      xmss_pk_from_sig(root, idx_leaf, csig, root, pk_seed, adrs);
    }

    csig += (WOTSP_LEN + HP) * ENN;
  }

  return 0;
}

int ht_verify(const uint8_t msg[ENN], const uint8_t *sig_ht,
              const uint8_t pk_seed[ENN], idx_tree_t idx_tree,
              uint64_t idx_leaf, const uint8_t pk_root[ENN]) {
  uint32_t adrs[ADRS_LEN] = {0};
  set_tree_address(adrs, idx_tree);

  const uint8_t *csig = sig_ht;
  uint8_t node[ENN];
  xmss_pk_from_sig(node, idx_leaf, csig, msg, pk_seed, adrs);
  csig += (WOTSP_LEN + HP) * ENN;

  size_t j;
  for (j = 1; j < D; j++) {
    idx_leaf = idx_tree_mod_2hp(idx_tree);
    idx_tree_shift(&idx_tree, HP);

    adrs[ADRS_LAYER_ADDRESS_IDX] = htobe32(j);
    set_tree_address(adrs, idx_tree);

    xmss_pk_from_sig(node, idx_leaf, csig, node, pk_seed, adrs);
    csig += (WOTSP_LEN + HP) * ENN;
  }

  if (memcmp(node, pk_root, ENN) == 0)
    return 1;
  else
    return 0;
}
