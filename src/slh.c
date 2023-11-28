#include "slh.h"

static inline void idx_tree_mod_2d(idx_tree_t *x, const size_t s) {
  if (s >= 64) {
    size_t sp = s - 64;
    x->valhb &= (1ul << sp) - 1;
  } else {
    x->valhb = 0;
    x->vallb &= (1ull << s) - 1;
  }
}

static inline void set_tree_address(uint32_t adrs[ADRS_LEN], idx_tree_t idx) {
  idx_tree_t tmp;
  tmp.valhb = htobe32(idx.valhb);
  tmp.vallb = htobe64(idx.vallb);

  memcpy(&adrs[ADRS_TREE_ADDRESS_IDX], &tmp, sizeof(tmp));
}

void slh_keygen(uint8_t *sk, uint8_t *pk) {
  randombytes(sk, ENN);
  randombytes(sk + ENN, ENN);
  randombytes(pk, ENN);
  memcpy(sk + 2 * ENN, pk, ENN);

  uint32_t adrs[ADRS_LEN] = {0};
  adrs[ADRS_LAYER_ADDRESS_IDX] = htobe32(D - 1);

  xmss_node(pk + ENN, sk, 0, HP, pk, adrs);

  memcpy(sk + 3 * ENN, pk + ENN, ENN);
}

void slh_sign(uint8_t *out, const uint8_t *m, const size_t mlen,
              const uint8_t *sk, int randomize) {
  const uint8_t *sk_seed = sk;
  const uint8_t *sk_prf = sk + ENN;
  const uint8_t *pk_seed = sk + 2 * ENN;
  const uint8_t *pk_root = sk + 3 * ENN;

  uint8_t opt_rand[ENN];
  memcpy(opt_rand, pk_seed, ENN);
  if (randomize) {
    randombytes(opt_rand, ENN);
  }

  uint8_t *cout = out;
  hash_prf_msg(out, sk_prf, opt_rand, m, mlen);

  uint8_t digest[M];
  hash_h_msg(digest, M, cout, pk_seed, pk_root, m, mlen);
  cout += ENN;

  uint8_t *md = digest;
  uint8_t *tmp_idx_tree = digest + FORS_MD_LEN;
  uint8_t *tmp_idx_leaf = digest + FORS_MD_LEN + IDX_TREE_LEN;

  idx_tree_t idx_tree;
  memcpy((uint8_t *)&idx_tree + (sizeof(idx_tree) - IDX_TREE_LEN), tmp_idx_tree,
         IDX_TREE_LEN);
  idx_tree.valhb = htobe32(idx_tree.valhb);
  idx_tree.vallb = htobe64(idx_tree.vallb);
  idx_tree_mod_2d(&idx_tree, H - H / D);
  uint64_t idx_leaf = to_int(tmp_idx_leaf, IDX_LEAF_LEN);
  idx_leaf &= ((1 << (H / D)) - 1);

  uint32_t adrs[ADRS_LEN] = {0};
  set_tree_address(adrs, idx_tree);
  adrs[ADRS_TYPE_IDX] = FORS_TREE;
  adrs[ADRS_KEYPAIR_IDX] = htobe32(idx_leaf);
  bzero(&adrs[ADRS_KEYPAIR_IDX + 1], 2 * sizeof(*adrs));

  fors_sign(cout, md, sk_seed, pk_seed, adrs);

  uint8_t pk_fors[ENN];
  fors_pk_from_sig(pk_fors, cout, md, pk_seed, adrs);
  cout += FORS_SIG_LEN;

  ht_sign(cout, pk_fors, sk_seed, pk_seed, idx_tree, idx_leaf);
}

int slh_verify(const uint8_t *m, const size_t mlen, const uint8_t *sig,
               const size_t siglen, const uint8_t *pk) {
  if (siglen != (ENN * (1 + K * (1 + A) + H + D * WOTSP_LEN))) {
    return 0;
  }

  const uint8_t *pk_seed = pk;
  const uint8_t *pk_root = pk + ENN;
  const uint8_t *csig = sig;
  const uint8_t *sig_fors = sig + ENN;
  const uint8_t *sig_ht = sig + ENN + FORS_SIG_LEN;

  uint8_t digest[M];
  hash_h_msg(digest, M, csig, pk_seed, pk_root, m, mlen);

  uint8_t *md = digest;
  uint8_t *tmp_idx_tree = digest + FORS_MD_LEN;
  uint8_t *tmp_idx_leaf = digest + FORS_MD_LEN + IDX_TREE_LEN;

  idx_tree_t idx_tree;
  memcpy((uint8_t *)&idx_tree + (sizeof(idx_tree) - IDX_TREE_LEN), tmp_idx_tree,
         IDX_TREE_LEN);
  idx_tree.valhb = htobe32(idx_tree.valhb);
  idx_tree.vallb = htobe64(idx_tree.vallb);
  idx_tree_mod_2d(&idx_tree, H - H / D);
  uint64_t idx_leaf = to_int(tmp_idx_leaf, IDX_LEAF_LEN);
  idx_leaf &= ((1 << (H / D)) - 1);

  uint32_t adrs[ADRS_LEN] = {0};
  set_tree_address(adrs, idx_tree);
  adrs[ADRS_TYPE_IDX] = FORS_TREE;
  adrs[ADRS_KEYPAIR_IDX] = htobe32(idx_leaf);
  bzero(&adrs[ADRS_KEYPAIR_IDX + 1], 2 * sizeof(*adrs));

  uint8_t pk_fors[ENN];
  fors_pk_from_sig(pk_fors, sig_fors, md, pk_seed, adrs);

  return ht_verify(pk_fors, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root);
}
