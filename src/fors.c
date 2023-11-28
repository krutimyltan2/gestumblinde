#include "fors.h"
#include "address.h"
#include "utils.h"

void fors_skgen(uint8_t *out, const uint8_t sk_seed[ENN],
                const uint8_t pk_seed[ENN], uint32_t adrs[ADRS_LEN],
                const uint64_t idx) {
  uint32_t skadrs[ADRS_LEN];
  memcpy(skadrs, adrs, ADRS_TYPE_IDX * sizeof(*skadrs));
  skadrs[ADRS_TYPE_IDX] = FORS_PRF;
  skadrs[ADRS_KEYPAIR_IDX] = adrs[ADRS_KEYPAIR_IDX];
  skadrs[ADRS_TREE_HEIGHT_IDX] = 0;
  skadrs[ADRS_TREE_INDEX_IDX] = htobe32(idx);

  hash_prf(out, pk_seed, sk_seed, skadrs);
}

void fors_node(uint8_t *out, const uint8_t sk_seed[ENN], const uint64_t i,
               const uint64_t z, const uint8_t pk_seed[ENN],
               uint32_t adrs[ADRS_LEN]) {
  assert(z <= A);
  assert(i < K * (1ull << (A - z)));

  uint8_t sk[ENN];
  if (z == 0) {
    fors_skgen(sk, sk_seed, pk_seed, adrs, i);
    adrs[ADRS_TREE_HEIGHT_IDX] = 0;
    adrs[ADRS_TREE_INDEX_IDX] = htobe32(i);
    hash_f(out, pk_seed, adrs, sk);
  } else {
    uint8_t buffer[2 * ENN];
    uint8_t *lnode = buffer;
    uint8_t *rnode = buffer + ENN;

    fors_node(lnode, sk_seed, 2 * i, z - 1, pk_seed, adrs);
    fors_node(rnode, sk_seed, 2 * i + 1, z - 1, pk_seed, adrs);

    adrs[ADRS_TREE_HEIGHT_IDX] = htobe32(z);
    adrs[ADRS_TREE_INDEX_IDX] = htobe32(i);

    hash_h(out, pk_seed, adrs, buffer);
  }
}

void fors_sign(uint8_t *out, const uint8_t md[FORS_MD_LEN],
               const uint8_t sk_seed[ENN], const uint8_t pk_seed[ENN],
               uint32_t adrs[ADRS_LEN]) {
  uint64_t indices[K];
  base_2b(indices, md, FORS_MD_LEN, A, K);

  uint8_t *cout = out;

  size_t i, j;
  for (i = 0; i < K; i++) {
    fors_skgen(cout, sk_seed, pk_seed, adrs, i * (1ull << A) + indices[i]);
    cout += ENN;

    for (j = 0; j < A; j++) {
      uint64_t s = (indices[i] >> j) ^ 0x01;
      fors_node(cout, sk_seed, i * (1ull << (A - j)) + s, j, pk_seed, adrs);
      cout += ENN;
    }
  }
}

void fors_pk_from_sig(uint8_t *out, const uint8_t sig_fors[FORS_SIG_LEN],
                      const uint8_t md[FORS_MD_LEN], const uint8_t pk_seed[ENN],
                      uint32_t adrs[ADRS_LEN]) {
  uint64_t indices[K];
  base_2b(indices, md, FORS_MD_LEN, A, K);

  const uint8_t *csig = sig_fors;
  uint8_t buffer[3 * ENN];
  uint8_t root[K * ENN];
  uint8_t *croot = root;

  size_t i, j;
  for (i = 0; i < K; i++) {
    adrs[ADRS_TREE_HEIGHT_IDX] = 0;
    adrs[ADRS_TREE_INDEX_IDX] = htobe32(i * (1ull << A) + indices[i]);
    hash_f(buffer + ENN, pk_seed, adrs, csig);
    csig += ENN;

    for (j = 0; j < A; j++) {
      adrs[ADRS_TREE_HEIGHT_IDX] = htobe32(j + 1);
      if (((indices[i] >> j) & 0x01) == 0) {
        adrs[ADRS_TREE_INDEX_IDX] =
            htobe32(betoh32(adrs[ADRS_TREE_INDEX_IDX]) >> 1);
        memcpy(buffer + 2 * ENN, csig, ENN);
        hash_h(buffer + ENN, pk_seed, adrs, buffer + ENN);
      } else {
        adrs[ADRS_TREE_INDEX_IDX] =
            htobe32((betoh32(adrs[ADRS_TREE_INDEX_IDX]) - 1) >> 1);
        memcpy(buffer, csig, ENN);
        hash_h(buffer + ENN, pk_seed, adrs, buffer);
      }
      csig += ENN;
    }
    memcpy(croot, buffer + ENN, ENN);
    croot += ENN;
  }

  uint32_t forspkadrs[ADRS_LEN];
  memcpy(forspkadrs, adrs, ADRS_TYPE_IDX * sizeof(*adrs));
  forspkadrs[ADRS_TYPE_IDX] = FORS_ROOTS;
  forspkadrs[ADRS_KEYPAIR_IDX] = adrs[ADRS_KEYPAIR_IDX];
  bzero(&forspkadrs[ADRS_KEYPAIR_IDX + 1], 2 * sizeof(*adrs));

  hash_t(out, K, pk_seed, forspkadrs, root);
}
