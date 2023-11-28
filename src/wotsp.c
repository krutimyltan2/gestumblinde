#include "wotsp.h"

/*
 * Chaining function used in WOTS+.
 */
static inline void wotsp_chain(uint8_t out[ENN], const uint8_t X[ENN],
                               const uint64_t i, const uint64_t s,
                               const uint8_t pk_seed[ENN],
                               uint32_t adrs[ADRS_LEN]) {
  assert(i + s < WOTSP_W);

  uint8_t tmp[ENN];
  memcpy(tmp, X, ENN);

  uint32_t j;
  for (j = i; j < i + s; j++) {
    adrs[ADRS_HASH_ADDRESS_IDX] = htobe32(j);
    hash_f(tmp, pk_seed, adrs, tmp);
  }

  memcpy(out, tmp, ENN);
}

/*
 * Generate a WOTS+ public key.
 */
int wotsp_pkgen(uint8_t *out, const uint8_t sk_seed[ENN],
                const uint8_t pk_seed[ENN], uint32_t adrs[ADRS_LEN]) {
  uint32_t sk_adrs[ADRS_LEN];
  uint8_t tmp[WOTSP_LEN * ENN];
  uint8_t *tmpp = tmp;

  memcpy(sk_adrs, adrs, ADRS_TYPE_IDX * sizeof(*adrs));
  sk_adrs[ADRS_TYPE_IDX] = WOTS_PRF;
  sk_adrs[ADRS_KEYPAIR_IDX] = adrs[ADRS_KEYPAIR_IDX];
  sk_adrs[ADRS_HASH_ADDRESS_IDX] = 0;

  uint8_t prf_buffer[ENN];
  uint32_t be_i;

  size_t i;
  for (i = 0; i < WOTSP_LEN; i++) {
    be_i = htobe32(i);
    sk_adrs[ADRS_CHAIN_ADDRESS_IDX] = be_i;
    hash_prf(prf_buffer, pk_seed, sk_seed, sk_adrs);
    adrs[ADRS_CHAIN_ADDRESS_IDX] = be_i;
    wotsp_chain(tmpp, prf_buffer, 0, WOTSP_W - 1, pk_seed, adrs);
    tmpp += ENN;
  }

  uint32_t wotspk_adrs[ADRS_LEN];
  memcpy(wotspk_adrs, adrs, ADRS_TYPE_IDX * sizeof(*adrs));
  wotspk_adrs[ADRS_TYPE_IDX] = WOTS_PK;
  wotspk_adrs[ADRS_KEYPAIR_IDX] = adrs[ADRS_KEYPAIR_IDX];
  wotspk_adrs[ADRS_CHAIN_ADDRESS_IDX] = 0;
  wotspk_adrs[ADRS_HASH_ADDRESS_IDX] = 0;
  hash_t(out, WOTSP_LEN, pk_seed, wotspk_adrs, tmp);

  return 0;
}

/*
 * Generate a WOTS+ signature on an n-byte message
 */
int wotsp_sign(uint8_t *out, const uint8_t *m, const uint8_t sk_seed[ENN],
               const uint8_t pk_seed[ENN], uint32_t adrs[ADRS_LEN]) {
  uint64_t csum = 0;

  uint64_t msg[WOTSP_LEN];
  base_2b(msg, m, ENN, LGW, WOTSP_LEN1);

  size_t i;
  for (i = 0; i < WOTSP_LEN1; i++) {
    assert(WOTSP_W > msg[i]);
    csum += WOTSP_W - 1 - msg[i];
  }

  csum <<= (8 - ((WOTSP_LEN2 * LGW) % 8)) % 8;

  uint8_t csum_bytes[(WOTSP_LEN2 * LGW + 7) / 8];
  to_bytes(csum_bytes, (WOTSP_LEN2 * LGW + 7) / 8, csum);
  base_2b(&msg[WOTSP_LEN1], csum_bytes, (WOTSP_LEN2 * LGW + 7) / 8, LGW,
          WOTSP_LEN2);

  uint32_t sk_adrs[ADRS_LEN] = {0};
  memcpy(sk_adrs, adrs, ADRS_TYPE_IDX * sizeof(*adrs));
  sk_adrs[ADRS_TYPE_IDX] = WOTS_PRF;
  sk_adrs[ADRS_KEYPAIR_IDX] = adrs[ADRS_KEYPAIR_IDX];

  uint8_t *cout = out;
  uint8_t sk[ENN];
  for (i = 0; i < WOTSP_LEN; i++) {
    uint32_t be_i = htobe32(i);
    sk_adrs[ADRS_CHAIN_ADDRESS_IDX] = be_i;
    hash_prf(sk, pk_seed, sk_seed, sk_adrs);
    adrs[ADRS_CHAIN_ADDRESS_IDX] = be_i;
    wotsp_chain(cout, sk, 0, msg[i], pk_seed, adrs);
    cout += ENN;
  }

  return 0;
}

/*
 * Computes a WOTS+ public key from a message and its signature.
 */
int wotsp_pk_from_sig(uint8_t *out, const uint8_t *sig, const uint8_t *m,
                      const size_t nm, const uint8_t pk_seed[ENN],
                      uint32_t adrs[ADRS_LEN]) {
  uint64_t csum = 0;

  uint64_t msg[WOTSP_LEN];
  base_2b(msg, m, nm, LGW, WOTSP_LEN1);

  size_t i;
  for (i = 0; i < WOTSP_LEN1; i++) {
    assert(WOTSP_W > msg[i]);
    csum += WOTSP_W - 1 - msg[i];
  }

  csum <<= (8 - ((WOTSP_LEN2 * LGW) % 8)) % 8;

  uint8_t csum_bytes[(WOTSP_LEN2 * LGW + 7) / 8];
  to_bytes(csum_bytes, (WOTSP_LEN2 * LGW + 7) / 8, csum);
  base_2b(&msg[WOTSP_LEN1], csum_bytes, (WOTSP_LEN2 * LGW + 7) / 8, LGW,
          WOTSP_LEN2);

  uint8_t tmp[WOTSP_LEN * ENN];
  const uint8_t *csig = sig;
  uint8_t *cout = tmp;
  for (i = 0; i < WOTSP_LEN; i++) {
    adrs[ADRS_CHAIN_ADDRESS_IDX] = htobe32(i);
    wotsp_chain(cout, csig, msg[i], WOTSP_W - 1 - msg[i], pk_seed, adrs);
    cout += ENN;
    csig += ENN;
  }

  uint32_t wotspk_adrs[ADRS_LEN];
  memcpy(wotspk_adrs, adrs, ADRS_TYPE_IDX * sizeof(*adrs));
  wotspk_adrs[ADRS_TYPE_IDX] = WOTS_PK;
  wotspk_adrs[ADRS_KEYPAIR_IDX] = adrs[ADRS_KEYPAIR_IDX];
  wotspk_adrs[ADRS_CHAIN_ADDRESS_IDX] = 0;
  wotspk_adrs[ADRS_HASH_ADDRESS_IDX] = 0;

  hash_t(out, WOTSP_LEN, pk_seed, wotspk_adrs, tmp);

  return 0;
}
