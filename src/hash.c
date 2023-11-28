#include "hash.h"

#if defined(SLH_DSA_SHAKE_128S) || defined(SLH_DSA_SHAKE_128F) ||              \
    defined(SLH_DSA_SHAKE_192S) || defined(SLH_DSA_SHAKE_192F) ||              \
    defined(SLH_DSA_SHAKE_256S) || defined(SLH_DSA_SHAKE_256F)

void hash_t(uint8_t *out, const size_t len, const uint8_t pk_seed[ENN],
            const uint32_t adrs[ADRS_LEN], const uint8_t *m_ell) {
  sha3_ctx_t h;
  shake256_init(&h);
  shake_update(&h, pk_seed, ENN);
  shake_update(&h, adrs, ADRS_LEN * sizeof(*adrs));
  shake_update(&h, m_ell, ENN * len);
  shake_xof(&h);
  shake_out(&h, out, ENN);
}

void hash_h_msg(uint8_t *out, const size_t out_len, const uint8_t *r,
                const uint8_t *pk_seed, const uint8_t *pk_root,
                const uint8_t *m, const size_t mlen) {
  sha3_ctx_t h;
  shake256_init(&h);
  shake_update(&h, r, ENN);
  shake_update(&h, pk_seed, ENN);
  shake_update(&h, pk_root, ENN);
  shake_update(&h, m, mlen);
  shake_xof(&h);
  shake_out(&h, out, out_len);
}

void hash_prf_msg(uint8_t *out, const uint8_t *sk_prf, const uint8_t *opt_rand,
                  const uint8_t *m, const size_t mlen) {
  sha3_ctx_t h;
  shake256_init(&h);
  shake_update(&h, sk_prf, ENN);
  shake_update(&h, opt_rand, ENN);
  shake_update(&h, m, mlen);
  shake_xof(&h);
  shake_out(&h, out, ENN);
}

#elif defined(SLH_DSA_SHA2_128S) || defined(SLH_DSA_SHA2_128F)

static inline int adrs_update(SHA256_CTX *c, const uint32_t adrs[ADRS_LEN]) {
  const uint8_t *adrsb = (const uint8_t *)adrs;
  int res = 1;
  res &= SHA256_Update(c, &adrsb[3], 1);
  res &= SHA256_Update(c, &adrsb[8], 8);
  res &= SHA256_Update(c, &adrsb[19], 1);
  res &= SHA256_Update(c, &adrsb[20], 12);
  return res;
}

static inline void mgf1_sha256(uint8_t *out, const uint8_t *seed,
                               const size_t seedlen, const size_t mlen) {
  uint32_t c;

  uint8_t buffer[seedlen + 4];
  memcpy(buffer, seed, seedlen);

  size_t steps = (mlen + SHA256_DIGEST_LENGTH - 1) / SHA256_DIGEST_LENGTH;
  uint8_t tmp[mlen + SHA256_DIGEST_LENGTH]; // always enough space
  uint8_t *ctmp = tmp;

  for (c = 0; c < steps; c++) {
    uint32_t cbe = htobe32(c);
    memcpy(buffer + seedlen, &cbe, sizeof(cbe));
    SHA256(buffer, seedlen + 4, ctmp);
    ctmp += SHA256_DIGEST_LENGTH;
  }

  memcpy(out, tmp, mlen);
}

void hash_t(uint8_t *out, const size_t len, const uint8_t pk_seed[ENN],
            const uint32_t adrs[ADRS_LEN], const uint8_t *m_ell) {
  SHA256_CTX c;

  if (!SHA256_Init(&c)) {
    fprintf(stderr, "Failed to init SHA256.");
    exit(1);
  }

  if (!SHA256_Update(&c, pk_seed, ENN)) {
    fprintf(stderr, "Failed to update SHA256 with R.");
    exit(1);
  }

  uint8_t zero_bytes[64] = {0};

  if (!SHA256_Update(&c, zero_bytes, 64 - ENN)) {
    fprintf(stderr, "Failed to update SHA256 with zero_bytes.");
    exit(1);
  }

  if (!adrs_update(&c, adrs)) {
    fprintf(stderr, "Failed to update SHA256 with address.");
    exit(1);
  }

  if (!SHA256_Update(&c, m_ell, ENN * len)) {
    fprintf(stderr, "Could not update SHA256 with M_ell.");
    exit(1);
  }

  uint8_t tmp[SHA256_DIGEST_LENGTH];
  if (!SHA256_Final(tmp, &c)) {
    fprintf(stderr, "Could not compute SHA256 digest.");
    exit(1);
  }

  memcpy(out, tmp, ENN);
}

void hash_h_msg(uint8_t *out, const size_t out_len, const uint8_t *r,
                const uint8_t *pk_seed, const uint8_t *pk_root,
                const uint8_t *m, const size_t mlen) {
  SHA256_CTX c;

  if (!SHA256_Init(&c)) {
    fprintf(stderr, "Failed to init SHA256.");
    exit(1);
  }

  if (!SHA256_Update(&c, r, ENN)) {
    fprintf(stderr, "Failed to update SHA256 with R.");
    exit(1);
  }

  if (!SHA256_Update(&c, pk_seed, ENN)) {
    fprintf(stderr, "Failed to update SHA256 with pk_seed.");
    exit(1);
  }

  if (!SHA256_Update(&c, pk_root, ENN)) {
    fprintf(stderr, "Failed to update SHA256 with pk_root.");
    exit(1);
  }

  if (!SHA256_Update(&c, m, mlen)) {
    fprintf(stderr, "Failed to update SHA256 with m.");
    exit(1);
  }

  uint8_t hash_buffer[2 * ENN + SHA256_DIGEST_LENGTH];
  if (!SHA256_Final(hash_buffer + 2 * ENN, &c)) {
    fprintf(stderr, "Failed to compute digest.");
    exit(1);
  }

  memcpy(hash_buffer, r, ENN);
  memcpy(hash_buffer + ENN, pk_seed, ENN);

  mgf1_sha256(out, hash_buffer, 2 * ENN + SHA256_DIGEST_LENGTH, out_len);
}

void hash_prf_msg(uint8_t *out, const uint8_t *sk_prf, const uint8_t *opt_rand,
                  const uint8_t *m, const size_t mlen) {
  HMAC_CTX *hmac = HMAC_CTX_new();

  if (!HMAC_Init(hmac, sk_prf, ENN, EVP_sha256())) {
    fprintf(stderr, "Failed to init HMAC-SHA256.");
    exit(1);
  }

  if (!HMAC_Update(hmac, opt_rand, ENN)) {
    fprintf(stderr, "Failed to update HMAC-SHA256 with opt_rand.");
    exit(1);
  }

  if (!HMAC_Update(hmac, m, mlen)) {
    fprintf(stderr, "Could not update HMAC-SHA256 with message.");
    exit(1);
  }

  uint8_t tmp[SHA256_DIGEST_LENGTH];
  if (!HMAC_Final(hmac, tmp, NULL)) {
    fprintf(stderr, "Could not compute HMAC-SHA256 digest.");
    exit(1);
  }

  HMAC_CTX_free(hmac);

  memcpy(out, tmp, ENN);
}

#elif defined(SLH_DSA_SHA2_192S) || defined(SLH_DSA_SHA2_192F) ||              \
    defined(SLH_DSA_SHA2_256S) || defined(SLH_DSA_SHA2_256F)

static inline int adrs_update_sha256(SHA256_CTX *c,
                                     const uint32_t adrs[ADRS_LEN]) {
  const uint8_t *adrsb = (const uint8_t *)adrs;
  int res = 1;
  res &= SHA256_Update(c, &adrsb[3], 1);
  res &= SHA256_Update(c, &adrsb[8], 8);
  res &= SHA256_Update(c, &adrsb[19], 1);
  res &= SHA256_Update(c, &adrsb[20], 12);
  return res;
}

static inline int adrs_update_sha512(SHA512_CTX *c,
                                     const uint32_t adrs[ADRS_LEN]) {
  const uint8_t *adrsb = (const uint8_t *)adrs;
  int res = 1;
  res &= SHA512_Update(c, &adrsb[3], 1);
  res &= SHA512_Update(c, &adrsb[8], 8);
  res &= SHA512_Update(c, &adrsb[19], 1);
  res &= SHA512_Update(c, &adrsb[20], 12);
  return res;
}

static inline void mgf1_sha512(uint8_t *out, const uint8_t *seed,
                               const size_t seedlen, const size_t mlen) {
  uint32_t c;

  uint8_t buffer[seedlen + 4];
  memcpy(buffer, seed, seedlen);

  size_t steps = (mlen + SHA512_DIGEST_LENGTH - 1) / SHA512_DIGEST_LENGTH;
  uint8_t tmp[mlen + SHA512_DIGEST_LENGTH]; // always enough space
  uint8_t *ctmp = tmp;

  for (c = 0; c < steps; c++) {
    uint32_t cbe = htobe32(c);
    memcpy(buffer + seedlen, &cbe, sizeof(cbe));
    SHA512(buffer, seedlen + 4, ctmp);
    ctmp += SHA512_DIGEST_LENGTH;
  }

  memcpy(out, tmp, mlen);
}

void hash_t(uint8_t *out, const size_t len, const uint8_t pk_seed[ENN],
            const uint32_t adrs[ADRS_LEN], const uint8_t *m_ell) {
  SHA512_CTX c;

  if (!SHA512_Init(&c)) {
    fprintf(stderr, "Failed to init SHA512.");
    exit(1);
  }

  if (!SHA512_Update(&c, pk_seed, ENN)) {
    fprintf(stderr, "Failed to update SHA512 with R.");
    exit(1);
  }

  uint8_t zero_bytes[128] = {0};

  if (!SHA512_Update(&c, zero_bytes, 128 - ENN)) {
    fprintf(stderr, "Failed to update SHA512 with zero_bytes.");
    exit(1);
  }

  if (!adrs_update_sha512(&c, adrs)) {
    fprintf(stderr, "Failed to update SHA512 with address.");
    exit(1);
  }

  if (!SHA512_Update(&c, m_ell, ENN * len)) {
    fprintf(stderr, "Could not update SHA512 with M_ell.");
    exit(1);
  }

  uint8_t tmp[SHA512_DIGEST_LENGTH];
  if (!SHA512_Final(tmp, &c)) {
    fprintf(stderr, "Could not compute SHA512 digest.");
    exit(1);
  }

  memcpy(out, tmp, ENN);
}

void hash_h_msg(uint8_t *out, const size_t out_len, const uint8_t *r,
                const uint8_t *pk_seed, const uint8_t *pk_root,
                const uint8_t *m, const size_t mlen) {
  SHA512_CTX c;

  if (!SHA512_Init(&c)) {
    fprintf(stderr, "Failed to init SHA512.");
    exit(1);
  }

  if (!SHA512_Update(&c, r, ENN)) {
    fprintf(stderr, "Failed to update SHA512 with R.");
    exit(1);
  }

  if (!SHA512_Update(&c, pk_seed, ENN)) {
    fprintf(stderr, "Failed to update SHA512 with pk_seed.");
    exit(1);
  }

  if (!SHA512_Update(&c, pk_root, ENN)) {
    fprintf(stderr, "Failed to update SHA512 with pk_root.");
    exit(1);
  }

  if (!SHA512_Update(&c, m, mlen)) {
    fprintf(stderr, "Failed to update SHA512 with m.");
    exit(1);
  }

  uint8_t hash_buffer[2 * ENN + SHA512_DIGEST_LENGTH];
  if (!SHA512_Final(hash_buffer + 2 * ENN, &c)) {
    fprintf(stderr, "Failed to compute digest.");
    exit(1);
  }

  memcpy(hash_buffer, r, ENN);
  memcpy(hash_buffer + ENN, pk_seed, ENN);

  mgf1_sha512(out, hash_buffer, 2 * ENN + SHA512_DIGEST_LENGTH, out_len);
}

void hash_prf_msg(uint8_t *out, const uint8_t *sk_prf, const uint8_t *opt_rand,
                  const uint8_t *m, const size_t mlen) {
  HMAC_CTX *hmac = HMAC_CTX_new();

  if (!HMAC_Init(hmac, sk_prf, ENN, EVP_sha512())) {
    fprintf(stderr, "Failed to init HMAC-SHA512.");
    exit(1);
  }

  if (!HMAC_Update(hmac, opt_rand, ENN)) {
    fprintf(stderr, "Failed to update HMAC-SHA512 with opt_rand.");
    exit(1);
  }

  if (!HMAC_Update(hmac, m, mlen)) {
    fprintf(stderr, "Could not update HMAC-SHA512 with message.");
    exit(1);
  }

  uint8_t tmp[SHA512_DIGEST_LENGTH];
  if (!HMAC_Final(hmac, tmp, NULL)) {
    fprintf(stderr, "Could not compute HMAC-SHA512 digest.");
    exit(1);
  }

  HMAC_CTX_free(hmac);

  memcpy(out, tmp, ENN);
}

void hash_f(uint8_t *out, const uint8_t pk_seed[ENN],
            const uint32_t adrs[ADRS_LEN], const uint8_t *m1) {
  SHA256_CTX c;

  if (!SHA256_Init(&c)) {
    fprintf(stderr, "Failed to init SHA256.");
    exit(1);
  }

  if (!SHA256_Update(&c, pk_seed, ENN)) {
    fprintf(stderr, "Failed to update SHA256 with R.");
    exit(1);
  }

  uint8_t zero_bytes[64] = {0};

  if (!SHA256_Update(&c, zero_bytes, 64 - ENN)) {
    fprintf(stderr, "Failed to update SHA256 with zero_bytes.");
    exit(1);
  }

  if (!adrs_update_sha256(&c, adrs)) {
    fprintf(stderr, "Failed to update SHA256 with address.");
    exit(1);
  }

  if (!SHA256_Update(&c, m1, ENN)) {
    fprintf(stderr, "Could not update SHA256 with M1.");
    exit(1);
  }

  uint8_t tmp[SHA256_DIGEST_LENGTH];
  if (!SHA256_Final(tmp, &c)) {
    fprintf(stderr, "Could not compute SHA256 digest.");
    exit(1);
  }

  memcpy(out, tmp, ENN);
}

#else

#error "Could not recognize parameter set definition."

#endif
