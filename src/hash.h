#ifndef HASH_H
#define HASH_H

#include "context.h"
#include <stdint.h>
#include <stdlib.h>

#if defined(SLH_DSA_SHAKE_128S) || defined(SLH_DSA_SHAKE_128F) ||              \
    defined(SLH_DSA_SHAKE_192S) || defined(SLH_DSA_SHAKE_192F) ||              \
    defined(SLH_DSA_SHAKE_256S) || defined(SLH_DSA_SHAKE_256F)

#include <sha3.h>

#define hash_h(out, pk_seed, adrs, m) (hash_t(out, 2, pk_seed, adrs, m))
#define hash_f(out, pk_seed, adrs, m) (hash_t(out, 1, pk_seed, adrs, m))
#define hash_prf(out, pk_seed, sk_seed, adrs)                                  \
  (hash_t(out, 1, pk_seed, adrs, sk_seed))

#else

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>

#define hash_h(out, pk_seed, adrs, m) (hash_t(out, 2, pk_seed, adrs, m))

#if defined(SLH_DSA_SHA2_192S) || defined(SLH_DSA_SHA2_192F) ||                \
    defined(SLH_DSA_SHA2_256S) || defined(SLH_DSA_SHA2_256F)

void hash_f(uint8_t *out, const uint8_t pk_seed[ENN],
            const uint32_t adrs[ADRS_LEN], const uint8_t *m1);
#define hash_prf(out, pk_seed, sk_seed, adrs)                                  \
  (hash_f(out, pk_seed, adrs, sk_seed))

#else

#define hash_f(out, pk_seed, adrs, m) (hash_t(out, 1, pk_seed, adrs, m))
#define hash_prf(out, pk_seed, sk_seed, adrs)                                  \
  (hash_t(out, 1, pk_seed, adrs, sk_seed))

#endif

#endif

void hash_t(uint8_t *out, const size_t len, const uint8_t pk_seed[ENN],
            const uint32_t adrs[ADRS_LEN], const uint8_t *m_ell);

void hash_prf_msg(uint8_t *out, const uint8_t *sk_prf, const uint8_t *opt_rand,
                  const uint8_t *m, const size_t mlen);

void hash_h_msg(uint8_t *out, const size_t out_len, const uint8_t *r,
                const uint8_t *pk_seed, const uint8_t *pk_root,
                const uint8_t *m, const size_t mlen);

#endif
