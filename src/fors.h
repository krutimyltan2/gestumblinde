#ifndef FORS_H
#define FORS_H

#include <assert.h>
#include <stdlib.h>

#include "address.h"
#include "context.h"
#include "hash.h"
#include "utils.h"

void fors_skgen(uint8_t *out, const uint8_t sk_seed[ENN],
                const uint8_t pk_seed[ENN], uint32_t adrs[ADRS_LEN],
                const uint64_t idx);
void fors_node(uint8_t *out, const uint8_t sk_seed[ENN], const uint64_t i,
               const uint64_t z, const uint8_t pk_seed[ENN],
               uint32_t adrs[ADRS_LEN]);
void fors_sign(uint8_t *out, const uint8_t md[FORS_MD_LEN],
               const uint8_t sk_seed[ENN], const uint8_t pk_seed[ENN],
               uint32_t adrs[ADRS_LEN]);
void fors_pk_from_sig(uint8_t *out, const uint8_t sig_fors[FORS_SIG_LEN],
                      const uint8_t md[FORS_MD_LEN], const uint8_t pk_seed[ENN],
                      uint32_t adrs[ADRS_LEN]);

#endif
