#ifndef WOTSP_H
#define WOTSP_H

#include <assert.h>
#include <endian.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "address.h"
#include "context.h"
#include "hash.h"
#include "utils.h"

int wotsp_pkgen(uint8_t *out, const uint8_t sk_seed[ENN],
                const uint8_t pk_seed[ENN], uint32_t adrs[ADRS_LEN]);
int wotsp_sign(uint8_t *out, const uint8_t *m, const uint8_t sk_seed[ENN],
               const uint8_t pk_seed[ENN], uint32_t adrs[ADRS_LEN]);
int wotsp_pk_from_sig(uint8_t *out, const uint8_t *sig, const uint8_t *m,
                      const size_t nm, const uint8_t pk_seed[ENN],
                      uint32_t adrs[ADRS_LEN]);
#endif
