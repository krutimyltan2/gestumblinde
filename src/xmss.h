#ifndef XMSS_H
#define XMSS_H

#include <assert.h>
#include <endian.h>
#include <stdint.h>
#include <stdlib.h>
#include <strings.h>

#include "context.h"
#include "wotsp.h"

int xmss_node(uint8_t *out, const uint8_t sk_seed[ENN], const uint64_t i,
              const uint64_t z, const uint8_t pk_seed[ENN],
              uint32_t adrs[ADRS_LEN]);

int xmss_sign(uint8_t *out, const uint8_t m[ENN], const uint8_t sk_seed[ENN],
              const uint64_t idx, const uint8_t pk_seed[ENN],
              uint32_t adrs[ADRS_LEN]);

int xmss_pk_from_sig(uint8_t *out, const uint64_t idx, const uint8_t *sig,
                     const uint8_t m[ENN], const uint8_t pk_seed[ENN],
                     uint32_t adrs[ADRS_LEN]);
#endif
