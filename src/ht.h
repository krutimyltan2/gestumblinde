#ifndef HT_H
#define HT_H

#include <assert.h>
#include <endian.h>
#include <stdint.h>
#include <stdlib.h>
#include <strings.h>

#include "address.h"
#include "context.h"
#include "xmss.h"

int ht_sign(uint8_t *out, const uint8_t msg[ENN], const uint8_t sk_seed[ENN],
            const uint8_t pk_seed[ENN], idx_tree_t idx_tree, uint64_t idx_leaf);

int ht_verify(const uint8_t msg[ENN], const uint8_t *sig_ht,
              const uint8_t pk_seed[ENN], const idx_tree_t idx_tree,
              const uint64_t idx_leaf, const uint8_t pk_root[ENN]);

#endif
