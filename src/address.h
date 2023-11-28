#ifndef ADDRESS_H
#define ADDRESS_H

#include <stdlib.h>
#include <string.h>

#include "context.h"

#define WOTS_HASH 0x00000000  // htobe32(0)
#define WOTS_PK 0x01000000    // htobe32(1)
#define TREE 0x02000000       // htobe32(2)
#define FORS_TREE 0x03000000  // htobe32(3)
#define FORS_ROOTS 0x04000000 // htobe32(4)
#define WOTS_PRF 0x05000000   // htobe32(5)
#define FORS_PRF 0x06000000   // htobe32(6)

#define ADRS_LAYER_ADDRESS_IDX 0
#define ADRS_TREE_ADDRESS_IDX 1
#define ADRS_TYPE_IDX 4
#define ADRS_KEYPAIR_IDX 5
#define ADRS_CHAIN_ADDRESS_IDX 6
#define ADRS_HASH_ADDRESS_IDX 7
#define ADRS_TREE_HEIGHT_IDX 6
#define ADRS_TREE_INDEX_IDX 7

typedef struct __attribute__((packed)) {
  uint32_t valhb;
  uint64_t vallb;
} idx_tree_t;

#define idx_tree_mod_2hp(x) (x.vallb & ((1ull << HP) - 1))
#define it_highmask(s) ((1 << s) - 1)
#define it_highand(x, s) (((uint64_t)x->valhb & it_highmask(s)) << (64 - s))
#define idx_tree_shift(x, s)                                                   \
  do {                                                                         \
    (x)->vallb = ((x)->vallb >> s) + it_highand((x), s);                       \
    (x)->valhb >>= s;                                                          \
  } while (0)

#endif
