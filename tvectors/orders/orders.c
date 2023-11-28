#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Use values as in params/params-sphincs-shake-128s.h
#define SPX_FORS_HEIGHT 12
#define SPX_FORS_TREES 14

/*
 * Implementation as in ref/fors.c.
 */
static void message_to_indices(uint32_t *indices, const unsigned char *m)
{
    unsigned int i, j;
    unsigned int offset = 0;

    for (i = 0; i < SPX_FORS_TREES; i++) {
        indices[i] = 0;
        for (j = 0; j < SPX_FORS_HEIGHT; j++) {
            indices[i] ^= ((m[offset >> 3] >> (offset & 0x7)) & 1u) << j;
            offset++;
        }
    }
}

/*
 * Implementation prior to commit
 *   74b618d4b1311a9946170fbcb85d9bca06033460
 */
static void message_to_indices_old(uint32_t *indices, const unsigned char *m)
{
    unsigned int i, j;
    unsigned int offset = 0;

    for (i = 0; i < SPX_FORS_TREES; i++) {
        indices[i] = 0;
        for (j = 0; j < SPX_FORS_HEIGHT; j++) {
            indices[i] <<= 1;
            indices[i] ^= (m[offset >> 3] >> (offset & 0x7)) & 0x1;
            offset++;
        }
    }
}

/*
 * Algorithm 3 base_2b, with
 *  b = SPX_FORS_HEIGHT = 12
 *  out_len = SPX_FORS_TREES = 14
 */
static void message_to_indices_fips(uint32_t* indices, const unsigned char* m)
{
  uint64_t in = 0;
  uint64_t bits = 0;
  uint64_t total = 0;

  size_t out;
  for(out = 0; out < SPX_FORS_TREES; out++) {
    while(bits < SPX_FORS_HEIGHT) {
      total = (total << 8) + ((uint64_t) m[in]); // overflow ok
      in++;
      bits += 8;
    }
    bits -= SPX_FORS_HEIGHT;
    indices[out] = (total >> bits) % (1 << SPX_FORS_HEIGHT);
  }
}

int main(void)
{
  // Bit string
  //   111111110000000100...0
  unsigned char m[(SPX_FORS_HEIGHT*SPX_FORS_TREES+7)/8];
  m[0] = 0xff;
  m[1] = 0x01;
  size_t i;
  for(i = 2; i < (SPX_FORS_HEIGHT*SPX_FORS_TREES+7)/8; i++) {
    m[i] = 0x00;
  }

  // Computing indices using implementation from the reference
  // implementation.
  uint32_t indices[SPX_FORS_TREES];
  message_to_indices(indices, m);

  for(i = 0; i < SPX_FORS_TREES; i++) {
    printf("ref impl index (%zu): %lu\n", i, indices[i]);
  }

  // Computing it using a implementation of the function from
  // the FIPS.205 way.
  uint32_t indices_std[SPX_FORS_TREES];
  message_to_indices_fips(indices_std, m);

  for(i = 0; i < SPX_FORS_TREES; i++) {
    printf("fips.205 index (%zu): %lu\n", i, indices_std[i]);
  }

  // Computing the indices using the implementation from the
  // reference implementation before commit
  //   74b618d4b1311a9946170fbcb85d9bca06033460
  uint32_t indices_old[SPX_FORS_TREES];
  message_to_indices_old(indices_old, m);

  for(i = 0; i < SPX_FORS_TREES; i++) {
    printf("old impl index (%zu): %lu\n", i, indices_old[i]);
  }
}
