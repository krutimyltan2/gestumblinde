#include "utils.h"

/*
 * Convert a byte string to an integer.
 */
uint64_t to_int(const uint8_t *x, const size_t n) {
  assert(n <= 8); // max 64 bits

  uint64_t res = 0;
  size_t i;
  for (i = 0; i < n; i++) {
    res = (res << 8) + (uint64_t)x[i];
  }

  return res;
}

/*
 * Convert an integer to bytes.
 */
void to_bytes(uint8_t *bytes, const size_t len, uint64_t in) {
  assert(len <= 8);
  size_t i;
  for (i = 0; i < len; i++) {
    bytes[len - 1 - i] = (uint8_t)(in & 0xff);
    in >>= 8;
  }
}

/*
 * Compute the base 2^b representation of X.
 */
void base_2b(uint64_t *out, const uint8_t *x, const size_t xsz,
             const uint64_t b, const size_t out_len) {
  uint64_t in = 0;
  uint64_t bits = 0;
  uint64_t total = 0;

  assert(b < 64);
  uint64_t b_mask = (1 << b) - 1;

  size_t i;
  for (i = 0; i < out_len; i++) {
    while (bits < b) {
      total = (total << 8) + (uint64_t)x[in]; // overflow ok
      in++;
      bits += 8;
    }

    bits -= b;
    out[i] = (total >> bits) & b_mask;
  }
}
