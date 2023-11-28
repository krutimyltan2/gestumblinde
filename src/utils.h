#ifndef UTILS_H
#define UTILS_H

#include <assert.h>
#include <endian.h>
#include <stdint.h>
#include <stdlib.h>

uint64_t to_int(const uint8_t *x, const size_t n);
void to_bytes(uint8_t *bytes, const size_t len, uint64_t in);
void base_2b(uint64_t *out, const uint8_t *x, const size_t xsz,
             const uint64_t b, const size_t out_len);

#endif
