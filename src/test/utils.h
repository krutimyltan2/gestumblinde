#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <jansson.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include "../address.h"

int read_array(uint8_t **data, size_t *ndata, const json_t *array);
int read_key_array(void *data, const size_t ndata, const char *key, json_t *tv);
int read_key_aoa(void *data, const size_t ndata, const char *key, json_t *tv);
uint64_t read_key_uint64(const char *key, const json_t *tv);
idx_tree_t read_key_idx_tree(const char *key, const json_t *tv);

#endif
