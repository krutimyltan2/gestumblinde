#include "utils.h"

int read_array(uint8_t **data, size_t *ndata, const json_t *array) {
  size_t n = json_array_size(array);
  uint8_t *res = malloc(n);

  size_t i;
  for (i = 0; i < n; i++) {
    json_int_t a = json_integer_value(json_array_get(array, i));
    if (a > 0xff) {
      free(res);
      return -1;
    }

    assert(a < 256);
    res[i] = (uint8_t)a;
  }

  *data = res;
  *ndata = n;

  return 0;
}

int read_key_array(void *data, const size_t ndata, const char *key,
                   json_t *tv) {
  json_t *json_get = json_object_get(tv, key);
  if (json_get == NULL) {
    return -1;
  }

  uint8_t *dd;
  size_t ndd;

  if (read_array(&dd, &ndd, json_get)) {
    return -2;
  }

  if (ndata < ndd) {
    free(dd);
    return -3;
  }

  memcpy(data, dd, ndd);

  if (ndata > ndd) {
    memset((char *)data + ndd, 0, ndata - ndd);
  }

  free(dd);

  return 0;
}

int read_key_aoa(void *data, const size_t ndata, const char *key, json_t *tv) {
  json_t *json_get = json_object_get(tv, key);
  if (json_get == NULL) {
    return -1;
  }

  uint8_t *cdata = data;

  size_t n = json_array_size(json_get);

  uint8_t *ap;
  size_t nap;

  size_t i;
  for (i = 0; i < n; i++) {
    json_t *a = json_array_get(json_get, i);

    if (read_array(&ap, &nap, a) != 0) {
      fprintf(stderr, "JSON read_array error.");
      exit(1);
    }

    memcpy(cdata, ap, nap); // buffer of:able!
    cdata += nap;
    free(ap);
  }

  return 0;
}

uint64_t read_key_uint64(const char *key, const json_t *tv) {
  json_t *json_get = json_object_get(tv, key);
  assert(json_get != NULL); // crash and burn

  return ((uint64_t)json_integer_value(json_get));
}

// TODO: allow for big numbers as idx_tree
idx_tree_t read_key_idx_tree(const char *key, const json_t *tv) {
  json_t *json_get = json_object_get(tv, key);
  assert(json_get != NULL); // crash and burn

  idx_tree_t r;
  r.valhb = 0; // max 2^64 address in test vectors
  r.vallb = json_integer_value(json_get);

  return r;
}
