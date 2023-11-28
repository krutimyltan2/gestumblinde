#ifndef SLH_H
#define SLH_H

#include <assert.h>
#include <endian.h>
#include <stdint.h>
#include <stdlib.h>
#include <strings.h>

#include "address.h"
#include "context.h"
#include "fors.h"
#include "ht.h"
#include "random.h"

void slh_keygen(uint8_t *sk, uint8_t *pk);
void slh_sign(uint8_t *out, const uint8_t *m, const size_t mlen,
              const uint8_t *sk, int randomize);
int slh_verify(const uint8_t *m, const size_t mlen, const uint8_t *sig,
               const size_t siglen, const uint8_t *pk);

#endif
