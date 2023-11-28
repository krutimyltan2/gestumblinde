#ifndef RANDOM_H
#define RANDOM_H

#include <stdlib.h>

#define randombytes(x, n) (arc4random_buf(x, n))

#endif
