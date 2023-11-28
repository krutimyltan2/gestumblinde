#ifndef TEST_HT_H
#define TEST_HT_H

#include <CUnit/Basic.h>
#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>

#include "../context.h"
#include "../ht.h"

#include "files.h"
#include "utils.h"

void test_ht_sign(void);
void test_ht_verify(void);

#endif
