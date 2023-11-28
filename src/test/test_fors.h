#ifndef TEST_FORS_H
#define TEST_FORS_H

#include <CUnit/Basic.h>
#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>

#include "../context.h"
#include "../fors.h"

#include "files.h"
#include "utils.h"

void test_fors_skgen(void);
void test_fors_node(void);
void test_fors_sign(void);
void test_fors_pk_from_sig(void);

#endif
