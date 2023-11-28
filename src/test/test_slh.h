#ifndef TEST_SLH_H
#define TEST_SLH_H

#include <CUnit/Basic.h>
#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>

#include "../context.h"
#include "../slh.h"

#include "files.h"
#include "utils.h"

void test_slh_keygen(void);
void test_slh_sign(void);
void test_slh_verify(void);
void test_slh_ref_sign(void);

#endif
