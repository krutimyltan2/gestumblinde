#ifndef TEST_WOTSP_H
#define TEST_WOTSP_H

#include <CUnit/Basic.h>
#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>

#include "../context.h"
#include "../wotsp.h"

#include "files.h"
#include "utils.h"

void test_wotsp_pkgen(void);
void test_wotsp_sign(void);
void test_wotsp_verify(void);

#endif
