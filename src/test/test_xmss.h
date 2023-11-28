#ifndef TEST_XMSS_H
#define TEST_XMSS_H

#include <CUnit/Basic.h>
#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>

#include "../context.h"
#include "../xmss.h"

#include "files.h"
#include "utils.h"

void test_xmss_node(void);
void test_xmss_sign(void);
void test_xmss_verify(void);

#endif
