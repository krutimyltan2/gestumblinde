#include <CUnit/Basic.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "test_fors.h"
#include "test_ht.h"
#include "test_slh.h"
#include "test_wotsp.h"
#include "test_xmss.h"

static CU_pSuite add_suite(char *name, CU_InitializeFunc pInit,
                           CU_CleanupFunc pClean) {
  CU_pSuite pSuite = NULL;

  if (CUE_SUCCESS != CU_initialize_registry())
    exit(CU_get_error());

  pSuite = CU_add_suite(name, pInit, pClean);
  if (NULL == pSuite) {
    CU_cleanup_registry();
    exit(CU_get_error());
  }

  return (pSuite);
}

static void add_test(CU_pSuite s, char *desc, CU_TestFunc fn) {
  if (NULL == CU_add_test(s, desc, fn)) {
    CU_cleanup_registry();
    exit(CU_get_error());
  }
}

int main() {
  if (CUE_SUCCESS != CU_initialize_registry())
    return CU_get_error();

  CU_pSuite s_all = add_suite("suite_all", NULL, NULL);

  add_test(s_all, "wotsp_pkgen()", test_wotsp_pkgen);
  add_test(s_all, "wots_sign()", test_wotsp_sign);
  add_test(s_all, "wots_verify()", test_wotsp_verify);

  add_test(s_all, "xmss_node()", test_xmss_node);
  add_test(s_all, "xmss_sign()", test_xmss_sign);
  add_test(s_all, "xmss_verify()", test_xmss_verify);

  add_test(s_all, "ht_sign()", test_ht_sign);
  add_test(s_all, "ht_verify()", test_ht_verify);

  add_test(s_all, "fors_skgen()", test_fors_skgen);
  add_test(s_all, "fors_node()", test_fors_node);
  add_test(s_all, "fors_sign()", test_fors_sign);
  add_test(s_all, "fors_pk_from_sig()", test_fors_pk_from_sig);

  add_test(s_all, "slh_keygen()", test_slh_keygen);
  add_test(s_all, "slh_sign()", test_slh_sign);
  add_test(s_all, "slh_verify()", test_slh_verify);
  add_test(s_all, "slh_ref_sign()", test_slh_ref_sign);

  CU_basic_set_mode(CU_BRM_VERBOSE);
  CU_basic_run_tests();
  CU_cleanup_registry();
  return CU_get_error();
}
