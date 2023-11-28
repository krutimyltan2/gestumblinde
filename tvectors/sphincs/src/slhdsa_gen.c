#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <api.h>
#include <params.h>
#include <randombytes.h>
#include <jansson.h>

#define str(s) #s
#define xstr(s) str(s)
#define STRING_PK xstr(PFX SLH PK)
#define STRING_SK xstr(PFX SLH SK)
#define STRING_MSG xstr(PFX SLH MSG)
#define STRING_SIG xstr(PFX SLH SIGNATURE)

#define SPX_MLEN 32

int main(void)
{
    int ret = 0;

    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    unsigned char pk[SPX_PK_BYTES];
    unsigned char sk[SPX_SK_BYTES];
    unsigned char *m = malloc(SPX_MLEN);
    unsigned char *sm = malloc(SPX_BYTES + SPX_MLEN);
    unsigned char *mout = malloc(SPX_BYTES + SPX_MLEN);
    size_t smlen;

    randombytes(m,  SPX_MLEN);
    randombytes(pk, SPX_PK_BYTES);
    randombytes(sk, SPX_SK_BYTES-SPX_PK_BYTES);
    memcpy(sk + (SPX_SK_BYTES-SPX_PK_BYTES), pk, SPX_PK_BYTES);

    json_t* jtv = json_object();
    json_t* jpk = json_array();
    json_t* jpk_seed = json_array();
    json_t* jpk_root = json_array();
    json_t* jsk_seed = json_array();
    json_t* jsk_prf  = json_array();
    json_t* jsk = json_array();
    json_t* jmsg = json_array();

    size_t i;
    for(i = 0; i < SPX_N; i++) {
      json_t* t = json_integer((json_int_t) pk[i]);
      json_array_append(jpk_seed, t);

      t = json_integer((json_int_t) pk[i+SPX_N]);
      json_array_append(jpk_root, t);

      t = json_integer((json_int_t) sk[i]);
      json_array_append(jsk_seed, t);

      t = json_integer((json_int_t) sk[i+SPX_N]);
      json_array_append(jsk_prf,  t);
    }

    json_array_append(jsk, jsk_seed);
    json_array_append(jsk, jsk_prf);
    json_array_append(jsk, jpk_seed);
    json_array_append(jsk, jpk_root);

    json_array_append(jpk, jpk_seed);
    json_array_append(jpk, jpk_root);

    for(i = 0; i < SPX_MLEN; i++) {
      json_t* t = json_integer((json_int_t) m[i]);
      json_array_append(jmsg, t);
    }

    json_object_set(jtv, STRING_PK, jpk);
    json_object_set(jtv, STRING_SK, jsk);
    json_object_set(jtv, STRING_MSG, jmsg);

    crypto_sign_signature(sm, &smlen, m, SPX_MLEN, sk);

    json_t* jsig = json_array();

    for(i = 0; i < SPX_BYTES; i++) {
      json_t* t = json_integer((json_int_t) sm[i]);
      json_array_append(jsig, t);
    }

    json_object_set(jtv, STRING_SIG, jsig);

    json_dumpf(jtv, stdout, JSON_INDENT(2));

    free(m);
    free(sm);
    free(mout);

    return ret;
}
