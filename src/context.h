#define ADRS_LEN 8

#if defined(SLH_DSA_SHAKE_128S) || defined(SLH_DSA_SHA2_128S)

#define ENN 16
#define H 63
#define D 7
#define HP 9
#define A 12
#define K 14
#define LGW 4
#define M 30
#define SLH_SIGNATURE_LEN 7856

#elif defined(SLH_DSA_SHAKE_128F) || defined(SLH_DSA_SHA2_128F)

#define ENN 16
#define H 66
#define D 22
#define HP 3
#define A 6
#define K 33
#define LGW 4
#define M 34
#define SLH_SIGNATURE_LEN 17088

#elif defined(SLH_DSA_SHAKE_192S) || defined(SLH_DSA_SHA2_192S)

#define ENN 24
#define H 63
#define D 7
#define HP 9
#define A 14
#define K 17
#define LGW 4
#define M 39
#define SLH_SIGNATURE_LEN 16224

#elif defined(SLH_DSA_SHAKE_192F) || defined(SLH_DSA_SHA2_192F)

#define ENN 24
#define H 66
#define D 22
#define HP 3
#define A 8
#define K 33
#define LGW 4
#define M 42
#define SLH_SIGNATURE_LEN 35664

#elif defined(SLH_DSA_SHAKE_256S) || defined(SLH_DSA_SHA2_256S)

#define ENN 32
#define H 64
#define D 8
#define HP 8
#define A 14
#define K 22
#define LGW 4
#define M 47
#define SLH_SIGNATURE_LEN 29792

#elif defined(SLH_DSA_SHAKE_256F) || defined(SLH_DSA_SHA2_256F)

#define ENN 32
#define H 68
#define D 17
#define HP 4
#define A 9
#define K 35
#define LGW 4
#define M 49
#define SLH_SIGNATURE_LEN 49856

#else

#error "No recognizable parameter set definition."

#endif

#define WOTSP_W 16
#define WOTSP_LEN1 (2 * ENN)
#define WOTSP_LEN2 3
#define WOTSP_LEN (2 * ENN + 3)
#define FORS_MD_LEN ((A * K + 7) >> 3)
#define FORS_SIG_LEN (K * (A + 1) * ENN)
#define IDX_TREE_LEN ((H - H / D + 7) >> 3)
#define IDX_LEAF_LEN ((H + 8 * D - 1) / (8 * D))
