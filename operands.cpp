#include "findcrypt3.hpp"

// Various operand constants used in crypto algorithms
// They were copied from public domain codes

// Adler
static const word32 Adler32_BASE[] = { 65521 };

// TEA
static const word32 TEA_DELTA[] = { 0x9E3779B9 };
static const word32 TEA_ALTERNATIVE_DELTA[] = { 0x61C88647 };

// HTC: https://en.wikipedia.org/wiki/Cyclic_redundancy_check
//
// CRC_32
static const word32 CRC32_Normal[]              = { 0x04C11DB7 };
static const word32 CRC32_Reversed[]            = { 0xEDB88320 };
static const word32 CRC32_Reciprocal[]          = { 0xDB710641 };
static const word32 CRC32_Reversed_Reciprocal[] = { 0x82608EDB };

// CRC32_C
static const word32 CRC32_C_Normal[]              = { 0x1EDC6F41 };
static const word32 CRC32_C_Reversed[]            = { 0x82F63B78 };
static const word32 CRC32_C_Reciprocal[]          = { 0x05EC76F1 };
static const word32 CRC32_C_Reversed_Reciprocal[] = { 0x8F6E37A0 };

// CRC32_K
static const word32 CRC32_K_Normal[]              = { 0x741B8CD7 };
static const word32 CRC32_K_Reversed[]            = { 0xEB31D82E };
static const word32 CRC32_K_Reciprocal[]          = { 0xD663B05D };
static const word32 CRC32_K_Reversed_Reciprocal[] = { 0xBA0DC66B };

// CRC32_K2
static const word32 CRC32_K2_Normal[]              = { 0x32583499 };
static const word32 CRC32_K2_Reversed[]            = { 0x992C1A4C };

// CRC32_Q
static const word32 CRC32_Q_Normal[]              = { 0x814141AB };
static const word32 CRC32_Q_Reversed[]            = { 0xD5828281 };
static const word32 CRC32_Q_Reciprocal[]          = { 0xAB050503 };
static const word32 CRC32_Q_Reversed_Reciprocal[] = { 0xC0A0A0D5 };

// CRC64-ECMA
static const word64 CRC64_ECMA_Normal[]              = { W64LIT(0x42F0E1EBA9EA3693) };
static const word64 CRC64_ECMA_Reversed[]            = { W64LIT(0xC96C5795D7870F42) };
static const word64 CRC64_ECMA_Reciprocal[]          = { W64LIT(0x92D8AF2BAF0E1E85) };
static const word64 CRC64_ECMA_Reversed_Reciprocal[] = { W64LIT(0xA17870F5D4F51B49) };

// CRC64-ISO
static const word64 CRC64_ISO_Normal[]              = { W64LIT(0x000000000000001B) };
static const word64 CRC64_ISO_Reversed[]            = { W64LIT(0xD800000000000000) };
static const word64 CRC64_ISO_Reciprocal[]          = { W64LIT(0xB000000000000001) };
static const word64 CRC64_ISO_Reversed_Reciprocal[] = { W64LIT(0x800000000000000D) };

// HTC: MurmurHash
// https://github.com/aappleby/smhasher/blob/master/src/MurmurHash1,2,3.cpp
//
static const word32 MurmurHash_1[] = { 0xC6A4A793 };
static const word32 MurmurHash_2[] = { 0x5BD1E995 };
static const word64 MurmurHash64A_2[] = { W64LIT(0xC6A4A7935BD1E995) };

// rand() magic
static const word32 rand_magic_0[] = { 0x000343FD };
static const word32 rand_magic_1[] = { 0x00269EC3 };

static const word32 ZipCrypto_PRNG[] = { 0x08088405 };

// HTC: Mersenne Twister
// https://en.wikipedia.org/wiki/Mersenne_Twister
static const word32 MT19937_coefficient_a[] = { 0x9908B0DF };
static const word64 MT19937_64_coefficient_a[] = { W64LIT(0xB5026F5AA96619E9) };

// HTC: xxHash32/xxHash64
// https://github.com/Cyan4973/xxHash/blob/dev/xxhash.h
//
static const word32 XXH_PRIME32_1[] = { 0x9E3779B1 };
static const word32 XXH_PRIME32_2[] = { 0x85EBCA77 };
static const word32 XXH_PRIME32_3[] = { 0xC2B2AE3D };
static const word32 XXH_PRIME32_4[] = { 0x27D4EB2F };
static const word32 XXH_PRIME32_5[] = { 0x165667B1 };

static const word64 XXH_PRIME64_1[] = { W64LIT(0x9E3779B185EBCA87) };
static const word64 XXH_PRIME64_2[] = { W64LIT(0xC2B2AE3D27D4EB4F) };
static const word64 XXH_PRIME64_3[] = { W64LIT(0x165667B19E3779F9) };
static const word64 XXH_PRIME64_4[] = { W64LIT(0x85EBCA77C2B2AE63) };
static const word64 XXH_PRIME64_5[] = { W64LIT(0x27D4EB2F165667C5) };

// XXH3
static const word64 XXH3_avalanche[] = { W64LIT(0x165667919E3779F9) };
static const word64 XXH3_rrmxmx[] = { W64LIT(0x9FB21C651E98DF25) };

// MD6
static const word64 MD6_S_Init[] = { W64LIT(0x0123456789abcdef) };
static const word64 MD6_S_Recur[] = { W64LIT(0x7311c2812425cfa0) };

//------------------------------------------------------------------------------
// HTC: CryptoPP
//

// Donna32: donna_32.h
/* multiples of p */
static const word32 Donna32_twoP0[]       = { 0x07ffffda };
static const word32 Donna32_twoP13579[]   = { 0x03fffffe };
static const word32 Donna32_twoP2468[]    = { 0x07fffffe };
static const word32 Donna32_fourP0[]      = { 0x0fffffb4 };
static const word32 Donna32_fourP13579[]  = { 0x07fffffc };
static const word32 Donna32_fourP2468[]   = { 0x0ffffffc };

// Donna64: donna_64.h
static const word64 Donna64_twoP0[]      = { 0x0fffffffffffda };
static const word64 Donna64_twoP1234[]   = { 0x0ffffffffffffe };
static const word64 Donna64_fourP0[]     = { 0x1fffffffffffb4 };
static const word64 Donna64_fourP1234[]  = { 0x1ffffffffffffc };

// Kalyna: kalyna.cpp
static const word64 Kalyna_constant[] = { W64LIT(0x0001000100010001) };

// SIMECK64
static const word64 SIMECK64_sequence[] = { 0x938BCA3083F };

// SIMON: simon.cpp
static const word64 SIMON64_3W_SIMON128_2W[] = { W64LIT(0x7369f885192c0ef5) };
static const word64 SIMON64_4W_SIMON128_3W[] = { W64LIT(0xfc2ce51207a635db) };
static const word64 SIMON128_4w[] = { W64LIT(0xfdc94c3a046d678b) };

// Sosemanuk: sosemanuk.cpp
static const word32 Sosemanuk_state10[] = { 0x54655307 };

// Threefish: threefish.cpp
static const word64 Threefish_rkey[] = { W64LIT(0x1BD11BDAA9FC1A22) };

const array_info_t operand_consts[] =
{
    { ARR_LE(Adler32_BASE),                    "Adler32"                },

    { ARR_LE(TEA_DELTA),                       "TEA"                    },
    { ARR_LE(TEA_ALTERNATIVE_DELTA),           "TEA"                    },

    { ARR_LE(CRC32_Normal),                    "CRC32"                  },
    { ARR_LE(CRC32_Reversed),                  "CRC32"                  },
    { ARR_LE(CRC32_Reciprocal),                "CRC32"                  },
    { ARR_LE(CRC32_Reversed_Reciprocal),       "CRC32"                  },

    { ARR_LE(CRC32_C_Normal),                  "CRC32_C"                },
    { ARR_LE(CRC32_C_Reversed),                "CRC32_C"                },
    { ARR_LE(CRC32_C_Reciprocal),              "CRC32_C"                },
    { ARR_LE(CRC32_C_Reversed_Reciprocal),     "CRC32_C"                },

    { ARR_LE(CRC32_K_Normal),                  "CRC32_K"                },
    { ARR_LE(CRC32_K_Reversed),                "CRC32_K"                },
    { ARR_LE(CRC32_K_Reciprocal),              "CRC32_K"                },
    { ARR_LE(CRC32_K_Reversed_Reciprocal),     "CRC32_K"                },

    { ARR_LE(CRC32_K2_Normal),                 "CRC32_K2"               },
    { ARR_LE(CRC32_K2_Reversed),               "CRC32_K2"               },

    { ARR_LE(CRC32_Q_Normal),                  "CRC32_Q"                },
    { ARR_LE(CRC32_Q_Reversed),                "CRC32_Q"                },
    { ARR_LE(CRC32_Q_Reciprocal),              "CRC32_Q"                },
    { ARR_LE(CRC32_Q_Reversed_Reciprocal),     "CRC32_Q"                },

    { ARR_LE(CRC64_ECMA_Normal),               "CRC64-ECMA"             },
    { ARR_LE(CRC64_ECMA_Reversed),             "CRC64-ECMA"             },
    { ARR_LE(CRC64_ECMA_Reciprocal),           "CRC64-ECMA"             },
    { ARR_LE(CRC64_ECMA_Reversed_Reciprocal),  "CRC64-ECMA"             },

    { ARR_LE(CRC64_ISO_Normal),                "CRC64-ISO"              },
    { ARR_LE(CRC64_ISO_Reversed),              "CRC64-ISO"              },
    { ARR_LE(CRC64_ISO_Reciprocal),            "CRC64-ISO"              },
    { ARR_LE(CRC64_ISO_Reversed_Reciprocal),   "CRC64-ISO"              },

    { ARR_LE(MurmurHash_1),                    "MurmurHash"             },
    { ARR_LE(MurmurHash_2),                    "MurmurHash"             },
    { ARR_LE(MurmurHash64A_2),                 "MurmurHash"             },

    { ARR_LE(rand_magic_0),                    "rand() magic"           },
    { ARR_LE(rand_magic_1),                    "rand() magic"           },

    { ARR_LE(ZipCrypto_PRNG),                  "ZipCrypto/Delphi_PRNG"  },

    { ARR_LE(MT19937_coefficient_a),           "Mersenne Twister"       },
    { ARR_LE(MT19937_64_coefficient_a),        "Mersenne Twister"       },

    { ARR_LE(XXH_PRIME32_1),                   "xxHash32"               },
    { ARR_LE(XXH_PRIME32_2),                   "xxHash32"               },
    { ARR_LE(XXH_PRIME32_3),                   "xxHash32"               },
    { ARR_LE(XXH_PRIME32_4),                   "xxHash32"               },
    { ARR_LE(XXH_PRIME32_5),                   "xxHash32"               },

    { ARR_LE(XXH_PRIME64_1),                   "xxHash64"               },
    { ARR_LE(XXH_PRIME64_2),                   "xxHash64"               },
    { ARR_LE(XXH_PRIME64_3),                   "xxHash64"               },
    { ARR_LE(XXH_PRIME64_4),                   "xxHash64"               },
    { ARR_LE(XXH_PRIME64_5),                   "xxHash64"               },

    { ARR_LE(XXH3_avalanche),                  "XXH3"                   },
    { ARR_LE(XXH3_rrmxmx),                     "XXH3"                   },

    { ARR_LE(MD6_S_Init),                      "MD6"                    },
    { ARR_LE(MD6_S_Recur),                     "MD6"                    },

    // begin - CryptoPP
    //
    { ARR_LE(Donna32_twoP0),                    "Donna32"               },
    { ARR_LE(Donna32_twoP13579),                "Donna32"               },
    { ARR_LE(Donna32_twoP2468),                 "Donna32"               },
    { ARR_LE(Donna32_fourP0),                   "Donna32"               },
    { ARR_LE(Donna32_fourP13579),               "Donna32"               },
    { ARR_LE(Donna32_fourP2468),                "Donna32"               },

    { ARR_LE(Donna64_twoP0),                    "Donna64"               },
    { ARR_LE(Donna64_twoP1234),                 "Donna64"               },
    { ARR_LE(Donna64_fourP0),                   "Donna64"               },
    { ARR_LE(Donna64_fourP1234),                "Donna64"               },

    { ARR_LE(Kalyna_constant),                  "Kalyna"                },

    { ARR_LE(SIMECK64_sequence),                "SIMECK64"              },

    { ARR_LE(SIMON64_3W_SIMON128_2W),           "SIMON64/128"           },
    { ARR_LE(SIMON64_4W_SIMON128_3W),           "SIMON64/128"           },
    { ARR_LE(SIMON128_4w),                      "SIMON64/128"           },

    { ARR_LE(Sosemanuk_state10),                "Sosemanuk"             },
    { ARR_LE(Threefish_rkey),                   "Threefish"             },
    //
    // end

    { NULL, 0, 0, NULL, NULL                                            },
};
