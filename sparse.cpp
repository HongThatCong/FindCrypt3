#include "findcrypt3.hpp"

// Various constants used in crypto algorithms
// They were copied from public domain codes

// HTC: RFC-6234
static const word32 SHA1_H0[] =
{
    0x67452301L,
    0xEFCDAB89L,
    0x98BADCFEL,
    0x10325476L,
    0xC3D2E1F0L,
};

static const word32 SHA224_H0[] =
{
    0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
    0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4
};

static const word32 SHA256_H0[] =
{
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

static const word64 SHA384_H0[] =
{
    W64LIT(0xCBBB9D5DC1059ED8),
    W64LIT(0x629A292A367CD507),
    W64LIT(0x9159015A3070DD17),
    W64LIT(0x152FECD8F70E5939),
    W64LIT(0x67332667FFC00B31),
    W64LIT(0x8EB44A8768581511),
    W64LIT(0xDB0C2E0D64F98FA7),
    W64LIT(0x47B5481DBEFA4FA4),
};

static const word64 SHA512_H0[] =
{
    W64LIT(0x6A09E667F3BCC908),
    W64LIT(0xBB67AE8584CAA73B),
    W64LIT(0x3C6EF372FE94F82B),
    W64LIT(0xA54FF53A5F1D36F1),
    W64LIT(0x510E527FADE682D1),
    W64LIT(0x9B05688C2B3E6C1F),
    W64LIT(0x1F83D9ABFB41BD6B),
    W64LIT(0x5BE0CD19137E2179),
};

// HTC: https://en.wikipedia.org/wiki/RC5
static const word32 RC5_RC6_PQ[] =
{
    0xB7E15163L,    // magic constant P for word size
    0x9E3779B9L,    // magic constant Q for word size
};

static const word64 RC5_RC6_64_PQ[] =
{
    W64LIT(0xB7E151628AED2A6B),     // magic constant P for qword size
    W64LIT(0x9E3779B97F4A7C15),     // magic constant Q for qword size
};

static const word32 MD5_Transform[] =
{
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
    0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,

    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
    0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
    0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,

    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
    0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,

    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
    0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391
};

static const word32 MD5_initState[] =
{
    0x67452301L,
    0xEFCDAB89L,
    0x98BADCFEL,
    0x10325476L
};

static const word32 aPLib_magic[] = { 0x32335041 };

// MurmurHash: https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp
static const word32 MurmurHash_3_fmix32[] = { 0x85ebca6b, 0xc2b2ae35 };
static const word64 MurmurHash_3_fmix64[] = { W64LIT(0xff51afd7ed558ccd), W64LIT(0xc4ceb9fe1a85ec53) };
static const word32 MurmurHash3_x86_32[] = { 0xcc9e2d51, 0x1b873593, 0xe6546b64 };

static const word32 MurmurHash3_x86_128[] =
{
    0x239b961b, 0xab0e9789, 0x38b34ae5, 0xa1e38b93,
    0x561ccd1b, 0x0bcaa747, 0x96cd1c35, 0x32ac3b17
};

static const word32 MurmurHash3_x64_128[] =
{
    // HTC - split to dwords LE
    0x114253d5, 0x87c37b91,     // = 0x87c37b91114253d5
    0x2745937f, 0x4cf5ad43,     // = 0x4cf5ad432745937f
    0x52dce729, 0x38495ab5
};

static const word32 ZipCrypto_Init[] = { 0x12345678, 0x23456789, 0x34567890 };

// Random Generator: https://gist.github.com/maximecb/617de45a99347a9911b1e0d974da5d62
static const word32 RandomGen_Constant_32[] = { 0x0019660D, 0x3C6EF35F };
static const word64 RandomGen_Constant_64[] =
{
    W64LIT(0x27BB2EE6) * 0x010000 * 0x010000 + W64LIT(0x87B0B0F),
    W64LIT(0xB504F32D)
};

// Mersenne Twister:https://en.wikipedia.org/wiki/Mersenne_Twister
static const word32 MT19937_coefficient_dbc[] = { 0xFFFFFFFF, 0x9D2C5680, 0xEFC60000 };
static const word64 MT19937_64_coefficient_dbc[] =
{
    W64LIT(0x5555555555555555),     // d
    W64LIT(0x71D67FFFEDA60000),     // b
    W64LIT(0xFFF7EEE000000000)      // c
};

// https://yesteapea.wordpress.com/2013/03/03/counting-the-number-of-set-bits-in-an-integer/
static const word64 NumberOfBit1_64[] = { 0x5555555555555555, 0x3333333333333333, 0x0F0F0F0F0F0F0F0F };

// https://github.com/BLAKE3-team/BLAKE3
static const word32 BLAKE3_IV[] = { 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A };

//------------------------------------------------------------------------------
// HTC: CryptoHash ASM Lib - by drizz
//

// 3Way - 3-way.asm
static const word32 THREEWAY_SwapBits[] = { 0x55555555, 0x33333333, 0xF0F0F0F };

// rc4.asm
static const word32 RC4_Key_Init[] = { 0xFFFEFDFC, 0xFBFAF9F8, 0xF7F6F5F4, 0xF3F2F1F0 };

// haval.asm
static const word32 HavalDigest_Init[] =
{
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
    0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89
};

// md4.asm
static const word32 MD4_Transform[] = { 0x5A827999, 0x6ED9EBA1 };

// rmd128.asm
static const word32 RMD128_Transform[] =
{
    0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC,
    0x50A28BE6, 0x5C4DD124, 0x6D703EF3
};

static const word32 RMD160_Transform[] =
{
    0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E,
    0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9
};

// rmd256.asm
static const word32 RMD256_Init[] =
{
    0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476,
    0x76543210, 0xFEDCBA98, 0x89ABCDEF, 0x01234567
};

static const word32 RMD256_Transform[] =
{
    0x50A28BE6, 0x5A827999, 0x5C4DD124,
    0x6ED9EBA1, 0x6D703EF3, 0x8F1BBCDC,
};

// rmd320.asm
static const word32 RMD320_Init[] =
{
    0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476,
    0xC3D2E1F0, 0x76543210, 0xFEDCBA98, 0x89ABCDEF,
    0x01234567, 0x3C2D1E0F
};

// sha0.asm and sha1.asm
static const word32 SHA1_Transform[] = { 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 };

// tiger.asm
static const word32 Tiger_Key_Schedule[] =
{
    0xA5A5A5A5, 0xA5A5A5A5, 0x89ABCDEF, 0x01234567,
};

//------------------------------------------------------------------------------
// HTC: LibTomCrypt
//

// sha512_224.c
static const word64 SHA512_224_initState[] =
{
    W64LIT(0x8C3D37C819544DA2),
    W64LIT(0x73E1996689DCD4D6),
    W64LIT(0x1DFAB7AE32FF9C82),
    W64LIT(0x679DD514582F9FCF),
    W64LIT(0x0F6D2B697BD44DA8),
    W64LIT(0x77E36F7304C48942),
    W64LIT(0x3F9D85A86A1D36C8),
    W64LIT(0x1112E6AD91D692A1),
};

// sha512_256.c
static const word64 SHA512_256_initState[] =
{
    W64LIT(0x22312194FC2BF72C),
    W64LIT(0x9F555FA3C84C64C2),
    W64LIT(0x2393B86B6F53B151),
    W64LIT(0x963877195940EABD),
    W64LIT(0x96283EE2A88EFFE3),
    W64LIT(0xBE5E1E2553863992),
    W64LIT(0x2B0199FC2C85B8AA),
    W64LIT(0x0EB72DDC81C52CA2),
};

//------------------------------------------------------------------------------
// HTC: CryptoPP
//

// SipHash: siphash.h
static const word64 SipHash_initState[] =
{
    W64LIT(0x736f6d6570736575),
    W64LIT(0x646f72616e646f6d),
    W64LIT(0x6c7967656e657261),
    W64LIT(0x7465646279746573),
};

// Rabbit: rabbit.cpp
static const word32 Rabbit_NextState[] = { 0x4D34D34D, 0xD34D34D3, 0x34D34D34 };

// LCRNG: rng.cpp
static const word32 LC_RNG[] =
{
    2147483647L,    // = m
    44488L,         // = q
    48271L,         // = a
    3399,           // = r
};

static const word32 LC_RNG_ORG_NUM[] =
{
    2147483647L,    // = m
    127773L,        // = q
    16807,          // = a
    2836,           // = r
};

// SIMECK32: simeck.cpp
static const word32 SIMECK32_consts[] =
{
    0xFFFC,         // constant
    0x9A42BB1F      // sequence
};

// SM3: sm3.cpp
static const word32 SM3_CXX[]
{
    0x79CC4519, 0xF3988A32, 0xE7311465, 0xCE6228CB,
    0x9CC45197, 0x3988A32F, 0x7311465E, 0xE6228CBC,
    0xCC451979, 0x988A32F3, 0x311465E7, 0x6228CBCE,
    0xC451979C, 0x88A32F39, 0x11465E73, 0x228CBCE6,
    0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C,
    0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE,
    0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC,
    0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5,
    0x7A879D8A, 0xF50F3B14, 0xEA1E7629, 0xD43CEC53,
    0xA879D8A7, 0x50F3B14F, 0xA1E7629E, 0x43CEC53D,
    0x879D8A7A, 0x0F3B14F5, 0x1E7629EA, 0x3CEC53D4,
    0x79D8A7A8, 0xF3B14F50, 0xE7629EA1, 0xCEC53D43,
};

// SM4: sm4.cpp
static const word32 SM4_wspace[] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

// Tiger: tiger.cpp
static const word64 Tiger_initState[] =
{
    W64LIT(0x123456789ABCDEF), W64LIT(0xFEDCBA9876543210), W64LIT(0xF096A5B4C3B2E187)
};

// HTC: - we change the search algorithm, so we don't need all sparse arrays must be word32!
const array_info_t sparse_consts[] =
{
    { ARR_LE(SHA1_H0),                      "SHA1/RMD160"           },
    { ARR_LE(SHA224_H0),                    "SHA224"                },
    { ARR_LE(SHA256_H0),                    "SHA256/BLAKE2s_IV"     },
    { ARR_LE(SHA384_H0),                    "SHA384"                },
    { ARR_LE(SHA512_H0),                    "SHA512/BLAKE2b_IV"     },

    { ARR_LE(RC5_RC6_PQ),                   "RC5/RC6"               },
    { ARR_LE(RC5_RC6_64_PQ),                "RC5/RC6"               },

    { ARR_LE(MD5_Transform),                "MD5"                   },
    { ARR_LE(MD5_initState),                "MD4/MD5/RMD128"        },

    { ARR_LE(aPLib_magic),                  "aPLib"                 },

    { ARR_LE(MurmurHash_3_fmix32),          "MurmurHash"            },
    { ARR_LE(MurmurHash_3_fmix64),          "MurmurHash"            },
    { ARR_LE(MurmurHash3_x86_32),           "MurmurHash"            },
    { ARR_LE(MurmurHash3_x86_128),          "MurmurHash"            },
    { ARR_LE(MurmurHash3_x64_128),          "MurmurHash"            },

    { ARR_LE(ZipCrypto_Init),               "ZipCrypto"             },

    { ARR_LE(RandomGen_Constant_32),        "RandomGenerator"       },
    { ARR_LE(RandomGen_Constant_64),        "RandomGenerator"       },

    { ARR_LE(MT19937_coefficient_dbc),      "Mersenne Twister"      },
    { ARR_LE(MT19937_64_coefficient_dbc),   "Mersenne Twister"      },

    { ARR_LE(NumberOfBit1_64),              "Number of bits is 1"   },

    { ARR_LE(BLAKE3_IV),                    "BLAKE3"                },

    // begin - CryptoHash ASM Lib
    //
    { ARR_LE(THREEWAY_SwapBits),            "3-Way"                 },
    { ARR_LE(RC4_Key_Init),                 "RC4"                   },
    { ARR_LE(HavalDigest_Init),             "Haval"                 },
    { ARR_LE(MD4_Transform),                "MD4"                   },
    { ARR_LE(RMD128_Transform),             "RMD128"                },
    { ARR_LE(RMD160_Transform),             "RMD160/RMD320"         },

    { ARR_LE(RMD256_Init),                  "RMD256"                },
    { ARR_LE(RMD256_Transform),             "RMD256"                },

    { ARR_LE(RMD320_Init),                  "RMD320"                },
    { ARR_LE(SHA1_Transform),               "SHA1"                  },

    { ARR_LE(Tiger_Key_Schedule),           "Tiger"                 },
    //
    // end

    // begin - LibTomCrypt
    //
    { ARR_LE(SHA512_224_initState),         "SHA512_224"            },
    { ARR_LE(SHA512_256_initState),         "SHA512_256"            },
    //
    // end

    // begin - CryptoPP
    //
    { ARR_LE(LC_RNG),                       "LC_RNG"                },
    { ARR_LE(LC_RNG_ORG_NUM),               "LC_RNG"                },

    { ARR_LE(SipHash_initState),            "SipHash"               },
    { ARR_LE(Rabbit_NextState),             "Rabbit"                },

    { ARR_LE(SIMECK32_consts),              "SIMECK32"              },

    { ARR_LE(SM3_CXX),                      "SM3"                   },
    { ARR_LE(SM4_wspace),                   "SM4"                   },

    { ARR_LE(Tiger_initState),              "Tiger"                 },
    //
    // end

    { NULL, 0, 0, NULL, NULL                                        },
};
