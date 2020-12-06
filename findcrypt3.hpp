#ifndef _FINDCRYPT_HPP_
#define _FINDCRYPT_HPP_

#pragma once

#include <pro.h>

#define IS_LITTLE_ENDIAN

#if defined(__GNUC__) || defined(__MWERKS__)
    #define WORD64_AVAILABLE
    typedef unsigned long long word64;
    typedef unsigned long word32;
    typedef unsigned short word16;
    typedef unsigned char byte;
    #define W64LIT(x) x##LL
#elif defined(_MSC_VER) || defined(__BCPLUSPLUS__)
    #define WORD64_AVAILABLE
    typedef unsigned __int64 word64;
    typedef unsigned __int32 word32;
    typedef unsigned __int16 word16;
    typedef unsigned __int8 byte;
    #define W64LIT(x) x##ui64
#endif

struct array_info_t
{
    const void *array;
    size_t size;
    size_t elsize;
    size_t big_endian;
    const char *name;
    const char *algorithm;
};

extern const array_info_t non_sparse_consts[];
extern const array_info_t sparse_consts[];
extern const array_info_t operand_consts[];

#define ARR_LE(x)  x, _countof(x), sizeof(x[0]), 0, #x
#define ARR_BE(x)  x, _countof(x), sizeof(x[0]), 1, #x

// HTC: string constant
#define ARR_SZ(x) x, sizeof(x), 1, 1, #x

#endif  // _FINDCRYPT_HPP_
