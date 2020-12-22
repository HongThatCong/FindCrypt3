// code provided by Andrew based on the work of David Musser and Nishanov
// http://www.team5150.com/~andrew/
// http://www.cs.rpi.edu/~musser/gp/gensearch/index.html
//

#include <windows.h>
#include <pro.h>
#include <kernwin.hpp>

#include "findcrypt3.hpp"

#define HASH_RANGE_MAX  512
#define SUFFIX_SIZE     2

static inline ssize_t Hash(PBYTE pData)
{
    return ((((ssize_t) pData[-1]) + ((ssize_t) pData[0])) & (HASH_RANGE_MAX - 1));
}

static ssize_t SearchSmallpat(PBYTE pSrc, ssize_t iSrcLen, PBYTE pPattern, ssize_t iPatternLen)
{
    if ((0 == iSrcLen) || (0 == iPatternLen) || (iPatternLen > iSrcLen))
        return -1;

    PBYTE pLimit = (pSrc + iSrcLen - iPatternLen);
    for (PBYTE p = pSrc; p <= pLimit; p++)
    {
        if (0 == memcmp(p, pPattern, iPatternLen))
            return (p - pSrc);
    }

    return -1;
}

static void ComputeBacktrackTable(PBYTE pPattern, ssize_t iPatternLen, ssize_t *piPatternBacktrack)
{
    ssize_t j = 0, t = -1;
    piPatternBacktrack[j] = -1;

    while (j < iPatternLen - 1)
    {
        while ((t >= 0) && (pPattern[j] != pPattern[t]))
        {
            t = piPatternBacktrack[t];
        }

        ++j, ++t;
        piPatternBacktrack[j] = pPattern[j] == pPattern[t] ? piPatternBacktrack[t] : t;
    };
}

static ssize_t SearchHashed2(PBYTE pSrc, ssize_t iSrcLen, PBYTE pPattern, ssize_t iPatternLen, ssize_t *piPatternBacktrack)
{
    if ((iSrcLen <= 0) || (iPatternLen <= 0) || (iPatternLen > iSrcLen))
        return -1;

    if (iPatternLen < SUFFIX_SIZE)
        return SearchSmallpat(pSrc, iSrcLen, pPattern, iPatternLen);

    ComputeBacktrackTable(pPattern, iPatternLen, piPatternBacktrack);

    ssize_t aSkip[HASH_RANGE_MAX];
    for (ssize_t i = 0; i < HASH_RANGE_MAX; i++)
        aSkip[i] = iPatternLen - SUFFIX_SIZE + 1;

    for (ssize_t i = 0; i < iPatternLen - 1; i++)
        aSkip[Hash(pPattern + i)] = iPatternLen - 1 - i;

    ssize_t iLarge         = iSrcLen + 1;
    ssize_t iMismatchShift = aSkip[Hash(pPattern + iPatternLen - 1)];
    aSkip[Hash(pPattern + iPatternLen - 1)] = iLarge;

    PBYTE pSrcEnd = pSrc + iSrcLen;
    ssize_t k = -iSrcLen;
    ssize_t iAdjustment = iLarge + iPatternLen - 1;

    while (true)
    {
        k += iPatternLen - 1;
        if (k >= 0)
            return -1;

        do
        {
            k += aSkip[Hash(pSrcEnd + k)];
        }
        while (k < 0);

        if (k < iPatternLen)
        {
            return -1;
        }

        k -= iAdjustment;

        if (pSrcEnd[k] != pPattern[0])
        {
            k += iMismatchShift;
            continue;
        }

        ssize_t i = 1;
        while (true)
        {
            if (pSrcEnd[++k] != pPattern[i])
            {
                break;
            }

            if (++i == iPatternLen)
            {
                return (iSrcLen + k) - iPatternLen + 1;
            }
        }

        if (iMismatchShift > i)
        {
            k += iMismatchShift - i;
            continue;
        }

        while (true)
        {
            i = piPatternBacktrack[i];
            if (i <= 0)
            {
                if (i < 0)
                {
                    k++;
                }

                break;
            }

            while (pSrcEnd[k] == pPattern[i])
            {
                k++;
                if (++i == iPatternLen)
                {
                    return (iSrcLen + k) - iPatternLen;
                }

                if (k == 0)
                {
                    return -1;
                }
            }
        }
    }
}

static ssize_t *piPatternBacktrack = nullptr;
static ssize_t iPatternBacktrackSize = 0;

// Clean up pattern search data
void ClearPatternSearchData()
{
    if (piPatternBacktrack)
    {
        qfree(piPatternBacktrack);
        piPatternBacktrack = nullptr;
    };
    iPatternBacktrackSize = 0;
}

// Search for pattern
ssize_t PatternSearch(PBYTE pSrc, ssize_t iSrcLen, PBYTE pPattern, ssize_t iPatternLen, ssize_t iAnd)
{
    // Init backtrack buffer the first time
    if (!piPatternBacktrack)
    {
        // Largest seen 7/9/2012 131072 bytes
        iPatternBacktrackSize = qmax((iPatternLen * sizeof(ssize_t)), 131072);
        piPatternBacktrack    = qalloc_array<ssize_t>(iPatternBacktrackSize);
        if (!piPatternBacktrack)
        {
            msg("** Failed to allocate pattern backtrace bufferr! **\n");
            iPatternBacktrackSize = 0;
            return -1;
        }
    }

    // Expand buffer as needed
    ssize_t iNeeded = (iPatternLen * sizeof(ssize_t));
    if (iNeeded > iPatternBacktrackSize)
    {
        // msg("Expanding backtrace buffer from %d to %d bytes\n", iPatternBacktrackSize, iNeeded);
        piPatternBacktrack = qrealloc_array<ssize_t>(piPatternBacktrack, iNeeded);
        if (nullptr != piPatternBacktrack)
        {
            iPatternBacktrackSize = iNeeded;
        }
        else
        {
            msg("** Failed to expand pattern backtrace bufferr from %d to %d bytes! **\n",
                iPatternBacktrackSize, iNeeded);
            iPatternBacktrackSize = 0;
            return -1;
        }
    }

    ssize_t iGranularity = iAnd >> 3;
    ssize_t iSlicesize   = iGranularity ? iGranularity : iPatternLen;
    ssize_t iRemaining   = iSrcLen;
    ssize_t iOfs         = -1;
    ssize_t iMaxAndDistance = iPatternLen * 16;
    PBYTE pPatLimit  = pPattern + iPatternLen;
    PBYTE pPatStart  = nullptr;

    for (PBYTE pStart = pSrc, p = pPattern; p < pPatLimit;)
    {
        iOfs = SearchHashed2(pStart, iRemaining, p, iSlicesize, piPatternBacktrack);
        if (iOfs != -1)
        {
            iRemaining -= (iOfs + iSlicesize);
            if (!pPatStart)
            {
                pPatStart = pStart + iOfs;
                if (iRemaining > iMaxAndDistance)
                {
                    iRemaining = iMaxAndDistance;
                }
            }

            pStart += (iOfs + iSlicesize);
            p      += iSlicesize;
        }
        else
        {
            if (!pPatStart)
            {
                break;
            }

            pStart = pPatStart + iSlicesize;
            iRemaining = iSrcLen - (pStart - pSrc);
            p = pPattern;
            pPatStart = 0;
        }
    }

    return (iOfs != -1) ? (pPatStart - pSrc) : (ssize_t) -1;
}
