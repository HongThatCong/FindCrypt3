// FindCrypt - find constants used in crypto algorithms
// Copyright 2006 Ilfak Guilfanov <ig@hexblog.com>
// This is a freeware program.
// This copyright message must be kept intact.

// This plugin looks for constant arrays used in popular crypto algorithms.
// If a crypto algorithm is found, it will rename the appropriate locations
// of the program and put bookmarks on them.

// Version 3 - add some constants by HTC (TQN)

#include <set>

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <auto.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <moves.hpp>

#include "findcrypt3.hpp"

#define VERIFY_CONSTANTS    1   // Turn on to test the duplicate of constants for the first build and test
#define PLUGIN_NAME         "FindCrypt3"

//--------------------------------------------------------------------------
// retrieve the first byte of the specified array
// take into account the byte sex
inline uchar get_first_byte(const array_info_t *a)
{
    const uchar *ptr = (const uchar *) a->array;
    if (!inf.is_be())
    {
        return ptr[0];
    }
    return ptr[a->elsize - 1];
}

//--------------------------------------------------------------------------
// check that all constant arrays are distinct (no duplicates)
// lint -e528 not used
#ifdef VERIFY_CONSTANTS

static int array_compare(const void *a_ptr, const void *b_ptr)
{
    const array_info_t *a = *(const array_info_t **) a_ptr;
    const array_info_t *b = *(const array_info_t **) b_ptr;
    size_t diff = a->size * a->elsize - b->size * b->elsize;
    if (diff != 0)
    {
        return diff;
    }
    return memcmp(a->array, b->array, a->size * a->elsize);
}

static int verify_constants(const array_info_t *consts)
{
    size_t i, count = 0;
    int ret = 0;

    while (consts[count].array != nullptr)
    {
        ++count;
    }

    const array_info_t **sorted = (const array_info_t **) malloc(count * sizeof(array_info_t *));
    for (i = 0; i < count; ++i)
    {
        sorted[i] = &consts[i];
    }

    qsort((void *) sorted, count, sizeof(array_info_t *), &array_compare);

    for (i = 0; i < count - 1; ++i)
    {
        if (array_compare((const void *) &sorted[i], (const void *) &sorted[i + 1]) == 0)
        {
            msg("[%s] - duplicate array %s and %s!\n",
                PLUGIN_NAME, sorted[i]->name, sorted[i + 1]->name);
        }
    }

    free(sorted);
    return ret;
}

#endif

//--------------------------------------------------------------------------
// match a constant array against the database at the specified address
static bool match_array_pattern(ea_t ea, const array_info_t *ai)
{
    assert(nullptr != ai);
    assert(nullptr != ai->array);
    if (nullptr == ai || nullptr == ai->array)
    {
        msg("[%s] - " __FUNCTION__ ": Invalid input parameters: %s\n",
            PLUGIN_NAME, (nullptr != ai) ? ai->name : "ai is nullptr");
        return false;
    }

    uchar *ptr = (uchar *) ai->array;
    for (size_t i = 0; i < ai->size; ++i)
    {
        switch (ai->elsize)
        {
            case 1:
                if (get_byte(ea) != *((uchar*) ptr))
                    return false;
                break;

            case 2:
                if (get_word(ea) != *((ushort*) ptr))
                    return false;
                break;

            case 4:
                if (get_dword(ea) != *((uint32*) ptr))
                    return false;
                break;

            case 8:
                if (get_qword(ea) != *((uint64*) ptr))
                    return false;
                break;

            default:
                msg("[%s] - unexpected array '%s' element size %d\n",
                    PLUGIN_NAME, ai->name, ai->elsize);
                return false;
        }

        ptr += ai->elsize;
        ea  += ai->elsize;
    }

    return true;
}

//--------------------------------------------------------------------------
// match a sparse array against the database at the specified address
// NB: all sparse arrays must be word32!
static bool match_sparse_pattern(ea_t ea, const array_info_t *ai, eavec_t &eaFounds)
{
    assert(nullptr != ai);
    assert(nullptr != ai->array);
    if (nullptr == ai || nullptr == ai->array)
    {
        msg("[%s] - " __FUNCTION__ ": Invalid input parameters: %s\n",
            PLUGIN_NAME, (nullptr != ai) ? ai->name : "ai is nullptr");
        return false;
    }

    const word32 *ptr = (const word32*) ai->array;

    eaFounds.clear();

    // Optimize for size is 1
    if (get_dword(ea) != *ptr)
    {
        return false;
    }

    eaFounds.push_back(ea);
    if (1 == ai->size)
    {
        return true;
    }

    // Scan next ea
    ea += 4;

    // look for the constant in the next 64 x ai->size bytes
    size_t sizeN = (64 * ai->size) + 4;

    qvector<byte> mem;
    mem.resize(sizeN);

    ssize_t sizeRead = get_bytes(mem.begin(), sizeN, ea, GMB_READALL);
    if (sizeRead <= 0)
    {
        // msg("[%s] - " __FUNCTION__ ": get_bytes at %a failed\n", PLUGIN_NAME, ea);
        return false;
    }

    for (size_t i = 1; i < ai->size; ++i)
    {
        word32 c = ptr[i];
        if (inf.is_be())
        {
            c = swap32(c);
        }

        ssize_t j = 0;
        for (j = 0; j < sizeRead; j++)
        {
            if (c == *(word32 *)(mem.begin() + j))
            {
                const ea_t ea_found = ea + j;
                // msg("DEBUG - 0x%a - 0x%x\n", ea_found, c);
                eaFounds.push_back(ea_found);
                break;
            }
        }

        if (j == sizeRead)
        {
            return false;
        }
    }

    return eaFounds.size() > 0;
}

//--------------------------------------------------------------------------
// Set or append comment at the address ea
//
static bool force_comment(ea_t ea, const char *pszCmt)
{
    assert(nullptr != pszCmt);
    assert(BADADDR != ea);
    if (nullptr == pszCmt || BADADDR == ea)
    {
        msg("[%s] - " __FUNCTION__ ": invalid parameter\n", PLUGIN_NAME);
        return false;
    }

    ea = get_item_head(ea);

    qstring cmt;
    get_cmt(&cmt, ea, false);
    if (cmt.length() > 0)
    {
        if (cmt.find(pszCmt) == qstring::npos)
        {
            cmt += "\n";
            cmt += pszCmt;
        }
    }
    else
    {
        cmt = pszCmt;
    }

    return set_cmt(ea, cmt.c_str(), false);
}

//--------------------------------------------------------------------------
// mark a location with the name of the algorithm
// set comment of a location with name of constants
// use the first free slot for the marker
static void mark_location(ea_t ea, const char *algorithm)
{
    idaplace_t ipl(ea, 0);
    renderer_info_t rinfo;
    rinfo.rtype = TCCRT_FLAT;
    rinfo.pos.cx = 0;
    rinfo.pos.cy = 5;
    lochist_entry_t e(&ipl, rinfo);

    uint32 i, n = bookmarks_t::size(e, nullptr);
    ea = get_item_head(ea);
    for (i = 0; i < n; ++i)
    {
        qstring desc;
        lochist_entry_t loc(e);
        if (!bookmarks_t::get(&loc, &desc, &i, nullptr))
            break;
        // reuse old "Crypto: " slots
        if (strneq(desc.c_str(), "Crypto: ", 7) && loc.place()->toea() == ea)
            break;
    }

    qstring buf;
    buf.sprnt("Crypto: %s", algorithm);
    bookmarks_t::mark(e, i, nullptr, buf.c_str(), nullptr);
}

//--------------------------------------------------------------------------
// Make array of ptr->size of ptr->elsize at address ea
//
static bool make_array(ea_t ea, const array_info_t *ptr)
{
    assert(BADADDR != ea);
    assert(nullptr != ptr);
    if (BADADDR ==  ea || nullptr == ptr)
    {
        return false;
    }

    asize_t length = ptr->size * ptr->elsize;
    del_items(ea, DELIT_DELNAMES, length);

    // make C-string if ptr is ARR_SZ
    if ((1 == ptr->elsize) && (1 == ptr->big_endian))
    {
        return create_strlit(ea, length, STRTYPE_C);
    }

    switch (ptr->elsize)
    {
        case 1:
            create_byte(ea, length);
            break;

        case 2:
            create_word(ea, length);
            break;

        case 4:
            create_dword(ea, length);
            break;

        case 8:
            create_qword(ea, length);
            break;

        default:
            assert(false);
            return false;
    }

    array_parameters_t arr_params = { AP_INDEX  | AP_ARRAY | AP_IDXDEC, 1, (int32) ptr->elsize };
    set_array_parameters(ea, &arr_params);

    return true;
}

//--------------------------------------------------------------------------
// try to find constants at the given address range
static void recognize_constants(ea_t ea1, ea_t ea2)
{
    int count = 0;

    msg_clear();
    show_wait_box("Searching for crypto constants in range 0x%a - 0x%a...", ea1, ea2);

    for (ea_t ea = ea1; ea < ea2; ea = next_addr(ea))
    {
        if (0 == (ea % 0x1000))
        {
            show_addr(ea);
            if (user_cancelled())
            {
                break;
            }
        }

        uchar b = get_byte(ea);

        // check against normal constants
        for (const array_info_t *ptr = non_sparse_consts; ptr->size != 0; ++ptr)
        {
            if (b != get_first_byte(ptr))
            {
                continue;
            }

            if (match_array_pattern(ea, ptr))
            {
                msg("[%s] - 0x%a: found const array %s (used in %s), size = %d, elsize = %d\n",
                    PLUGIN_NAME, ea, ptr->name, ptr->algorithm, ptr->size, ptr->elsize);
                mark_location(ea, ptr->algorithm);
                make_array(ea, ptr);
                force_name(ea, ptr->name);
                force_comment(ea, ptr->name);
                count++;
                break;
            }
        }

        // check against sparse constants
        eavec_t eaFounds;
        for (const array_info_t *ptr = sparse_consts; ptr->size != 0; ++ptr)
        {
            if (b != get_first_byte(ptr))
            {
                continue;
            }

            if (match_sparse_pattern(ea, ptr, eaFounds))
            {
                msg("[%s] - 0x%a: found sparse constants %s for %s\n",
                    PLUGIN_NAME, ea, ptr->name, ptr->algorithm);
                mark_location(ea, ptr->algorithm);

                for (eavec_t::const_iterator it = eaFounds.begin(); it < eaFounds.end(); ++it)
                {
                    force_comment(*it, ptr->name);
                }
                count++;
                break;
            }
        }
    }

    hide_wait_box();
    msg("[%s] - Found %d known constant arrays in total.\n", PLUGIN_NAME, count);
}

//--------------------------------------------------------------------------
bool idaapi run(size_t)
{
    if (!auto_is_ok())
    {
        warning("IDA is still analysing !\nPlugin will start after autoanalysis is finished");
        auto_wait();
    }

    ea_t ea1 = inf.min_ea;
    ea_t ea2 = inf.max_ea;

    read_range_selection(nullptr, &ea1, &ea2);     // if fails, inf.min_ea and inf.max_ea will be used
    recognize_constants(ea1, ea2);

    return true;
}

//--------------------------------------------------------------------------
int idaapi init(void)
{
#ifdef VERIFY_CONSTANTS
    verify_constants(non_sparse_consts);
    verify_constants(sparse_consts);
    verify_constants(operand_consts);
#endif

    msg("\n=================================================================================\n"
        "[%s] plugin initialized\n"
        "Version 2 - Copyright 2006 Ilfak Guilfanov <ig@hexblog.com>\n"
        "Version 3 - by HTC (TQN)\n"
        "    Fix some bugs, optimize and add some functions, crypto constants...\n"
        "=================================================================================\n\n",
        PLUGIN_NAME);

    return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
    msg("[%s] plugin terminated\n", PLUGIN_NAME);
}

//--------------------------------------------------------------------------
static const char *help = PLUGIN_NAME;
static const char *comment = PLUGIN_NAME;
static const char *wanted_name = PLUGIN_NAME;
static const char *wanted_hotkey = "";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_PROC,          // plugin flags
    init,                 // initialize
    term,                 // terminate. this pointer may be nullptr.
    run,                  // invoke plugin
    comment,              // long comment about the plugin
                          // it could appear in the status line
                          // or as a hint
    help,                 // multiline help about the plugin
    wanted_name,          // the preferred short name of the plugin
    wanted_hotkey         // the preferred hotkey to run the plugin
};
