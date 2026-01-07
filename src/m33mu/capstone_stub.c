/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "m33mu/capstone.h"

mm_bool capstone_available(void)
{
    return MM_FALSE;
}

mm_bool capstone_init(void)
{
    return MM_FALSE;
}

void capstone_shutdown(void)
{
}

mm_bool capstone_set_enabled(mm_bool enabled)
{
    (void)enabled;
    return MM_FALSE;
}

mm_bool capstone_is_enabled(void)
{
    return MM_FALSE;
}

void capstone_log(const struct mm_fetch_result *fetch)
{
    (void)fetch;
}

int capstone_decode_one(const struct mm_fetch_result *fetch, int *id_out,
                        char *mnemonic_out, size_t mnemonic_cap,
                        char *op_str_out, size_t op_str_cap)
{
    (void)fetch;
    (void)id_out;
    (void)mnemonic_out;
    (void)mnemonic_cap;
    (void)op_str_out;
    (void)op_str_cap;
    return 0;
}

mm_bool capstone_cross_check(const struct mm_fetch_result *fetch, const struct mm_decoded *dec)
{
    (void)fetch;
    (void)dec;
    return MM_TRUE;
}

mm_bool capstone_it_check_pre(const struct mm_fetch_result *fetch, const struct mm_decoded *dec,
                              mm_u8 it_pattern, mm_u8 it_remaining, mm_u8 it_cond)
{
    (void)fetch;
    (void)dec;
    (void)it_pattern;
    (void)it_remaining;
    (void)it_cond;
    return MM_TRUE;
}

mm_bool capstone_it_check_post(const struct mm_fetch_result *fetch, const struct mm_decoded *dec,
                               mm_u8 it_pattern, mm_u8 it_remaining, mm_u8 it_cond)
{
    (void)fetch;
    (void)dec;
    (void)it_pattern;
    (void)it_remaining;
    (void)it_cond;
    return MM_TRUE;
}
