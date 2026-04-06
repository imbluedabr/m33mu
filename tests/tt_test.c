/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>

#include "m33mu/cpu.h"
#include "m33mu/scs.h"
#include "m33mu/tt.h"

static void setup_priv_only_region(struct mm_scs *scs, mm_u32 base, mm_u32 limit)
{
    mm_scs_init(scs, 0);
    scs->mpu_ctrl_s = 0x1u; /* ENABLE */
    scs->mpu_rbar_s[0] = base | (0x0u << 1); /* AP=00: privileged RW, unpriv no access */
    scs->mpu_rlar_s[0] = (limit & ~0x1fu) | 0x1u; /* ENABLE */
}

static int test_tt_uses_privileged_thread_state_not_xpsr_bit0(void)
{
    struct mm_cpu cpu;
    struct mm_scs scs;
    mm_u32 resp;

    memset(&cpu, 0, sizeof(cpu));
    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.xpsr = 0u; /* IPSR=0, bit0 clear */
    mm_cpu_set_privileged(&cpu, MM_FALSE); /* privileged thread */

    setup_priv_only_region(&scs, 0x00001000u, 0x00001fe0u);
    resp = mm_tt_resp(&cpu, &scs, 0x00001010u, MM_FALSE, MM_FALSE);

    if ((resp & (1u << 16)) == 0u || (resp & (1u << 17)) == 0u) {
        printf("tt_test: privileged thread got resp=0x%08lx expected R/RW set\n",
               (unsigned long)resp);
        return 1;
    }
    return 0;
}

static int test_tt_handler_mode_stays_privileged_with_even_ipsr(void)
{
    struct mm_cpu cpu;
    struct mm_scs scs;
    mm_u32 resp;

    memset(&cpu, 0, sizeof(cpu));
    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_HANDLER;
    cpu.xpsr = 2u; /* NMI exception number, bit0 clear */
    mm_cpu_set_privileged(&cpu, MM_FALSE);

    setup_priv_only_region(&scs, 0x00001000u, 0x00001fe0u);
    resp = mm_tt_resp(&cpu, &scs, 0x00001010u, MM_FALSE, MM_FALSE);

    if ((resp & (1u << 16)) == 0u || (resp & (1u << 17)) == 0u) {
        printf("tt_test: handler mode got resp=0x%08lx expected R/RW set\n",
               (unsigned long)resp);
        return 1;
    }
    return 0;
}

static int test_tt_reports_sau_region_number_when_secure(void)
{
    struct mm_cpu cpu;
    struct mm_scs scs;
    mm_u32 resp;

    memset(&cpu, 0, sizeof(cpu));
    mm_scs_init(&scs, 0);
    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    scs.sau_ctrl = 0x1u; /* ENABLE */
    scs.sau_rbar[3] = 0x00002000u;
    scs.sau_rlar[3] = 0x000020E0u | 0x1u; /* region 3, enabled */

    resp = mm_tt_resp(&cpu, &scs, 0x00002010u, MM_FALSE, MM_FALSE);
    if ((resp & (1u << 7)) == 0u) {
        printf("tt_test: secure TT missing SRVALID resp=0x%08lx\n", (unsigned long)resp);
        return 1;
    }
    if (((resp >> 8) & 0xFFu) != 3u) {
        printf("tt_test: secure TT wrong SREGION resp=0x%08lx\n", (unsigned long)resp);
        return 1;
    }
    return 0;
}

static int test_tt_leaves_srvalid_clear_without_matching_sau_region(void)
{
    struct mm_cpu cpu;
    struct mm_scs scs;
    mm_u32 resp;

    memset(&cpu, 0, sizeof(cpu));
    mm_scs_init(&scs, 0);
    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    scs.sau_ctrl = 0x1u; /* ENABLE */

    resp = mm_tt_resp(&cpu, &scs, 0x00003010u, MM_FALSE, MM_FALSE);
    if ((resp & (1u << 7)) != 0u || ((resp >> 8) & 0xFFu) != 0u) {
        printf("tt_test: unmatched SAU region should clear SRVALID/SREGION resp=0x%08lx\n",
               (unsigned long)resp);
        return 1;
    }
    return 0;
}

int main(void)
{
    struct { const char *name; int (*fn)(void); } tests[] = {
        { "privileged_thread_state", test_tt_uses_privileged_thread_state_not_xpsr_bit0 },
        { "handler_mode_even_ipsr", test_tt_handler_mode_stays_privileged_with_even_ipsr },
        { "secure_sau_region", test_tt_reports_sau_region_number_when_secure },
        { "no_sau_region", test_tt_leaves_srvalid_clear_without_matching_sau_region },
    };
    int failures = 0;
    int i;
    const int count = (int)(sizeof(tests) / sizeof(tests[0]));

    for (i = 0; i < count; ++i) {
        if (tests[i].fn() != 0) {
            ++failures;
            printf("FAIL: %s\n", tests[i].name);
        } else {
            printf("PASS: %s\n", tests[i].name);
        }
    }
    if (failures != 0) {
        printf("tt_test: %d failure(s)\n", failures);
        return 1;
    }
    return 0;
}
