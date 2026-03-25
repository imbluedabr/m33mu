/* m33mu -- an ARMv8-M Emulator
 *
 * Copyright (C) 2025  Daniele Lacamera <root@danielinux.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 */

#include <stdio.h>
#include "m33mu/cpu.h"
#include "m33mu/tz.h"

static void cpu_init(struct mm_cpu *cpu)
{
    int i;
    for (i = 0; i < 16; ++i) cpu->r[i] = 0;
    cpu->sec_state = MM_SECURE;
    cpu->mode = MM_THREAD;
    cpu->exc_depth = 0;
    cpu->tz_depth = 0;
}

static int test_sg_ns_to_s(void)
{
    struct mm_cpu cpu;
    cpu_init(&cpu);
    cpu.sec_state = MM_NONSECURE;
    mm_tz_exec_sg(&cpu);
    if (cpu.sec_state != MM_SECURE) return 1;
    return 0;
}

static int test_bxns_s_to_ns(void)
{
    struct mm_cpu cpu;
    cpu_init(&cpu);
    mm_tz_exec_bxns(&cpu, 0x08000100u);
    if (cpu.sec_state != MM_NONSECURE) return 1;
    if (cpu.r[15] != (0x08000100u | 1u)) return 1;
    return 0;
}

static int test_blxns_sets_lr_and_branches(void)
{
    struct mm_cpu cpu;
    cpu_init(&cpu);
    cpu.r[14] = 0;
    mm_tz_exec_blxns(&cpu, 0x08000200u, 0x0c000123u);
    if (cpu.sec_state != MM_NONSECURE) return 1;
    if (cpu.r[15] != (0x08000200u | 1u)) return 1;
    if (cpu.r[14] != MM_TZ_FNC_RETURN) return 1;
    if (cpu.tz_depth != 1) return 1;
    if (cpu.tz_ret_pc[0] != (0x0c000123u | 1u)) return 1;
    if (cpu.tz_ret_sec[0] != MM_SECURE) return 1;
    return 0;
}

static int test_blxns_stack_full_aborts_transition(void)
{
    struct mm_cpu cpu;
    mm_u32 i;
    cpu_init(&cpu);
    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[14] = 0x12345679u;
    cpu.r[15] = 0x08001001u;
    cpu.r[13] = 0x20002000u;
    cpu.tz_depth = MM_TZ_STACK_MAX;
    for (i = 0; i < MM_TZ_STACK_MAX; ++i) {
        cpu.tz_ret_pc[i] = 0x10000001u + (i << 1);
        cpu.tz_ret_sec[i] = MM_SECURE;
        cpu.tz_ret_mode[i] = MM_THREAD;
    }

    mm_tz_exec_blxns(&cpu, 0x08000200u, 0x0c000123u);

    if (cpu.sec_state != MM_SECURE) return 1;
    if (cpu.mode != MM_THREAD) return 1;
    if (cpu.r[14] != 0x12345679u) return 1;
    if (cpu.r[15] != 0x08001001u) return 1;
    if (cpu.r[13] != 0x20002000u) return 1;
    if (cpu.tz_depth != MM_TZ_STACK_MAX) return 1;
    for (i = 0; i < MM_TZ_STACK_MAX; ++i) {
        if (cpu.tz_ret_pc[i] != (0x10000001u + (i << 1))) return 1;
        if (cpu.tz_ret_sec[i] != MM_SECURE) return 1;
        if (cpu.tz_ret_mode[i] != MM_THREAD) return 1;
    }
    return 0;
}

int main(void)
{
    struct { const char *name; int (*fn)(void); } tests[] = {
        { "sg_ns_to_s", test_sg_ns_to_s },
        { "bxns_s_to_ns", test_bxns_s_to_ns },
        { "blxns_sets_lr_and_branches", test_blxns_sets_lr_and_branches },
        { "blxns_stack_full_aborts_transition", test_blxns_stack_full_aborts_transition },
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
        printf("tz_branch_test: %d failure(s)\n", failures);
        return 1;
    }
    return 0;
}
