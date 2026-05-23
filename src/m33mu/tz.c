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

#include "m33mu/tz.h"
#include "m33mu/memmap.h"
#include "m33mu/sau.h"
#include <stdio.h>
#include <stdlib.h>

#define SFSR_INVEP     (1u << 0)
#define SFSR_AUVIOL    (1u << 3)
#define SFSR_SFARVALID (1u << 6)

static int g_tz_trace = -1;

static mm_bool tz_trace_enabled(void)
{
    if (g_tz_trace < 0) {
        const char *v = getenv("M33MU_TZ_TRACE");
        g_tz_trace = (v && v[0] != '\0') ? 1 : 0;
    }
    return g_tz_trace ? MM_TRUE : MM_FALSE;
}

static void tz_sync_r13_from_active_sp(struct mm_cpu *cpu)
{
    mm_u32 sp;
    if (cpu == 0) {
        return;
    }
    sp = mm_cpu_get_active_sp(cpu);
    mm_cpu_set_active_sp(cpu, sp);
}

static void tz_note_ns_msp_top(struct mm_cpu *cpu)
{
    if (cpu == 0) {
        return;
    }
    if (cpu->sec_state == MM_NONSECURE) {
        mm_cpu_note_msp_top(cpu, MM_NONSECURE);
    }
}

static mm_bool tz_target_is_valid_ns(struct mm_scs *scs, mm_u32 target)
{
    mm_u32 addr = target & ~1u;

    if (target == 0u || addr == 0u) {
        return MM_FALSE;
    }
    if ((target & 1u) != 0u) {
        return MM_FALSE;
    }
    if (scs == 0) {
        return MM_TRUE;
    }
    return mm_sau_attr_for_addr(scs, addr) == MM_SAU_NONSECURE;
}

static void tz_record_invalid_entry(struct mm_scs *scs, mm_u32 target)
{
    if (scs == 0) {
        return;
    }
    scs->sau_sfsr |= SFSR_INVEP | SFSR_AUVIOL | SFSR_SFARVALID;
    scs->sau_sfar = target & ~1u;
    scs->securefault_pending = MM_TRUE;
}

static void tz_warn_if_reset_vector_mismatch(struct mm_scs *scs, mm_u32 target)
{
    static mm_u32 last_vtor;
    static mm_u32 last_target;
    struct mm_memmap *map;
    mm_u32 reset = 0u;
    mm_u32 target_addr = target & ~1u;
    mm_u32 reset_addr;
    mm_u32 delta;

    if (scs == 0 || scs->vtor_ns == 0u || target_addr == 0u) {
        return;
    }
    map = mm_memmap_current();
    if (map == 0) {
        return;
    }
    if (!mm_memmap_read(map, MM_NONSECURE, scs->vtor_ns + 4u, 4u, &reset)) {
        return;
    }
    reset_addr = reset & ~1u;
    if (reset_addr == 0u || reset_addr == target_addr) {
        return;
    }
    delta = (target_addr > reset_addr) ? (target_addr - reset_addr) : (reset_addr - target_addr);
    if (delta > 0x400u) {
        return;
    }
    if (last_vtor == scs->vtor_ns && last_target == target_addr) {
        return;
    }
    last_vtor = scs->vtor_ns;
    last_target = target_addr;
    printf("[TZ_WARN] non-secure branch target 0x%08lx differs from VTOR_NS reset vector 0x%08lx (VTOR_NS=0x%08lx)\n",
           (unsigned long)target_addr,
           (unsigned long)reset_addr,
           (unsigned long)scs->vtor_ns);
}

static void tz_dump_words(const char *tag, struct mm_cpu *cpu, enum mm_sec_state sec,
    mm_u32 addr, unsigned count)
{
    struct mm_memmap *map;
    unsigned i;

    if (!tz_trace_enabled() || cpu == 0) {
        return;
    }

    map = mm_memmap_current();
    if (map == 0) {
        return;
    }

    printf("[%s] sec=%d addr=0x%08lx", tag, (int)sec, (unsigned long)addr);
    for (i = 0; i < count; i++) {
        mm_u32 word;
        mm_bool ok;

        ok = mm_memmap_read(map, sec, addr + (i * 4u), 4u, &word);
        if (!ok) {
            printf(" +%u=<fault>", i * 4u);
            break;
        }
        printf(" +%u=0x%08lx", i * 4u, (unsigned long)word);
    }
    printf("\n");
}

static void tz_push_secure_call_frame(struct mm_cpu *cpu, mm_u32 return_addr)
{
    struct mm_memmap *map;
    mm_u32 sp;
    mm_u32 retpsr;
    mm_u32 stacked_ra;

    if (cpu == 0 || cpu->sec_state != MM_SECURE) {
        return;
    }

    map = mm_memmap_current();
    if (map == 0) {
        return;
    }

    sp = mm_cpu_get_active_sp(cpu);
    sp -= 8u;
    stacked_ra = return_addr | 1u;
    retpsr = 0u;

    if (!mm_memmap_write(map, MM_SECURE, sp, 4u, stacked_ra)) {
        return;
    }
    if (!mm_memmap_write(map, MM_SECURE, sp + 4u, 4u, retpsr)) {
        return;
    }

    mm_cpu_set_active_sp(cpu, sp);
}

void mm_tz_exec_sg(struct mm_cpu *cpu, struct mm_scs *scs, mm_u32 insn_addr)
{
    if (cpu == 0) {
        return;
    }
    /* Minimal model: SG is used for NS->S transition via an NSC veneer. */
    if (cpu->sec_state == MM_NONSECURE) {
        if (scs != 0 && mm_sau_attr_for_addr(scs, insn_addr) != MM_SAU_NSC) {
            scs->sau_sfsr |= SFSR_INVEP | SFSR_SFARVALID;
            scs->sau_sfar = insn_addr;
            scs->securefault_pending = MM_TRUE;
            return;
        }
        if (tz_trace_enabled()) {
            printf("[TZ_SG] pc=0x%08lx lr=0x%08lx r13=0x%08lx r0=0x%08lx sec %d->%d mode=%d msp_s=0x%08lx msp_ns=0x%08lx psp_s=0x%08lx psp_ns=0x%08lx\n",
                   (unsigned long)insn_addr,
                   (unsigned long)cpu->r[14],
                   (unsigned long)cpu->r[13],
                   (unsigned long)cpu->r[0],
                   (int)MM_NONSECURE,
                   (int)MM_SECURE,
                   (int)cpu->mode,
                   (unsigned long)cpu->msp_s,
                   (unsigned long)cpu->msp_ns,
                   (unsigned long)cpu->psp_s,
                   (unsigned long)cpu->psp_ns);
            tz_dump_words("TZ_SG_NS_SP", cpu, MM_NONSECURE, cpu->r[13], 8u);
            tz_dump_words("TZ_SG_NS_R0", cpu, MM_NONSECURE, cpu->r[0], 8u);
            tz_dump_words("TZ_SG_S_MSP_PRE", cpu, MM_SECURE, cpu->msp_s, 8u);
            tz_dump_words("TZ_SG_S_PSP_PRE", cpu, MM_SECURE, cpu->psp_s, 8u);
        }
        cpu->r[14] &= ~1u;
        cpu->sec_state = MM_SECURE;
        tz_sync_r13_from_active_sp(cpu);
        if (tz_trace_enabled()) {
            printf("[TZ_SG_POST] lr=0x%08lx r13=0x%08lx active_sp=0x%08lx\n",
                   (unsigned long)cpu->r[14],
                   (unsigned long)cpu->r[13],
                   (unsigned long)mm_cpu_get_active_sp(cpu));
            tz_dump_words("TZ_SG_S_SP_POST", cpu, MM_SECURE, cpu->r[13], 8u);
        }
    }
}

void mm_tz_exec_bxns(struct mm_cpu *cpu, struct mm_scs *scs, mm_u32 target)
{
    if (cpu == 0) {
        return;
    }
    /* BXNS is defined for Secure->Non-secure transition. */
    if (tz_trace_enabled()) {
        printf("[TZ_BXNS] pc=0x%08lx lr=0x%08lx target=0x%08lx r13=0x%08lx sec %d->%d mode=%d msp_s=0x%08lx msp_ns=0x%08lx psp_s=0x%08lx psp_ns=0x%08lx\n",
               (unsigned long)cpu->r[15],
               (unsigned long)cpu->r[14],
               (unsigned long)target,
               (unsigned long)cpu->r[13],
               (int)MM_SECURE,
               (int)MM_NONSECURE,
               (int)cpu->mode,
               (unsigned long)cpu->msp_s,
               (unsigned long)cpu->msp_ns,
               (unsigned long)cpu->psp_s,
               (unsigned long)cpu->psp_ns);
    }
    if (!tz_target_is_valid_ns(scs, target)) {
        tz_record_invalid_entry(scs, target);
        return;
    }
    tz_warn_if_reset_vector_mismatch(scs, target);
    cpu->sec_state = MM_NONSECURE;
    tz_note_ns_msp_top(cpu);
    tz_sync_r13_from_active_sp(cpu);
    cpu->r[15] = target | 1u;
}

void mm_tz_exec_blxns(struct mm_cpu *cpu, struct mm_scs *scs, mm_u32 target, mm_u32 return_addr)
{
    mm_u32 ra;
    if (cpu == 0) {
        return;
    }
    /* BLXNS is defined for Secure->Non-secure call. */
    if (!tz_target_is_valid_ns(scs, target)) {
        tz_record_invalid_entry(scs, target);
        return;
    }
    tz_warn_if_reset_vector_mismatch(scs, target);
    ra = return_addr | 1u;
    tz_push_secure_call_frame(cpu, ra);
    if (tz_trace_enabled()) {
        printf("[TZ_BLXNS] pc=0x%08lx lr=0x%08lx target=0x%08lx ra=0x%08lx r13=0x%08lx sec %d->%d mode=%d msp_s=0x%08lx msp_ns=0x%08lx psp_s=0x%08lx psp_ns=0x%08lx\n",
               (unsigned long)cpu->r[15],
               (unsigned long)cpu->r[14],
               (unsigned long)target,
               (unsigned long)ra,
               (unsigned long)cpu->r[13],
               (int)cpu->sec_state,
               (int)MM_NONSECURE,
               (int)cpu->mode,
               (unsigned long)cpu->msp_s,
               (unsigned long)cpu->msp_ns,
               (unsigned long)cpu->psp_s,
               (unsigned long)cpu->psp_ns);
    }
    if (cpu->tz_depth >= MM_TZ_STACK_MAX) {
        if (tz_trace_enabled()) {
            printf("[TZ_BLXNS] overflow depth=%u max=%u, call aborted\n",
                   (unsigned)cpu->tz_depth,
                   (unsigned)MM_TZ_STACK_MAX);
        }
        return;
    }
    cpu->tz_ret_pc[cpu->tz_depth] = ra;
    cpu->tz_ret_sec[cpu->tz_depth] = cpu->sec_state;
    cpu->tz_ret_mode[cpu->tz_depth] = cpu->mode;
    cpu->tz_depth++;
    cpu->r[14] = MM_TZ_FNC_RETURN;
    cpu->sec_state = MM_NONSECURE;
    tz_note_ns_msp_top(cpu);
    tz_sync_r13_from_active_sp(cpu);
    cpu->r[15] = target | 1u;
}
