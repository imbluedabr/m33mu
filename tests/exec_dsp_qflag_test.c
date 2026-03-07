/* m33mu -- an ARMv8-M Emulator
 *
 * Copyright (C) 2026
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>

#include "m33mu/cpu.h"
#include "m33mu/decode.h"
#include "m33mu/execute.h"
#include "m33mu/fetch.h"
#include "m33mu/memmap.h"
#include "m33mu/scs.h"

static mm_bool stub_handle_pc_write(struct mm_cpu *cpu,
                                    struct mm_memmap *map,
                                    struct mm_scs *scs,
                                    mm_u32 value,
                                    mm_u8 *it_pattern,
                                    mm_u8 *it_remaining,
                                    mm_u8 *it_cond)
{
    (void)cpu;
    (void)map;
    (void)scs;
    (void)value;
    (void)it_pattern;
    (void)it_remaining;
    (void)it_cond;
    return MM_TRUE;
}

static mm_bool stub_raise_mem_fault(struct mm_cpu *cpu,
                                    struct mm_memmap *map,
                                    struct mm_scs *scs,
                                    mm_u32 fault_pc,
                                    mm_u32 fault_xpsr,
                                    mm_u32 addr,
                                    mm_bool is_exec)
{
    (void)cpu;
    (void)map;
    (void)scs;
    (void)fault_pc;
    (void)fault_xpsr;
    (void)addr;
    (void)is_exec;
    return MM_FALSE;
}

static mm_bool stub_raise_usage_fault(struct mm_cpu *cpu,
                                      struct mm_memmap *map,
                                      struct mm_scs *scs,
                                      mm_u32 fault_pc,
                                      mm_u32 fault_xpsr,
                                      mm_u32 ufsr_bits)
{
    (void)cpu;
    (void)map;
    (void)scs;
    (void)fault_pc;
    (void)fault_xpsr;
    (void)ufsr_bits;
    return MM_FALSE;
}

static mm_bool stub_exc_return_unstack(struct mm_cpu *cpu,
                                       struct mm_memmap *map,
                                       struct mm_scs *scs,
                                       mm_u32 exc_ret)
{
    (void)cpu;
    (void)map;
    (void)scs;
    (void)exc_ret;
    return MM_FALSE;
}

static mm_bool stub_enter_exception(struct mm_cpu *cpu,
                                    struct mm_memmap *map,
                                    struct mm_scs *scs,
                                    mm_u32 exc_num,
                                    mm_u32 return_pc,
                                    mm_u32 xpsr_in)
{
    (void)cpu;
    (void)map;
    (void)scs;
    (void)exc_num;
    (void)return_pc;
    (void)xpsr_in;
    return MM_FALSE;
}

static int test_smla_sets_q_on_accumulate_overflow(void)
{
    struct mm_cpu cpu;
    struct mm_memmap map;
    struct mm_scs scs;
    struct mm_gdb_stub gdb;
    struct mm_fetch_result fetch;
    struct mm_decoded dec;
    struct mm_execute_ctx ctx;
    struct mmio_region regions[1];
    mm_u8 it_pattern = 0;
    mm_u8 it_remaining = 0;
    mm_u8 it_cond = 0;
    mm_bool done = MM_FALSE;

    memset(&cpu, 0, sizeof(cpu));
    memset(&map, 0, sizeof(map));
    memset(&scs, 0, sizeof(scs));
    memset(&gdb, 0, sizeof(gdb));
    memset(&fetch, 0, sizeof(fetch));
    memset(&dec, 0, sizeof(dec));
    memset(&ctx, 0, sizeof(ctx));
    memset(regions, 0, sizeof(regions));

    mm_memmap_init(&map, regions, 1u);

    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[0] = 0x00007fffu;
    cpu.r[1] = 0x00007fffu;
    cpu.r[2] = 0x7fffffffu;
    cpu.q_flag = MM_FALSE;

    dec.kind = MM_OP_SMLA;
    dec.rn = 0u;
    dec.rm = 1u;
    dec.ra = 2u;
    dec.rd = 3u;
    dec.imm = 0u;
    dec.len = 4u;
    dec.undefined = MM_FALSE;

    ctx.cpu = &cpu;
    ctx.map = &map;
    ctx.scs = &scs;
    ctx.gdb = &gdb;
    ctx.fetch = &fetch;
    ctx.dec = &dec;
    ctx.it_pattern = &it_pattern;
    ctx.it_remaining = &it_remaining;
    ctx.it_cond = &it_cond;
    ctx.done = &done;
    ctx.handle_pc_write = stub_handle_pc_write;
    ctx.raise_mem_fault = stub_raise_mem_fault;
    ctx.raise_usage_fault = stub_raise_usage_fault;
    ctx.exc_return_unstack = stub_exc_return_unstack;
    ctx.enter_exception = stub_enter_exception;

    if (mm_execute_decoded(&ctx) != MM_EXEC_OK) {
        printf("exec_dsp_qflag_test: SMLA execution failed\n");
        return 1;
    }
    if (done) {
        printf("exec_dsp_qflag_test: unexpected done flag\n");
        return 1;
    }
    if (cpu.r[3] != 0xbfff0000u) {
        printf("exec_dsp_qflag_test: result mismatch got=0x%08lx\n",
               (unsigned long)cpu.r[3]);
        return 1;
    }
    if (!cpu.q_flag) {
        printf("exec_dsp_qflag_test: Q flag not set on overflow\n");
        return 1;
    }

    return 0;
}

int main(void)
{
    if (test_smla_sets_q_on_accumulate_overflow() != 0) return 1;
    return 0;
}
