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

static int run_sequence(const mm_u8 *code, size_t code_len, struct mm_cpu *cpu)
{
    struct mm_mem mem;
    struct mm_memmap map;
    struct mmio_region regions[1];
    struct mm_scs scs;
    mm_u8 it_pattern = 0;
    mm_u8 it_remaining = 0;
    mm_u8 it_cond = 0;
    mm_bool done = MM_FALSE;

    memset(&map, 0, sizeof(map));
    memset(regions, 0, sizeof(regions));
    memset(&scs, 0, sizeof(scs));
    mm_memmap_init(&map, regions, 1u);

    mem.buffer = code;
    mem.length = code_len;
    mem.base = 0;

    while ((cpu->r[15] & ~1u) < code_len) {
        struct mm_fetch_result fetch;
        struct mm_decoded dec;
        struct mm_execute_ctx ctx;

        fetch = mm_fetch_t32(cpu, &mem);
        if (fetch.fault) {
            return 1;
        }
        dec = mm_decode_t32(&fetch);

        if (!mm_it_should_execute(cpu, &dec, &it_pattern, &it_remaining, &it_cond) &&
            dec.kind != MM_OP_IT) {
            mm_it_advance(cpu, &dec, &it_pattern, &it_remaining, &it_cond);
            continue;
        }

        memset(&ctx, 0, sizeof(ctx));
        ctx.cpu = cpu;
        ctx.map = &map;
        ctx.scs = &scs;
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
            return 1;
        }
        if (done) {
            return 1;
        }

        if (it_remaining > 0u && dec.kind != MM_OP_IT) {
            mm_it_advance(cpu, &dec, &it_pattern, &it_remaining, &it_cond);
        }
    }

    return 0;
}

struct alu_case {
    const char *name;
    const mm_u8 *code;
    size_t code_len;
};

static int run_case(const struct alu_case *tc)
{
    struct mm_cpu cpu;
    size_t i;

    memset(&cpu, 0, sizeof(cpu));
    for (i = 0; i < 16u; ++i) {
        cpu.r[i] = 0u;
    }
    cpu.r[15] = 1u;
    cpu.xpsr = 0x01000000u;

    if (run_sequence(tc->code, tc->code_len, &cpu) != 0) {
        printf("%s: sequence execution failed\n", tc->name);
        return 1;
    }
    if (cpu.r[2] != 1u) {
        printf("%s: final MOVNE did not execute, r2=0x%08lx xpsr=0x%08lx\n",
               tc->name,
               (unsigned long)cpu.r[2],
               (unsigned long)cpu.xpsr);
        return 1;
    }
    return 0;
}

int main(void)
{
    static const mm_u8 add_reg_case[] = {
        0x00, 0x20, 0x47, 0x21, 0x3d, 0x29, 0x18, 0xbf, 0x00, 0x18, 0x18, 0xbf,
        0x01, 0x22,
    };
    static const mm_u8 sub_reg_case[] = {
        0x00, 0x20, 0x47, 0x21, 0x3d, 0x29, 0x18, 0xbf, 0x00, 0x1a, 0x18, 0xbf,
        0x01, 0x22,
    };
    static const mm_u8 and_reg_case[] = {
        0x00, 0x20, 0x47, 0x21, 0x3d, 0x29, 0x18, 0xbf, 0x00, 0x40, 0x18, 0xbf,
        0x01, 0x22,
    };
    static const mm_u8 eor_reg_case[] = {
        0x00, 0x20, 0x47, 0x21, 0x3d, 0x29, 0x18, 0xbf, 0x40, 0x40, 0x18, 0xbf,
        0x01, 0x22,
    };
    static const mm_u8 orr_reg_case[] = {
        0x00, 0x20, 0x47, 0x21, 0x3d, 0x29, 0x18, 0xbf, 0x00, 0x43, 0x18, 0xbf,
        0x01, 0x22,
    };
    static const mm_u8 bic_reg_case[] = {
        0xff, 0x20, 0x47, 0x21, 0x3d, 0x29, 0x18, 0xbf, 0x80, 0x43, 0x18, 0xbf,
        0x01, 0x22,
    };
    static const mm_u8 mul_reg_case[] = {
        0x00, 0x20, 0x47, 0x21, 0x3d, 0x29, 0x18, 0xbf, 0x48, 0x43, 0x18, 0xbf,
        0x01, 0x22,
    };
    static const struct alu_case cases[] = {
        { "add_reg_it_flags", add_reg_case, sizeof(add_reg_case) },
        { "sub_reg_it_flags", sub_reg_case, sizeof(sub_reg_case) },
        { "and_reg_it_flags", and_reg_case, sizeof(and_reg_case) },
        { "eor_reg_it_flags", eor_reg_case, sizeof(eor_reg_case) },
        { "orr_reg_it_flags", orr_reg_case, sizeof(orr_reg_case) },
        { "bic_reg_it_flags", bic_reg_case, sizeof(bic_reg_case) },
        { "mul_reg_it_flags", mul_reg_case, sizeof(mul_reg_case) },
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        if (run_case(&cases[i]) != 0) {
            return 1;
        }
    }

    return 0;
}
