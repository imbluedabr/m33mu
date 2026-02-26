/* m33mu -- an ARMv8-M Emulator
 *
 * Copyright (C) 2025  Daniele Lacamera <root@danielinux.net>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Minimal repro for ECC compare sequence extracted from wolfcrypt trace.
 */

#include <stdio.h>
#include <string.h>
#include "m33mu/fetch.h"
#include "m33mu/decode.h"
#include "m33mu/memmap.h"
#include "m33mu/scs.h"
#include "m33mu/cpu.h"
#include "m33mu/execute.h"
#include "m33mu/exec_helpers.h"

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

static void setup_ram_map(struct mm_memmap *map, mm_u8 *ram, size_t ram_len)
{
    struct mmio_region regions[1];
    struct mm_target_cfg cfg;

    memset(regions, 0, sizeof(regions));
    mm_memmap_init(map, regions, 1u);

    memset(&cfg, 0, sizeof(cfg));
    cfg.ram_base_s = 0x20000000u;
    cfg.ram_size_s = (mm_u32)ram_len;
    cfg.ram_base_ns = 0x20000000u;
    cfg.ram_size_ns = (mm_u32)ram_len;

    (void)mm_memmap_configure_ram(map, &cfg, ram, MM_FALSE);
}

static void write_u32(mm_u8 *ram, size_t ram_len, mm_u32 addr, mm_u32 value)
{
    size_t off = (size_t)(addr - 0x20000000u);
    if (off + 4u > ram_len) {
        return;
    }
    ram[off + 0] = (mm_u8)(value & 0xffu);
    ram[off + 1] = (mm_u8)((value >> 8) & 0xffu);
    ram[off + 2] = (mm_u8)((value >> 16) & 0xffu);
    ram[off + 3] = (mm_u8)((value >> 24) & 0xffu);
}

static int run_sequence(const mm_u8 *code, size_t code_len,
                        struct mm_cpu *cpu, struct mm_memmap *map,
                        struct mm_scs *scs, struct mm_gdb_stub *gdb)
{
    struct mm_mem mem;
    mm_u8 it_pattern = 0;
    mm_u8 it_remaining = 0;
    mm_u8 it_cond = 0;
    mm_bool done = MM_FALSE;

    mem.buffer = code;
    mem.length = code_len;
    mem.base = 0;

    while ((cpu->r[15] & ~1u) < code_len) {
        struct mm_fetch_result fetch = mm_fetch_t32(cpu, &mem);
        struct mm_decoded dec;
        struct mm_execute_ctx ctx;

        if (fetch.fault) {
            return 1;
        }
        dec = mm_decode_t32(&fetch);

        if (!mm_it_should_execute(cpu, &dec, &it_pattern, &it_remaining, &it_cond) && dec.kind != MM_OP_IT) {
            mm_it_advance(cpu, &dec, &it_pattern, &it_remaining, &it_cond);
            continue;
        }

        memset(&ctx, 0, sizeof(ctx));
        ctx.cpu = cpu;
        ctx.map = map;
        ctx.scs = scs;
        ctx.gdb = gdb;
        ctx.fetch = &fetch;
        ctx.dec = &dec;
        ctx.opt_dump = MM_FALSE;
        ctx.opt_gdb = MM_FALSE;
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
        mm_it_advance(cpu, &dec, &it_pattern, &it_remaining, &it_cond);
    }
    return 0;
}

static int test_sp_256_cmp_trace_window(void)
{
    static const mm_u8 code[] = {
        0x38, 0xbf, /* it cc */
        0x1a, 0x46, /* movcc r2, r3 */
        0x18, 0xbf, /* it ne */
        0x3b, 0x46, /* movne r3, r7 */
        0xc4, 0x68, /* ldr r4, [r0, #12] */
        0xcd, 0x68, /* ldr r5, [r1, #12] */
        0x04, 0xea, 0x03, 0x04, /* and.w r4, r4, r3 */
        0x05, 0xea, 0x03, 0x05, /* and.w r5, r5, r3 */
        0x64, 0x1b, /* subs r4, r4, r5 */
        0x88, 0xbf, /* it hi */
        0x42, 0x46, /* movhi r2, r8 */
        0x38, 0xbf, /* it cc */
        0x1a, 0x46, /* movcc r2, r3 */
        0x18, 0xbf, /* it ne */
        0x3b, 0x46, /* movne r3, r7 */
        0x84, 0x68, /* ldr r4, [r0, #8] */
        0x8d, 0x68, /* ldr r5, [r1, #8] */
        0x04, 0xea, 0x03, 0x04, /* and.w r4, r4, r3 */
        0x05, 0xea, 0x03, 0x05, /* and.w r5, r5, r3 */
        0x64, 0x1b, /* subs r4, r4, r5 */
        0x88, 0xbf, /* it hi */
        0x42, 0x46, /* movhi r2, r8 */
        0x38, 0xbf, /* it cc */
        0x1a, 0x46, /* movcc r2, r3 */
        0x18, 0xbf, /* it ne */
        0x3b, 0x46, /* movne r3, r7 */
        0x44, 0x68, /* ldr r4, [r0, #4] */
        0x4d, 0x68, /* ldr r5, [r1, #4] */
        0x04, 0xea, 0x03, 0x04, /* and.w r4, r4, r3 */
        0x05, 0xea, 0x03, 0x05  /* and.w r5, r5, r3 */
    };
    struct mm_memmap map;
    struct mm_scs scs;
    struct mm_gdb_stub gdb;
    struct mm_cpu cpu;
    mm_u8 ram[0x4000];
    mm_u32 n, z, c, v;
    mm_u32 r0_base = 0x20001000u;
    mm_u32 r1_base = 0x20002000u;

    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));
    memset(&scs, 0, sizeof(scs));
    memset(&gdb, 0, sizeof(gdb));
    memset(&cpu, 0, sizeof(cpu));

    /* Trace-derived limb values from the failing wolfcrypt run. */
    write_u32(ram, sizeof(ram), r0_base + 0u, 0xa4a5a4b3u);
    write_u32(ram, sizeof(ram), r0_base + 4u, 0x931565e8u);
    write_u32(ram, sizeof(ram), r0_base + 8u, 0x1e4ff569u);
    write_u32(ram, sizeof(ram), r0_base + 12u, 0xb363bc25u);

    write_u32(ram, sizeof(ram), r1_base + 0u, 0x27d2520bu);
    write_u32(ram, sizeof(ram), r1_base + 4u, 0x3bce3c3eu);
    write_u32(ram, sizeof(ram), r1_base + 8u, 0xcc53b0f6u);
    write_u32(ram, sizeof(ram), r1_base + 12u, 0x651d06b0u);

    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[15] = 1u;
    cpu.r[0] = r0_base;
    cpu.r[1] = r1_base;
    cpu.r[2] = 1u;
    cpu.r[3] = 0u;
    cpu.r[4] = 0u;
    cpu.r[5] = 0u;
    cpu.r[6] = 0x3009f8f4u;
    cpu.r[7] = 0u;
    cpu.r[8] = 1u;
    cpu.r[9] = 0x3009f6ccu;
    cpu.r[10] = 0x3009f6f0u;
    cpu.r[11] = 0x00000020u;
    cpu.r[12] = 0xe7171bd1u;
    cpu.xpsr = 0x61000200u; /* N=0 Z=1 C=1 V=0 */

    if (run_sequence(code, sizeof(code), &cpu, &map, &scs, &gdb) != 0) {
        printf("exec_ecc_cmp_repro_test: execution failed\n");
        return 1;
    }

    if (cpu.r[2] != 1u || cpu.r[3] != 0u) {
        printf("exec_ecc_cmp_repro_test: r2/r3 mismatch r2=0x%08lx r3=0x%08lx\n",
               (unsigned long)cpu.r[2], (unsigned long)cpu.r[3]);
        return 1;
    }
    if (cpu.r[4] != 0u || cpu.r[5] != 0u) {
        printf("exec_ecc_cmp_repro_test: r4/r5 mismatch r4=0x%08lx r5=0x%08lx\n",
               (unsigned long)cpu.r[4], (unsigned long)cpu.r[5]);
        return 1;
    }

    n = (cpu.xpsr >> 31) & 1u;
    z = (cpu.xpsr >> 30) & 1u;
    c = (cpu.xpsr >> 29) & 1u;
    v = (cpu.xpsr >> 28) & 1u;
    if (n != 0u || z != 1u || c != 1u || v != 0u) {
        printf("exec_ecc_cmp_repro_test: flags mismatch N=%lu Z=%lu C=%lu V=%lu\n",
               (unsigned long)n, (unsigned long)z, (unsigned long)c, (unsigned long)v);
        return 1;
    }

    return 0;
}

int main(void)
{
    if (test_sp_256_cmp_trace_window() != 0) {
        return 1;
    }
    printf("exec_ecc_cmp_repro_test: ok\n");
    return 0;
}
