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
#include <string.h>
#include "m33mu/fetch.h"
#include "m33mu/decode.h"
#include "m33mu/memmap.h"
#include "m33mu/scs.h"
#include "m33mu/cpu.h"
#include "m33mu/execute.h"

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

        {
            int res = (int)mm_execute_decoded(&ctx);
            if (res != MM_EXEC_OK) {
                printf("exec_longmul_test: execution failed kind=%d raw=0x%08lx pc=0x%08lx\n",
                       (int)dec.kind, (unsigned long)dec.raw,
                       (unsigned long)(cpu->r[15] & ~1u));
                return 1;
            }
        }
        if (done) {
            return 1;
        }
    }
    return 0;
}

static int test_umull(void)
{
    static const mm_u8 code[] = { 0xa0, 0xfb, 0x04, 0xab }; /* umull sl, fp, r0, r4 */
    struct mm_memmap map;
    struct mm_scs scs;
    struct mm_gdb_stub gdb;
    struct mm_cpu cpu;
    mm_u8 ram[64];
    mm_u64 prod;
    mm_u32 a;
    mm_u32 b;
    mm_u32 exp_lo;
    mm_u32 exp_hi;
    mm_u32 xpsr_before;

    a = 0x12345678u;
    b = 0x9abcdef0u;
    exp_lo = (mm_u32)((mm_u64)a * (mm_u64)b);
    exp_hi = (mm_u32)(((mm_u64)a * (mm_u64)b) >> 32);
    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));
    memset(&scs, 0, sizeof(scs));
    memset(&gdb, 0, sizeof(gdb));
    memset(&cpu, 0, sizeof(cpu));
    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[15] = 1u;
    cpu.xpsr = 0xa0000000u;
    xpsr_before = cpu.xpsr;
    cpu.r[0] = a;
    cpu.r[4] = b;
    if (run_sequence(code, sizeof(code), &cpu, &map, &scs, &gdb) != 0) {
        printf("exec_longmul_test: UMULL execution failed (case1)\n");
        return 1;
    }
    if (cpu.r[10] != exp_lo || cpu.r[11] != exp_hi) {
        printf("exec_longmul_test: UMULL result mismatch case1 lo=0x%08lx hi=0x%08lx\n",
               (unsigned long)cpu.r[10], (unsigned long)cpu.r[11]);
        return 1;
    }
    if (cpu.xpsr != xpsr_before) {
        printf("exec_longmul_test: UMULL flags changed case1\n");
        return 1;
    }

    a = 0xffffffffu;
    b = 0xffffffffu;
    prod = (mm_u64)a * (mm_u64)b;
    exp_lo = (mm_u32)prod;
    exp_hi = (mm_u32)(prod >> 32);
    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));
    memset(&scs, 0, sizeof(scs));
    memset(&gdb, 0, sizeof(gdb));
    memset(&cpu, 0, sizeof(cpu));
    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[15] = 1u;
    cpu.xpsr = 0x50000000u;
    xpsr_before = cpu.xpsr;
    cpu.r[0] = a;
    cpu.r[4] = b;
    if (run_sequence(code, sizeof(code), &cpu, &map, &scs, &gdb) != 0) {
        printf("exec_longmul_test: UMULL execution failed (case2)\n");
        return 1;
    }
    if (cpu.r[10] != exp_lo || cpu.r[11] != exp_hi) {
        printf("exec_longmul_test: UMULL result mismatch case2 lo=0x%08lx hi=0x%08lx\n",
               (unsigned long)cpu.r[10], (unsigned long)cpu.r[11]);
        return 1;
    }
    if (cpu.xpsr != xpsr_before) {
        printf("exec_longmul_test: UMULL flags changed case2\n");
        return 1;
    }

    a = 0x00000000u;
    b = 0xdeadbeefu;
    exp_lo = 0u;
    exp_hi = 0u;
    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));
    memset(&scs, 0, sizeof(scs));
    memset(&gdb, 0, sizeof(gdb));
    memset(&cpu, 0, sizeof(cpu));
    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[15] = 1u;
    cpu.xpsr = 0xf0000000u;
    xpsr_before = cpu.xpsr;
    cpu.r[0] = a;
    cpu.r[4] = b;
    if (run_sequence(code, sizeof(code), &cpu, &map, &scs, &gdb) != 0) {
        printf("exec_longmul_test: UMULL execution failed (case3)\n");
        return 1;
    }
    if (cpu.r[10] != exp_lo || cpu.r[11] != exp_hi) {
        printf("exec_longmul_test: UMULL result mismatch case3 lo=0x%08lx hi=0x%08lx\n",
               (unsigned long)cpu.r[10], (unsigned long)cpu.r[11]);
        return 1;
    }
    if (cpu.xpsr != xpsr_before) {
        printf("exec_longmul_test: UMULL flags changed case3\n");
        return 1;
    }
    return 0;
}

static int test_umlal(void)
{
    static const mm_u8 code[] = { 0xe0, 0xfb, 0x04, 0x8c }; /* umlal r8, ip, r0, r4 */
    struct mm_memmap map;
    struct mm_scs scs;
    struct mm_gdb_stub gdb;
    struct mm_cpu cpu;
    mm_u8 ram[64];
    mm_u32 a;
    mm_u32 b;
    mm_u32 acc_lo;
    mm_u32 acc_hi;
    mm_u64 exp;
    mm_u64 acc;
    mm_u32 xpsr_before;

    a = 0x13579bdfu;
    b = 0x2468ace0u;
    acc_lo = 0x11111111u;
    acc_hi = 0x22222222u;
    acc = ((mm_u64)acc_hi << 32) | acc_lo;
    exp = acc + (mm_u64)a * (mm_u64)b;
    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));
    memset(&scs, 0, sizeof(scs));
    memset(&gdb, 0, sizeof(gdb));
    memset(&cpu, 0, sizeof(cpu));
    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[15] = 1u;
    cpu.xpsr = 0xa0000000u;
    xpsr_before = cpu.xpsr;
    cpu.r[0] = a;
    cpu.r[4] = b;
    cpu.r[8] = acc_lo;
    cpu.r[12] = acc_hi;
    if (run_sequence(code, sizeof(code), &cpu, &map, &scs, &gdb) != 0) {
        printf("exec_longmul_test: UMLAL execution failed (case1)\n");
        return 1;
    }
    if (cpu.r[8] != (mm_u32)exp || cpu.r[12] != (mm_u32)(exp >> 32)) {
        printf("exec_longmul_test: UMLAL result mismatch case1 lo=0x%08lx hi=0x%08lx\n",
               (unsigned long)cpu.r[8], (unsigned long)cpu.r[12]);
        return 1;
    }
    if (cpu.xpsr != xpsr_before) {
        printf("exec_longmul_test: UMLAL flags changed case1\n");
        return 1;
    }

    a = 1u;
    b = 1u;
    acc_lo = 0xffffffffu;
    acc_hi = 0xffffffffu;
    exp = ((mm_u64)acc_hi << 32) | acc_lo;
    exp += (mm_u64)a * (mm_u64)b;
    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));
    memset(&scs, 0, sizeof(scs));
    memset(&gdb, 0, sizeof(gdb));
    memset(&cpu, 0, sizeof(cpu));
    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[15] = 1u;
    cpu.xpsr = 0x50000000u;
    xpsr_before = cpu.xpsr;
    cpu.r[0] = a;
    cpu.r[4] = b;
    cpu.r[8] = acc_lo;
    cpu.r[12] = acc_hi;
    if (run_sequence(code, sizeof(code), &cpu, &map, &scs, &gdb) != 0) {
        printf("exec_longmul_test: UMLAL execution failed (case2)\n");
        return 1;
    }
    if (cpu.r[8] != (mm_u32)exp || cpu.r[12] != (mm_u32)(exp >> 32)) {
        printf("exec_longmul_test: UMLAL result mismatch case2 lo=0x%08lx hi=0x%08lx\n",
               (unsigned long)cpu.r[8], (unsigned long)cpu.r[12]);
        return 1;
    }
    if (cpu.xpsr != xpsr_before) {
        printf("exec_longmul_test: UMLAL flags changed case2\n");
        return 1;
    }
    return 0;
}

static int test_umaal(void)
{
    static const mm_u8 code[] = { 0xe0, 0xfb, 0x65, 0xbc }; /* umaal fp, ip, r0, r5 */
    struct mm_memmap map;
    struct mm_scs scs;
    struct mm_gdb_stub gdb;
    struct mm_cpu cpu;
    mm_u8 ram[64];
    mm_u32 a;
    mm_u32 b;
    mm_u32 acc_lo;
    mm_u32 acc_hi;
    mm_u64 exp;
    mm_u32 xpsr_before;

    a = 0x0badf00du;
    b = 0x00c0ffeeu;
    acc_lo = 0x01020304u;
    acc_hi = 0x05060708u;
    exp = (mm_u64)a * (mm_u64)b;
    exp += (mm_u64)acc_lo;
    exp += (mm_u64)acc_hi;
    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));
    memset(&scs, 0, sizeof(scs));
    memset(&gdb, 0, sizeof(gdb));
    memset(&cpu, 0, sizeof(cpu));
    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[15] = 1u;
    cpu.xpsr = 0xa0000000u;
    xpsr_before = cpu.xpsr;
    cpu.r[0] = a;
    cpu.r[5] = b;
    cpu.r[11] = acc_lo;
    cpu.r[12] = acc_hi;
    if (run_sequence(code, sizeof(code), &cpu, &map, &scs, &gdb) != 0) {
        printf("exec_longmul_test: UMAAL execution failed (case1)\n");
        return 1;
    }
    if (cpu.r[11] != (mm_u32)exp || cpu.r[12] != (mm_u32)(exp >> 32)) {
        printf("exec_longmul_test: UMAAL result mismatch case1 lo=0x%08lx hi=0x%08lx\n",
               (unsigned long)cpu.r[11], (unsigned long)cpu.r[12]);
        return 1;
    }
    if (cpu.xpsr != xpsr_before) {
        printf("exec_longmul_test: UMAAL flags changed case1\n");
        return 1;
    }

    a = 0xffffffffu;
    b = 0xffffffffu;
    acc_lo = 0xffffffffu;
    acc_hi = 0u;
    exp = (mm_u64)a * (mm_u64)b;
    exp += (mm_u64)acc_lo;
    exp += (mm_u64)acc_hi;
    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));
    memset(&scs, 0, sizeof(scs));
    memset(&gdb, 0, sizeof(gdb));
    memset(&cpu, 0, sizeof(cpu));
    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[15] = 1u;
    cpu.xpsr = 0x50000000u;
    xpsr_before = cpu.xpsr;
    cpu.r[0] = a;
    cpu.r[5] = b;
    cpu.r[11] = acc_lo;
    cpu.r[12] = acc_hi;
    if (run_sequence(code, sizeof(code), &cpu, &map, &scs, &gdb) != 0) {
        printf("exec_longmul_test: UMAAL execution failed (case2)\n");
        return 1;
    }
    if (cpu.r[11] != (mm_u32)exp || cpu.r[12] != (mm_u32)(exp >> 32)) {
        printf("exec_longmul_test: UMAAL result mismatch case2 lo=0x%08lx hi=0x%08lx\n",
               (unsigned long)cpu.r[11], (unsigned long)cpu.r[12]);
        return 1;
    }
    if (cpu.xpsr != xpsr_before) {
        printf("exec_longmul_test: UMAAL flags changed case2\n");
        return 1;
    }
    return 0;
}

static void umull_ref(mm_u32 a, mm_u32 b, mm_u32 *lo, mm_u32 *hi)
{
    mm_u64 prod = (mm_u64)a * (mm_u64)b;
    if (lo) *lo = (mm_u32)prod;
    if (hi) *hi = (mm_u32)(prod >> 32);
}

static void umaal_ref(mm_u32 *lo, mm_u32 *hi, mm_u32 rn, mm_u32 rm)
{
    mm_u64 acc = (mm_u64)rn * (mm_u64)rm;
    acc += (mm_u64)(*lo);
    acc += (mm_u64)(*hi);
    *lo = (mm_u32)acc;
    *hi = (mm_u32)(acc >> 32);
}

static int test_umaal_chain(void)
{
    static const mm_u8 code[] = {
        0xa0, 0xfb, 0x04, 0xab, /* umull sl, fp, r0, r4 */
        0xa1, 0xfb, 0x04, 0xc7, /* umull ip, r7, r1, r4 */
        0xe0, 0xfb, 0x65, 0xbc, /* umaal fp, ip, r0, r5 */
        0xa2, 0xfb, 0x04, 0x89, /* umull r8, r9, r2, r4 */
        0xe1, 0xfb, 0x65, 0xc8, /* umaal ip, r8, r1, r5 */
        0xe0, 0xfb, 0x66, 0xc7, /* umaal ip, r7, r0, r6 */
        0xe3, 0xfb, 0x64, 0x89  /* umaal r8, r9, r3, r4 */
    };
    struct mm_memmap map;
    struct mm_scs scs;
    struct mm_gdb_stub gdb;
    struct mm_cpu cpu;
    mm_u8 ram[64];
    mm_u32 r0 = 0x8c1844f2u;
    mm_u32 r1 = 0x1aa0461cu;
    mm_u32 r2 = 0xc0b50149u;
    mm_u32 r3 = 0xc8f5a643u;
    mm_u32 r4 = 0xf10eacaeu;
    mm_u32 r5 = 0x2c346c45u;
    mm_u32 r6 = 0xe722e62eu;
    mm_u32 sl = 0;
    mm_u32 fp = 0;
    mm_u32 ip = 0;
    mm_u32 r7 = 0;
    mm_u32 r8 = 0;
    mm_u32 r9 = 0;

    umull_ref(r0, r4, &sl, &fp);
    umull_ref(r1, r4, &ip, &r7);
    umaal_ref(&fp, &ip, r0, r5);
    umull_ref(r2, r4, &r8, &r9);
    umaal_ref(&ip, &r8, r1, r5);
    umaal_ref(&ip, &r7, r0, r6);
    umaal_ref(&r8, &r9, r3, r4);

    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));
    memset(&scs, 0, sizeof(scs));
    memset(&gdb, 0, sizeof(gdb));
    memset(&cpu, 0, sizeof(cpu));
    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[15] = 1u;
    cpu.r[0] = r0;
    cpu.r[1] = r1;
    cpu.r[2] = r2;
    cpu.r[3] = r3;
    cpu.r[4] = r4;
    cpu.r[5] = r5;
    cpu.r[6] = r6;

    if (run_sequence(code, sizeof(code), &cpu, &map, &scs, &gdb) != 0) {
        printf("exec_longmul_test: UMAAL chain execution failed\n");
        return 1;
    }
    if (cpu.r[10] != sl || cpu.r[11] != fp || cpu.r[12] != ip ||
        cpu.r[7] != r7 || cpu.r[8] != r8 || cpu.r[9] != r9) {
        printf("exec_longmul_test: UMAAL chain regs mismatch\n");
        printf(" got sl=0x%08lx fp=0x%08lx ip=0x%08lx r7=0x%08lx r8=0x%08lx r9=0x%08lx\n",
               (unsigned long)cpu.r[10], (unsigned long)cpu.r[11], (unsigned long)cpu.r[12],
               (unsigned long)cpu.r[7], (unsigned long)cpu.r[8], (unsigned long)cpu.r[9]);
        printf(" exp sl=0x%08lx fp=0x%08lx ip=0x%08lx r7=0x%08lx r8=0x%08lx r9=0x%08lx\n",
               (unsigned long)sl, (unsigned long)fp, (unsigned long)ip,
               (unsigned long)r7, (unsigned long)r8, (unsigned long)r9);
        return 1;
    }
    return 0;
}

static int test_smull(void)
{
    static const mm_u8 code[] = { 0x80, 0xfb, 0x04, 0xab }; /* smull sl, fp, r0, r4 */
    struct mm_memmap map;
    struct mm_scs scs;
    struct mm_gdb_stub gdb;
    struct mm_cpu cpu;
    mm_u8 ram[64];
    mm_i64 prod;
    mm_u32 exp_lo;
    mm_u32 exp_hi;
    mm_u32 xpsr_before;

    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));
    memset(&scs, 0, sizeof(scs));
    memset(&gdb, 0, sizeof(gdb));
    memset(&cpu, 0, sizeof(cpu));
    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[15] = 1u;
    cpu.xpsr = 0xa0000000u;
    xpsr_before = cpu.xpsr;
    cpu.r[0] = 0x80000000u;
    cpu.r[4] = 0x00000002u;

    if (run_sequence(code, sizeof(code), &cpu, &map, &scs, &gdb) != 0) {
        printf("exec_longmul_test: SMULL execution failed (case1)\n");
        return 1;
    }
    prod = (mm_i64)(mm_i32)cpu.r[0] * (mm_i64)(mm_i32)cpu.r[4];
    exp_lo = (mm_u32)prod;
    exp_hi = (mm_u32)(((mm_u64)prod) >> 32);
    if (cpu.r[10] != exp_lo || cpu.r[11] != exp_hi) {
        printf("exec_longmul_test: SMULL result mismatch case1 lo=0x%08lx hi=0x%08lx\n",
               (unsigned long)cpu.r[10], (unsigned long)cpu.r[11]);
        return 1;
    }
    if (cpu.xpsr != xpsr_before) {
        printf("exec_longmul_test: SMULL flags changed case1\n");
        return 1;
    }

    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));
    memset(&scs, 0, sizeof(scs));
    memset(&gdb, 0, sizeof(gdb));
    memset(&cpu, 0, sizeof(cpu));
    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[15] = 1u;
    cpu.xpsr = 0x50000000u;
    xpsr_before = cpu.xpsr;
    cpu.r[0] = 0xffffffffu; /* -1 */
    cpu.r[4] = 0xffffffffu; /* -1 */

    if (run_sequence(code, sizeof(code), &cpu, &map, &scs, &gdb) != 0) {
        printf("exec_longmul_test: SMULL execution failed (case2)\n");
        return 1;
    }
    prod = (mm_i64)(mm_i32)cpu.r[0] * (mm_i64)(mm_i32)cpu.r[4];
    exp_lo = (mm_u32)prod;
    exp_hi = (mm_u32)(((mm_u64)prod) >> 32);
    if (cpu.r[10] != exp_lo || cpu.r[11] != exp_hi) {
        printf("exec_longmul_test: SMULL result mismatch case2 lo=0x%08lx hi=0x%08lx\n",
               (unsigned long)cpu.r[10], (unsigned long)cpu.r[11]);
        return 1;
    }
    if (cpu.xpsr != xpsr_before) {
        printf("exec_longmul_test: SMULL flags changed case2\n");
        return 1;
    }
    return 0;
}

static int test_smlal(void)
{
    static const mm_u8 code[] = { 0xc0, 0xfb, 0x04, 0x8c }; /* smlal r8, ip, r0, r4 */
    struct mm_memmap map;
    struct mm_scs scs;
    struct mm_gdb_stub gdb;
    struct mm_cpu cpu;
    mm_u8 ram[64];
    mm_i64 acc;
    mm_i64 prod;
    mm_i64 exp;
    mm_u32 xpsr_before;

    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));
    memset(&scs, 0, sizeof(scs));
    memset(&gdb, 0, sizeof(gdb));
    memset(&cpu, 0, sizeof(cpu));
    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[15] = 1u;
    cpu.xpsr = 0xa0000000u;
    xpsr_before = cpu.xpsr;
    cpu.r[0] = 0xffffffffu; /* -1 */
    cpu.r[4] = 0x00000002u; /* 2 */
    cpu.r[8] = 0x00000000u;
    cpu.r[12] = 0x00000000u;

    if (run_sequence(code, sizeof(code), &cpu, &map, &scs, &gdb) != 0) {
        printf("exec_longmul_test: SMLAL execution failed (case1)\n");
        return 1;
    }
    acc = (mm_i64)(((mm_u64)cpu.r[12] << 32) | cpu.r[8]);
    prod = (mm_i64)(mm_i32)cpu.r[0] * (mm_i64)(mm_i32)cpu.r[4];
    exp = prod;
    if (acc != exp) {
        printf("exec_longmul_test: SMLAL result mismatch case1 lo=0x%08lx hi=0x%08lx\n",
               (unsigned long)cpu.r[8], (unsigned long)cpu.r[12]);
        return 1;
    }
    if (cpu.xpsr != xpsr_before) {
        printf("exec_longmul_test: SMLAL flags changed case1\n");
        return 1;
    }

    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));
    memset(&scs, 0, sizeof(scs));
    memset(&gdb, 0, sizeof(gdb));
    memset(&cpu, 0, sizeof(cpu));
    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[15] = 1u;
    cpu.xpsr = 0x50000000u;
    xpsr_before = cpu.xpsr;
    cpu.r[0] = 0x80000000u; /* -2147483648 */
    cpu.r[4] = 0x00000002u; /* 2 */
    cpu.r[8] = 0xffffffffu;
    cpu.r[12] = 0xffffffffu; /* -1 as accumulator */

    if (run_sequence(code, sizeof(code), &cpu, &map, &scs, &gdb) != 0) {
        printf("exec_longmul_test: SMLAL execution failed (case2)\n");
        return 1;
    }
    acc = (mm_i64)(((mm_u64)cpu.r[12] << 32) | cpu.r[8]);
    prod = (mm_i64)(mm_i32)cpu.r[0] * (mm_i64)(mm_i32)cpu.r[4];
    exp = (mm_i64)-1 + prod;
    if (acc != exp) {
        printf("exec_longmul_test: SMLAL result mismatch case2 lo=0x%08lx hi=0x%08lx\n",
               (unsigned long)cpu.r[8], (unsigned long)cpu.r[12]);
        return 1;
    }
    if (cpu.xpsr != xpsr_before) {
        printf("exec_longmul_test: SMLAL flags changed case2\n");
        return 1;
    }
    return 0;
}

int main(void)
{
    if (test_umull() != 0) return 1;
    if (test_umlal() != 0) return 1;
    if (test_umaal() != 0) return 1;
    if (test_umaal_chain() != 0) return 1;
    if (test_smull() != 0) return 1;
    if (test_smlal() != 0) return 1;
    return 0;
}
