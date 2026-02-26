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

static int decode_from_bytes(const mm_u8 *bytes, size_t len_bytes, struct mm_decoded *out_dec, size_t pc)
{
    struct mm_mem mem;
    struct mm_cpu cpu;
    struct mm_fetch_result fetch;
    size_t i;

    mem.buffer = bytes;
    mem.length = len_bytes;
    mem.base = 0;
    for (i = 0; i < 16; ++i) {
        cpu.r[i] = 0;
    }
    cpu.r[15] = ((mm_u32)pc) | 1u;
    cpu.xpsr = 0;

    fetch = mm_fetch_t32(&cpu, &mem);
    if (fetch.fault) {
        return 1;
    }
    *out_dec = mm_decode_t32(&fetch);
    return 0;
}

static int expect_decode(const mm_u8 *code, size_t code_len, size_t pc,
                         enum mm_op_kind kind, mm_u8 rd, mm_u8 rn, mm_u8 rm,
                         mm_u8 len, mm_u32 raw)
{
    struct mm_decoded dec;

    if (decode_from_bytes(code, code_len, &dec, pc) != 0) {
        printf("exec_ecc_alu_chain_test: decode failed at pc=0x%08lx\n", (unsigned long)pc);
        return 1;
    }
    if (dec.kind != kind || dec.rd != rd || dec.rn != rn || dec.rm != rm || dec.len != len || dec.raw != raw) {
        printf("exec_ecc_alu_chain_test: decode mismatch pc=0x%08lx kind=%d rd=%u rn=%u rm=%u len=%u raw=0x%08lx\n",
               (unsigned long)pc, (int)dec.kind, (unsigned)dec.rd, (unsigned)dec.rn,
               (unsigned)dec.rm, (unsigned)dec.len, (unsigned long)dec.raw);
        return 1;
    }
    return 0;
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

static int test_adc_sbc_chain(void)
{
    static const mm_u8 code[] = {
        0x56, 0xf1, 0x00, 0x06, /* adcs.w r6, r6, #0 */
        0x77, 0xf1, 0x00, 0x07, /* sbcs.w r7, r7, #0 */
        0x6c, 0xf1, 0x00, 0x0c, /* sbc.w  ip, ip, #0 */
        0xcc, 0xf1, 0x00, 0x0c  /* rsb    ip, ip, #0 */
    };
    struct mm_memmap map;
    struct mm_scs scs;
    struct mm_gdb_stub gdb;
    struct mm_cpu cpu;
    mm_u8 ram[64];
    mm_u32 n, z, c, v;

    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));
    memset(&scs, 0, sizeof(scs));
    memset(&gdb, 0, sizeof(gdb));
    memset(&cpu, 0, sizeof(cpu));

    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[15] = 1u;
    cpu.r[6] = 0u;
    cpu.r[7] = 0u;
    cpu.r[12] = 0u;
    cpu.xpsr = (1u << 29);

    if (run_sequence(code, sizeof(code), &cpu, &map, &scs, &gdb) != 0) {
        printf("exec_ecc_alu_chain_test: execution failed\n");
        return 1;
    }

    if (cpu.r[6] != 1u) {
        printf("exec_ecc_alu_chain_test: r6 mismatch got=0x%08lx\n", (unsigned long)cpu.r[6]);
        return 1;
    }
    if (cpu.r[7] != 0xffffffffu) {
        printf("exec_ecc_alu_chain_test: r7 mismatch got=0x%08lx\n", (unsigned long)cpu.r[7]);
        return 1;
    }
    if (cpu.r[12] != 1u) {
        printf("exec_ecc_alu_chain_test: r12 mismatch got=0x%08lx\n", (unsigned long)cpu.r[12]);
        return 1;
    }

    n = (cpu.xpsr >> 31) & 1u;
    z = (cpu.xpsr >> 30) & 1u;
    c = (cpu.xpsr >> 29) & 1u;
    v = (cpu.xpsr >> 28) & 1u;
    if (n != 1u || z != 0u || c != 0u || v != 0u) {
        printf("exec_ecc_alu_chain_test: flags mismatch N=%lu Z=%lu C=%lu V=%lu\n",
               (unsigned long)n, (unsigned long)z, (unsigned long)c, (unsigned long)v);
        return 1;
    }
    return 0;
}

static int test_adc_sbc_reg_and_no_flag(void)
{
    static const mm_u8 code_reg[] = {
        0x48, 0x41, /* adcs r0, r1 */
        0x9a, 0x41, /* sbcs r2, r3 */
        0x6c, 0x41, /* adcs r4, r5 */
        0xbe, 0x41  /* sbcs r6, r7 */
    };
    static const mm_u8 code_wide[] = {
        0x59, 0xeb, 0x0a, 0x08, /* adcs.w r8, r9, sl */
        0x7c, 0xeb, 0x00, 0x0b, /* sbcs.w fp, ip, r0 */
        0x42, 0xeb, 0x03, 0x01, /* adc.w r1, r2, r3 */
        0x65, 0xeb, 0x06, 0x04  /* sbc.w r4, r5, r6 */
    };
    struct mm_memmap map;
    struct mm_scs scs;
    struct mm_gdb_stub gdb;
    struct mm_cpu cpu;
    mm_u8 ram[64];
    mm_u32 n, z, c, v;

    if (expect_decode(code_reg, sizeof(code_reg), 0u,
                      MM_OP_ADCS_REG, 0u, 0u, 1u, 2u, 0x00004148u) != 0) {
        return 1;
    }
    if (expect_decode(code_reg, sizeof(code_reg), 2u,
                      MM_OP_SBCS_REG, 2u, 2u, 3u, 2u, 0x0000419au) != 0) {
        return 1;
    }
    if (expect_decode(code_reg, sizeof(code_reg), 4u,
                      MM_OP_ADCS_REG, 4u, 4u, 5u, 2u, 0x0000416cu) != 0) {
        return 1;
    }
    if (expect_decode(code_reg, sizeof(code_reg), 6u,
                      MM_OP_SBCS_REG, 6u, 6u, 7u, 2u, 0x000041beu) != 0) {
        return 1;
    }

    if (expect_decode(code_wide, sizeof(code_wide), 0u,
                      MM_OP_ADCS_REG, 8u, 9u, 10u, 4u, 0xeb59080au) != 0) {
        return 1;
    }
    if (expect_decode(code_wide, sizeof(code_wide), 4u,
                      MM_OP_SBCS_REG, 11u, 12u, 0u, 4u, 0xeb7c0b00u) != 0) {
        return 1;
    }
    if (expect_decode(code_wide, sizeof(code_wide), 8u,
                      MM_OP_ADCS_REG, 1u, 2u, 3u, 4u, 0xeb420103u) != 0) {
        return 1;
    }
    if (expect_decode(code_wide, sizeof(code_wide), 12u,
                      MM_OP_SBCS_REG, 4u, 5u, 6u, 4u, 0xeb650406u) != 0) {
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
    cpu.xpsr = (1u << 29); /* C=1 */

    cpu.r[0] = 0xffffffffu;
    cpu.r[1] = 0u;
    cpu.r[2] = 0u;
    cpu.r[3] = 1u;
    cpu.r[4] = 0u;
    cpu.r[5] = 0u;
    cpu.r[6] = 0u;
    cpu.r[7] = 0u;

    if (run_sequence(code_reg, sizeof(code_reg), &cpu, &map, &scs, &gdb) != 0) {
        printf("exec_ecc_alu_chain_test: reg execution failed\n");
        return 1;
    }

    if (cpu.r[0] != 0u) {
        printf("exec_ecc_alu_chain_test: reg r0 mismatch got=0x%08lx\n", (unsigned long)cpu.r[0]);
        return 1;
    }
    if (cpu.r[2] != 0xffffffffu) {
        printf("exec_ecc_alu_chain_test: reg r2 mismatch got=0x%08lx\n", (unsigned long)cpu.r[2]);
        return 1;
    }
    if (cpu.r[4] != 0u) {
        printf("exec_ecc_alu_chain_test: reg r4 mismatch got=0x%08lx\n", (unsigned long)cpu.r[4]);
        return 1;
    }
    if (cpu.r[6] != 0xffffffffu) {
        printf("exec_ecc_alu_chain_test: reg r6 mismatch got=0x%08lx\n", (unsigned long)cpu.r[6]);
        return 1;
    }

    n = (cpu.xpsr >> 31) & 1u;
    z = (cpu.xpsr >> 30) & 1u;
    c = (cpu.xpsr >> 29) & 1u;
    v = (cpu.xpsr >> 28) & 1u;
    if (n != 1u || z != 0u || c != 0u || v != 0u) {
        printf("exec_ecc_alu_chain_test: reg flags mismatch N=%lu Z=%lu C=%lu V=%lu\n",
               (unsigned long)n, (unsigned long)z, (unsigned long)c, (unsigned long)v);
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
    cpu.xpsr = (1u << 29); /* C=1 */

    cpu.r[0] = 1u;
    cpu.r[1] = 0u;
    cpu.r[2] = 1u;
    cpu.r[3] = 2u;
    cpu.r[4] = 0u;
    cpu.r[5] = 5u;
    cpu.r[6] = 3u;
    cpu.r[8] = 0u;
    cpu.r[9] = 0xffffffffu;
    cpu.r[10] = 0u;
    cpu.r[11] = 0u;
    cpu.r[12] = 0u;

    if (run_sequence(code_wide, sizeof(code_wide), &cpu, &map, &scs, &gdb) != 0) {
        printf("exec_ecc_alu_chain_test: wide/no-flag execution failed\n");
        return 1;
    }
    if (cpu.r[8] != 0u) {
        printf("exec_ecc_alu_chain_test: wide r8 mismatch got=0x%08lx\n", (unsigned long)cpu.r[8]);
        return 1;
    }
    if (cpu.r[11] != 0xffffffffu) {
        printf("exec_ecc_alu_chain_test: wide r11 mismatch got=0x%08lx\n", (unsigned long)cpu.r[11]);
        return 1;
    }
    if (cpu.r[1] != 3u) {
        printf("exec_ecc_alu_chain_test: wide r1 mismatch got=0x%08lx\n", (unsigned long)cpu.r[1]);
        return 1;
    }
    if (cpu.r[4] != 1u) {
        printf("exec_ecc_alu_chain_test: wide r4 mismatch got=0x%08lx\n", (unsigned long)cpu.r[4]);
        return 1;
    }

    n = (cpu.xpsr >> 31) & 1u;
    z = (cpu.xpsr >> 30) & 1u;
    c = (cpu.xpsr >> 29) & 1u;
    v = (cpu.xpsr >> 28) & 1u;
    if (n != 1u || z != 0u || c != 0u || v != 0u) {
        printf("exec_ecc_alu_chain_test: wide/no-flag flags mismatch N=%lu Z=%lu C=%lu V=%lu\n",
               (unsigned long)n, (unsigned long)z, (unsigned long)c, (unsigned long)v);
        return 1;
    }

    return 0;
}

static int test_adc_sbc_no_flag_preserve_xpsr(void)
{
    static const mm_u8 code[] = {
        0x42, 0xeb, 0x03, 0x01, /* adc.w r1, r2, r3 */
        0x65, 0xeb, 0x06, 0x04  /* sbc.w r4, r5, r6 */
    };
    struct mm_memmap map;
    struct mm_scs scs;
    struct mm_gdb_stub gdb;
    struct mm_cpu cpu;
    mm_u8 ram[64];
    mm_u32 xpsr_before;

    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));
    memset(&scs, 0, sizeof(scs));
    memset(&gdb, 0, sizeof(gdb));
    memset(&cpu, 0, sizeof(cpu));

    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[15] = 1u;
    cpu.xpsr = 0xb0000000u; /* N=1, Z=0, C=1, V=0 */
    xpsr_before = cpu.xpsr;

    cpu.r[2] = 0xffffffffu;
    cpu.r[3] = 0u;
    cpu.r[5] = 1u;
    cpu.r[6] = 0u;

    if (run_sequence(code, sizeof(code), &cpu, &map, &scs, &gdb) != 0) {
        printf("exec_ecc_alu_chain_test: no-flag preserve execution failed\n");
        return 1;
    }
    if (cpu.xpsr != xpsr_before) {
        printf("exec_ecc_alu_chain_test: no-flag preserve xpsr changed 0x%08lx -> 0x%08lx\n",
               (unsigned long)xpsr_before, (unsigned long)cpu.xpsr);
        return 1;
    }
    return 0;
}

static int test_adc_sbc_carry_propagation(void)
{
    static const mm_u8 code[] = {
        0x50, 0xf1, 0x00, 0x00, /* adcs.w r0, r0, #0 */
        0x51, 0xf1, 0x01, 0x01, /* adcs.w r1, r1, #1 */
        0x72, 0xf1, 0x00, 0x02, /* sbcs.w r2, r2, #0 */
        0x73, 0xf1, 0x01, 0x03, /* sbcs.w r3, r3, #1 */
        0x54, 0xf1, 0x00, 0x04, /* adcs.w r4, r4, #0 */
        0x75, 0xf1, 0x00, 0x05, /* sbcs.w r5, r5, #0 */
        0x56, 0xf1, 0x00, 0x06, /* adcs.w r6, r6, #0 */
        0x77, 0xf1, 0x00, 0x07  /* sbcs.w r7, r7, #0 */
    };
    struct mm_memmap map;
    struct mm_scs scs;
    struct mm_gdb_stub gdb;
    struct mm_cpu cpu;
    mm_u8 ram[64];
    mm_u32 c, z, n;

    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));
    memset(&scs, 0, sizeof(scs));
    memset(&gdb, 0, sizeof(gdb));
    memset(&cpu, 0, sizeof(cpu));

    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[15] = 1u;
    cpu.xpsr = (1u << 29); /* C=1 */

    cpu.r[0] = 0xffffffffu;
    cpu.r[1] = 0xffffffffu;
    cpu.r[2] = 0u;
    cpu.r[3] = 0u;
    cpu.r[4] = 0xffffffffu;
    cpu.r[5] = 0u;
    cpu.r[6] = 0xffffffffu;
    cpu.r[7] = 0u;

    if (run_sequence(code, sizeof(code), &cpu, &map, &scs, &gdb) != 0) {
        printf("exec_ecc_alu_chain_test: carry propagation execution failed\n");
        return 1;
    }

    if (cpu.r[0] != 0x00000000u) {
        printf("exec_ecc_alu_chain_test: carry r0 got=0x%08lx\n", (unsigned long)cpu.r[0]);
        return 1;
    }
    if (cpu.r[1] != 0x00000001u) {
        printf("exec_ecc_alu_chain_test: carry r1 got=0x%08lx\n", (unsigned long)cpu.r[1]);
        return 1;
    }
    if (cpu.r[2] != 0x00000000u) {
        printf("exec_ecc_alu_chain_test: carry r2 got=0x%08lx\n", (unsigned long)cpu.r[2]);
        return 1;
    }
    if (cpu.r[3] != 0xffffffffu) {
        printf("exec_ecc_alu_chain_test: carry r3 got=0x%08lx\n", (unsigned long)cpu.r[3]);
        return 1;
    }
    if (cpu.r[4] != 0xffffffffu) {
        printf("exec_ecc_alu_chain_test: carry r4 got=0x%08lx\n", (unsigned long)cpu.r[4]);
        return 1;
    }
    if (cpu.r[5] != 0xffffffffu) {
        printf("exec_ecc_alu_chain_test: carry r5 got=0x%08lx\n", (unsigned long)cpu.r[5]);
        return 1;
    }
    if (cpu.r[6] != 0xffffffffu) {
        printf("exec_ecc_alu_chain_test: carry r6 got=0x%08lx\n", (unsigned long)cpu.r[6]);
        return 1;
    }
    if (cpu.r[7] != 0xffffffffu) {
        printf("exec_ecc_alu_chain_test: carry r7 got=0x%08lx\n", (unsigned long)cpu.r[7]);
        return 1;
    }

    c = (cpu.xpsr >> 29) & 1u;
    z = (cpu.xpsr >> 30) & 1u;
    n = (cpu.xpsr >> 31) & 1u;
    if (c != 0u || z != 0u || n != 1u) {
        printf("exec_ecc_alu_chain_test: carry propagation flags N=%lu Z=%lu C=%lu\n",
               (unsigned long)n, (unsigned long)z, (unsigned long)c);
        return 1;
    }
    return 0;
}

static int test_it_blocks(void)
{
    static const mm_u8 code[] = {
        0x00, 0x28, /* cmp r0, #0 */
        0x02, 0xbf, /* ittt eq */
        0x01, 0x31, /* adds r1, #1 */
        0x01, 0x3a, /* subs r2, #1 */
        0x01, 0x33, /* adds r3, #1 */
        0x01, 0x28, /* cmp r0, #1 */
        0x1e, 0xbf, /* ittt ne */
        0x01, 0x34, /* adds r4, #1 */
        0x01, 0x3d, /* subs r5, #1 */
        0x01, 0x36  /* adds r6, #1 */
    };
    struct mm_memmap map;
    struct mm_scs scs;
    struct mm_gdb_stub gdb;
    struct mm_cpu cpu;
    mm_u8 ram[64];

    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));
    memset(&scs, 0, sizeof(scs));
    memset(&gdb, 0, sizeof(gdb));
    memset(&cpu, 0, sizeof(cpu));

    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[15] = 1u;
    cpu.r[0] = 0u;
    cpu.r[1] = 1u;
    cpu.r[2] = 2u;
    cpu.r[3] = 3u;
    cpu.r[4] = 4u;
    cpu.r[5] = 5u;
    cpu.r[6] = 6u;

    if (run_sequence(code, sizeof(code), &cpu, &map, &scs, &gdb) != 0) {
        printf("exec_ecc_alu_chain_test: it blocks execution failed (case1)\n");
        return 1;
    }
    if (cpu.r[1] != 2u || cpu.r[2] != 1u || cpu.r[3] != 4u ||
        cpu.r[4] != 5u || cpu.r[5] != 4u || cpu.r[6] != 7u) {
        printf("exec_ecc_alu_chain_test: it blocks case1 regs r1=%lu r2=%lu r3=%lu r4=%lu r5=%lu r6=%lu\n",
               (unsigned long)cpu.r[1], (unsigned long)cpu.r[2], (unsigned long)cpu.r[3],
               (unsigned long)cpu.r[4], (unsigned long)cpu.r[5], (unsigned long)cpu.r[6]);
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
    cpu.r[0] = 1u;
    cpu.r[1] = 1u;
    cpu.r[2] = 2u;
    cpu.r[3] = 3u;
    cpu.r[4] = 4u;
    cpu.r[5] = 5u;
    cpu.r[6] = 6u;

    if (run_sequence(code, sizeof(code), &cpu, &map, &scs, &gdb) != 0) {
        printf("exec_ecc_alu_chain_test: it blocks execution failed (case2)\n");
        return 1;
    }
    if (cpu.r[1] != 1u || cpu.r[2] != 2u || cpu.r[3] != 3u ||
        cpu.r[4] != 4u || cpu.r[5] != 5u || cpu.r[6] != 6u) {
        printf("exec_ecc_alu_chain_test: it blocks case2 regs r1=%lu r2=%lu r3=%lu r4=%lu r5=%lu r6=%lu\n",
               (unsigned long)cpu.r[1], (unsigned long)cpu.r[2], (unsigned long)cpu.r[3],
               (unsigned long)cpu.r[4], (unsigned long)cpu.r[5], (unsigned long)cpu.r[6]);
        return 1;
    }
    return 0;
}

static int test_itttt_long_chain(void)
{
    static const mm_u8 code[] = {
        0x00, 0x28, /* cmp r0, #0 */
        0x01, 0xbf, /* itttt eq */
        0x01, 0x31, /* adds r1, #1 */
        0x01, 0x3a, /* subs r2, #1 */
        0x01, 0x33, /* adds r3, #1 */
        0x01, 0x3c  /* subs r4, #1 */
    };
    struct mm_memmap map;
    struct mm_scs scs;
    struct mm_gdb_stub gdb;
    struct mm_cpu cpu;
    mm_u8 ram[64];

    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));
    memset(&scs, 0, sizeof(scs));
    memset(&gdb, 0, sizeof(gdb));
    memset(&cpu, 0, sizeof(cpu));

    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[15] = 1u;
    cpu.r[0] = 0u;
    cpu.r[1] = 1u;
    cpu.r[2] = 2u;
    cpu.r[3] = 3u;
    cpu.r[4] = 4u;

    if (run_sequence(code, sizeof(code), &cpu, &map, &scs, &gdb) != 0) {
        printf("exec_ecc_alu_chain_test: itttt execution failed (case1)\n");
        return 1;
    }
    if (cpu.r[1] != 2u || cpu.r[2] != 1u || cpu.r[3] != 4u || cpu.r[4] != 3u) {
        printf("exec_ecc_alu_chain_test: itttt case1 regs r1=%lu r2=%lu r3=%lu r4=%lu\n",
               (unsigned long)cpu.r[1], (unsigned long)cpu.r[2],
               (unsigned long)cpu.r[3], (unsigned long)cpu.r[4]);
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
    cpu.r[0] = 1u;
    cpu.r[1] = 1u;
    cpu.r[2] = 2u;
    cpu.r[3] = 3u;
    cpu.r[4] = 4u;

    if (run_sequence(code, sizeof(code), &cpu, &map, &scs, &gdb) != 0) {
        printf("exec_ecc_alu_chain_test: itttt execution failed (case2)\n");
        return 1;
    }
    if (cpu.r[1] != 1u || cpu.r[2] != 2u || cpu.r[3] != 3u || cpu.r[4] != 4u) {
        printf("exec_ecc_alu_chain_test: itttt case2 regs r1=%lu r2=%lu r3=%lu r4=%lu\n",
               (unsigned long)cpu.r[1], (unsigned long)cpu.r[2],
               (unsigned long)cpu.r[3], (unsigned long)cpu.r[4]);
        return 1;
    }
    return 0;
}

static void set_nzcv(mm_u32 *xpsr, mm_u32 res, mm_bool c, mm_bool v)
{
    mm_u32 next = *xpsr & ~0xF0000000u;
    if (res == 0u) next |= (1u << 30);
    if (res & 0x80000000u) next |= (1u << 31);
    if (c) next |= (1u << 29);
    if (v) next |= (1u << 28);
    *xpsr = next;
}

static void set_nzc_preserve_v(mm_u32 *xpsr, mm_u32 res, mm_bool c)
{
    mm_u32 v = *xpsr & (1u << 28);
    mm_u32 next = *xpsr & ~0xE0000000u;
    if (res == 0u) next |= (1u << 30);
    if (res & 0x80000000u) next |= (1u << 31);
    if (c) next |= (1u << 29);
    next |= v;
    *xpsr = next;
}

static void set_nz_preserve_cv(mm_u32 *xpsr, mm_u32 res)
{
    mm_u32 cv = *xpsr & 0x30000000u;
    mm_u32 next = *xpsr & ~0xC0000000u;
    if (res == 0u) next |= (1u << 30);
    if (res & 0x80000000u) next |= (1u << 31);
    next |= cv;
    *xpsr = next;
}

static mm_u32 lsr_imm(mm_u32 val, mm_u32 imm, mm_bool *carry_out)
{
    if (imm == 0u) {
        if (carry_out) {
            *carry_out = MM_FALSE;
        }
        return val;
    }
    if (carry_out) {
        *carry_out = ((val >> (imm - 1u)) & 1u) ? MM_TRUE : MM_FALSE;
    }
    return val >> imm;
}

static mm_u32 lsl_imm(mm_u32 val, mm_u32 imm, mm_bool *carry_out)
{
    if (imm == 0u) {
        if (carry_out) {
            *carry_out = MM_FALSE;
        }
        return val;
    }
    if (carry_out) {
        *carry_out = ((val >> (32u - imm)) & 1u) ? MM_TRUE : MM_FALSE;
    }
    return val << imm;
}

static void add_with_carry_ref(mm_u32 x, mm_u32 y, mm_bool carry_in,
                               mm_u32 *res_out, mm_bool *carry_out, mm_bool *overflow_out)
{
    mm_u64 unsigned_sum;
    mm_i64 signed_sum;
    mm_u32 res;
    mm_bool carry;
    mm_bool overflow;

    unsigned_sum = (mm_u64)x + (mm_u64)y + (carry_in ? 1u : 0u);
    res = (mm_u32)unsigned_sum;
    carry = (unsigned_sum >> 32) != 0u;

    signed_sum = (mm_i64)(mm_i32)x + (mm_i64)(mm_i32)y + (carry_in ? 1 : 0);
    overflow = (signed_sum < (mm_i64)(-0x80000000LL) || signed_sum > (mm_i64)0x7fffffffLL) ? MM_TRUE : MM_FALSE;

    if (res_out) {
        *res_out = res;
    }
    if (carry_out) {
        *carry_out = carry;
    }
    if (overflow_out) {
        *overflow_out = overflow;
    }
}

static int test_ecc_like_chain(void)
{
    static const mm_u8 code[] = {
        0x00, 0x23, /* movs r3, #0 */
        0x00, 0x24, /* movs r4, #0 */
        0x00, 0x25, /* movs r5, #0 */
        0x00, 0x26, /* movs r6, #0 */
        0x00, 0x27, /* movs r7, #0 */
        0x12, 0x27, /* movs r7, #0x12 */
        0x1c, 0x38, /* subs r0, #28 */
        0xb6, 0x41, /* sbcs r6, r6 */
        0x6f, 0xea, 0x06, 0x06, /* mvn.w r6, r6 */
        0x30, 0x40, /* ands r0, r6 */
        0x09, 0x1a, /* subs r1, r1, r0 */
        0x77, 0x43, /* muls r7, r6 */
        0xdb, 0x19, /* adds r3, r3, r7 */
        0x6c, 0x41, /* adcs r4, r5 */
        0x75, 0x41, /* adcs r5, r6 */
        0x17, 0x0c, /* lsrs r7, r2, #16 */
        0x16, 0x46, /* mov r6, r2 */
        0x7e, 0x43, /* muls r6, r7 */
        0x37, 0x0c, /* lsrs r7, r6, #16 */
        0x36, 0x04, /* lsls r6, r6, #16 */
        0x9b, 0x19, /* adds r3, r3, r6 */
        0x7c, 0x41, /* adcs r4, r7 */
        0x75, 0x41  /* adcs r5, r6 */
    };
    struct mm_memmap map;
    struct mm_scs scs;
    struct mm_gdb_stub gdb;
    struct mm_cpu cpu;
    mm_u8 ram[128];
    mm_u32 xpsr;
    mm_u32 r0, r1, r2, r3, r4, r5, r6, r7;
    mm_u32 res;
    mm_bool c;
    mm_bool v;

    r0 = 0x12345678u;
    r1 = 0x9abcdef0u;
    r2 = 0x00c0ffeeu;
    r3 = 0u;
    r4 = 0u;
    r5 = 0u;
    r6 = 0u;
    r7 = 0x12u;
    xpsr = 0u;

    mm_add_with_carry(r0, ~28u, MM_TRUE, &res, &c, &v);
    r0 = res;
    set_nzcv(&xpsr, res, c, v);

    mm_add_with_carry(r6, ~r6, ((xpsr >> 29) & 1u) != 0u, &res, &c, &v);
    r6 = res;
    set_nzcv(&xpsr, res, c, v);

    r6 = ~r6; /* mvn.w, no flags */

    res = r0 & r6;
    r0 = res;
    c = ((xpsr >> 29) & 1u) != 0u;
    set_nzc_preserve_v(&xpsr, res, c);

    mm_add_with_carry(r1, ~r0, MM_TRUE, &res, &c, &v);
    r1 = res;
    set_nzcv(&xpsr, res, c, v);

    r7 = r7 * r6;
    set_nz_preserve_cv(&xpsr, r7);

    mm_add_with_carry(r3, r7, MM_FALSE, &res, &c, &v);
    r3 = res;
    set_nzcv(&xpsr, res, c, v);

    mm_add_with_carry(r4, r5, ((xpsr >> 29) & 1u) != 0u, &res, &c, &v);
    r4 = res;
    set_nzcv(&xpsr, res, c, v);

    mm_add_with_carry(r5, r6, ((xpsr >> 29) & 1u) != 0u, &res, &c, &v);
    r5 = res;
    set_nzcv(&xpsr, res, c, v);

    r7 = lsr_imm(r2, 16u, &c);
    set_nzc_preserve_v(&xpsr, r7, c);

    r6 = r2;
    r6 = r6 * r7;
    set_nz_preserve_cv(&xpsr, r6);

    r7 = lsr_imm(r6, 16u, &c);
    set_nzc_preserve_v(&xpsr, r7, c);

    r6 = lsl_imm(r6, 16u, &c);
    set_nzc_preserve_v(&xpsr, r6, c);

    mm_add_with_carry(r3, r6, MM_FALSE, &res, &c, &v);
    r3 = res;
    set_nzcv(&xpsr, res, c, v);

    mm_add_with_carry(r4, r7, ((xpsr >> 29) & 1u) != 0u, &res, &c, &v);
    r4 = res;
    set_nzcv(&xpsr, res, c, v);

    mm_add_with_carry(r5, r6, ((xpsr >> 29) & 1u) != 0u, &res, &c, &v);
    r5 = res;
    set_nzcv(&xpsr, res, c, v);

    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));
    memset(&scs, 0, sizeof(scs));
    memset(&gdb, 0, sizeof(gdb));
    memset(&cpu, 0, sizeof(cpu));
    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[15] = 1u;
    cpu.r[0] = 0x12345678u;
    cpu.r[1] = 0x9abcdef0u;
    cpu.r[2] = 0x00c0ffeeu;
    cpu.r[3] = 0u;
    cpu.r[4] = 0u;
    cpu.r[5] = 0u;
    cpu.r[6] = 0u;
    cpu.r[7] = 0u;
    cpu.xpsr = 0u;

    if (run_sequence(code, sizeof(code), &cpu, &map, &scs, &gdb) != 0) {
        printf("exec_ecc_alu_chain_test: ecc-like chain execution failed\n");
        return 1;
    }

    if (cpu.r[0] != r0 || cpu.r[1] != r1 || cpu.r[2] != r2 ||
        cpu.r[3] != r3 || cpu.r[4] != r4 || cpu.r[5] != r5 ||
        cpu.r[6] != r6 || cpu.r[7] != r7) {
        printf("exec_ecc_alu_chain_test: ecc-like chain regs mismatch\n");
        return 1;
    }
    if ((cpu.xpsr & 0xF0000000u) != (xpsr & 0xF0000000u)) {
        printf("exec_ecc_alu_chain_test: ecc-like chain flags mismatch got=0x%08lx exp=0x%08lx\n",
               (unsigned long)cpu.xpsr, (unsigned long)xpsr);
        return 1;
    }

    return 0;
}

static int test_sp_256_mont_add_chain(void)
{
    static const mm_u8 code[] = {
        0x18, 0xca,             /* ldmia r2!, {r3, r4} */
        0xed, 0x18,             /* adds r5, r5, r3 */
        0x66, 0x41,             /* adcs r6, r4 */
        0x18, 0xca,             /* ldmia r2!, {r3, r4} */
        0x5f, 0x41,             /* adcs r7, r3 */
        0x58, 0xeb, 0x04, 0x08, /* adcs.w r8, r8, r4 */
        0x18, 0xca,             /* ldmia r2!, {r3, r4} */
        0x59, 0xeb, 0x03, 0x09, /* adcs.w r9, r9, r3 */
        0x5a, 0xeb, 0x04, 0x0a, /* adcs.w sl, sl, r4 */
        0x18, 0xca,             /* ldmia r2!, {r3, r4} */
        0x5b, 0xeb, 0x03, 0x0b, /* adcs.w fp, fp, r3 */
        0x5c, 0xeb, 0x04, 0x0c, /* adcs.w ip, ip, r4 */
        0x4e, 0xf1, 0x00, 0x0e, /* adc.w lr, lr, #0 */
        0xce, 0xf1, 0x00, 0x0e, /* rsb lr, lr, #0 */
        0xb5, 0xeb, 0x0e, 0x05, /* subs.w r5, r5, lr */
        0x76, 0xeb, 0x0e, 0x06, /* sbcs.w r6, r6, lr */
        0x77, 0xeb, 0x0e, 0x07, /* sbcs.w r7, r7, lr */
        0x78, 0xf1, 0x00, 0x08, /* sbcs.w r8, r8, #0 */
        0x79, 0xf1, 0x00, 0x09, /* sbcs.w r9, r9, #0 */
        0x7a, 0xf1, 0x00, 0x0a, /* sbcs.w sl, sl, #0 */
        0x7b, 0xeb, 0xde, 0x7b, /* sbcs.w fp, fp, lr, lsr #31 */
        0x7c, 0xeb, 0x0e, 0x0c  /* sbcs.w ip, ip, lr */
    };
    mm_u8 ram[256];
    struct mm_memmap map;
    struct mm_scs scs;
    struct mm_gdb_stub gdb;
    struct mm_cpu cpu;
    mm_u32 r2_base = 0x20000040u;
    mm_u32 mem_words[] = {
        0xf10eacaeu, 0x2c346c45u,
        0xe722e62eu, 0x0d716a46u,
        0x55a90ceeu, 0x2f38aa0du,
        0x583d433eu, 0x8b29c893u
    };
    mm_u32 r3 = 0;
    mm_u32 r4 = 0;
    mm_u32 r5 = 0xb38f1ec5u;
    mm_u32 r6 = 0x66e0f9a2u;
    mm_u32 r7 = 0x372d0f3bu;
    mm_u32 r8 = 0xa5f251deu;
    mm_u32 r9 = 0x717b7c5fu;
    mm_u32 r10 = 0x8fb653e0u;
    mm_u32 r11 = 0x6ba4f17cu;
    mm_u32 r12 = 0x5bed533eu;
    mm_u32 lr = 0x00000000u;
    mm_u32 xpsr = 0x21000200u;
    mm_bool c = MM_TRUE;
    mm_bool v = MM_FALSE;
    mm_u32 res = 0;
    mm_u32 i;

    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));
    memset(&scs, 0, sizeof(scs));
    memset(&gdb, 0, sizeof(gdb));
    memset(&cpu, 0, sizeof(cpu));
    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[15] = 1u;
    cpu.r[2] = r2_base;
    cpu.r[3] = r3;
    cpu.r[4] = r4;
    cpu.r[5] = r5;
    cpu.r[6] = r6;
    cpu.r[7] = r7;
    cpu.r[8] = r8;
    cpu.r[9] = r9;
    cpu.r[10] = r10;
    cpu.r[11] = r11;
    cpu.r[12] = r12;
    cpu.r[14] = lr;
    cpu.xpsr = xpsr;

    for (i = 0; i < sizeof(mem_words) / sizeof(mem_words[0]); ++i) {
        mm_u32 addr = r2_base + (i * 4u);
        ram[addr - 0x20000000u + 0] = (mm_u8)(mem_words[i] & 0xffu);
        ram[addr - 0x20000000u + 1] = (mm_u8)((mem_words[i] >> 8) & 0xffu);
        ram[addr - 0x20000000u + 2] = (mm_u8)((mem_words[i] >> 16) & 0xffu);
        ram[addr - 0x20000000u + 3] = (mm_u8)((mem_words[i] >> 24) & 0xffu);
    }

    /* Reference model for expected results. */
    r3 = mem_words[0];
    r4 = mem_words[1];
    add_with_carry_ref(r5, r3, MM_FALSE, &res, &c, &v);
    r5 = res;
    set_nzcv(&xpsr, res, c, v);
    add_with_carry_ref(r6, r4, c, &res, &c, &v);
    r6 = res;
    set_nzcv(&xpsr, res, c, v);
    r3 = mem_words[2];
    r4 = mem_words[3];
    add_with_carry_ref(r7, r3, c, &res, &c, &v);
    r7 = res;
    set_nzcv(&xpsr, res, c, v);
    add_with_carry_ref(r8, r4, c, &res, &c, &v);
    r8 = res;
    set_nzcv(&xpsr, res, c, v);
    r3 = mem_words[4];
    r4 = mem_words[5];
    add_with_carry_ref(r9, r3, c, &res, &c, &v);
    r9 = res;
    set_nzcv(&xpsr, res, c, v);
    add_with_carry_ref(r10, r4, c, &res, &c, &v);
    r10 = res;
    set_nzcv(&xpsr, res, c, v);
    r3 = mem_words[6];
    r4 = mem_words[7];
    add_with_carry_ref(r11, r3, c, &res, &c, &v);
    r11 = res;
    set_nzcv(&xpsr, res, c, v);
    add_with_carry_ref(r12, r4, c, &res, &c, &v);
    r12 = res;
    set_nzcv(&xpsr, res, c, v);
    add_with_carry_ref(lr, 0u, c, &res, &c, &v);
    lr = res;
    lr = (mm_u32)(0u - lr);
    add_with_carry_ref(r5, ~lr, MM_TRUE, &res, &c, &v);
    r5 = res;
    set_nzcv(&xpsr, res, c, v);
    add_with_carry_ref(r6, ~lr, c, &res, &c, &v);
    r6 = res;
    set_nzcv(&xpsr, res, c, v);
    add_with_carry_ref(r7, ~lr, c, &res, &c, &v);
    r7 = res;
    set_nzcv(&xpsr, res, c, v);
    add_with_carry_ref(r8, ~0u, c, &res, &c, &v);
    r8 = res;
    set_nzcv(&xpsr, res, c, v);
    add_with_carry_ref(r9, ~0u, c, &res, &c, &v);
    r9 = res;
    set_nzcv(&xpsr, res, c, v);
    add_with_carry_ref(r10, ~0u, c, &res, &c, &v);
    r10 = res;
    set_nzcv(&xpsr, res, c, v);
    add_with_carry_ref(r11, ~(lr >> 31), c, &res, &c, &v);
    r11 = res;
    set_nzcv(&xpsr, res, c, v);
    add_with_carry_ref(r12, ~lr, c, &res, &c, &v);
    r12 = res;
    set_nzcv(&xpsr, res, c, v);

    if (run_sequence(code, sizeof(code), &cpu, &map, &scs, &gdb) != 0) {
        printf("exec_ecc_alu_chain_test: mont_add chain execution failed\n");
        return 1;
    }

    if (cpu.r[2] != (0x20000040u + 32u) || cpu.r[5] != r5 || cpu.r[6] != r6 ||
        cpu.r[7] != r7 || cpu.r[8] != r8 || cpu.r[9] != r9 ||
        cpu.r[10] != r10 || cpu.r[11] != r11 || cpu.r[12] != r12 ||
        cpu.r[14] != lr) {
        printf("exec_ecc_alu_chain_test: mont_add chain regs mismatch\n");
        return 1;
    }
    if ((cpu.xpsr & 0xF0000000u) != (xpsr & 0xF0000000u)) {
        printf("exec_ecc_alu_chain_test: mont_add chain flags mismatch got=0x%08lx exp=0x%08lx\n",
               (unsigned long)cpu.xpsr, (unsigned long)xpsr);
        return 1;
    }

    return 0;
}

int main(void)
{
    if (test_adc_sbc_chain() != 0) {
        return 1;
    }
    if (test_adc_sbc_reg_and_no_flag() != 0) {
        return 1;
    }
    if (test_adc_sbc_no_flag_preserve_xpsr() != 0) {
        return 1;
    }
    if (test_adc_sbc_carry_propagation() != 0) {
        return 1;
    }
    if (test_it_blocks() != 0) {
        return 1;
    }
    if (test_itttt_long_chain() != 0) {
        return 1;
    }
    if (test_ecc_like_chain() != 0) {
        return 1;
    }
    if (test_sp_256_mont_add_chain() != 0) {
        return 1;
    }
    printf("exec_ecc_alu_chain_test: ok\n");
    return 0;
}
