/* m33mu -- an ARMv8-M Emulator
 *
 * Copyright (C) 2025  Daniele Lacamera <root@danielinux.net>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>
#include "m33mu/execute.h"
#include "m33mu/vector.h"

static mm_u32 g_last_exc_num;
static mm_u32 g_last_return_pc;
static int g_enter_exception_calls;

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
    g_last_exc_num = exc_num;
    g_last_return_pc = return_pc;
    g_enter_exception_calls++;
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

static int exec_one(struct mm_cpu *cpu,
                    struct mm_memmap *map,
                    struct mm_scs *scs,
                    struct mm_decoded *dec)
{
    struct mm_fetch_result fetch;
    struct mm_gdb_stub gdb;
    struct mm_execute_ctx ctx;
    mm_u8 it_pattern = 0;
    mm_u8 it_remaining = 0;
    mm_u8 it_cond = 0;
    mm_bool done = MM_FALSE;

    memset(&fetch, 0, sizeof(fetch));
    memset(&gdb, 0, sizeof(gdb));
    memset(&ctx, 0, sizeof(ctx));
    fetch.pc_fetch = cpu->r[15] & ~1u;
    ctx.cpu = cpu;
    ctx.map = map;
    ctx.scs = scs;
    ctx.gdb = &gdb;
    ctx.fetch = &fetch;
    ctx.dec = dec;
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
    return done ? 1 : 0;
}

static int test_unprivileged_t_forms_execute(void)
{
    struct mm_cpu cpu;
    struct mm_memmap map;
    struct mm_scs scs;
    struct mm_decoded dec;
    mm_u8 ram[128];
    mm_u32 value;

    memset(&cpu, 0, sizeof(cpu));
    memset(&scs, 0, sizeof(scs));
    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));

    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[15] = 1u;
    cpu.r[0] = 0x20000000u;
    memset(&dec, 0, sizeof(dec));
    dec.rn = 0u;
    dec.rd = 1u;

    dec.kind = MM_OP_STRT;
    dec.imm = 4u;
    cpu.r[1] = 0x11223344u;
    if (exec_one(&cpu, &map, &scs, &dec) != 0) return 1;
    if (!mm_memmap_read(&map, cpu.sec_state, cpu.r[0] + 4u, 4u, &value) || value != 0x11223344u) return 1;

    dec.kind = MM_OP_LDRT;
    cpu.r[1] = 0u;
    if (exec_one(&cpu, &map, &scs, &dec) != 0 || cpu.r[1] != 0x11223344u) return 1;

    dec.kind = MM_OP_STRBT;
    dec.imm = 8u;
    cpu.r[1] = 0xA5u;
    if (exec_one(&cpu, &map, &scs, &dec) != 0) return 1;

    dec.kind = MM_OP_LDRBT;
    cpu.r[1] = 0u;
    if (exec_one(&cpu, &map, &scs, &dec) != 0 || cpu.r[1] != 0xA5u) return 1;

    dec.kind = MM_OP_STRHT;
    dec.imm = 12u;
    cpu.r[1] = 0xBEEFu;
    if (exec_one(&cpu, &map, &scs, &dec) != 0) return 1;

    dec.kind = MM_OP_LDRHT;
    cpu.r[1] = 0u;
    if (exec_one(&cpu, &map, &scs, &dec) != 0 || cpu.r[1] != 0xBEEFu) return 1;

    if (!mm_memmap_write(&map, cpu.sec_state, cpu.r[0] + 16u, 1u, 0x80u)) return 1;
    dec.kind = MM_OP_LDRSBT;
    dec.imm = 16u;
    cpu.r[1] = 0u;
    if (exec_one(&cpu, &map, &scs, &dec) != 0 || cpu.r[1] != 0xFFFFFF80u) return 1;

    if (!mm_memmap_write(&map, cpu.sec_state, cpu.r[0] + 20u, 2u, 0x8001u)) return 1;
    dec.kind = MM_OP_LDRSHT;
    dec.imm = 20u;
    cpu.r[1] = 0u;
    if (exec_one(&cpu, &map, &scs, &dec) != 0 || cpu.r[1] != 0xFFFF8001u) return 1;

    return 0;
}

static int test_wide_hints_execute(void)
{
    struct mm_cpu cpu;
    struct mm_memmap map;
    struct mm_scs scs;
    struct mm_decoded dec;
    mm_u8 ram[32];

    memset(&cpu, 0, sizeof(cpu));
    memset(&scs, 0, sizeof(scs));
    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));

    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[15] = 1u;
    memset(&dec, 0, sizeof(dec));

    dec.kind = MM_OP_YIELD_W;
    if (exec_one(&cpu, &map, &scs, &dec) != 0) return 1;

    dec.kind = MM_OP_SEV_W;
    if (exec_one(&cpu, &map, &scs, &dec) != 0 || cpu.event_reg != MM_TRUE) return 1;

    cpu.event_reg = MM_FALSE;
    dec.kind = MM_OP_SEVL_W;
    if (exec_one(&cpu, &map, &scs, &dec) != 0 || cpu.event_reg != MM_TRUE) return 1;

    cpu.event_reg = MM_FALSE;
    dec.kind = MM_OP_WFE_W;
    if (exec_one(&cpu, &map, &scs, &dec) != 0 || cpu.sleeping != MM_TRUE || cpu.sleep_wfe != MM_TRUE) return 1;

    cpu.sleeping = MM_FALSE;
    cpu.sleep_wfe = MM_FALSE;
    dec.kind = MM_OP_WFI_W;
    if (exec_one(&cpu, &map, &scs, &dec) != 0 || cpu.sleeping != MM_TRUE || cpu.sleep_wfe != MM_FALSE) return 1;

    return 0;
}

static int test_bkpt_enters_debugmon(void)
{
    struct mm_cpu cpu;
    struct mm_memmap map;
    struct mm_scs scs;
    struct mm_decoded dec;
    mm_u8 ram[32];

    memset(&cpu, 0, sizeof(cpu));
    memset(&scs, 0, sizeof(scs));
    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));
    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[15] = 0x101u;
    dec.kind = MM_OP_BKPT;
    dec.imm = 0;
    g_last_exc_num = 0;
    g_last_return_pc = 0;
    g_enter_exception_calls = 0;

    if (exec_one(&cpu, &map, &scs, &dec) == 0) {
        return 1;
    }
    if (g_enter_exception_calls != 1) return 1;
    if (g_last_exc_num != MM_VECT_DEBUGMON) return 1;
    if (g_last_return_pc != 0x102u) return 1;
    if ((scs.dfsr & (1u << 1)) == 0u) return 1;
    return 0;
}

static int test_ldrexh_strexh_execute(void)
{
    struct mm_cpu cpu;
    struct mm_memmap map;
    struct mm_scs scs;
    struct mm_decoded dec;
    mm_u8 ram[64];
    mm_u32 value = 0;

    memset(&cpu, 0, sizeof(cpu));
    memset(&scs, 0, sizeof(scs));
    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));
    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[15] = 1u;
    cpu.r[0] = 0x20000000u;
    if (!mm_memmap_write(&map, cpu.sec_state, cpu.r[0], 2u, 0xABCDu)) return 1;

    memset(&dec, 0, sizeof(dec));
    dec.kind = MM_OP_LDREXH;
    dec.rn = 0u;
    dec.rd = 1u;
    if (exec_one(&cpu, &map, &scs, &dec) != 0) return 1;
    if (cpu.r[1] != 0xABCDu) return 1;

    dec.kind = MM_OP_STREXH;
    dec.rn = 0u;
    dec.rm = 2u;
    dec.rd = 3u;
    cpu.r[2] = 0x1234u;
    if (exec_one(&cpu, &map, &scs, &dec) != 0) return 1;
    if (cpu.r[3] != 0u) return 1;
    if (!mm_memmap_read(&map, cpu.sec_state, cpu.r[0], 2u, &value)) return 1;
    if ((value & 0xffffu) != 0x1234u) return 1;
    return 0;
}

static int test_ldrex_strex_word_offset_execute(void)
{
    struct mm_cpu cpu;
    struct mm_memmap map;
    struct mm_scs scs;
    struct mm_decoded dec;
    mm_u8 ram[64];
    mm_u32 value = 0;

    memset(&cpu, 0, sizeof(cpu));
    memset(&scs, 0, sizeof(scs));
    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));
    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[15] = 1u;
    cpu.r[0] = 0x20000000u;
    if (!mm_memmap_write(&map, cpu.sec_state, cpu.r[0], 4u, 0x11111111u)) return 1;
    if (!mm_memmap_write(&map, cpu.sec_state, cpu.r[0] + 8u, 4u, 0xA5A5A5A5u)) return 1;

    memset(&dec, 0, sizeof(dec));
    dec.kind = MM_OP_LDREX;
    dec.rn = 0u;
    dec.rd = 1u;
    dec.imm = 8u;
    if (exec_one(&cpu, &map, &scs, &dec) != 0) return 1;
    if (cpu.r[1] != 0xA5A5A5A5u) return 1;

    dec.kind = MM_OP_STREX;
    dec.rn = 0u;
    dec.rm = 2u;
    dec.rd = 3u;
    dec.imm = 8u;
    cpu.r[2] = 0x12345678u;
    if (exec_one(&cpu, &map, &scs, &dec) != 0) return 1;
    if (cpu.r[3] != 0u) return 1;
    if (!mm_memmap_read(&map, cpu.sec_state, cpu.r[0], 4u, &value)) return 1;
    if (value != 0x11111111u) return 1;
    if (!mm_memmap_read(&map, cpu.sec_state, cpu.r[0] + 8u, 4u, &value)) return 1;
    if (value != 0x12345678u) return 1;
    return 0;
}

static int test_sub_imm_pc_align_execute(void)
{
    struct mm_cpu cpu;
    struct mm_memmap map;
    struct mm_scs scs;
    struct mm_decoded dec;
    mm_u8 ram[32];

    memset(&cpu, 0, sizeof(cpu));
    memset(&scs, 0, sizeof(scs));
    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));
    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[15] = 0x1003u;

    memset(&dec, 0, sizeof(dec));
    dec.kind = MM_OP_SUB_IMM;
    dec.rn = 15u;
    dec.rd = 0u;
    dec.imm = 4u;
    dec.len = 2u;
    if (exec_one(&cpu, &map, &scs, &dec) != 0) return 1;
    if (cpu.r[0] != 0x1000u) return 1;

    cpu.r[1] = 0u;
    dec.kind = MM_OP_SUB_IMM_NF;
    dec.rd = 1u;
    if (exec_one(&cpu, &map, &scs, &dec) != 0) return 1;
    if (cpu.r[1] != 0x1000u) return 1;
    return 0;
}

int main(void)
{
    if (test_unprivileged_t_forms_execute() != 0) {
        printf("FAIL: unprivileged_t_forms_execute\n");
        return 1;
    }
    if (test_wide_hints_execute() != 0) {
        printf("FAIL: wide_hints_execute\n");
        return 1;
    }
    if (test_bkpt_enters_debugmon() != 0) {
        printf("FAIL: bkpt_enters_debugmon\n");
        return 1;
    }
    if (test_ldrexh_strexh_execute() != 0) {
        printf("FAIL: ldrexh_strexh_execute\n");
        return 1;
    }
    if (test_ldrex_strex_word_offset_execute() != 0) {
        printf("FAIL: ldrex_strex_word_offset_execute\n");
        return 1;
    }
    if (test_sub_imm_pc_align_execute() != 0) {
        printf("FAIL: sub_imm_pc_align_execute\n");
        return 1;
    }
    return 0;
}
