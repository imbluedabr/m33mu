/* m33mu -- an ARMv8-M Emulator
 *
 * Copyright (C) 2026
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>
#include <math.h>

#include "m33mu/cpu.h"
#include "m33mu/decode.h"
#include "m33mu/execute.h"
#include "m33mu/fetch.h"
#include "m33mu/memmap.h"
#include "m33mu/scs.h"

static mm_u32 f32_to_u32(float f)
{
    union {
        float f;
        mm_u32 u;
    } v;

    v.f = f;
    return v.u;
}

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
    struct mm_target_cfg cfg;
    struct mmio_region regions[1];

    memset(regions, 0, sizeof(regions));
    memset(&cfg, 0, sizeof(cfg));
    mm_memmap_init(map, regions, 1u);
    cfg.ram_base_s = 0x20000000u;
    cfg.ram_size_s = (mm_u32)ram_len;
    cfg.ram_base_ns = 0x20000000u;
    cfg.ram_size_ns = (mm_u32)ram_len;
    (void)mm_memmap_configure_ram(map, &cfg, ram, MM_FALSE);
}

static int run_vcvt_case_with_fpscr(enum mm_op_kind kind,
                                    float input,
                                    mm_u32 expected,
                                    mm_u32 fpscr,
                                    const char *name)
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
    cpu.s[1] = f32_to_u32(input);
    cpu.fpscr = fpscr;

    scs.fpu_present = MM_TRUE;
    scs.cpacr_s = 0x00f00000u;

    dec.kind = kind;
    dec.rd = 0u;
    dec.rm = 1u;
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
        printf("%s: execution failed\n", name);
        return 1;
    }
    if (done) {
        printf("%s: unexpected done flag\n", name);
        return 1;
    }
    if (cpu.s[0] != expected) {
        printf("%s: got=0x%08lx expected=0x%08lx\n",
               name,
               (unsigned long)cpu.s[0],
               (unsigned long)expected);
        return 1;
    }

    return 0;
}

static int run_vcvt_case(enum mm_op_kind kind, float input, mm_u32 expected, const char *name)
{
    return run_vcvt_case_with_fpscr(kind, input, expected, 0u, name);
}

static int run_vmov_sr_case(mm_u32 src_reg, mm_u32 value, mm_u32 dest_s, const char *name)
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
    cpu.r[src_reg] = value;

    scs.fpu_present = MM_TRUE;
    scs.cpacr_s = 0x00f00000u;

    dec.kind = MM_OP_VMOV_SR;
    dec.rd = dest_s;
    dec.rn = src_reg;
    dec.len = 4u;

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
        printf("%s: execution failed\n", name);
        return 1;
    }
    if (done) {
        printf("%s: unexpected undef\n", name);
        return 1;
    }
    if (cpu.s[dest_s] != value) {
        printf("%s: got=0x%08lx expected=0x%08lx\n",
               name,
               (unsigned long)cpu.s[dest_s],
               (unsigned long)value);
        return 1;
    }
    return 0;
}

static int run_vmov_rs_case(mm_u32 src_s, mm_u32 value, mm_u32 dest_reg, const char *name)
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
    cpu.s[src_s] = value;

    scs.fpu_present = MM_TRUE;
    scs.cpacr_s = 0x00f00000u;

    dec.kind = MM_OP_VMOV_RS;
    dec.rn = src_s;
    dec.rd = dest_reg;
    dec.len = 4u;

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
        printf("%s: execution failed\n", name);
        return 1;
    }
    if (done) {
        printf("%s: unexpected undef\n", name);
        return 1;
    }
    if (cpu.r[dest_reg] != value) {
        printf("%s: got=0x%08lx expected=0x%08lx\n",
               name,
               (unsigned long)cpu.r[dest_reg],
               (unsigned long)value);
        return 1;
    }
    return 0;
}

static int test_lazy_fp_save_on_first_handler_fp_use(void)
{
    struct mm_cpu cpu;
    struct mm_memmap map;
    struct mm_scs scs;
    struct mm_gdb_stub gdb;
    struct mm_fetch_result fetch;
    struct mm_decoded dec;
    struct mm_execute_ctx ctx;
    mm_u8 ram[256];
    mm_u8 it_pattern = 0;
    mm_u8 it_remaining = 0;
    mm_u8 it_cond = 0;
    mm_bool done = MM_FALSE;
    mm_u32 val = 0;
    int i;

    memset(&cpu, 0, sizeof(cpu));
    memset(&map, 0, sizeof(map));
    memset(&scs, 0, sizeof(scs));
    memset(&gdb, 0, sizeof(gdb));
    memset(&fetch, 0, sizeof(fetch));
    memset(&dec, 0, sizeof(dec));
    memset(&ctx, 0, sizeof(ctx));
    memset(ram, 0, sizeof(ram));

    setup_ram_map(&map, ram, sizeof(ram));

    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_HANDLER;
    cpu.fp_active = MM_TRUE;
    cpu.control_s = (1u << 2);
    cpu.exc_depth = 1u;
    cpu.exc_sp[0] = 0x20000040u;
    cpu.exc_sec[0] = MM_SECURE;
    cpu.exc_fp_reserved[0] = MM_TRUE;
    cpu.exc_fp_saved[0] = MM_FALSE;
    for (i = 0; i < 16; ++i) {
        cpu.s[i] = 0x10000000u + (mm_u32)i;
    }
    cpu.fpscr = 0x89abcdefu;

    scs.fpu_present = MM_TRUE;
    scs.cpacr_s = 0x00f00000u;
    scs.fpccr = 1u;

    dec.kind = MM_OP_VMOV_RS;
    dec.rn = 5u;
    dec.rd = 0u;
    dec.len = 4u;

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
        printf("lazy_fp_save: execution failed\n");
        return 1;
    }
    if (done) {
        printf("lazy_fp_save: unexpected done flag\n");
        return 1;
    }
    if (cpu.r[0] != cpu.s[5]) {
        printf("lazy_fp_save: vmov result mismatch got=0x%08lx expected=0x%08lx\n",
               (unsigned long)cpu.r[0],
               (unsigned long)cpu.s[5]);
        return 1;
    }
    if (!cpu.exc_fp_saved[0] || (scs.fpccr & 1u) != 0u) {
        printf("lazy_fp_save: lazy-save state not updated saved=%d fpccr=0x%08lx\n",
               (int)cpu.exc_fp_saved[0],
               (unsigned long)scs.fpccr);
        return 1;
    }
    for (i = 0; i < 16; ++i) {
        if (!mm_memmap_read(&map, MM_SECURE, 0x20000060u + (mm_u32)(i * 4u), 4u, &val) ||
            val != cpu.s[i]) {
            printf("lazy_fp_save: s%d got=0x%08lx expected=0x%08lx\n",
                   i,
                   (unsigned long)val,
                   (unsigned long)cpu.s[i]);
            return 1;
        }
    }
    if (!mm_memmap_read(&map, MM_SECURE, 0x200000a0u, 4u, &val) || val != cpu.fpscr) {
        printf("lazy_fp_save: fpscr got=0x%08lx expected=0x%08lx\n",
               (unsigned long)val,
               (unsigned long)cpu.fpscr);
        return 1;
    }
    if (!mm_memmap_read(&map, MM_SECURE, 0x200000a4u, 4u, &val) || val != 0u) {
        printf("lazy_fp_save: reserved word got=0x%08lx expected=0\n",
               (unsigned long)val);
        return 1;
    }

    return 0;
}

int main(void)
{
    if (run_vcvt_case(MM_OP_VCVT_S32_F32, NAN, 0u, "vcvt_s32_f32_nan_zero") != 0) return 1;
    if (run_vcvt_case(MM_OP_VCVTR_S32_F32, 0.5f, 0u, "vcvtr_s32_f32_half_even") != 0) return 1;
    if (run_vcvt_case(MM_OP_VCVTR_S32_F32, 2147483648.0f, 0x7fffffffu, "vcvtr_s32_f32_sat_max") != 0) return 1;
    if (run_vcvt_case(MM_OP_VCVT_U32_F32, -1.0f, 0u, "vcvt_u32_f32_sat_zero") != 0) return 1;
    if (run_vcvt_case(MM_OP_VCVTR_U32_F32, 0.5f, 0u, "vcvtr_u32_f32_half_even") != 0) return 1;
    if (run_vcvt_case(MM_OP_VCVTR_U32_F32, 4294967296.0f, 0xffffffffu, "vcvtr_u32_f32_sat_max") != 0) return 1;
    if (run_vcvt_case_with_fpscr(MM_OP_VCVTR_S32_F32, 1.25f, 2u, 1u << 22, "vcvtr_s32_f32_round_plus_inf") != 0) return 1;
    if (run_vcvt_case_with_fpscr(MM_OP_VCVTR_S32_F32, -1.25f, 0xfffffffeu, 2u << 22, "vcvtr_s32_f32_round_minus_inf") != 0) return 1;
    if (run_vcvt_case_with_fpscr(MM_OP_VCVTR_U32_F32, 1.75f, 1u, 3u << 22, "vcvtr_u32_f32_round_zero") != 0) return 1;
    if (run_vmov_sr_case(14u, 0x12345678u, 3u, "vmov_sr_lr_allowed") != 0) return 1;
    if (run_vmov_rs_case(5u, 0x89abcdefu, 14u, "vmov_rs_lr_allowed") != 0) return 1;
    if (test_lazy_fp_save_on_first_handler_fp_use() != 0) return 1;
    return 0;
}
