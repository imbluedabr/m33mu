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
#include "m33mu/execute.h"
#include "m33mu/cpu.h"
#include "m33mu/memmap.h"
#include "m33mu/scs.h"

struct mem_fault_log {
    int count;
    mm_u32 last_addr;
    mm_bool last_is_exec;
};

static struct mem_fault_log g_mem_fault;

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
    g_mem_fault.count++;
    g_mem_fault.last_addr = addr;
    g_mem_fault.last_is_exec = is_exec;
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

static int run_decoded(struct mm_cpu *cpu,
                       struct mm_memmap *map,
                       struct mm_decoded *dec,
                       struct mm_fetch_result *fetch,
                       mm_bool *done_out)
{
    struct mm_scs scs;
    struct mm_gdb_stub gdb;
    struct mm_execute_ctx ctx;
    mm_u8 it_pattern = 0;
    mm_u8 it_remaining = 0;
    mm_u8 it_cond = 0;
    mm_bool done = MM_FALSE;

    memset(&scs, 0, sizeof(scs));
    memset(&gdb, 0, sizeof(gdb));
    memset(&ctx, 0, sizeof(ctx));

    ctx.cpu = cpu;
    ctx.map = map;
    ctx.scs = &scs;
    ctx.gdb = &gdb;
    ctx.fetch = fetch;
    ctx.dec = dec;
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
        enum mm_exec_status status = mm_execute_decoded(&ctx);
        if (status != MM_EXEC_OK && status != MM_EXEC_CONTINUE) {
            return 1;
        }
    }
    if (done_out != 0) {
        *done_out = done;
    }
    return 0;
}

static int test_stmia_cross_boundary_faults_on_second_word(void)
{
    struct mm_memmap map;
    struct mm_cpu cpu;
    struct mm_decoded dec;
    struct mm_fetch_result fetch;
    mm_u8 ram[4];
    mm_u32 stored = 0;
    mm_bool done = MM_FALSE;

    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));
    memset(&cpu, 0, sizeof(cpu));
    memset(&dec, 0, sizeof(dec));
    memset(&fetch, 0, sizeof(fetch));
    memset(&g_mem_fault, 0, sizeof(g_mem_fault));

    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[0] = 0x11111111u;
    cpu.r[1] = 0x22222222u;
    cpu.r[2] = 0x20000000u;

    dec.kind = MM_OP_STM;
    dec.rn = 2u;
    dec.imm = (1u << 24) | (1u << 16) | 0x0003u;
    dec.len = 2u;
    fetch.pc_fetch = 0x100u;

    if (run_decoded(&cpu, &map, &dec, &fetch, &done) != 0) {
        printf("exec_mem_boundary_test: STM run failed\n");
        return 1;
    }
    if (!done) {
        printf("exec_mem_boundary_test: STM expected done on mem fault\n");
        return 1;
    }
    if (g_mem_fault.count != 1 || g_mem_fault.last_addr != 0x20000004u || g_mem_fault.last_is_exec) {
        printf("exec_mem_boundary_test: STM fault mismatch count=%d addr=0x%08lx exec=%d\n",
               g_mem_fault.count,
               (unsigned long)g_mem_fault.last_addr,
               (int)g_mem_fault.last_is_exec);
        return 1;
    }
    if (!mm_memmap_read(&map, cpu.sec_state, 0x20000000u, 4u, &stored) || stored != 0x11111111u) {
        printf("exec_mem_boundary_test: STM first word mismatch got=0x%08lx\n",
               (unsigned long)stored);
        return 1;
    }
    return 0;
}

static int test_ldmia_cross_boundary_faults_on_second_word(void)
{
    struct mm_memmap map;
    struct mm_cpu cpu;
    struct mm_decoded dec;
    struct mm_fetch_result fetch;
    mm_u8 ram[4];
    mm_bool done = MM_FALSE;

    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));
    memset(&cpu, 0, sizeof(cpu));
    memset(&dec, 0, sizeof(dec));
    memset(&fetch, 0, sizeof(fetch));
    memset(&g_mem_fault, 0, sizeof(g_mem_fault));

    if (!mm_memmap_write(&map, MM_SECURE, 0x20000000u, 4u, 0xa5a5a5a5u)) {
        printf("exec_mem_boundary_test: LDM setup write failed\n");
        return 1;
    }

    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[2] = 0x20000000u;
    cpu.r[0] = 0u;
    cpu.r[1] = 0u;

    dec.kind = MM_OP_LDM;
    dec.rn = 2u;
    dec.imm = (1u << 24) | (1u << 16) | 0x0003u;
    dec.len = 2u;
    fetch.pc_fetch = 0x200u;

    if (run_decoded(&cpu, &map, &dec, &fetch, &done) != 0) {
        printf("exec_mem_boundary_test: LDM run failed\n");
        return 1;
    }
    if (!done) {
        printf("exec_mem_boundary_test: LDM expected done on mem fault\n");
        return 1;
    }
    if (g_mem_fault.count != 1 || g_mem_fault.last_addr != 0x20000004u || g_mem_fault.last_is_exec) {
        printf("exec_mem_boundary_test: LDM fault mismatch count=%d addr=0x%08lx exec=%d\n",
               g_mem_fault.count,
               (unsigned long)g_mem_fault.last_addr,
               (int)g_mem_fault.last_is_exec);
        return 1;
    }
    if (cpu.r[0] != 0xa5a5a5a5u) {
        printf("exec_mem_boundary_test: LDM first register mismatch got=0x%08lx\n",
               (unsigned long)cpu.r[0]);
        return 1;
    }
    if (cpu.r[1] != 0u) {
        printf("exec_mem_boundary_test: LDM second register changed got=0x%08lx\n",
               (unsigned long)cpu.r[1]);
        return 1;
    }
    return 0;
}

static int test_add_imm_does_not_touch_memory(void)
{
    struct mm_memmap map;
    struct mm_cpu cpu;
    struct mm_decoded dec;
    struct mm_fetch_result fetch;
    mm_u8 ram[4];
    mm_bool done = MM_FALSE;

    memset(ram, 0, sizeof(ram));
    setup_ram_map(&map, ram, sizeof(ram));
    memset(&cpu, 0, sizeof(cpu));
    memset(&dec, 0, sizeof(dec));
    memset(&fetch, 0, sizeof(fetch));
    memset(&g_mem_fault, 0, sizeof(g_mem_fault));

    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[1] = 0xfffffffeu;

    dec.kind = MM_OP_ADD_IMM;
    dec.rn = 1u;
    dec.rd = 0u;
    dec.imm = 5u;
    dec.len = 2u;
    fetch.pc_fetch = 0x300u;

    if (run_decoded(&cpu, &map, &dec, &fetch, &done) != 0) {
        printf("exec_mem_boundary_test: ADD run failed\n");
        return 1;
    }
    if (done) {
        printf("exec_mem_boundary_test: ADD unexpectedly set done\n");
        return 1;
    }
    if (g_mem_fault.count != 0) {
        printf("exec_mem_boundary_test: ADD unexpectedly raised mem fault count=%d\n",
               g_mem_fault.count);
        return 1;
    }
    if (cpu.r[0] != 3u) {
        printf("exec_mem_boundary_test: ADD result mismatch got=0x%08lx\n",
               (unsigned long)cpu.r[0]);
        return 1;
    }
    return 0;
}

int main(void)
{
    if (test_stmia_cross_boundary_faults_on_second_word() != 0) {
        return 1;
    }
    if (test_ldmia_cross_boundary_faults_on_second_word() != 0) {
        return 1;
    }
    if (test_add_imm_does_not_touch_memory() != 0) {
        return 1;
    }

    printf("exec_mem_boundary_test: ok\n");
    return 0;
}
