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

static mm_u32 g_pc_write_value;
static mm_u32 g_pc_write_count;
static mm_u32 g_usage_fault_count;

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
    (void)it_pattern;
    (void)it_remaining;
    (void)it_cond;
    g_pc_write_value = value;
    g_pc_write_count++;
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
    g_usage_fault_count++;
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

static void setup_ram_map(struct mm_memmap *map, mm_u8 *ram, size_t ram_len, mm_u32 base)
{
    struct mmio_region regions[1];
    struct mm_target_cfg cfg;

    memset(regions, 0, sizeof(regions));
    mm_memmap_init(map, regions, 1u);

    memset(&cfg, 0, sizeof(cfg));
    cfg.ram_base_s = base;
    cfg.ram_size_s = (mm_u32)ram_len;
    cfg.ram_base_ns = base;
    cfg.ram_size_ns = (mm_u32)ram_len;

    (void)mm_memmap_configure_ram(map, &cfg, ram, MM_FALSE);
}

static int execute_one(const mm_u8 *code, size_t code_len,
                       struct mm_cpu *cpu, struct mm_memmap *map,
                       struct mm_scs *scs, struct mm_gdb_stub *gdb)
{
    struct mm_mem mem;
    struct mm_fetch_result fetch;
    struct mm_decoded dec;
    struct mm_execute_ctx ctx;
    mm_u8 it_pattern = 0;
    mm_u8 it_remaining = 0;
    mm_u8 it_cond = 0;
    mm_bool done = MM_FALSE;

    mem.buffer = code;
    mem.length = code_len;
    mem.base = 0;

    fetch = mm_fetch_t32(cpu, &mem);
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
        enum mm_exec_status status = mm_execute_decoded(&ctx);
        if (status != MM_EXEC_OK && status != MM_EXEC_CONTINUE) {
            return 1;
        }
    }
    if (done) {
        return 1;
    }
    return 0;
}

static int test_addw_pc_base_for_jump_table(void)
{
    static const mm_u8 code[] = {
        0x0f, 0xf2, 0x08, 0x0c, /* addw ip, pc, #8 */
        0x5c, 0xf8, 0x20, 0xf0, /* ldr.w pc, [ip, r0, lsl #2] */
        0x00, 0xbf,             /* nop */
        0x00, 0xbf,             /* nop */
        0x19, 0x00, 0x00, 0x00  /* jump-table entry -> 0x19 */
    };
    struct mm_memmap map;
    struct mm_scs scs;
    struct mm_gdb_stub gdb;
    struct mm_cpu cpu;
    mm_u8 ram[64];

    memcpy(ram, code, sizeof(code));
    memset(ram + sizeof(code), 0, sizeof(ram) - sizeof(code));
    setup_ram_map(&map, ram, sizeof(ram), 0u);
    memset(&scs, 0, sizeof(scs));
    memset(&gdb, 0, sizeof(gdb));
    memset(&cpu, 0, sizeof(cpu));
    g_pc_write_value = 0;
    g_pc_write_count = 0;
    g_usage_fault_count = 0;

    cpu.sec_state = MM_SECURE;
    cpu.mode = MM_THREAD;
    cpu.r[0] = 0u;
    cpu.r[15] = 1u;

    if (execute_one(code, sizeof(code), &cpu, &map, &scs, &gdb) != 0) {
        printf("exec_ldr_pc_jump_table_test: addw execution failed\n");
        return 1;
    }
    if (cpu.r[12] != 12u) {
        printf("exec_ldr_pc_jump_table_test: addw pc base mismatch got=0x%08lx\n",
               (unsigned long)cpu.r[12]);
        return 1;
    }

    if (execute_one(code, sizeof(code), &cpu, &map, &scs, &gdb) != 0) {
        printf("exec_ldr_pc_jump_table_test: ldr pc execution failed\n");
        return 1;
    }
    if (g_usage_fault_count != 0u) {
        printf("exec_ldr_pc_jump_table_test: unexpected usage fault\n");
        return 1;
    }
    if (g_pc_write_count != 1u) {
        printf("exec_ldr_pc_jump_table_test: expected one pc write, got=%lu\n",
               (unsigned long)g_pc_write_count);
        return 1;
    }
    if (g_pc_write_value != 0x19u) {
        printf("exec_ldr_pc_jump_table_test: pc write mismatch got=0x%08lx\n",
               (unsigned long)g_pc_write_value);
        return 1;
    }

    return 0;
}

int main(void)
{
    if (test_addw_pc_base_for_jump_table() != 0) {
        return 1;
    }
    printf("PASS: addw_pc_base_for_jump_table\n");
    return 0;
}
