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

/*
 * Unicorn side-by-side execution support, for debugging purposes when developing m33mu.
 */

#include "m33mu/unicorn.h"
#include "m33mu/mmio.h"
#include "m33mu/memmap.h"
#include "m33mu/exec_helpers.h"
#include "m33mu/cpu.h"
#include "m33mu/execute.h"
#include <unicorn/unicorn.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#define UNICORN_PAGE_SIZE 0x1000u
#define UNICORN_XPSR_MASK 0xF8000000u /* NZCVQ */
#define UNICORN_PENDING_MAX 64u
#define UNICORN_SCRATCH_BASE 0x20100000u

struct mm_unicorn_pending_write {
    mm_u32 addr;
    mm_u32 size;
    mm_u32 value;
    mm_u32 old_value;
    mm_bool has_old;
};

struct mm_unicorn_state {
    uc_engine *uc;
    mm_bool active;
    mm_u32 entry_pc;
    mm_u32 entry_lr;
    mm_u32 stack_window;
    mm_u32 max_steps;
    mm_u32 steps;
    enum mm_sec_state sec_state;
    struct mm_memmap *map;
    struct mm_unicorn_pending_write m33mu_writes[UNICORN_PENDING_MAX];
    struct mm_unicorn_pending_write uc_writes[UNICORN_PENDING_MAX];
    mm_u32 m33mu_write_count;
    mm_u32 uc_write_count;
    mm_bool pending_overflow;
    mm_bool intr_seen;
    mm_u32 intr_no;
    mm_u32 intr_pc;
    mm_bool use_scratch;
    mm_u32 scratch_base;
    struct mm_cpu pre_cpu;
    mm_bool pre_valid;
    mm_bool read_hook_logged;
    mm_bool map_flash;
    mm_u8 it_pattern;
    mm_u8 it_remaining;
    mm_u8 it_cond;
    mm_u8 itstate_raw;
    mm_bool saved_primask_valid;
    mm_u32 saved_primask_s;
    mm_u32 saved_primask_ns;
};

static struct mm_unicorn_state g_uni;

static mm_u32 align_down(mm_u32 v)
{
    return v & ~(UNICORN_PAGE_SIZE - 1u);
}

static mm_u32 align_up(mm_u32 v)
{
    mm_u32 mask = UNICORN_PAGE_SIZE - 1u;
    return (v + mask) & ~mask;
}

static mm_bool addr_in_range(mm_u32 addr, mm_u32 base, mm_u32 len)
{
    if (len == 0u) return MM_FALSE;
    if (addr < base) return MM_FALSE;
    return (addr - base) < len;
}

static mm_bool addr_in_ram(const struct mm_memmap *map, mm_u32 addr)
{
    if (map == 0) return MM_FALSE;
    if (addr_in_range(addr, map->ram_base_s, map->ram_size_s)) return MM_TRUE;
    if (addr_in_range(addr, map->ram_base_ns, map->ram_size_ns)) return MM_TRUE;
    if (addr_in_range(addr, map->ram.base, (mm_u32)map->ram.length)) return MM_TRUE;
    return MM_FALSE;
}

static void pending_clear(void)
{
    g_uni.m33mu_write_count = 0u;
    g_uni.uc_write_count = 0u;
    g_uni.pending_overflow = MM_FALSE;
    g_uni.intr_seen = MM_FALSE;
    g_uni.intr_no = 0u;
    g_uni.intr_pc = 0u;
}

static void unicorn_restore_cpu(struct mm_cpu *cpu)
{
    if (!g_uni.saved_primask_valid || cpu == 0) {
        return;
    }
    cpu->primask_s = g_uni.saved_primask_s;
    cpu->primask_ns = g_uni.saved_primask_ns;
    g_uni.saved_primask_valid = MM_FALSE;
}

static void record_write(struct mm_unicorn_pending_write *list, mm_u32 *count,
                         mm_u32 addr, mm_u32 size, mm_u32 value, mm_bool has_old, mm_u32 old_value)
{
    if (*count >= UNICORN_PENDING_MAX) {
        g_uni.pending_overflow = MM_TRUE;
        return;
    }
    list[*count].addr = addr;
    list[*count].size = size;
    list[*count].value = value;
    list[*count].old_value = old_value;
    list[*count].has_old = has_old;
    (*count)++;
}

static uc_err map_region(uc_engine *uc, mm_u32 base, mm_u32 len, int perms)
{
    mm_u32 map_base = align_down(base);
    mm_u32 map_end = align_up(base + len);
    mm_u32 map_len = map_end - map_base;
    if (map_len == 0u) return UC_ERR_OK;
    return uc_mem_map(uc, (uint64_t)map_base, (size_t)map_len, perms);
}

static uc_err map_page(uc_engine *uc, mm_u32 addr)
{
    mm_u32 base = align_down(addr);
    return uc_mem_map(uc, (uint64_t)base, UNICORN_PAGE_SIZE, UC_PROT_ALL);
}

static mm_bool uc_write_mem(uc_engine *uc, mm_u32 addr, mm_u32 size, mm_u32 value)
{
    mm_u8 buf[4];
    mm_u32 i;
    if (size == 0u || size > 4u) return MM_FALSE;
    for (i = 0; i < size; ++i) {
        buf[i] = (mm_u8)((value >> (8u * i)) & 0xffu);
    }
    return uc_mem_write(uc, (uint64_t)addr, buf, size) == UC_ERR_OK;
}

static mm_bool mm_read_bytes(const struct mm_memmap *map, enum mm_sec_state sec,
                             mm_u32 addr, mm_u8 *dst, mm_u32 len)
{
    mm_u32 i;
    for (i = 0; i < len; ++i) {
        if (!mm_memmap_read8(map, sec, addr + i, &dst[i])) {
            return MM_FALSE;
        }
    }
    return MM_TRUE;
}

static void print_reg_diff(const char *label, mm_u32 m_val, mm_u32 u_val)
{
    if (g_uni.pre_valid) {
        mm_u8 itraw = itstate_get(g_uni.pre_cpu.xpsr);
        printf("[UNICORN_DIFF] pre_xpsr=0x%08lx itstate=0x%02x\n",
               (unsigned long)g_uni.pre_cpu.xpsr,
               (unsigned)itraw);
    }
    printf("[UNICORN_DIFF] %s m33mu=0x%08lx unicorn=0x%08lx\n",
           label, (unsigned long)m_val, (unsigned long)u_val);
}

static void it_mask_to_pattern(mm_u8 cond, mm_u8 mask, mm_u8 *pattern_out, mm_u8 *remaining_out)
{
    mm_u8 remaining = 0;
    mm_u8 pattern = 0;
    if (mask != 0u) {
        mm_u8 i;
        for (i = 0u; i < 4u; ++i) {
            if (((mask >> i) & 1u) != 0u) {
                remaining = (mm_u8)(4u - i);
                break;
            }
        }
        if (remaining != 0u) {
            pattern = 1u;
            for (i = 1u; i < remaining; ++i) {
                mm_u8 bit = (mm_u8)((mask >> (4u - i)) & 1u);
                mm_u8 pat_bit = (bit != 0u) ? 0u : 1u;
                pattern |= (mm_u8)(pat_bit << i);
            }
            if ((cond & 1u) != 0u && remaining > 1u) {
                mm_u8 flip = (mm_u8)(((1u << remaining) - 1u) & 0x0eu);
                pattern ^= flip;
            }
        }
    }
    if (pattern_out) {
        *pattern_out = pattern;
    }
    if (remaining_out) {
        *remaining_out = remaining;
    }
}

static void unicorn_report_context(const struct mm_cpu *cpu, uc_engine *uc)
{
    mm_u32 regs_m[16];
    mm_u32 regs_u[16];
    mm_u32 pc_u = 0;
    mm_u32 r4_u_explicit = 0;
    mm_u32 xpsr_u = 0;
    int i;

    for (i = 0; i < 13; ++i) {
        regs_m[i] = cpu->r[i];
        (void)uc_reg_read(uc, UC_ARM_REG_R0 + i, &regs_u[i]);
    }
    regs_m[13] = cpu->r[13];
    regs_m[14] = cpu->r[14];
    regs_m[15] = cpu->r[15];
    (void)uc_reg_read(uc, UC_ARM_REG_SP, &regs_u[13]);
    (void)uc_reg_read(uc, UC_ARM_REG_LR, &regs_u[14]);
    (void)uc_reg_read(uc, UC_ARM_REG_PC, &regs_u[15]);
    (void)uc_reg_read(uc, UC_ARM_REG_PC, &pc_u);
    (void)uc_reg_read(uc, UC_ARM_REG_R4, &r4_u_explicit);
    (void)uc_reg_read(uc, UC_ARM_REG_XPSR, &xpsr_u);

    printf("[UNICORN_CTX] m33mu pc=0x%08lx lr=0x%08lx sp=0x%08lx xpsr=0x%08lx\n",
           (unsigned long)regs_m[15], (unsigned long)regs_m[14],
           (unsigned long)regs_m[13], (unsigned long)cpu->xpsr);
    printf("[UNICORN_CTX] unicorn pc=0x%08lx r15=0x%08lx lr=0x%08lx sp=0x%08lx xpsr=0x%08lx\n",
           (unsigned long)pc_u, (unsigned long)regs_u[15],
           (unsigned long)regs_u[14], (unsigned long)regs_u[13],
           (unsigned long)xpsr_u);
    if (regs_u[4] != r4_u_explicit) {
        printf("[UNICORN_CTX] r4 read mismatch regset=0x%08lx explicit=0x%08lx\n",
               (unsigned long)regs_u[4], (unsigned long)r4_u_explicit);
    }

    for (i = 0; i < 13; ++i) {
        if (regs_m[i] != regs_u[i]) {
            char name[8];
            snprintf(name, sizeof(name), "r%d", i);
            print_reg_diff(name, regs_m[i], regs_u[i]);
        }
    }
}

static mm_bool compare_stack(const struct mm_cpu *cpu, uc_engine *uc,
                             const struct mm_memmap *map, mm_u32 window)
{
    mm_u32 sp = mm_cpu_get_active_sp(cpu);
    mm_u32 start = sp;
    mm_u32 len = window;
    mm_u8 buf_m[512];
    mm_u8 buf_u[512];
    mm_u32 i;

    if (window == 0u) return MM_TRUE;
    if (len > sizeof(buf_m)) len = (mm_u32)sizeof(buf_m);

    if (!addr_in_ram(map, start) || !addr_in_ram(map, start + len - 1u)) {
        return MM_TRUE; /* out of RAM; skip */
    }
    if (!mm_read_bytes(map, cpu->sec_state, start, buf_m, len)) {
        return MM_TRUE;
    }
    if (uc_mem_read(uc, (uint64_t)start, buf_u, len) != UC_ERR_OK) {
        return MM_TRUE;
    }
    for (i = 0; i < len; ++i) {
        if (buf_m[i] != buf_u[i]) {
            printf("[UNICORN_DIFF] stack addr=0x%08lx m33mu=0x%02x unicorn=0x%02x\n",
                   (unsigned long)(start + i), buf_m[i], buf_u[i]);
            return MM_FALSE;
        }
    }
    return MM_TRUE;
}

static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type,
                             uint64_t address, int size, int64_t value, void *user_data)
{
    struct mm_unicorn_state *st = (struct mm_unicorn_state *)user_data;
    mm_u32 addr = (mm_u32)address;
    mm_u32 val = (mm_u32)value;
    uc_err err;

    if (st == 0 || st->map == 0) return false;

    if (type == UC_MEM_READ_UNMAPPED || type == UC_MEM_FETCH_UNMAPPED) {
        mm_u32 tmp = 0;
        mm_bool ok = MM_FALSE;
        if (!st->read_hook_logged) {
            printf("[UNICORN_UNMAPPED] type=%d addr=0x%08lx size=%d\n",
                   (int)type, (unsigned long)addr, size);
            st->read_hook_logged = MM_TRUE;
        }
        ok = mm_memmap_read(st->map, st->sec_state, addr, (mm_u32)size, &tmp);
        if (!ok) {
            if (mmio_bus_peek(&st->map->mmio, addr, (mm_u32)size, &tmp) == MMIO_PEEK_OK) {
                ok = MM_TRUE;
            }
        }
        if (!ok) return false;
        err = map_page(uc, addr);
        (void)err;
        if (!uc_write_mem(uc, addr, (mm_u32)size, tmp)) {
            return false;
        }
        return true;
    }

    if (type == UC_MEM_WRITE_UNMAPPED) {
        err = map_page(uc, addr);
        (void)err;
        (void)uc_write_mem(uc, addr, (mm_u32)size, val);
        return true;
    }

    return false;
}

static void hook_mem_read(uc_engine *uc, uc_mem_type type,
                          uint64_t address, int size, int64_t value, void *user_data)
{
    struct mm_unicorn_state *st = (struct mm_unicorn_state *)user_data;
    mm_u32 addr = (mm_u32)address;
    mm_u32 tmp = 0;
    (void)type;
    (void)value;
    if (st == 0 || st->map == 0) {
        return;
    }
    if (!mm_memmap_read(st->map, st->sec_state, addr, (mm_u32)size, &tmp)) {
        return;
    }
    (void)uc_write_mem(uc, addr, (mm_u32)size, tmp);
}

static void hook_mem_write(uc_engine *uc, uc_mem_type type,
                           uint64_t address, int size, int64_t value, void *user_data)
{
    struct mm_unicorn_state *st = (struct mm_unicorn_state *)user_data;
    mm_u32 addr = (mm_u32)address;
    mm_u32 val = (mm_u32)value;
    mm_u32 old = 0;
    mm_bool has_old = MM_FALSE;

    (void)type;
    if (st == 0 || st->map == 0) {
        return;
    }
    if (!addr_in_ram(st->map, addr)) {
        return;
    }
    if (uc_mem_read(uc, (uint64_t)addr, &old, (size_t)size) == UC_ERR_OK) {
        has_old = MM_TRUE;
    } else if (mm_memmap_read(st->map, st->sec_state, addr, (mm_u32)size, &old)) {
        has_old = MM_TRUE;
    }
    record_write(st->uc_writes, &st->uc_write_count, addr, (mm_u32)size, val, has_old, old);
}

static void hook_intr(uc_engine *uc, uint32_t intno, void *user_data)
{
    struct mm_unicorn_state *st = (struct mm_unicorn_state *)user_data;
    mm_u32 pc = 0;
    (void)uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    if (st != 0 && !st->intr_seen) {
        st->intr_seen = MM_TRUE;
        st->intr_no = (mm_u32)intno;
        st->intr_pc = pc;
    }
    uc_emu_stop(uc);
}

static bool hook_invalid_insn(uc_engine *uc, void *user_data)
{
    struct mm_unicorn_state *st = (struct mm_unicorn_state *)user_data;
    mm_u32 pc = 0;
    (void)st;
    (void)uc;
    (void)uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    printf("[UNICORN_INVALID] pc=0x%08lx\n", (unsigned long)pc);
    return false;
}

static mm_bool compare_and_commit_writes(struct mm_memmap *map)
{
    mm_u32 i;

    if (g_uni.pending_overflow) {
        printf("[UNICORN_DIFF] pending write overflow\n");
        return MM_FALSE;
    }
    if (g_uni.m33mu_write_count != g_uni.uc_write_count) {
        printf("[UNICORN_DIFF] write count m33mu=%lu unicorn=%lu\n",
               (unsigned long)g_uni.m33mu_write_count,
               (unsigned long)g_uni.uc_write_count);
        return MM_FALSE;
    }
    for (i = 0u; i < g_uni.m33mu_write_count; ++i) {
        struct mm_unicorn_pending_write *mw = &g_uni.m33mu_writes[i];
        struct mm_unicorn_pending_write *uw = &g_uni.uc_writes[i];
        mm_u32 uval = 0;
        if (uc_mem_read(g_uni.uc, uw->addr, &uval, uw->size) != UC_ERR_OK) {
            printf("[UNICORN_DIFF] read failed addr=0x%08lx size=%lu\n",
                   (unsigned long)uw->addr,
                   (unsigned long)uw->size);
            return MM_FALSE;
        }
        uw->value = uval;
        if (mw->addr != uw->addr || mw->size != uw->size || mw->value != uw->value) {
            printf("[UNICORN_DIFF] write[%lu] m33mu addr=0x%08lx size=%lu val=0x%08lx\n",
                   (unsigned long)i,
                   (unsigned long)mw->addr,
                   (unsigned long)mw->size,
                   (unsigned long)mw->value);
            printf("[UNICORN_DIFF] write[%lu] unicorn addr=0x%08lx size=%lu val=0x%08lx\n",
                   (unsigned long)i,
                   (unsigned long)uw->addr,
                   (unsigned long)uw->size,
                   (unsigned long)uw->value);
            return MM_FALSE;
        }
    }
    for (i = 0u; i < g_uni.m33mu_write_count; ++i) {
        struct mm_unicorn_pending_write *mw = &g_uni.m33mu_writes[i];
        (void)mm_memmap_write_ram_raw(map, mw->addr, mw->size, mw->value);
        (void)uc_write_mem(g_uni.uc, mw->addr, mw->size, mw->value);
    }
    pending_clear();
    return MM_TRUE;
}

static void sync_stack_window(const struct mm_cpu *cpu, uc_engine *uc,
                              const struct mm_memmap *map, mm_u32 window)
{
    mm_u32 sp = mm_cpu_get_active_sp(cpu);
    mm_u32 len = window;
    mm_u8 buf[512];
    if (window == 0u) return;
    if (len > sizeof(buf)) len = (mm_u32)sizeof(buf);
    if (!addr_in_ram(map, sp) || !addr_in_ram(map, sp + len - 1u)) {
        return;
    }
    if (!mm_read_bytes(map, cpu->sec_state, sp, buf, len)) {
        return;
    }
    (void)uc_mem_write(uc, (uint64_t)sp, buf, len);
}

static void unicorn_write_regs(const struct mm_cpu *src_cpu, mm_u32 pc_set, mm_bool use_scratch)
{
    int i;
    mm_u32 sp = mm_cpu_get_active_sp(src_cpu);
    mm_u32 control = mm_cpu_get_control(src_cpu, src_cpu->sec_state);
    mm_u32 msp = mm_cpu_get_msp(src_cpu, src_cpu->sec_state);
    mm_u32 psp = mm_cpu_get_psp(src_cpu, src_cpu->sec_state);
    mm_u32 cpsr_mask = 0xF8000000u | 0x06000000u;
    mm_u32 cpsr = (src_cpu->xpsr & cpsr_mask) | 0x20u;
    mm_u32 pc_thumb = pc_set | 1u;
    (void)uc_reg_write(g_uni.uc, UC_ARM_REG_PC, &pc_thumb);
    (void)uc_reg_write(g_uni.uc, UC_ARM_REG_R15, &pc_thumb);
    for (i = 0; i < 13; ++i) {
        (void)uc_reg_write(g_uni.uc, UC_ARM_REG_R0 + i, &src_cpu->r[i]);
    }
    {
        mm_u32 lr = src_cpu->r[14];
        (void)uc_reg_write(g_uni.uc, UC_ARM_REG_LR, &lr);
    }
    if (use_scratch) {
        (void)uc_reg_write(g_uni.uc, UC_ARM_REG_SP, &sp);
        (void)uc_reg_write(g_uni.uc, UC_ARM_REG_R13, &sp);
    } else {
        (void)uc_reg_write(g_uni.uc, UC_ARM_REG_CONTROL, &control);
        (void)uc_reg_write(g_uni.uc, UC_ARM_REG_MSP, &msp);
        (void)uc_reg_write(g_uni.uc, UC_ARM_REG_PSP, &psp);
        (void)uc_reg_write(g_uni.uc, UC_ARM_REG_SP, &sp);
        (void)uc_reg_write(g_uni.uc, UC_ARM_REG_R13, &sp);
    }
    (void)uc_reg_write(g_uni.uc, UC_ARM_REG_CPSR, &cpsr);
}

mm_bool mm_unicorn_available(void)
{
    return MM_TRUE;
}

mm_bool mm_unicorn_active(void)
{
    return g_uni.active;
}

mm_bool mm_unicorn_configure(mm_u32 entry_pc, mm_u32 stack_window, mm_u32 max_steps)
{
    g_uni.entry_pc = entry_pc & ~1u;
    g_uni.stack_window = stack_window;
    g_uni.max_steps = max_steps;
    return MM_TRUE;
}

mm_bool mm_unicorn_maybe_start(struct mm_cpu *cpu, struct mm_memmap *map)
{
    uc_err err;
    mm_u32 pc;
    int i;

    if (cpu == 0 || map == 0) return MM_FALSE;
    if (g_uni.active) return MM_TRUE;
    pc = cpu->r[15] & ~1u;
    if (pc != g_uni.entry_pc) return MM_FALSE;

    if (g_uni.uc != 0) {
        uc_close(g_uni.uc);
        g_uni.uc = 0;
    }
    g_uni.entry_pc = pc;
    g_uni.entry_lr = cpu->r[14] & ~1u;
    g_uni.stack_window = (g_uni.stack_window == 0u) ? 256u : g_uni.stack_window;
    g_uni.max_steps = (g_uni.max_steps == 0u) ? 10000000u : g_uni.max_steps;
    g_uni.sec_state = cpu->sec_state;
    g_uni.map = map;
    g_uni.use_scratch = MM_FALSE;
    g_uni.scratch_base = UNICORN_SCRATCH_BASE;
    g_uni.map_flash = MM_TRUE;
    err = uc_open(UC_ARCH_ARM, UC_MODE_THUMB, &g_uni.uc);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "[UNICORN] uc_open failed: %s\n", uc_strerror(err));
        return MM_FALSE;
    }

    if (g_uni.map_flash && map->flash.buffer != 0) {
        if (map->flash_size_s > 0u) {
            err = map_region(g_uni.uc, map->flash_base_s, map->flash_size_s, UC_PROT_ALL);
            if (err == UC_ERR_OK) {
                (void)uc_mem_write(g_uni.uc, (uint64_t)map->flash_base_s,
                                   map->flash.buffer, (size_t)map->flash_size_s);
            }
        }
        if (map->flash_base_ns != map->flash_base_s && map->flash_size_ns > 0u) {
            err = map_region(g_uni.uc, map->flash_base_ns, map->flash_size_ns, UC_PROT_ALL);
            if (err == UC_ERR_OK) {
                (void)uc_mem_write(g_uni.uc, (uint64_t)map->flash_base_ns,
                                   map->flash.buffer, (size_t)map->flash_size_ns);
            }
        }
    }
    if (map->ram.buffer != 0 && map->ram.length > 0u) {
        if (map->ram_region_count > 0u) {
            mm_u32 i;
            for (i = 0; i < map->ram_region_count; ++i) {
                const struct mm_ram_region *r = &map->ram_regions[i];
                mm_u32 offset = map->ram_region_offsets[i];
                if (r->size == 0u) {
                    continue;
                }
                if (r->base_s != 0u) {
                    err = map_region(g_uni.uc, r->base_s, r->size, UC_PROT_ALL);
                    if (err == UC_ERR_OK) {
                        (void)uc_mem_write(g_uni.uc, (uint64_t)r->base_s,
                                           map->ram.buffer + offset,
                                           (size_t)r->size);
                    }
                }
                if (r->base_ns != 0u && r->base_ns != r->base_s) {
                    err = map_region(g_uni.uc, r->base_ns, r->size, UC_PROT_ALL);
                    if (err == UC_ERR_OK) {
                        (void)uc_mem_write(g_uni.uc, (uint64_t)r->base_ns,
                                           map->ram.buffer + offset,
                                           (size_t)r->size);
                    }
                }
            }
        } else {
            if (map->ram_size_s > 0u) {
                err = map_region(g_uni.uc, map->ram_base_s, map->ram_size_s, UC_PROT_ALL);
                if (err == UC_ERR_OK) {
                    (void)uc_mem_write(g_uni.uc, (uint64_t)map->ram_base_s,
                                       map->ram.buffer, (size_t)map->ram_size_s);
                }
            }
            if (map->ram_base_ns != map->ram_base_s && map->ram_size_ns > 0u) {
                err = map_region(g_uni.uc, map->ram_base_ns, map->ram_size_ns, UC_PROT_ALL);
                if (err == UC_ERR_OK) {
                    (void)uc_mem_write(g_uni.uc, (uint64_t)map->ram_base_ns,
                                       map->ram.buffer, (size_t)map->ram_size_ns);
                }
            }
        }
    }

    err = map_region(g_uni.uc, g_uni.scratch_base, UNICORN_PAGE_SIZE, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        printf("[UNICORN] scratch map failed base=0x%08lx err=%s\n",
               (unsigned long)g_uni.scratch_base, uc_strerror(err));
    }

    {
        mm_u32 sp = mm_cpu_get_active_sp(cpu);
        mm_u32 control = mm_cpu_get_control(cpu, cpu->sec_state);
        mm_u32 msp = mm_cpu_get_msp(cpu, cpu->sec_state);
        mm_u32 psp = mm_cpu_get_psp(cpu, cpu->sec_state);
        mm_u32 primask = 1u;
        mm_u32 faultmask = 1u;
        mm_u32 basepri = 0xffu;
        (void)uc_reg_write(g_uni.uc, UC_ARM_REG_CONTROL, &control);
        (void)uc_reg_write(g_uni.uc, UC_ARM_REG_MSP, &msp);
        (void)uc_reg_write(g_uni.uc, UC_ARM_REG_PSP, &psp);
        (void)uc_reg_write(g_uni.uc, UC_ARM_REG_SP, &sp);
        (void)uc_reg_write(g_uni.uc, UC_ARM_REG_R13, &sp);
        (void)uc_reg_write(g_uni.uc, UC_ARM_REG_PRIMASK, &primask);
        (void)uc_reg_write(g_uni.uc, UC_ARM_REG_FAULTMASK, &faultmask);
        (void)uc_reg_write(g_uni.uc, UC_ARM_REG_BASEPRI, &basepri);
        printf("[UNICORN] regs sp=0x%08lx msp=0x%08lx psp=0x%08lx control=0x%08lx\n",
               (unsigned long)sp, (unsigned long)msp,
               (unsigned long)psp, (unsigned long)control);
    }
    for (i = 0; i < 13; ++i) {
        mm_u32 regv = cpu->r[i];
        (void)uc_reg_write(g_uni.uc, UC_ARM_REG_R0 + i, &regv);
    }
    {
        mm_u32 sp = mm_cpu_get_active_sp(cpu);
        mm_u32 lr = cpu->r[14];
        mm_u32 pc_set = cpu->r[15] | 1u;
        (void)uc_reg_write(g_uni.uc, UC_ARM_REG_SP, &sp);
        (void)uc_reg_write(g_uni.uc, UC_ARM_REG_R13, &sp);
        (void)uc_reg_write(g_uni.uc, UC_ARM_REG_LR, &lr);
        (void)uc_reg_write(g_uni.uc, UC_ARM_REG_PC, &pc_set);
        (void)uc_reg_write(g_uni.uc, UC_ARM_REG_R15, &pc_set);
    }
    {
        mm_u32 cpsr_mask = 0xF8000000u | 0x06000000u;
        mm_u32 cpsr = (cpu->xpsr & cpsr_mask) | 0x20u; /* ensure Thumb, clear E */
        (void)uc_reg_write(g_uni.uc, UC_ARM_REG_CPSR, &cpsr);
    }

    {
        uc_hook hook;
        (void)uc_hook_add(g_uni.uc, &hook, UC_HOOK_MEM_UNMAPPED, hook_mem_invalid, &g_uni, 1, 0);
        (void)uc_hook_add(g_uni.uc, &hook, UC_HOOK_MEM_WRITE, hook_mem_write, &g_uni, 1, 0);
        (void)uc_hook_add(g_uni.uc, &hook, UC_HOOK_MEM_READ | UC_HOOK_MEM_FETCH, hook_mem_read, &g_uni, 1, 0);
        (void)uc_hook_add(g_uni.uc, &hook, UC_HOOK_INTR, hook_intr, &g_uni, 1, 0);
        (void)uc_hook_add(g_uni.uc, &hook, UC_HOOK_INSN_INVALID, hook_invalid_insn, &g_uni, 1, 0);
    }

    g_uni.active = MM_TRUE;
    g_uni.steps = 0u;
    pending_clear();
    g_uni.read_hook_logged = MM_FALSE;
    g_uni.saved_primask_valid = MM_FALSE;
    {
        mm_u8 raw = itstate_get(cpu->xpsr);
        mm_u8 mask = (mm_u8)(raw & 0x0fu);
        mm_u8 cond = (mm_u8)(raw >> 4);
        g_uni.itstate_raw = raw;
        g_uni.it_cond = cond;
        it_mask_to_pattern(cond, mask, &g_uni.it_pattern, &g_uni.it_remaining);
    }
    printf("[UNICORN] start pc=0x%08lx lr=0x%08lx\n",
           (unsigned long)g_uni.entry_pc, (unsigned long)g_uni.entry_lr);
    return MM_TRUE;
}

mm_unicorn_step_result mm_unicorn_step_compare(struct mm_cpu *cpu,
                                               struct mm_memmap *map,
                                               const struct mm_fetch_result *fetch,
                                               const struct mm_decoded *dec,
                                               mm_bool execute_it)
{
    uc_err err;
    mm_u32 pc_u = 0;
    mm_u32 xpsr_u = 0;
    mm_bool skip_exec = MM_FALSE;
    mm_u32 pc_m;
    mm_u32 xpsr_m;
    int i;
    mm_u32 step_index;
    const struct mm_cpu *src_cpu = cpu;

    if (!g_uni.active || g_uni.uc == 0) return MM_UNICORN_STEP_OK;
    if (cpu == 0 || map == 0) return MM_UNICORN_STEP_FAIL;
    if (!g_uni.saved_primask_valid) {
        g_uni.saved_primask_s = cpu->primask_s;
        g_uni.saved_primask_ns = cpu->primask_ns;
        g_uni.saved_primask_valid = MM_TRUE;
        cpu->primask_s = 1u;
        cpu->primask_ns = 1u;
    }

    step_index = g_uni.steps;
    if (g_uni.steps++ >= g_uni.max_steps) {
        printf("[UNICORN] stop: max steps reached (%lu)\n", (unsigned long)g_uni.max_steps);
        unicorn_report_context(cpu, g_uni.uc);
        unicorn_restore_cpu(cpu);
        mm_unicorn_stop();
        return MM_UNICORN_STEP_FAIL;
    }

    if (g_uni.pre_valid) {
        src_cpu = &g_uni.pre_cpu;
    }

    err = uc_reg_read(g_uni.uc, UC_ARM_REG_PC, &pc_u);
    if (err != UC_ERR_OK) {
        printf("[UNICORN] failed to read PC: %s\n", uc_strerror(err));
        unicorn_restore_cpu(cpu);
        mm_unicorn_stop();
        return MM_UNICORN_STEP_FAIL;
    }

    if (!execute_it && dec != 0) {
        /* Skip execution: advance Unicorn PC and IT state to match m33mu. */
        pc_u = (pc_u & ~1u) + dec->len;
        err = uc_reg_write(g_uni.uc, UC_ARM_REG_PC, &pc_u);
        if (err != UC_ERR_OK) {
            printf("[UNICORN] failed to write PC: %s\n", uc_strerror(err));
            unicorn_restore_cpu(cpu);
            mm_unicorn_stop();
            return MM_UNICORN_STEP_FAIL;
        }
        if (g_uni.it_remaining > 0u && dec->kind != MM_OP_IT) {
            g_uni.it_pattern >>= 1;
            g_uni.it_remaining--;
            g_uni.itstate_raw = itstate_advance(g_uni.itstate_raw);
        }
        return MM_UNICORN_STEP_OK;
    }

    if (fetch != 0 && dec != 0) {
        mm_u8 insn[4];
        mm_u32 len = dec->len;
        mm_u32 write_pc = fetch->pc_fetch;
        mm_bool exec_it = MM_TRUE;
        mm_bool cond_true = MM_FALSE;
        if (g_uni.it_remaining > 0u && itstate_get(src_cpu->xpsr) == 0u) {
            g_uni.it_remaining = 0u;
            g_uni.it_pattern = 0u;
            g_uni.it_cond = 0u;
            g_uni.itstate_raw = 0u;
        }
        if (dec->kind == MM_OP_IT) {
            mm_u8 cond = (mm_u8)((dec->imm >> 4) & 0x0fu);
            mm_u8 mask = (mm_u8)(dec->imm & 0x0fu);
            g_uni.it_cond = cond;
            g_uni.itstate_raw = (mm_u8)((cond << 4) | mask);
            it_mask_to_pattern(cond, mask, &g_uni.it_pattern, &g_uni.it_remaining);
            exec_it = MM_FALSE;
        } else if (g_uni.it_remaining > 0u) {
            mm_bool n = (src_cpu->xpsr & (1u << 31)) != 0u;
            mm_bool z = (src_cpu->xpsr & (1u << 30)) != 0u;
            mm_bool c = (src_cpu->xpsr & (1u << 29)) != 0u;
            mm_bool v = (src_cpu->xpsr & (1u << 28)) != 0u;
            switch (g_uni.it_cond) {
                case MM_COND_EQ: cond_true = z; break;
                case MM_COND_NE: cond_true = !z; break;
                case MM_COND_CS: cond_true = c; break;
                case MM_COND_CC: cond_true = !c; break;
                case MM_COND_MI: cond_true = n; break;
                case MM_COND_PL: cond_true = !n; break;
                case MM_COND_VS: cond_true = v; break;
                case MM_COND_VC: cond_true = !v; break;
                case MM_COND_HI: cond_true = c && !z; break;
                case MM_COND_LS: cond_true = !c || z; break;
                case MM_COND_GE: cond_true = (n == v); break;
                case MM_COND_LT: cond_true = (n != v); break;
                case MM_COND_GT: cond_true = !z && (n == v); break;
                case MM_COND_LE: cond_true = z || (n != v); break;
                case MM_COND_AL: cond_true = MM_TRUE; break;
                default: cond_true = MM_FALSE; break;
            }
            exec_it = ((g_uni.it_pattern & 0x1u) != 0u) ? cond_true : !cond_true;
        }
        {
            mm_u32 pc_set = g_uni.use_scratch ? g_uni.scratch_base : fetch->pc_fetch;
            write_pc = pc_set;
            pc_u = pc_set | 1u;
            unicorn_write_regs(src_cpu, pc_set, g_uni.use_scratch);
            {
                mm_u32 pc_chk = 0;
                if (uc_reg_read(g_uni.uc, UC_ARM_REG_R15, &pc_chk) == UC_ERR_OK &&
                    (pc_chk & ~1u) != (pc_u & ~1u)) {
                    printf("[UNICORN] pc readback mismatch wrote=0x%08lx got=0x%08lx\n",
                           (unsigned long)pc_u, (unsigned long)pc_chk);
                }
            }
        }
        sync_stack_window(src_cpu, g_uni.uc, map, g_uni.stack_window);
        if (g_uni.use_scratch) {
            if (len == 2u) {
                insn[0] = (mm_u8)(dec->raw & 0xffu);
                insn[1] = (mm_u8)((dec->raw >> 8) & 0xffu);
                if (uc_mem_write(g_uni.uc, (uint64_t)write_pc, insn, 2u) != UC_ERR_OK) {
                    printf("[UNICORN] insn write failed pc=0x%08lx\n",
                           (unsigned long)write_pc);
                }
            } else if (len == 4u) {
                mm_u16 hw1 = (mm_u16)((dec->raw >> 16) & 0xffffu);
                mm_u16 hw2 = (mm_u16)(dec->raw & 0xffffu);
                insn[0] = (mm_u8)(hw1 & 0xffu);
                insn[1] = (mm_u8)((hw1 >> 8) & 0xffu);
                insn[2] = (mm_u8)(hw2 & 0xffu);
                insn[3] = (mm_u8)((hw2 >> 8) & 0xffu);
                if (uc_mem_write(g_uni.uc, (uint64_t)write_pc, insn, 4u) != UC_ERR_OK) {
                    printf("[UNICORN] insn write failed pc=0x%08lx\n",
                           (unsigned long)write_pc);
                }
            }
            {
                mm_u8 rb[4];
                mm_u32 rb_len = (len == 4u) ? 4u : 2u;
                if (uc_mem_read(g_uni.uc, (uint64_t)write_pc, rb, rb_len) != UC_ERR_OK) {
                    printf("[UNICORN] insn readback failed pc=0x%08lx\n",
                           (unsigned long)write_pc);
                }
            }
        }
        if (!exec_it) {
            mm_u32 next_pc = (fetch->pc_fetch & ~1u) + len;
            mm_u32 pc_thumb = next_pc | 1u;
            (void)uc_reg_write(g_uni.uc, UC_ARM_REG_PC, &pc_thumb);
            (void)uc_reg_write(g_uni.uc, UC_ARM_REG_R15, &pc_thumb);
            pc_u = pc_thumb;
            skip_exec = MM_TRUE;
        }
        if (g_uni.it_remaining > 0u && dec->kind != MM_OP_IT) {
            g_uni.it_pattern >>= 1;
            g_uni.it_remaining--;
            g_uni.itstate_raw = itstate_advance(g_uni.itstate_raw);
        }
        if (!exec_it) {
            goto unicorn_compare;
        }
    }
    else {
        mm_u32 pc_set = src_cpu->r[15] & ~1u;
        pc_u = pc_set | 1u;
        unicorn_write_regs(src_cpu, pc_set, g_uni.use_scratch);
        sync_stack_window(src_cpu, g_uni.uc, map, g_uni.stack_window);
    }

    err = uc_emu_start(g_uni.uc, (uint64_t)(pc_u | 1u), 0, 0, 1);
    if (err != UC_ERR_OK) {
        printf("[UNICORN] step failed: %s\n", uc_strerror(err));
        unicorn_report_context(cpu, g_uni.uc);
        unicorn_restore_cpu(cpu);
        mm_unicorn_stop();
        return MM_UNICORN_STEP_FAIL;
    }

    if (g_uni.intr_seen) {
        printf("[UNICORN_INTR] intno=%lu pc=0x%08lx\n",
               (unsigned long)g_uni.intr_no,
               (unsigned long)g_uni.intr_pc);
        unicorn_report_context(cpu, g_uni.uc);
        unicorn_restore_cpu(cpu);
        mm_unicorn_stop();
        return MM_UNICORN_STEP_FAIL;
    }

    (void)uc_reg_read(g_uni.uc, UC_ARM_REG_PC, &pc_u);
    (void)uc_reg_read(g_uni.uc, UC_ARM_REG_XPSR, &xpsr_u);

unicorn_compare:
    if (skip_exec) {
        (void)uc_reg_read(g_uni.uc, UC_ARM_REG_PC, &pc_u);
        (void)uc_reg_read(g_uni.uc, UC_ARM_REG_XPSR, &xpsr_u);
    }
    pc_m = cpu->r[15] & ~1u;
    xpsr_m = cpu->xpsr & UNICORN_XPSR_MASK;
    if (g_uni.use_scratch && fetch != 0) {
        mm_u32 delta_m = pc_m - (fetch->pc_fetch & ~1u);
        mm_u32 delta_u = (pc_u & ~1u) - g_uni.scratch_base;
        if (delta_u != delta_m) {
            printf("[UNICORN_DIFF] PC(delta) m33mu=0x%08lx unicorn=0x%08lx\n",
                   (unsigned long)delta_m, (unsigned long)delta_u);
            if (fetch != 0 && dec != 0) {
                printf("[UNICORN_DIFF] last pc=0x%08lx len=%u raw=0x%08lx kind=%d\n",
                       (unsigned long)fetch->pc_fetch,
                       (unsigned)dec->len,
                       (unsigned long)dec->raw,
                       (int)dec->kind);
            }
            unicorn_report_context(cpu, g_uni.uc);
            unicorn_restore_cpu(cpu);
            mm_unicorn_stop();
            return MM_UNICORN_STEP_FAIL;
        }
    } else if (dec != 0 && dec->kind == MM_OP_IT) {
        mm_u32 pc_u_aligned = pc_u & ~1u;
        if (pc_u_aligned != pc_m && pc_u_aligned != (pc_m + 2u)) {
            printf("[UNICORN_DIFF] PC m33mu=0x%08lx unicorn=0x%08lx\n",
                   (unsigned long)pc_m, (unsigned long)pc_u_aligned);
            if (fetch != 0 && dec != 0) {
                printf("[UNICORN_DIFF] last pc=0x%08lx len=%u raw=0x%08lx kind=%d\n",
                       (unsigned long)fetch->pc_fetch,
                       (unsigned)dec->len,
                       (unsigned long)dec->raw,
                       (int)dec->kind);
            }
            unicorn_report_context(cpu, g_uni.uc);
            unicorn_restore_cpu(cpu);
            mm_unicorn_stop();
            return MM_UNICORN_STEP_FAIL;
        }
    } else if ((pc_u & ~1u) != pc_m) {
        printf("[UNICORN_DIFF] PC m33mu=0x%08lx unicorn=0x%08lx\n",
               (unsigned long)pc_m, (unsigned long)(pc_u & ~1u));
        if (fetch != 0 && dec != 0) {
            printf("[UNICORN_DIFF] last pc=0x%08lx len=%u raw=0x%08lx kind=%d\n",
                   (unsigned long)fetch->pc_fetch,
                   (unsigned)dec->len,
                   (unsigned long)dec->raw,
                   (int)dec->kind);
        }
        unicorn_report_context(cpu, g_uni.uc);
        unicorn_restore_cpu(cpu);
        mm_unicorn_stop();
        return MM_UNICORN_STEP_FAIL;
    }

    {
        mm_u32 mask = UNICORN_XPSR_MASK;
        if (dec != 0 && dec->kind == MM_OP_IT) {
            mask &= ~0x0000FC00u; /* Unicorn does not update ITSTATE reliably. */
        }
        if ((xpsr_u & mask) != (xpsr_m & mask)) {
            printf("[UNICORN_DIFF] step=%lu\n", (unsigned long)step_index);
            print_reg_diff("xpsr", xpsr_m & mask, xpsr_u & mask);
            unicorn_report_context(cpu, g_uni.uc);
            unicorn_restore_cpu(cpu);
            mm_unicorn_stop();
            return MM_UNICORN_STEP_FAIL;
        }
    }

    for (i = 0; i < 13; ++i) {
        mm_u32 u_val = 0;
        (void)uc_reg_read(g_uni.uc, UC_ARM_REG_R0 + i, &u_val);
        if (cpu->r[i] != u_val) {
            char name[8];
            snprintf(name, sizeof(name), "r%d", i);
            printf("[UNICORN_DIFF] step=%lu\n", (unsigned long)step_index);
            print_reg_diff(name, cpu->r[i], u_val);
            if (dec != 0 && dec->kind == MM_OP_LDR_IMM) {
                mm_u32 addr = cpu->r[dec->rn] + dec->imm;
                mm_u32 mem = 0;
                mm_bool ok = mm_memmap_read(map, cpu->sec_state, addr, 4u, &mem);
                printf("[UNICORN_DIFF] ldr addr=0x%08lx mem=%s0x%08lx rn=%u imm=0x%lx\n",
                       (unsigned long)addr,
                       ok ? "" : "!!",
                       (unsigned long)mem,
                       (unsigned)dec->rn,
                       (unsigned long)dec->imm);
            }
            if (fetch != 0 && dec != 0) {
                printf("[UNICORN_DIFF] last pc=0x%08lx len=%u raw=0x%08lx kind=%d\n",
                       (unsigned long)fetch->pc_fetch,
                       (unsigned)dec->len,
                       (unsigned long)dec->raw,
                       (int)dec->kind);
            }
            unicorn_report_context(cpu, g_uni.uc);
            unicorn_restore_cpu(cpu);
            mm_unicorn_stop();
            return MM_UNICORN_STEP_FAIL;
        }
    }

    if (!compare_and_commit_writes(map)) {
        printf("[UNICORN_DIFF] step=%lu\n", (unsigned long)step_index);
        if (fetch != 0 && dec != 0) {
            printf("[UNICORN_DIFF] last pc=0x%08lx len=%u raw=0x%08lx kind=%d\n",
                   (unsigned long)fetch->pc_fetch,
                   (unsigned)dec->len,
                   (unsigned long)dec->raw,
                   (int)dec->kind);
        }
        unicorn_report_context(cpu, g_uni.uc);
        unicorn_restore_cpu(cpu);
        mm_unicorn_stop();
        return MM_UNICORN_STEP_FAIL;
    }

    if (!compare_stack(cpu, g_uni.uc, map, g_uni.stack_window)) {
        printf("[UNICORN_DIFF] step=%lu\n", (unsigned long)step_index);
        if (fetch != 0 && dec != 0) {
            printf("[UNICORN_DIFF] last pc=0x%08lx len=%u raw=0x%08lx kind=%d\n",
                   (unsigned long)fetch->pc_fetch,
                   (unsigned)dec->len,
                   (unsigned long)dec->raw,
                   (int)dec->kind);
        }
        unicorn_report_context(cpu, g_uni.uc);
        unicorn_restore_cpu(cpu);
        mm_unicorn_stop();
        return MM_UNICORN_STEP_FAIL;
    }

    if ((cpu->r[15] & ~1u) == g_uni.entry_lr) {
        printf("[UNICORN] done: return reached (pc=0x%08lx)\n",
               (unsigned long)(cpu->r[15] & ~1u));
        unicorn_restore_cpu(cpu);
        mm_unicorn_stop();
        return MM_UNICORN_STEP_DONE;
    }

    return MM_UNICORN_STEP_OK;
}

void mm_unicorn_stop(void)
{
    if (g_uni.uc != 0) {
        uc_close(g_uni.uc);
    }
    g_uni.uc = 0;
    g_uni.active = MM_FALSE;
    pending_clear();
}

void mm_unicorn_clear_m33mu_write(void)
{
    pending_clear();
}

void mm_unicorn_record_m33mu_write(enum mm_sec_state sec, mm_u32 addr,
                                   mm_u32 size_bytes, mm_u32 value)
{
    (void)sec;
    if (!g_uni.active) {
        return;
    }
    if (g_uni.map == 0 || !addr_in_ram(g_uni.map, addr)) {
        return;
    }
    if (size_bytes == 1u) {
        value &= 0xffu;
    } else if (size_bytes == 2u) {
        value &= 0xffffu;
    }
    record_write(g_uni.m33mu_writes, &g_uni.m33mu_write_count, addr, size_bytes, value, MM_FALSE, 0u);
}
void mm_unicorn_snapshot_pre(const struct mm_cpu *cpu)
{
    if (cpu == 0) {
        g_uni.pre_valid = MM_FALSE;
        return;
    }
    g_uni.pre_cpu = *cpu;
    g_uni.pre_valid = MM_TRUE;
}
