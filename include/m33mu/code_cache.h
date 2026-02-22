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

#ifndef M33MU_CODE_CACHE_H
#define M33MU_CODE_CACHE_H

#include "m33mu/types.h"
#include "m33mu/cpu.h"
#include "m33mu/memmap.h"
#include "m33mu/fetch.h"
#include "m33mu/decode.h"
#include "m33mu/execute.h"

struct mm_scs;

#define M33MU_ICACHE_ENTRIES 4096u
#define M33MU_TB_ENTRIES 1024u
#define M33MU_CODE_PAGE_SHIFT 12u
#define M33MU_CODE_PAGE_SIZE (1u << M33MU_CODE_PAGE_SHIFT)

struct mm_icache_entry {
    mm_u32 pc;
    mm_u32 raw;
    mm_u8 len;
    enum mm_sec_state sec;
    mm_bool fpu_ok;
    mm_u32 page_gen;
    mm_u32 page_gen2;
    struct mm_decoded dec;
};

struct mm_tb_op {
    struct mm_fetch_result f;
    struct mm_decoded d;
};

struct mm_tb {
    mm_u32 start_pc;
    mm_u32 end_pc;
    enum mm_sec_state sec;
    mm_u32 page_id;
    mm_u32 page_gen;
    mm_u32 cache_gen;
    mm_u16 op_count;
    mm_u16 cycles_est;
    mm_u32 fallthrough_pc;
    mm_u32 branch_pc;
    mm_bool fpu_ok;
    mm_u32 fallthrough_idx;
    mm_u32 branch_idx;
    mm_u32 fallthrough_gen;
    mm_u32 branch_gen;
    struct mm_tb_op ops[1];
};

struct mm_code_cache {
    struct mm_icache_entry icache[M33MU_ICACHE_ENTRIES];
    struct mm_tb *tb_cache[M33MU_TB_ENTRIES];
    mm_u32 tb_cache_gen[M33MU_TB_ENTRIES];
    mm_bool fpu_ok;
    mm_u64 *page_has_tb;
    mm_u32 *page_gen;
    mm_u32 page_count;
    mm_u32 page_base;
    mm_u32 page_size;
};

void mm_code_cache_init(struct mm_code_cache *cc, struct mm_memmap *map);
void mm_code_cache_reset(struct mm_code_cache *cc);
void mm_code_cache_release(struct mm_code_cache *cc);
void mm_code_cache_note_write(struct mm_code_cache *cc, mm_u32 addr, mm_u32 size);

mm_bool mm_icache_lookup(struct mm_code_cache *cc,
                         const struct mm_fetch_result *fetch,
                         enum mm_sec_state sec,
                         mm_bool fpu_ok,
                         struct mm_decoded *out);
void mm_icache_store(struct mm_code_cache *cc,
                     const struct mm_fetch_result *fetch,
                     enum mm_sec_state sec,
                     mm_bool fpu_ok,
                     const struct mm_decoded *dec);

struct mm_tb *mm_tb_lookup(struct mm_code_cache *cc, mm_u32 pc, enum mm_sec_state sec);
struct mm_tb *mm_tb_build(struct mm_code_cache *cc,
                          struct mm_cpu *cpu,
                          struct mm_memmap *map,
                          struct mm_scs *scs,
                          mm_u32 pc,
                          enum mm_sec_state sec,
                          mm_bool opt_gdb);
struct mm_tb *mm_tb_run(struct mm_tb *tb,
                        struct mm_execute_ctx *exec_ctx,
                        mm_bool *done_out,
                        mm_bool *bkpt_hit_out,
                        mm_u32 *bkpt_imm_out,
                        mm_u32 *ops_executed_out);
struct mm_tb *mm_tb_chain_lookup(struct mm_code_cache *cc,
                                 mm_u32 idx,
                                 mm_u32 expected_gen,
                                 mm_u32 pc,
                                 enum mm_sec_state sec);

#endif /* M33MU_CODE_CACHE_H */
