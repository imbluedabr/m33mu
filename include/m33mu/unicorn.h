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
 * Unicorn side-by-side execution support (optional).
 */

#ifndef M33MU_UNICORN_H
#define M33MU_UNICORN_H

#include "m33mu/types.h"
#include "m33mu/cpu.h"
#include "m33mu/memmap.h"
#include "m33mu/fetch.h"
#include "m33mu/decode.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MM_UNICORN_STEP_OK = 0,
    MM_UNICORN_STEP_DONE = 1,
    MM_UNICORN_STEP_FAIL = -1
} mm_unicorn_step_result;

mm_bool mm_unicorn_available(void);
mm_bool mm_unicorn_active(void);

mm_bool mm_unicorn_configure(mm_u32 entry_pc, mm_u32 stack_window, mm_u32 max_steps);
mm_bool mm_unicorn_maybe_start(struct mm_cpu *cpu, struct mm_memmap *map);
mm_unicorn_step_result mm_unicorn_step_compare(struct mm_cpu *cpu,
                                               struct mm_memmap *map,
                                               const struct mm_fetch_result *fetch,
                                               const struct mm_decoded *dec,
                                               mm_bool execute_it);
void mm_unicorn_stop(void);

void mm_unicorn_clear_m33mu_write(void);
void mm_unicorn_record_m33mu_write(enum mm_sec_state sec, mm_u32 addr,
                                   mm_u32 size_bytes, mm_u32 value);
void mm_unicorn_snapshot_pre(const struct mm_cpu *cpu);

#ifdef __cplusplus
}
#endif

#endif /* M33MU_UNICORN_H */
