/* m33mu -- an ARMv8-M Emulator
 *
 * Copyright (C) 2025  Daniele Lacamera <root@danielinux.net>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef M33MU_TRACE_H
#define M33MU_TRACE_H

#include "m33mu/types.h"
#include "m33mu/cpu.h"
#include "m33mu/undo.h"
#include "m33mu/memmap.h"

/* Compile-time cap for the rolling trace buffer. */
#ifndef MM_TRACE_BUFFER_SIZE
#define MM_TRACE_BUFFER_SIZE (256ull * 1024ull * 1024ull)
#endif

/* Trace record flags for memory deltas. */
#define MM_TRACE_MEM_MMIO  (1u << 0)

/* Initialize rolling trace buffer (pre-alloc). */
void mm_trace_init(void);
void mm_trace_reset(void);
mm_bool mm_trace_enabled(void);

/* Begin/end a per-instruction trace step. */
void mm_trace_begin_step(const struct mm_cpu *cpu, mm_u32 pc_before);
void mm_trace_end_step(const struct mm_cpu *cpu);
mm_bool mm_trace_step_active(void);

/* Record memory/MMIO write old bytes for current step. */
void mm_trace_log_mem_write(mm_u32 addr, mm_u32 size, const mm_u8 *old_bytes, mm_u16 flags);

/* Optional device-specific undo blob. */
void mm_trace_log_device_undo(mm_u16 dev_id, const void *data, mm_u16 size);
const struct mm_undo_sink *mm_trace_get_undo_sink(void);
void mm_trace_reverse_reset(void);
mm_bool mm_trace_undo_step(struct mm_cpu *cpu, struct mm_memmap *map);

/* Decoder view for a single trace entry. */
struct mm_trace_mem_delta {
    mm_u32 addr;
    mm_u16 size;
    mm_u16 flags;
    const mm_u8 *old_bytes;
};

struct mm_trace_special_delta {
    mm_u8 id;
    const void *data;
    mm_u16 size;
};

struct mm_trace_entry_view {
    mm_u32 pc;
    mm_u32 gpr_mask;
    mm_u32 s_mask;
    mm_u32 special_mask_lo;
    mm_u32 special_mask_hi;
    const mm_u32 *gpr_old;
    const mm_u32 *s_old;
    const struct mm_trace_special_delta *specials;
    mm_u16 special_count;
    const struct mm_trace_mem_delta *mem_deltas;
    mm_u16 mem_count;
    const struct mm_trace_mem_delta *mmio_deltas;
    mm_u16 mmio_count;
    const mm_u8 *raw;
    mm_u32 raw_size;
};

struct mm_trace_iter {
    mm_u32 offset;
    mm_bool valid;
};

/* Initialize iterator at oldest entry. */
struct mm_trace_iter mm_trace_iter_begin(void);
/* Initialize iterator at newest entry (last committed). */
struct mm_trace_iter mm_trace_iter_end(void);
/* Step iterator forward/backward. */
mm_bool mm_trace_iter_next(struct mm_trace_iter *it, struct mm_trace_entry_view *out);
mm_bool mm_trace_iter_prev(struct mm_trace_iter *it, struct mm_trace_entry_view *out);

#endif /* M33MU_TRACE_H */
