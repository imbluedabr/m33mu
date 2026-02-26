/* m33mu -- an ARMv8-M Emulator
 *
 * Copyright (C) 2025  Daniele Lacamera <root@danielinux.net>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "m33mu/trace.h"
#include "m33mu/undo.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define TRACE_ALIGN 4u
#define TRACE_ENTRY_STEP 1u
#define TRACE_ENTRY_PAD  2u

#define TRACE_MAX_MEM_RECS 256u
#define TRACE_MAX_MEM_BYTES 8192u
#define TRACE_MAX_BLOB_RECS 64u
#define TRACE_MAX_BLOB_BYTES 4096u

struct trace_mem_rec {
    mm_u32 addr;
    mm_u16 size;
    mm_u16 flags;
    mm_u32 bytes_off;
};

struct trace_blob_rec {
    mm_u16 id;
    mm_u16 size;
    mm_u32 bytes_off;
};

struct trace_step {
    mm_bool active;
    mm_u32 pc;
    struct mm_cpu pre;
    struct trace_mem_rec mem[TRACE_MAX_MEM_RECS];
    mm_u16 mem_count;
    mm_u32 mem_bytes_used;
    mm_u8 mem_bytes[TRACE_MAX_MEM_BYTES];
    struct trace_blob_rec blobs[TRACE_MAX_BLOB_RECS];
    mm_u16 blob_count;
    mm_u32 blob_bytes_used;
    mm_u8 blob_bytes[TRACE_MAX_BLOB_BYTES];
};

struct trace_state {
    mm_u8 *buf;
    mm_u32 size;
    mm_u32 head;
    mm_u32 tail;
    mm_bool full;
    mm_bool enabled;
    struct trace_step step;
};

static struct trace_state g_trace;
static struct mm_undo_sink g_trace_undo_sink;
static struct mm_trace_iter g_trace_rev_it;
static mm_bool g_trace_rev_valid = MM_FALSE;

static mm_u32 align_up(mm_u32 v)
{
    return (v + (TRACE_ALIGN - 1u)) & ~(TRACE_ALIGN - 1u);
}

static mm_u32 popcount32(mm_u32 v)
{
    mm_u32 c = 0;
    while (v) {
        v &= (v - 1u);
        c++;
    }
    return c;
}

static mm_u32 trace_used(void)
{
    if (!g_trace.enabled) {
        return 0;
    }
    if (g_trace.full) {
        return g_trace.size;
    }
    if (g_trace.head >= g_trace.tail) {
        return g_trace.head - g_trace.tail;
    }
    return g_trace.size - (g_trace.tail - g_trace.head);
}

static mm_u32 trace_free(void)
{
    if (!g_trace.enabled) {
        return 0;
    }
    return g_trace.size - trace_used();
}

static mm_bool trace_read_u32(mm_u32 offset, mm_u32 *out)
{
    if (!g_trace.buf || !out || offset + 4u > g_trace.size) {
        return MM_FALSE;
    }
    memcpy(out, g_trace.buf + offset, 4u);
    return MM_TRUE;
}

static void trace_drop_oldest(mm_u32 need)
{
    while (trace_free() < need && trace_used() > 0u) {
        mm_u32 size = 0u;
        if (!trace_read_u32(g_trace.tail, &size) || size == 0u || size > g_trace.size) {
            g_trace.tail = g_trace.head;
            g_trace.full = MM_FALSE;
            return;
        }
        g_trace.tail = (g_trace.tail + size) % g_trace.size;
        g_trace.full = MM_FALSE;
    }
}

static mm_bool trace_reserve(mm_u32 size)
{
    if (!g_trace.enabled || size == 0u || size > g_trace.size) {
        return MM_FALSE;
    }
    trace_drop_oldest(size);
    if (g_trace.head + size > g_trace.size) {
        mm_u32 pad = g_trace.size - g_trace.head;
        if (pad >= 8u) {
            mm_u32 type = TRACE_ENTRY_PAD;
            memcpy(g_trace.buf + g_trace.head, &pad, 4u);
            memcpy(g_trace.buf + g_trace.head + 4u, &type, 2u);
            memset(g_trace.buf + g_trace.head + 6u, 0, pad - 6u);
        } else if (pad > 0u) {
            if (g_trace.tail >= g_trace.head) {
                g_trace.tail = 0;
                g_trace.full = MM_FALSE;
            }
        }
        g_trace.head = 0;
        trace_drop_oldest(size);
    }
    if (g_trace.head == g_trace.tail && trace_used() > 0u) {
        g_trace.full = MM_TRUE;
    }
    return MM_TRUE;
}

static mm_u32 trace_write(const void *src, mm_u32 len)
{
    mm_u32 off = g_trace.head;
    memcpy(g_trace.buf + g_trace.head, src, len);
    g_trace.head = (g_trace.head + len) % g_trace.size;
    if (g_trace.head == g_trace.tail) {
        g_trace.full = MM_TRUE;
    }
    return off;
}

void mm_trace_init(void)
{
    size_t size = (size_t)MM_TRACE_BUFFER_SIZE;
    if (g_trace.enabled) {
        return;
    }
    g_trace.buf = (mm_u8 *)malloc(size);
    if (!g_trace.buf) {
        fprintf(stderr, "[TRACE] failed to allocate %zu bytes\n", size);
        g_trace.enabled = MM_FALSE;
        return;
    }
    memset(g_trace.buf, 0, size);
    g_trace.size = (mm_u32)size;
    g_trace.head = 0;
    g_trace.tail = 0;
    g_trace.full = MM_FALSE;
    g_trace.enabled = MM_TRUE;
    memset(&g_trace.step, 0, sizeof(g_trace.step));
    fprintf(stderr, "[TRACE] buffer allocated %u bytes\n", g_trace.size);
}

void mm_trace_reset(void)
{
    if (!g_trace.enabled) {
        return;
    }
    g_trace.head = 0;
    g_trace.tail = 0;
    g_trace.full = MM_FALSE;
    memset(&g_trace.step, 0, sizeof(g_trace.step));
    mm_trace_reverse_reset();
}

mm_bool mm_trace_enabled(void)
{
    return g_trace.enabled ? MM_TRUE : MM_FALSE;
}

mm_bool mm_trace_step_active(void)
{
    return (g_trace.enabled && g_trace.step.active) ? MM_TRUE : MM_FALSE;
}

void mm_trace_begin_step(const struct mm_cpu *cpu, mm_u32 pc_before)
{
    if (!g_trace.enabled || cpu == 0) {
        return;
    }
    g_trace.step.active = MM_TRUE;
    g_trace.step.pc = pc_before;
    memcpy(&g_trace.step.pre, cpu, sizeof(struct mm_cpu));
    g_trace.step.mem_count = 0;
    g_trace.step.mem_bytes_used = 0;
    g_trace.step.blob_count = 0;
    g_trace.step.blob_bytes_used = 0;
}

void mm_trace_log_mem_write(mm_u32 addr, mm_u32 size, const mm_u8 *old_bytes, mm_u16 flags)
{
    struct trace_step *step = &g_trace.step;
    struct trace_mem_rec *rec = 0;
    if (!g_trace.enabled || !step->active || size == 0u || old_bytes == 0) {
        return;
    }
    if (step->mem_count > 0u) {
        rec = &step->mem[step->mem_count - 1u];
        if (rec->flags == flags && addr == (rec->addr + rec->size) &&
            (mm_u32)(rec->size + size) <= 0xffffu &&
            (mm_u32)(step->mem_bytes_used + size) <= TRACE_MAX_MEM_BYTES) {
            memcpy(&step->mem_bytes[step->mem_bytes_used], old_bytes, size);
            rec->size = (mm_u16)(rec->size + (mm_u16)size);
            step->mem_bytes_used += size;
            return;
        }
    }
    if (step->mem_count >= TRACE_MAX_MEM_RECS || (step->mem_bytes_used + size) > TRACE_MAX_MEM_BYTES) {
        return;
    }
    rec = &step->mem[step->mem_count++];
    rec->addr = addr;
    rec->size = (mm_u16)size;
    rec->flags = flags;
    rec->bytes_off = step->mem_bytes_used;
    memcpy(&step->mem_bytes[step->mem_bytes_used], old_bytes, size);
    step->mem_bytes_used += size;
}

void mm_trace_log_device_undo(mm_u16 dev_id, const void *data, mm_u16 size)
{
    struct trace_step *step = &g_trace.step;
    struct trace_blob_rec *rec = 0;
    if (!g_trace.enabled || !step->active || data == 0 || size == 0u) {
        return;
    }
    if (step->blob_count >= TRACE_MAX_BLOB_RECS || (step->blob_bytes_used + size) > TRACE_MAX_BLOB_BYTES) {
        return;
    }
    rec = &step->blobs[step->blob_count++];
    rec->id = dev_id;
    rec->size = size;
    rec->bytes_off = step->blob_bytes_used;
    memcpy(&step->blob_bytes[step->blob_bytes_used], data, size);
    step->blob_bytes_used += size;
}

static void trace_undo_emit(struct mm_undo_sink *sink, mm_u16 dev_id, const void *data, mm_u16 size)
{
    (void)sink;
    mm_trace_log_device_undo(dev_id, data, size);
}

const struct mm_undo_sink *mm_trace_get_undo_sink(void)
{
    g_trace_undo_sink.emit = trace_undo_emit;
    g_trace_undo_sink.opaque = 0;
    return &g_trace_undo_sink;
}

void mm_trace_reverse_reset(void)
{
    g_trace_rev_valid = MM_FALSE;
}

static mm_bool cpu_field_changed_u32(mm_u32 a, mm_u32 b)
{
    return a != b ? MM_TRUE : MM_FALSE;
}

static void append_special_record(mm_u8 id, const void *data, mm_u16 size, mm_u32 *out_size, mm_u8 *dst)
{
    memcpy(dst, &id, 1u);
    dst[1] = 0;
    memcpy(dst + 2u, &size, 2u);
    memcpy(dst + 4u, data, size);
    *out_size = 4u + size;
}

static void build_specials(const struct mm_cpu *pre, const struct mm_cpu *post,
                           mm_u32 *mask_lo, mm_u32 *mask_hi,
                           mm_u8 *out, mm_u32 *out_len)
{
    mm_u32 off = 0;
    mm_u32 lo = 0;
    mm_u32 hi = 0;
    mm_u32 tmp = 0;
    const mm_u32 limit = 2048u;

#define SPEC_SET(bit, value_ptr, size_bytes) \
    do { \
        mm_u32 __sz = 0; \
        mm_u32 __bit = (mm_u32)(bit); \
        if (off + 4u + (mm_u32)(size_bytes) > limit) { \
            break; \
        } \
        if (__bit < 32u) { \
            lo |= (mm_u32)(1u << __bit); \
        } else { \
            hi |= (mm_u32)(1u << (__bit - 32u)); \
        } \
        append_special_record((mm_u8)__bit, (value_ptr), (mm_u16)(size_bytes), &__sz, out + off); \
        off += __sz; \
    } while (0)

    if (cpu_field_changed_u32(pre->xpsr, post->xpsr)) {
        tmp = pre->xpsr; SPEC_SET(0u, &tmp, 4u);
    }
    if (cpu_field_changed_u32(pre->fpscr, post->fpscr)) {
        tmp = pre->fpscr; SPEC_SET(1u, &tmp, 4u);
    }
    if (pre->fp_active != post->fp_active) {
        tmp = pre->fp_active ? 1u : 0u; SPEC_SET(2u, &tmp, 4u);
    }
    if (pre->sec_state != post->sec_state) {
        tmp = (mm_u32)pre->sec_state; SPEC_SET(3u, &tmp, 4u);
    }
    if (pre->mode != post->mode) {
        tmp = (mm_u32)pre->mode; SPEC_SET(4u, &tmp, 4u);
    }
    if (pre->priv_s != post->priv_s) {
        tmp = pre->priv_s ? 1u : 0u; SPEC_SET(5u, &tmp, 4u);
    }
    if (pre->priv_ns != post->priv_ns) {
        tmp = pre->priv_ns ? 1u : 0u; SPEC_SET(6u, &tmp, 4u);
    }
    if (cpu_field_changed_u32(pre->msp_s, post->msp_s)) {
        tmp = pre->msp_s; SPEC_SET(7u, &tmp, 4u);
    }
    if (cpu_field_changed_u32(pre->psp_s, post->psp_s)) {
        tmp = pre->psp_s; SPEC_SET(8u, &tmp, 4u);
    }
    if (cpu_field_changed_u32(pre->msp_ns, post->msp_ns)) {
        tmp = pre->msp_ns; SPEC_SET(9u, &tmp, 4u);
    }
    if (cpu_field_changed_u32(pre->psp_ns, post->psp_ns)) {
        tmp = pre->psp_ns; SPEC_SET(10u, &tmp, 4u);
    }
    if (cpu_field_changed_u32(pre->msplim_s, post->msplim_s)) {
        tmp = pre->msplim_s; SPEC_SET(11u, &tmp, 4u);
    }
    if (cpu_field_changed_u32(pre->psplim_s, post->psplim_s)) {
        tmp = pre->psplim_s; SPEC_SET(12u, &tmp, 4u);
    }
    if (cpu_field_changed_u32(pre->msplim_ns, post->msplim_ns)) {
        tmp = pre->msplim_ns; SPEC_SET(13u, &tmp, 4u);
    }
    if (cpu_field_changed_u32(pre->psplim_ns, post->psplim_ns)) {
        tmp = pre->psplim_ns; SPEC_SET(14u, &tmp, 4u);
    }
    if (cpu_field_changed_u32(pre->control_s, post->control_s)) {
        tmp = pre->control_s; SPEC_SET(15u, &tmp, 4u);
    }
    if (cpu_field_changed_u32(pre->control_ns, post->control_ns)) {
        tmp = pre->control_ns; SPEC_SET(16u, &tmp, 4u);
    }
    if (cpu_field_changed_u32(pre->primask_s, post->primask_s)) {
        tmp = pre->primask_s; SPEC_SET(17u, &tmp, 4u);
    }
    if (cpu_field_changed_u32(pre->primask_ns, post->primask_ns)) {
        tmp = pre->primask_ns; SPEC_SET(18u, &tmp, 4u);
    }
    if (cpu_field_changed_u32(pre->basepri_s, post->basepri_s)) {
        tmp = pre->basepri_s; SPEC_SET(19u, &tmp, 4u);
    }
    if (cpu_field_changed_u32(pre->basepri_ns, post->basepri_ns)) {
        tmp = pre->basepri_ns; SPEC_SET(20u, &tmp, 4u);
    }
    if (cpu_field_changed_u32(pre->faultmask_s, post->faultmask_s)) {
        tmp = pre->faultmask_s; SPEC_SET(21u, &tmp, 4u);
    }
    if (cpu_field_changed_u32(pre->faultmask_ns, post->faultmask_ns)) {
        tmp = pre->faultmask_ns; SPEC_SET(22u, &tmp, 4u);
    }
    if (cpu_field_changed_u32(pre->vtor_s, post->vtor_s)) {
        tmp = pre->vtor_s; SPEC_SET(23u, &tmp, 4u);
    }
    if (cpu_field_changed_u32(pre->vtor_ns, post->vtor_ns)) {
        tmp = pre->vtor_ns; SPEC_SET(24u, &tmp, 4u);
    }
    if (pre->sleeping != post->sleeping) {
        tmp = pre->sleeping ? 1u : 0u; SPEC_SET(25u, &tmp, 4u);
    }
    if (pre->sleep_wfe != post->sleep_wfe) {
        tmp = pre->sleep_wfe ? 1u : 0u; SPEC_SET(26u, &tmp, 4u);
    }
    if (pre->event_reg != post->event_reg) {
        tmp = pre->event_reg ? 1u : 0u; SPEC_SET(27u, &tmp, 4u);
    }
    if (pre->excl_valid != post->excl_valid) {
        tmp = pre->excl_valid ? 1u : 0u; SPEC_SET(28u, &tmp, 4u);
    }
    if (pre->excl_sec != post->excl_sec) {
        tmp = (mm_u32)pre->excl_sec; SPEC_SET(29u, &tmp, 4u);
    }
    if (cpu_field_changed_u32(pre->excl_addr, post->excl_addr)) {
        tmp = pre->excl_addr; SPEC_SET(30u, &tmp, 4u);
    }
    if (cpu_field_changed_u32(pre->excl_size, post->excl_size)) {
        tmp = pre->excl_size; SPEC_SET(31u, &tmp, 4u);
    }
    if (cpu_field_changed_u32(pre->msp_top_s, post->msp_top_s)) {
        tmp = pre->msp_top_s; SPEC_SET(32u, &tmp, 4u);
    }
    if (cpu_field_changed_u32(pre->msp_min_s, post->msp_min_s)) {
        tmp = pre->msp_min_s; SPEC_SET(33u, &tmp, 4u);
    }
    if (cpu_field_changed_u32(pre->msp_top_ns, post->msp_top_ns)) {
        tmp = pre->msp_top_ns; SPEC_SET(34u, &tmp, 4u);
    }
    if (cpu_field_changed_u32(pre->msp_min_ns, post->msp_min_ns)) {
        tmp = pre->msp_min_ns; SPEC_SET(35u, &tmp, 4u);
    }
    if (pre->msp_top_s_valid != post->msp_top_s_valid) {
        tmp = pre->msp_top_s_valid ? 1u : 0u; SPEC_SET(36u, &tmp, 4u);
    }
    if (pre->msp_top_ns_valid != post->msp_top_ns_valid) {
        tmp = pre->msp_top_ns_valid ? 1u : 0u; SPEC_SET(37u, &tmp, 4u);
    }
    if (pre->exc_depth != post->exc_depth ||
        memcmp(pre->exc_sp, post->exc_sp, sizeof(pre->exc_sp)) != 0 ||
        memcmp(pre->exc_use_psp, post->exc_use_psp, sizeof(pre->exc_use_psp)) != 0 ||
        memcmp(pre->exc_sec, post->exc_sec, sizeof(pre->exc_sec)) != 0) {
        SPEC_SET(38u, pre->exc_sp, (mm_u16)sizeof(pre->exc_sp));
        SPEC_SET(39u, pre->exc_use_psp, (mm_u16)sizeof(pre->exc_use_psp));
        SPEC_SET(40u, pre->exc_sec, (mm_u16)sizeof(pre->exc_sec));
        tmp = (mm_u32)pre->exc_depth; SPEC_SET(41u, &tmp, 4u);
    }
    if (pre->tz_depth != post->tz_depth ||
        memcmp(pre->tz_ret_pc, post->tz_ret_pc, sizeof(pre->tz_ret_pc)) != 0 ||
        memcmp(pre->tz_ret_sec, post->tz_ret_sec, sizeof(pre->tz_ret_sec)) != 0 ||
        memcmp(pre->tz_ret_mode, post->tz_ret_mode, sizeof(pre->tz_ret_mode)) != 0) {
        SPEC_SET(42u, pre->tz_ret_pc, (mm_u16)sizeof(pre->tz_ret_pc));
        SPEC_SET(43u, pre->tz_ret_sec, (mm_u16)sizeof(pre->tz_ret_sec));
        SPEC_SET(44u, pre->tz_ret_mode, (mm_u16)sizeof(pre->tz_ret_mode));
        tmp = (mm_u32)pre->tz_depth; SPEC_SET(45u, &tmp, 4u);
    }

    *mask_lo = lo;
    *mask_hi = hi;
    *out_len = off;
#undef SPEC_SET
}

void mm_trace_end_step(const struct mm_cpu *cpu)
{
    struct trace_step *step = &g_trace.step;
    mm_u32 gpr_mask = 0;
    mm_u32 s_mask = 0;
    mm_u32 spec_mask_lo = 0;
    mm_u32 spec_mask_hi = 0;
    mm_u8 spec_buf[2048];
    mm_u32 spec_len = 0;
    mm_u32 header_size = 0;
    mm_u32 total = 0;
    mm_u16 i;
    mm_u32 entry_size = 0;
    mm_u16 mem_count = 0;
    mm_u16 mmio_count = 0;

    if (!g_trace.enabled || !step->active || cpu == 0) {
        return;
    }

    for (i = 0; i < 16u; ++i) {
        if (step->pre.r[i] != cpu->r[i]) {
            gpr_mask |= (1u << i);
        }
    }
    for (i = 0; i < 32u; ++i) {
        if (step->pre.s[i] != cpu->s[i]) {
            s_mask |= (1u << i);
        }
    }

    build_specials(&step->pre, cpu, &spec_mask_lo, &spec_mask_hi, spec_buf, &spec_len);

    for (i = 0; i < step->mem_count; ++i) {
        if (step->mem[i].flags & MM_TRACE_MEM_MMIO) {
            mmio_count++;
        } else {
            mem_count++;
        }
    }

    header_size = 4u + 2u + 2u + 4u + 4u + 4u + 4u + 4u + 2u + 2u;
    total = header_size;
    total += popcount32(gpr_mask) * 4u;
    total += popcount32(s_mask) * 4u;
    total += spec_len;
    for (i = 0; i < step->mem_count; ++i) {
        total += 4u + 2u + 2u + step->mem[i].size;
    }
    for (i = 0; i < step->blob_count; ++i) {
        total += 4u + 2u + 2u + step->blobs[i].size;
    }
    entry_size = align_up(total);

    if (!trace_reserve(entry_size)) {
        step->active = MM_FALSE;
        return;
    }

    trace_write(&entry_size, 4u);
    {
        mm_u16 type = TRACE_ENTRY_STEP;
        mm_u16 flags = 0;
        trace_write(&type, 2u);
        trace_write(&flags, 2u);
    }
    trace_write(&step->pc, 4u);
    trace_write(&gpr_mask, 4u);
    trace_write(&s_mask, 4u);
    trace_write(&spec_mask_lo, 4u);
    trace_write(&spec_mask_hi, 4u);
    trace_write(&mem_count, 2u);
    trace_write(&mmio_count, 2u);

    if (gpr_mask) {
        for (i = 0; i < 16u; ++i) {
            if (gpr_mask & (1u << i)) {
                trace_write(&step->pre.r[i], 4u);
            }
        }
    }
    if (s_mask) {
        for (i = 0; i < 32u; ++i) {
            if (s_mask & (1u << i)) {
                trace_write(&step->pre.s[i], 4u);
            }
        }
    }
    if (spec_len > 0u) {
        trace_write(spec_buf, spec_len);
    }

    for (i = 0; i < step->mem_count; ++i) {
        const struct trace_mem_rec *rec = &step->mem[i];
        trace_write(&rec->addr, 4u);
        trace_write(&rec->size, 2u);
        trace_write(&rec->flags, 2u);
        trace_write(&step->mem_bytes[rec->bytes_off], rec->size);
    }
    for (i = 0; i < step->blob_count; ++i) {
        const struct trace_blob_rec *rec = &step->blobs[i];
        mm_u32 tag = 0x80000000u | (mm_u32)rec->id;
        trace_write(&tag, 4u);
        trace_write(&rec->size, 2u);
        {
            mm_u16 zero = 0;
            trace_write(&zero, 2u);
        }
        trace_write(&step->blob_bytes[rec->bytes_off], rec->size);
    }

    if ((entry_size - total) > 0u) {
        mm_u32 pad = entry_size - total;
        mm_u8 zero[8] = {0};
        while (pad > 0u) {
            mm_u32 chunk = (pad > sizeof(zero)) ? (mm_u32)sizeof(zero) : pad;
            trace_write(zero, chunk);
            pad -= chunk;
        }
    }
    step->active = MM_FALSE;
    mm_trace_reverse_reset();
}

static mm_bool trace_decode_entry(mm_u32 offset, struct mm_trace_entry_view *out)
{
    const mm_u8 *base;
    mm_u32 size;
    mm_u16 type;
    mm_u16 mem_count;
    mm_u16 mmio_count;
    mm_u32 gpr_count;
    mm_u32 s_count;
    mm_u32 special_count = 0;
    const mm_u8 *p;
    if (!g_trace.enabled || out == 0 || !g_trace.buf) {
        return MM_FALSE;
    }
    if (offset + 8u > g_trace.size) {
        return MM_FALSE;
    }
    base = g_trace.buf + offset;
    memcpy(&size, base, 4u);
    if (size == 0u || size > g_trace.size) {
        return MM_FALSE;
    }
    memcpy(&type, base + 4u, 2u);
    if (type != TRACE_ENTRY_STEP) {
        return MM_FALSE;
    }
    memset(out, 0, sizeof(*out));
    out->raw = base;
    out->raw_size = size;
    memcpy(&out->pc, base + 8u, 4u);
    memcpy(&out->gpr_mask, base + 12u, 4u);
    memcpy(&out->s_mask, base + 16u, 4u);
    memcpy(&out->special_mask_lo, base + 20u, 4u);
    memcpy(&out->special_mask_hi, base + 24u, 4u);
    memcpy(&mem_count, base + 28u, 2u);
    memcpy(&mmio_count, base + 30u, 2u);
    out->mem_count = mem_count;
    out->mmio_count = mmio_count;

    p = base + 32u;
    gpr_count = popcount32(out->gpr_mask);
    s_count = popcount32(out->s_mask);
    out->gpr_old = (const mm_u32 *)p;
    p += gpr_count * 4u;
    out->s_old = (const mm_u32 *)p;
    p += s_count * 4u;

    /* Parse specials */
    {
        static struct mm_trace_special_delta specials[64];
        const mm_u8 *sp = p;
        mm_u32 mask_lo = out->special_mask_lo;
        mm_u32 mask_hi = out->special_mask_hi;
        mm_u32 id;
        special_count = 0;
        for (id = 0; id < 64u; ++id) {
            mm_bool set = (id < 32u) ? ((mask_lo >> id) & 1u) : ((mask_hi >> (id - 32u)) & 1u);
            if (set) {
                mm_u16 sz = 0;
                const mm_u8 *data;
                sp += 2u;
                memcpy(&sz, sp, 2u);
                sp += 2u;
                data = sp;
                sp += sz;
                specials[special_count].id = (mm_u8)id;
                specials[special_count].data = data;
                specials[special_count].size = sz;
                special_count++;
            }
        }
        out->specials = specials;
        out->special_count = (mm_u16)special_count;
        p = sp;
    }

    /* memory records */
    {
        const mm_u8 *mp = p;
        const mm_u16 total = (mm_u16)(mem_count + mmio_count);
        static struct mm_trace_mem_delta deltas[TRACE_MAX_MEM_RECS];
        mm_u16 m = 0;
        mm_u16 mmio_seen = 0;
        for (m = 0; m < total; ++m) {
            mm_u32 addr = 0;
            mm_u16 len = 0;
            mm_u16 flags = 0;
            memcpy(&addr, mp, 4u); mp += 4u;
            memcpy(&len, mp, 2u); mp += 2u;
            memcpy(&flags, mp, 2u); mp += 2u;
            deltas[m].addr = addr;
            deltas[m].size = len;
            deltas[m].flags = flags;
            deltas[m].old_bytes = mp;
            mp += len;
            if (flags & MM_TRACE_MEM_MMIO) {
                mmio_seen++;
            }
        }
        out->mem_deltas = deltas;
        out->mem_count = total;
        out->mmio_count = mmio_seen;
    }

    return MM_TRUE;
}

static void apply_special_delta(struct mm_cpu *cpu, mm_u8 id, const void *data, mm_u16 size)
{
    if (cpu == 0 || data == 0) {
        return;
    }
    switch (id) {
    case 0u:
        if (size == 4u) memcpy(&cpu->xpsr, data, 4u);
        break;
    case 1u:
        if (size == 4u) memcpy(&cpu->fpscr, data, 4u);
        break;
    case 2u:
        if (size == 4u) { mm_u32 v; memcpy(&v, data, 4u); cpu->fp_active = v ? MM_TRUE : MM_FALSE; }
        break;
    case 3u:
        if (size == 4u) { mm_u32 v; memcpy(&v, data, 4u); cpu->sec_state = (enum mm_sec_state)v; }
        break;
    case 4u:
        if (size == 4u) { mm_u32 v; memcpy(&v, data, 4u); cpu->mode = (enum mm_mode)v; }
        break;
    case 5u:
        if (size == 4u) { mm_u32 v; memcpy(&v, data, 4u); cpu->priv_s = v ? MM_TRUE : MM_FALSE; }
        break;
    case 6u:
        if (size == 4u) { mm_u32 v; memcpy(&v, data, 4u); cpu->priv_ns = v ? MM_TRUE : MM_FALSE; }
        break;
    case 7u:
        if (size == 4u) memcpy(&cpu->msp_s, data, 4u);
        break;
    case 8u:
        if (size == 4u) memcpy(&cpu->psp_s, data, 4u);
        break;
    case 9u:
        if (size == 4u) memcpy(&cpu->msp_ns, data, 4u);
        break;
    case 10u:
        if (size == 4u) memcpy(&cpu->psp_ns, data, 4u);
        break;
    case 11u:
        if (size == 4u) memcpy(&cpu->msplim_s, data, 4u);
        break;
    case 12u:
        if (size == 4u) memcpy(&cpu->psplim_s, data, 4u);
        break;
    case 13u:
        if (size == 4u) memcpy(&cpu->msplim_ns, data, 4u);
        break;
    case 14u:
        if (size == 4u) memcpy(&cpu->psplim_ns, data, 4u);
        break;
    case 15u:
        if (size == 4u) memcpy(&cpu->control_s, data, 4u);
        break;
    case 16u:
        if (size == 4u) memcpy(&cpu->control_ns, data, 4u);
        break;
    case 17u:
        if (size == 4u) memcpy(&cpu->primask_s, data, 4u);
        break;
    case 18u:
        if (size == 4u) memcpy(&cpu->primask_ns, data, 4u);
        break;
    case 19u:
        if (size == 4u) memcpy(&cpu->basepri_s, data, 4u);
        break;
    case 20u:
        if (size == 4u) memcpy(&cpu->basepri_ns, data, 4u);
        break;
    case 21u:
        if (size == 4u) memcpy(&cpu->faultmask_s, data, 4u);
        break;
    case 22u:
        if (size == 4u) memcpy(&cpu->faultmask_ns, data, 4u);
        break;
    case 23u:
        if (size == 4u) memcpy(&cpu->vtor_s, data, 4u);
        break;
    case 24u:
        if (size == 4u) memcpy(&cpu->vtor_ns, data, 4u);
        break;
    case 25u:
        if (size == 4u) { mm_u32 v; memcpy(&v, data, 4u); cpu->sleeping = v ? MM_TRUE : MM_FALSE; }
        break;
    case 26u:
        if (size == 4u) { mm_u32 v; memcpy(&v, data, 4u); cpu->sleep_wfe = v ? MM_TRUE : MM_FALSE; }
        break;
    case 27u:
        if (size == 4u) { mm_u32 v; memcpy(&v, data, 4u); cpu->event_reg = v ? MM_TRUE : MM_FALSE; }
        break;
    case 28u:
        if (size == 4u) { mm_u32 v; memcpy(&v, data, 4u); cpu->excl_valid = v ? MM_TRUE : MM_FALSE; }
        break;
    case 29u:
        if (size == 4u) { mm_u32 v; memcpy(&v, data, 4u); cpu->excl_sec = (enum mm_sec_state)v; }
        break;
    case 30u:
        if (size == 4u) memcpy(&cpu->excl_addr, data, 4u);
        break;
    case 31u:
        if (size == 4u) memcpy(&cpu->excl_size, data, 4u);
        break;
    case 32u:
        if (size == 4u) memcpy(&cpu->msp_top_s, data, 4u);
        break;
    case 33u:
        if (size == 4u) memcpy(&cpu->msp_min_s, data, 4u);
        break;
    case 34u:
        if (size == 4u) memcpy(&cpu->msp_top_ns, data, 4u);
        break;
    case 35u:
        if (size == 4u) memcpy(&cpu->msp_min_ns, data, 4u);
        break;
    case 36u:
        if (size == 4u) { mm_u32 v; memcpy(&v, data, 4u); cpu->msp_top_s_valid = v ? MM_TRUE : MM_FALSE; }
        break;
    case 37u:
        if (size == 4u) { mm_u32 v; memcpy(&v, data, 4u); cpu->msp_top_ns_valid = v ? MM_TRUE : MM_FALSE; }
        break;
    case 38u:
        if (size == (mm_u16)sizeof(cpu->exc_sp)) memcpy(cpu->exc_sp, data, sizeof(cpu->exc_sp));
        break;
    case 39u:
        if (size == (mm_u16)sizeof(cpu->exc_use_psp)) memcpy(cpu->exc_use_psp, data, sizeof(cpu->exc_use_psp));
        break;
    case 40u:
        if (size == (mm_u16)sizeof(cpu->exc_sec)) memcpy(cpu->exc_sec, data, sizeof(cpu->exc_sec));
        break;
    case 41u:
        if (size == 4u) { mm_u32 v; memcpy(&v, data, 4u); cpu->exc_depth = (mm_u8)(v & 0xffu); }
        break;
    case 42u:
        if (size == (mm_u16)sizeof(cpu->tz_ret_pc)) memcpy(cpu->tz_ret_pc, data, sizeof(cpu->tz_ret_pc));
        break;
    case 43u:
        if (size == (mm_u16)sizeof(cpu->tz_ret_sec)) memcpy(cpu->tz_ret_sec, data, sizeof(cpu->tz_ret_sec));
        break;
    case 44u:
        if (size == (mm_u16)sizeof(cpu->tz_ret_mode)) memcpy(cpu->tz_ret_mode, data, sizeof(cpu->tz_ret_mode));
        break;
    case 45u:
        if (size == 4u) { mm_u32 v; memcpy(&v, data, 4u); cpu->tz_depth = (mm_u8)(v & 0xffu); }
        break;
    default:
        break;
    }
}

mm_bool mm_trace_undo_step(struct mm_cpu *cpu, struct mm_memmap *map)
{
    struct mm_trace_entry_view view;
    mm_u32 i;
    mm_u32 idx;
    struct mm_trace_iter prev_it;
    if (!g_trace.enabled || cpu == 0 || map == 0) {
        return MM_FALSE;
    }
    if (!g_trace_rev_valid) {
        g_trace_rev_it = mm_trace_iter_end();
        g_trace_rev_valid = g_trace_rev_it.valid;
    }
    if (!g_trace_rev_valid) {
        return MM_FALSE;
    }
    if (!trace_decode_entry(g_trace_rev_it.offset, &view)) {
        g_trace_rev_valid = MM_FALSE;
        return MM_FALSE;
    }

    idx = 0;
    for (i = 0; i < 16u; ++i) {
        if (view.gpr_mask & (1u << i)) {
            cpu->r[i] = view.gpr_old[idx++];
        }
    }
    idx = 0;
    for (i = 0; i < 32u; ++i) {
        if (view.s_mask & (1u << i)) {
            cpu->s[i] = view.s_old[idx++];
        }
    }
    for (i = 0; i < view.special_count; ++i) {
        apply_special_delta(cpu, view.specials[i].id, view.specials[i].data, view.specials[i].size);
    }
    cpu->r[15] = view.pc | 1u;
    mm_cpu_set_active_sp(cpu, mm_cpu_get_active_sp(cpu));

    for (i = 0; i < view.mem_count; ++i) {
        const struct mm_trace_mem_delta *delta = &view.mem_deltas[i];
        mm_u32 addr = delta->addr;
        mm_u32 len = delta->size;
        mm_u32 j;
        for (j = 0; j < len; ++j) {
            (void)mm_memmap_write(map, cpu->sec_state, addr + j, 1u, delta->old_bytes[j]);
        }
    }
    prev_it = g_trace_rev_it;
    if (!mm_trace_iter_prev(&prev_it, &view)) {
        g_trace_rev_valid = MM_FALSE;
    } else {
        g_trace_rev_it = prev_it;
    }
    return MM_TRUE;
}

struct mm_trace_iter mm_trace_iter_begin(void)
{
    struct mm_trace_iter it;
    it.offset = g_trace.tail;
    it.valid = g_trace.enabled && (trace_used() > 0u) ? MM_TRUE : MM_FALSE;
    return it;
}

struct mm_trace_iter mm_trace_iter_end(void)
{
    struct mm_trace_iter it;
    mm_u32 off;
    if (!g_trace.enabled || trace_used() == 0u) {
        it.offset = 0;
        it.valid = MM_FALSE;
        return it;
    }
    off = g_trace.tail;
    while (off != g_trace.head) {
        mm_u32 size = 0;
        mm_u16 type = 0;
        if (!trace_read_u32(off, &size) || size == 0u || size > g_trace.size) {
            break;
        }
        memcpy(&type, g_trace.buf + off + 4u, 2u);
        if (type != TRACE_ENTRY_PAD) {
            it.offset = off;
        }
        if ((off + size) % g_trace.size == g_trace.head) {
            break;
        }
        off = (off + size) % g_trace.size;
    }
    it.valid = MM_TRUE;
    return it;
}

mm_bool mm_trace_iter_next(struct mm_trace_iter *it, struct mm_trace_entry_view *out)
{
    if (!it || !it->valid || !g_trace.enabled) {
        return MM_FALSE;
    }
    while (it->valid) {
        mm_u32 size = 0;
        mm_u16 type = 0;
        if (!trace_read_u32(it->offset, &size) || size == 0u || size > g_trace.size) {
            it->valid = MM_FALSE;
            return MM_FALSE;
        }
        memcpy(&type, g_trace.buf + it->offset + 4u, 2u);
        if (type == TRACE_ENTRY_PAD) {
            it->offset = (it->offset + size) % g_trace.size;
            if (it->offset == g_trace.head) {
                it->valid = MM_FALSE;
            }
            continue;
        }
        if (!trace_decode_entry(it->offset, out)) {
            it->valid = MM_FALSE;
            return MM_FALSE;
        }
        it->offset = (it->offset + size) % g_trace.size;
        if (it->offset == g_trace.head) {
            it->valid = MM_FALSE;
        }
        return MM_TRUE;
    }
    return MM_FALSE;
}

mm_bool mm_trace_iter_prev(struct mm_trace_iter *it, struct mm_trace_entry_view *out)
{
    if (!it || !g_trace.enabled) {
        return MM_FALSE;
    }
    if (!it->valid) {
        return MM_FALSE;
    }
    {
        mm_u32 off = g_trace.tail;
        mm_u32 prev = g_trace.tail;
        while (off != it->offset) {
            mm_u32 size = 0;
            if (!trace_read_u32(off, &size) || size == 0u || size > g_trace.size) {
                it->valid = MM_FALSE;
                return MM_FALSE;
            }
            prev = off;
            off = (off + size) % g_trace.size;
        }
        if (prev == it->offset) {
            it->valid = MM_FALSE;
            return MM_FALSE;
        }
        it->offset = prev;
        if (!trace_decode_entry(it->offset, out)) {
            it->valid = MM_FALSE;
            return MM_FALSE;
        }
        if (it->offset == g_trace.tail) {
            it->valid = MM_FALSE;
        }
        return MM_TRUE;
    }
}
