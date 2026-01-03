/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "m33mu/snapshot.h"
#include <string.h>

void mm_snapshot_writer_init(struct mm_snapshot_writer *w, void *buf, mm_u32 size)
{
    if (w == 0) {
        return;
    }
    w->buf = (mm_u8 *)buf;
    w->size = size;
    w->used = 0;
}

void mm_snapshot_reader_init(struct mm_snapshot_reader *r, const void *buf, mm_u32 size)
{
    if (r == 0) {
        return;
    }
    r->buf = (const mm_u8 *)buf;
    r->size = size;
    r->offset = 0;
}

mm_bool mm_snapshot_write(struct mm_snapshot_writer *w, const void *data, mm_u32 len)
{
    if (w == 0 || data == 0 || len == 0u) {
        return MM_FALSE;
    }
    if (w->used + len > w->size) {
        return MM_FALSE;
    }
    memcpy(w->buf + w->used, data, len);
    w->used += len;
    return MM_TRUE;
}

mm_bool mm_snapshot_write_u32(struct mm_snapshot_writer *w, mm_u32 value)
{
    return mm_snapshot_write(w, &value, 4u);
}

mm_bool mm_snapshot_writer_begin_section(struct mm_snapshot_writer *w, mm_u32 *size_offset_out)
{
    mm_u32 zero = 0;
    if (w == 0 || size_offset_out == 0) {
        return MM_FALSE;
    }
    *size_offset_out = w->used;
    return mm_snapshot_write(w, &zero, 4u);
}

mm_bool mm_snapshot_writer_end_section(struct mm_snapshot_writer *w, mm_u32 size_offset)
{
    mm_u32 payload;
    if (w == 0 || w->buf == 0) {
        return MM_FALSE;
    }
    if (size_offset + 4u > w->used || size_offset + 4u > w->size) {
        return MM_FALSE;
    }
    payload = w->used - (size_offset + 4u);
    memcpy(w->buf + size_offset, &payload, 4u);
    return MM_TRUE;
}

mm_u32 mm_snapshot_bytes_used(const struct mm_snapshot_writer *w)
{
    if (w == 0) {
        return 0;
    }
    return w->used;
}

mm_bool mm_snapshot_read(struct mm_snapshot_reader *r, void *data, mm_u32 len)
{
    if (r == 0 || data == 0 || len == 0u) {
        return MM_FALSE;
    }
    if (r->offset + len > r->size) {
        return MM_FALSE;
    }
    memcpy(data, r->buf + r->offset, len);
    r->offset += len;
    return MM_TRUE;
}

mm_bool mm_snapshot_read_u32(struct mm_snapshot_reader *r, mm_u32 *value_out)
{
    return mm_snapshot_read(r, value_out, 4u);
}

mm_bool mm_snapshot_reader_begin_section(struct mm_snapshot_reader *r, struct mm_snapshot_reader *section_out)
{
    mm_u32 len = 0;
    if (r == 0 || section_out == 0) {
        return MM_FALSE;
    }
    if (!mm_snapshot_read_u32(r, &len)) {
        return MM_FALSE;
    }
    if (r->offset + len > r->size) {
        return MM_FALSE;
    }
    section_out->buf = r->buf + r->offset;
    section_out->size = len;
    section_out->offset = 0;
    r->offset += len;
    return MM_TRUE;
}

mm_bool mm_snapshot_skip(struct mm_snapshot_reader *r, mm_u32 len)
{
    if (r == 0) {
        return MM_FALSE;
    }
    if (r->offset + len > r->size) {
        return MM_FALSE;
    }
    r->offset += len;
    return MM_TRUE;
}
