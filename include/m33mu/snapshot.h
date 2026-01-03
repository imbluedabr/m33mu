/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef M33MU_SNAPSHOT_H
#define M33MU_SNAPSHOT_H

#include "m33mu/types.h"

struct mm_snapshot_writer {
    mm_u8 *buf;
    mm_u32 size;
    mm_u32 used;
};

struct mm_snapshot_reader {
    const mm_u8 *buf;
    mm_u32 size;
    mm_u32 offset;
};

void mm_snapshot_writer_init(struct mm_snapshot_writer *w, void *buf, mm_u32 size);
void mm_snapshot_reader_init(struct mm_snapshot_reader *r, const void *buf, mm_u32 size);

mm_bool mm_snapshot_write(struct mm_snapshot_writer *w, const void *data, mm_u32 len);
mm_bool mm_snapshot_write_u32(struct mm_snapshot_writer *w, mm_u32 value);
mm_bool mm_snapshot_writer_begin_section(struct mm_snapshot_writer *w, mm_u32 *size_offset_out);
mm_bool mm_snapshot_writer_end_section(struct mm_snapshot_writer *w, mm_u32 size_offset);
mm_u32 mm_snapshot_bytes_used(const struct mm_snapshot_writer *w);

mm_bool mm_snapshot_read(struct mm_snapshot_reader *r, void *data, mm_u32 len);
mm_bool mm_snapshot_read_u32(struct mm_snapshot_reader *r, mm_u32 *value_out);
mm_bool mm_snapshot_reader_begin_section(struct mm_snapshot_reader *r, struct mm_snapshot_reader *section_out);
mm_bool mm_snapshot_skip(struct mm_snapshot_reader *r, mm_u32 len);

#endif /* M33MU_SNAPSHOT_H */
