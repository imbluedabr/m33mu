/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef M33MU_UNDO_H
#define M33MU_UNDO_H

#include "m33mu/types.h"

struct mm_undo_sink;
typedef void (*mm_undo_emit_fn)(struct mm_undo_sink *sink,
                                mm_u16 dev_id,
                                const void *data,
                                mm_u16 size);

struct mm_undo_sink {
    mm_undo_emit_fn emit;
    void *opaque;
};

#endif /* M33MU_UNDO_H */
