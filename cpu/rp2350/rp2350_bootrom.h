/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef M33MU_CPU_RP2350_BOOTROM_H
#define M33MU_CPU_RP2350_BOOTROM_H

#include "m33mu/types.h"
#include "m33mu/cpu.h"
#include "m33mu/memmap.h"

mm_bool mm_rp2350_bootrom_read(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out);
mm_bool mm_rp2350_bootrom_write(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 value);
mm_bool mm_rp2350_bootrom_handle(struct mm_cpu *cpu, struct mm_memmap *map);

#endif /* M33MU_CPU_RP2350_BOOTROM_H */
