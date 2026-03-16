/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef M33MU_PIC32CK_MMIO_H
#define M33MU_PIC32CK_MMIO_H

#include "m33mu/types.h"
#include "m33mu/sau.h"

struct mmio_bus;
struct mm_memmap;
struct mm_flash_persist;
struct mm_nvic;

mm_bool mm_pic32ck_register_mmio(struct mmio_bus *bus);
void mm_pic32ck_flash_bind(struct mm_memmap *map,
                               mm_u8 *flash, mm_u32 flash_size,
                               const struct mm_flash_persist *persist,
                               mm_u32 flags);
mm_u64 mm_pic32ck_cpu_hz(void);
void mm_pic32ck_mmio_reset(void);
mm_bool mm_pic32ck_tz_attr_for_addr(mm_u32 addr,
                                    enum mm_sau_attr *attr_out,
                                    mm_u32 *region_out);

/* Returns non-zero if the MCLK clock for the peripheral at CLKMSK register
 * index clkmsk_reg, bit clkmsk_bit is enabled. */
mm_bool mm_pic32ck_mclk_periph_active(mm_u32 clkmsk_reg, mm_u32 clkmsk_bit);

#endif /* M33MU_PIC32CK_MMIO_H */
