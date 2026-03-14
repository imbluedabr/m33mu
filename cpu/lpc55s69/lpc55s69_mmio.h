/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef M33MU_LPC55S69_MMIO_H
#define M33MU_LPC55S69_MMIO_H

#include "m33mu/types.h"

struct mmio_bus;
struct mm_memmap;
struct mm_flash_persist;
struct mm_nvic;

mm_bool mm_lpc55s69_register_mmio(struct mmio_bus *bus);
void mm_lpc55s69_flash_bind(struct mm_memmap *map,
                            mm_u8 *flash,
                            mm_u32 flash_size,
                            const struct mm_flash_persist *persist,
                            mm_u32 flags);
mm_u64 mm_lpc55s69_cpu_hz(void);
void mm_lpc55s69_mmio_reset(void);
mm_bool mm_lpc55s69_mpcbb_block_secure(int bank, mm_u32 block_index);

/*
 * Blank bitmap manipulation — called by the ROM API stubs to keep the
 * ECC blank tracker in sync with flash erase / program operations.
 * offset, len: byte offset and length within the flash buffer.
 */
void mm_lpc55s69_flash_mark_blank(mm_u32 offset, mm_u32 len);
void mm_lpc55s69_flash_mark_programmed(mm_u32 offset, mm_u32 len);

/*
 * Returns MM_TRUE when the peripheral at the given AHBCLKCTRL register offset
 * has its clock enabled AND its reset released (PRESETCTRL same offset/bit).
 * ahbclk_offset: byte offset of the AHBCLKCTRLn register (0x200/0x204/0x208)
 * bit:           bit number within that register
 */
mm_bool mm_lpc55s69_syscon_periph_active(mm_u32 ahbclk_offset, mm_u32 bit);

#endif /* M33MU_LPC55S69_MMIO_H */
