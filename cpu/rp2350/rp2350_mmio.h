/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef M33MU_CPU_RP2350_MMIO_H
#define M33MU_CPU_RP2350_MMIO_H

#include "m33mu/types.h"
#include "m33mu/mmio.h"
#include "m33mu/memmap.h"
#include "m33mu/flash_persist.h"

#define RP2350_RESET_IO_BANK0  (1u << 6)
#define RP2350_RESET_IO_QSPI   (1u << 7)
#define RP2350_RESET_PADS_BANK0 (1u << 9)
#define RP2350_RESET_PADS_QSPI (1u << 10)
#define RP2350_RESET_SPI0      (1u << 18)
#define RP2350_RESET_SPI1      (1u << 19)
#define RP2350_RESET_UART0     (1u << 26)
#define RP2350_RESET_UART1     (1u << 27)
#define RP2350_RESET_USBCTRL   (1u << 28)

mm_bool mm_rp2350_register_mmio(struct mmio_bus *bus);
void mm_rp2350_mmio_reset(void);
void mm_rp2350_flash_bind(struct mm_memmap *map,
                          mm_u8 *flash,
                          mm_u32 flash_size,
                          const struct mm_flash_persist *persist,
                          mm_u32 flags);
mm_u64 mm_rp2350_cpu_hz(void);
mm_bool mm_rp2350_reset_asserted(mm_u32 mask);
mm_bool mm_rp2350_clock_peri_enabled(void);
mm_bool mm_rp2350_active(void);
mm_bool mm_rp2350_cp0_mcr(enum mm_sec_state sec, mm_u8 op1, mm_u8 crn, mm_u8 crm, mm_u8 op2, mm_u32 value);
mm_bool mm_rp2350_cp0_mrc(enum mm_sec_state sec, mm_u8 op1, mm_u8 crn, mm_u8 crm, mm_u8 op2, mm_u32 *value_out);
mm_bool mm_rp2350_cp0_mcrr(enum mm_sec_state sec, mm_u8 op1, mm_u8 crm, mm_u32 lo, mm_u32 hi);
mm_bool mm_rp2350_cp0_mrrc(enum mm_sec_state sec, mm_u8 op1, mm_u8 crm, mm_u32 *lo_out, mm_u32 *hi_out);
mm_bool mm_rp2350_access_check(mm_u32 addr, enum mm_sec_state sec, mm_bool privileged);
mm_bool mm_rp2350_flash_erase(mm_u32 flash_offs, mm_u32 count);
mm_bool mm_rp2350_flash_program(struct mm_memmap *map,
                                enum mm_sec_state sec,
                                mm_u32 flash_offs,
                                mm_u32 data_addr,
                                mm_u32 count);

#endif /* M33MU_CPU_RP2350_MMIO_H */
