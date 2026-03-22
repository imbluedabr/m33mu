/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef M33MU_STM32_USB_FS_H
#define M33MU_STM32_USB_FS_H

#include "m33mu/types.h"

struct mmio_bus;
struct mm_nvic;

struct stm32_usb_fs_config {
    mm_u32 usb_base;
    mm_u32 usb_sec_base;
    mm_u32 pma_base;
    mm_u32 pma_sec_base;
    mm_u32 pma_size;
    mm_bool pma_32bit;
    mm_u32 irq;
};

struct stm32_usb_fs_state {
    mm_u32 regs[0x400u / 4u];
    mm_u32 ep[8];
    mm_u8 pma[0x800u];
    struct mm_nvic *nvic;
    const struct stm32_usb_fs_config *cfg;
    mm_u32 last_ep_read[8];
    mm_u8 last_tx_stat[8];
    mm_u16 last_tx_count[8];
    mm_u8 last_setup[8];
    mm_bool last_setup_valid;
};

mm_bool stm32_usb_fs_register_mmio(struct stm32_usb_fs_state *state,
                                   const struct stm32_usb_fs_config *cfg,
                                   struct mmio_bus *bus);
void stm32_usb_fs_set_nvic(struct stm32_usb_fs_state *state, struct mm_nvic *nvic);
void stm32_usb_fs_reset(struct stm32_usb_fs_state *state);

#endif /* M33MU_STM32_USB_FS_H */
