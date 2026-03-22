/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "stm32h563/stm32h563_usb.h"
#include "stm32_usb_fs.h"

static struct stm32_usb_fs_state g_usb;

static const struct stm32_usb_fs_config g_cfg = {
    0x40016000u,
    0x50016000u,
    0x40016400u,
    0x50016400u,
    0x800u,
    MM_TRUE,
    74u
};

mm_bool mm_stm32h563_usb_register_mmio(struct mmio_bus *bus)
{
    return stm32_usb_fs_register_mmio(&g_usb, &g_cfg, bus);
}

void mm_stm32h563_usb_set_nvic(struct mm_nvic *nvic)
{
    stm32_usb_fs_set_nvic(&g_usb, nvic);
}

void mm_stm32h563_usb_reset(void)
{
    stm32_usb_fs_reset(&g_usb);
}
