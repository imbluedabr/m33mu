/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef M33MU_CPU_RP2350_USB_H
#define M33MU_CPU_RP2350_USB_H

#include "m33mu/mmio.h"
#include "m33mu/nvic.h"

mm_bool mm_rp2350_usb_register_mmio(struct mmio_bus *bus);
void mm_rp2350_usb_set_nvic(struct mm_nvic *nvic);
void mm_rp2350_usb_reset(void);
void mm_rp2350_usb_set_irq_vector_ready(mm_bool ready);

#endif /* M33MU_CPU_RP2350_USB_H */
