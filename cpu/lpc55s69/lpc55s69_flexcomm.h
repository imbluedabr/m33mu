/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef M33MU_LPC55S69_FLEXCOMM_H
#define M33MU_LPC55S69_FLEXCOMM_H

struct mmio_bus;
struct mm_nvic;

/* Unified FLEXCOMM interface for all 9 FLEXCOMM modules on LPC55S69 */
void mm_lpc55s69_flexcomm_init(struct mmio_bus *bus, struct mm_nvic *nvic);
void mm_lpc55s69_flexcomm_poll(void);
void mm_lpc55s69_flexcomm_reset(void);

#endif /* M33MU_LPC55S69_FLEXCOMM_H */
