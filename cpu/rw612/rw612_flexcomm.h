/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef M33MU_RW612_FLEXCOMM_H
#define M33MU_RW612_FLEXCOMM_H

struct mmio_bus;
struct mm_nvic;

void mm_rw612_flexcomm_init(struct mmio_bus *bus, struct mm_nvic *nvic);
void mm_rw612_flexcomm_poll(void);
void mm_rw612_flexcomm_reset(void);

#endif /* M33MU_RW612_FLEXCOMM_H */
