/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef M33MU_PIC32CK_SERCOM_H
#define M33MU_PIC32CK_SERCOM_H

#include "m33mu/types.h"

struct mmio_bus;
struct mm_nvic;

void mm_pic32ck_sercom_init(struct mmio_bus *bus, struct mm_nvic *nvic);
void mm_pic32ck_sercom_reset(void);
void mm_pic32ck_sercom_poll(void);

#endif /* M33MU_PIC32CK_SERCOM_H */

