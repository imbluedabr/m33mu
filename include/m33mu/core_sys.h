/* m33mu -- an ARMv8-M Emulator
 *
 * Copyright (C) 2025  Daniele Lacamera <root@danielinux.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 */

#ifndef M33MU_CORE_SYS_H
#define M33MU_CORE_SYS_H

#include "m33mu/mmio.h"

struct mm_dwt {
    mm_u64 *vcycles;
    mm_u32 ctrl;
    mm_u32 cyccnt_base;
};

struct mm_core_sys {
    struct mm_dwt dwt;
};

/* Register minimal MMIO regions for core blocks (ITM/DWT/FPB). */
mm_bool mm_core_sys_register(struct mmio_bus *bus, struct mm_core_sys *core);

#endif /* M33MU_CORE_SYS_H */
