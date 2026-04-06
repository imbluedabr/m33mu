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

#include "m33mu/sau.h"

#define SAU_CTRL_ENABLE 0x1u
#define SAU_CTRL_ALLNS  0x2u

#define SAU_RLAR_ENABLE 0x1u
#define SAU_RLAR_NSC    0x2u

static mm_bool sau_region_matches(mm_u32 rbar, mm_u32 rlar, mm_u32 addr)
{
    mm_u32 base;
    mm_u32 limit;

    if ((rlar & SAU_RLAR_ENABLE) == 0u) {
        return MM_FALSE;
    }
    /* RBAR/RLAR define 32-byte aligned region bounds (bits [31:5]). */
    base = rbar & ~0x1Fu;
    limit = (rlar & ~0x1Fu) | 0x1Fu;
    if (addr < base) {
        return MM_FALSE;
    }
    return addr <= limit;
}

mm_bool mm_sau_attr_region_for_addr(const struct mm_scs *scs,
                                    mm_u32 addr,
                                    enum mm_sau_attr *attr_out,
                                    mm_u32 *region_out)
{
    int i;
    mm_bool enable;
    mm_bool allns;
    enum mm_sau_attr attr = MM_SAU_SECURE;

    if (scs == 0) {
        if (attr_out != 0) {
            *attr_out = MM_SAU_SECURE;
        }
        if (region_out != 0) {
            *region_out = 0u;
        }
        return MM_FALSE;
    }

    enable = (scs->sau_ctrl & SAU_CTRL_ENABLE) != 0u;
    allns = (scs->sau_ctrl & SAU_CTRL_ALLNS) != 0u;
    if (!enable) {
        if (attr_out != 0) {
            *attr_out = MM_SAU_SECURE;
        }
        if (region_out != 0) {
            *region_out = 0u;
        }
        return MM_FALSE;
    }

    /* Highest-numbered region has priority. */
    for (i = 7; i >= 0; --i) {
        mm_u32 rbar = scs->sau_rbar[i];
        mm_u32 rlar = scs->sau_rlar[i];
        if (sau_region_matches(rbar, rlar, addr)) {
            if ((rlar & SAU_RLAR_NSC) != 0u) {
                attr = MM_SAU_NSC;
            } else {
                attr = MM_SAU_NONSECURE;
            }
            if (attr_out != 0) {
                *attr_out = attr;
            }
            if (region_out != 0) {
                *region_out = (mm_u32)i;
            }
            return MM_TRUE;
        }
    }

    if (attr_out != 0) {
        *attr_out = allns ? MM_SAU_NONSECURE : MM_SAU_SECURE;
    }
    if (region_out != 0) {
        *region_out = 0u;
    }
    return MM_FALSE;
}

enum mm_sau_attr mm_sau_attr_for_addr(const struct mm_scs *scs, mm_u32 addr)
{
    enum mm_sau_attr attr = MM_SAU_SECURE;

    (void)mm_sau_attr_region_for_addr(scs, addr, &attr, 0);
    return attr;
}
