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

#include "m33mu/mpu.h"

#define MPU_CTRL_ENABLE (1u << 0)
#define MPU_CTRL_PRIVDEFENA (1u << 2)

static mm_bool mpu_background_region_enabled(mm_u32 ctrl, mm_bool privileged)
{
    if (!privileged) {
        return MM_FALSE;
    }
    return (ctrl & MPU_CTRL_PRIVDEFENA) != 0u ? MM_TRUE : MM_FALSE;
}

static void mpu_select_banks(const struct mm_scs *scs, enum mm_sec_state sec, const mm_u32 **rbar, const mm_u32 **rlar, mm_u32 *ctrl_out)
{
    if (sec == MM_NONSECURE) {
        *rbar = scs->mpu_rbar_ns;
        *rlar = scs->mpu_rlar_ns;
        *ctrl_out = scs->mpu_ctrl_ns;
    } else {
        *rbar = scs->mpu_rbar_s;
        *rlar = scs->mpu_rlar_s;
        *ctrl_out = scs->mpu_ctrl_s;
    }
}

mm_bool mm_mpu_enabled(const struct mm_scs *scs, enum mm_sec_state sec)
{
    mm_u32 ctrl;
    if (scs == 0) {
        return MM_FALSE;
    }
    if (sec == MM_NONSECURE) {
        ctrl = scs->mpu_ctrl_ns;
    } else {
        ctrl = scs->mpu_ctrl_s;
    }
    return (ctrl & MPU_CTRL_ENABLE) != 0u ? MM_TRUE : MM_FALSE;
}

mm_bool mm_mpu_region_lookup(const struct mm_scs *scs, enum mm_sec_state sec, mm_u32 addr, mm_u32 *rbar_out, mm_u32 *rlar_out)
{
    const mm_u32 *rbar;
    const mm_u32 *rlar;
    mm_u32 ctrl;
    int i;
    int best = -1;

    if (rbar_out != 0) {
        *rbar_out = 0;
    }
    if (rlar_out != 0) {
        *rlar_out = 0;
    }
    if (scs == 0) {
        return MM_FALSE;
    }

    mpu_select_banks(scs, sec, &rbar, &rlar, &ctrl);
    if ((ctrl & MPU_CTRL_ENABLE) == 0u) {
        return MM_FALSE;
    }

    for (i = 0; i < 8; ++i) {
        mm_u32 rb = rbar[i];
        mm_u32 rl = rlar[i];
        mm_u32 base;
        mm_u32 limit;
        mm_u32 end;

        if ((rl & 0x1u) == 0u) {
            continue;
        }
        base = rb & 0xFFFFFFE0u;
        limit = rl & 0xFFFFFFE0u;
        if (base > limit) {
            continue;
        }
        end = limit | 0x1Fu;
        if (addr < base || addr > end) {
            continue;
        }
        best = i;
    }

    if (best < 0) {
        return MM_FALSE;
    }
    if (rbar_out != 0) {
        *rbar_out = rbar[best];
    }
    if (rlar_out != 0) {
        *rlar_out = rlar[best];
    }
    return MM_TRUE;
}

mm_bool mm_mpu_is_xn_exec(const struct mm_scs *scs, enum mm_sec_state sec, mm_u32 addr)
{
    mm_u32 rbar;
    if (!mm_mpu_region_lookup(scs, sec, addr, &rbar, 0)) {
        return MM_FALSE;
    }
    return (rbar & 0x1u) != 0u ? MM_TRUE : MM_FALSE;
}

mm_bool mm_mpu_allows_access(const struct mm_scs *scs,
                             enum mm_sec_state sec,
                             mm_u32 addr,
                             mm_bool privileged,
                             enum mm_mpu_access access)
{
    mm_u32 ctrl;
    mm_u32 rbar;
    mm_u32 ap;
    mm_bool priv_write;
    mm_bool unpriv_read;
    mm_bool unpriv_write;

    if (scs == 0) {
        return MM_TRUE;
    }

    ctrl = (sec == MM_NONSECURE) ? scs->mpu_ctrl_ns : scs->mpu_ctrl_s;
    if ((ctrl & MPU_CTRL_ENABLE) == 0u) {
        return MM_TRUE;
    }

    if (!mm_mpu_region_lookup(scs, sec, addr, &rbar, 0)) {
        return mpu_background_region_enabled(ctrl, privileged);
    }

    if (access == MM_MPU_ACCESS_EXEC) {
        return (rbar & 0x1u) == 0u ? MM_TRUE : MM_FALSE;
    }

    ap = (rbar >> 1) & 0x3u;
    priv_write = (ap == 0x0u || ap == 0x1u) ? MM_TRUE : MM_FALSE;
    unpriv_read = (ap == 0x1u || ap == 0x3u) ? MM_TRUE : MM_FALSE;
    unpriv_write = (ap == 0x1u) ? MM_TRUE : MM_FALSE;

    if (privileged) {
        return (access == MM_MPU_ACCESS_WRITE) ? priv_write : MM_TRUE;
    }
    return (access == MM_MPU_ACCESS_WRITE) ? unpriv_write : unpriv_read;
}
