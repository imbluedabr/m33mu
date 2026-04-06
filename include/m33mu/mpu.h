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

#ifndef M33MU_MPU_H
#define M33MU_MPU_H

#include "m33mu/types.h"
#include "m33mu/scs.h"
#include "m33mu/cpu.h"

enum mm_mpu_access {
    MM_MPU_ACCESS_READ = 0,
    MM_MPU_ACCESS_WRITE = 1,
    MM_MPU_ACCESS_EXEC = 2
};

mm_bool mm_mpu_enabled(const struct mm_scs *scs, enum mm_sec_state sec);

/* Returns MM_TRUE if the MPU matches a region for addr and that region has XN set. */
mm_bool mm_mpu_is_xn_exec(const struct mm_scs *scs, enum mm_sec_state sec, mm_u32 addr);

/* Returns MM_TRUE if addr is covered by any enabled region (highest-numbered wins). */
mm_bool mm_mpu_region_lookup(const struct mm_scs *scs, enum mm_sec_state sec, mm_u32 addr, mm_u32 *rbar_out, mm_u32 *rlar_out);

/* Returns MM_TRUE when MPU rules allow the requested access. */
mm_bool mm_mpu_allows_access(const struct mm_scs *scs,
                             enum mm_sec_state sec,
                             mm_u32 addr,
                             mm_bool privileged,
                             enum mm_mpu_access access);

/* Extended variant that can model handler-context overrides such as
 * MPU_CTRL.HFNMIENA for HardFault/NMI accesses.
 */
mm_bool mm_mpu_allows_access_ex(const struct mm_scs *scs,
                                enum mm_sec_state sec,
                                mm_u32 addr,
                                mm_bool privileged,
                                enum mm_mpu_access access,
                                mm_u32 active_exc_num);

#endif /* M33MU_MPU_H */
