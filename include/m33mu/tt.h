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

#ifndef M33MU_TT_H
#define M33MU_TT_H

#include "m33mu/types.h"
#include "m33mu/cpu.h"
#include "m33mu/scs.h"

/*
 * TT (Test Target) instruction support for ARMv8-M TrustZone.
 * 
 * Returns a TT_RESP format value containing MPU/SAU/IDAU attribution info.
 */

/* Execute TT instruction and return TT_RESP formatted result.
 * 
 * Parameters:
 *   - cpu: current CPU state (contains sec_state)
 *   - scs: system control space (MPU/SAU registers)
 *   - addr: address to query (from Rn register)
 *   - alt: A bit - use alternate domain (Non-secure MPU view when in Secure state)
 *   - forceunpriv: T bit - query unprivileged access permissions
 *
 * TT_RESP format (32-bit return value):
 *   [31:24] IREGION - IDAU region number (0 if IRVALID=0)
 *   [23]    IRVALID - IDAU region valid
 *   [22:20] Reserved (0)
 *   [19]    NSRW    - Non-secure read/write (Secure state only)
 *   [18]    NSR     - Non-secure read (Secure state only)
 *   [17]    RW      - Read/write permission
 *   [16]    R       - Read permission
 *   [15:8]  SREGION - SAU region number (0 if SRVALID=0)
 *   [7]     SRVALID - SAU region valid (Secure state only)
 *   [6]     S       - Secure attribution (0=Non-secure, 1=Secure)
 *   [5:1]   Reserved (0)
 *   [0]     MREGION_MRVALID combined (simplified)
 */
mm_u32 mm_tt_resp(const struct mm_cpu *cpu, const struct mm_scs *scs, mm_u32 addr, 
                   mm_bool alt, mm_bool forceunpriv);

#endif /* M33MU_TT_H */
