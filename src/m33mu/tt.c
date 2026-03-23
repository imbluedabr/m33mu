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

#include "m33mu/tt.h"
#include "m33mu/mpu.h"
#include "m33mu/sau.h"
#include "m33mu/mem_prot.h"
#include "m33mu/target_hal.h"

#define TT_RESP_MRVALID  (1u << 0)
#define TT_RESP_S        (1u << 6)
#define TT_RESP_SRVALID  (1u << 7)
#define TT_RESP_R        (1u << 16)
#define TT_RESP_RW       (1u << 17)
#define TT_RESP_NSR      (1u << 18)
#define TT_RESP_NSRW     (1u << 19)
#define TT_RESP_IRVALID  (1u << 23)

mm_u32 mm_tt_resp(const struct mm_cpu *cpu, const struct mm_scs *scs, mm_u32 addr,
                   mm_bool alt, mm_bool forceunpriv)
{
    mm_u32 result = 0;
    enum mm_sec_state query_sec;
    mm_u32 rbar, rlar;
    mm_bool mpu_match;
    const struct mm_target_cfg *cfg = mm_target_current_cfg();
    
    /* Determine security state for query:
     * - If alt=1 and we're in Secure state, query Non-secure MPU
     * - Otherwise query current security state's MPU */
    if (alt && cpu->sec_state != MM_NONSECURE) {  /* Secure state */
        query_sec = MM_NONSECURE;
    } else {
        query_sec = cpu->sec_state;
    }
    
    /* Query SAU attribution (only valid when executed from Secure state) */
    if (cpu->sec_state != MM_NONSECURE) {  /* Secure state */
        enum mm_sau_attr sau_attr = mm_sau_attr_for_addr(scs, addr);
        
        /* Set S bit based on SAU attribution */
        if (sau_attr == MM_SAU_SECURE || sau_attr == MM_SAU_NSC) {
            result |= TT_RESP_S;  /* S bit = 1 (Secure) */
        }
        
        /* SRVALID and SREGION - simplified: always mark as invalid for now */
        /* TODO: track actual SAU region number when mm_sau_attr_for_addr is enhanced */
        result |= 0u;  /* SRVALID = 0 */
        result |= (0u << 8);  /* SREGION[7:0] = 0 */
    } else {
        /* When executed from Non-secure state, S bit is always 0 */
        result |= 0u;
    }
    
    /* Query MPU for region match and permissions */
    mpu_match = mm_mpu_region_lookup(scs, query_sec, addr, &rbar, &rlar);
    
    if (mpu_match) {
        mm_u32 ap = (rbar >> 1) & 0x3u;  /* AP[2:1] bits from RBAR */
        
        /* Decode AP bits to R/RW permissions:
         * AP[2:1]:
         *   00 = Privileged RW, Unprivileged no access
         *   01 = Privileged RW, Unprivileged RW
         *   10 = Privileged RO, Unprivileged no access
         *   11 = Privileged RO, Unprivileged RO
         */
        mm_bool priv_write = (ap == 0x0u) || (ap == 0x1u);
        mm_bool priv_read = MM_TRUE;  /* Privileged always has read if region matches */
        mm_bool unpriv_write = (ap == 0x1u);
        mm_bool unpriv_read = (ap == 0x1u) || (ap == 0x3u);
        
        /* Determine effective permissions based on forceunpriv flag. */
        if (forceunpriv || !mm_cpu_get_privileged(cpu)) {
            result |= (unpriv_read ? TT_RESP_R : 0u);
            result |= (unpriv_write ? TT_RESP_RW : 0u);
        } else {  /* Privileged */
            result |= (priv_read ? TT_RESP_R : 0u);
            result |= (priv_write ? TT_RESP_RW : 0u);
        }
        
        /* NSR/NSRW bits (only when in Secure state querying Non-secure) */
        if (cpu->sec_state != MM_NONSECURE && alt) {  /* Secure state */
            /* These would reflect Non-secure view - for now match R/RW */
            result |= ((result & TT_RESP_R) ? TT_RESP_NSR : 0u);
            result |= ((result & TT_RESP_RW) ? TT_RESP_NSRW : 0u);
        }
        
        /* MREGION/MRVALID combined in bit 0 for simplicity */
        result |= TT_RESP_MRVALID;
    }
    
    if (cfg != 0 && cfg->tz_attr_for_addr != 0) {
        enum mm_sau_attr idau_attr = MM_SAU_SECURE;
        mm_u32 idau_region = 0u;
        if (cfg->tz_attr_for_addr(addr, &idau_attr, &idau_region)) {
            result |= TT_RESP_IRVALID;
            result |= ((idau_region & 0xFFu) << 24);
            if (idau_attr == MM_SAU_NONSECURE) {
                result &= ~TT_RESP_S;
            } else {
                result |= TT_RESP_S;
            }
        }
    }

    return result;
}
