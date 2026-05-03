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

#define TT_RESP_MRVALID  (1u << 16)
#define TT_RESP_SRVALID  (1u << 17)
#define TT_RESP_R        (1u << 18)
#define TT_RESP_RW       (1u << 19)
#define TT_RESP_NSR      (1u << 20)
#define TT_RESP_NSRW     (1u << 21)
#define TT_RESP_S        (1u << 22)
#define TT_RESP_IRVALID  (1u << 23)

/* Decode MPU AP[2:1] bits into read/read-write permissions.
 * AP[2:1]: 00=priv-RW/unpriv-none, 01=RW/RW, 10=priv-RO/unpriv-none, 11=RO/RO */
static void tt_decode_perms(mm_u32 ap, mm_bool unpriv, mm_bool *r, mm_bool *rw)
{
    mm_bool priv_write = (ap == 0x0u) || (ap == 0x1u);
    mm_bool priv_read = MM_TRUE;
    mm_bool unpriv_write = (ap == 0x1u);
    mm_bool unpriv_read = (ap == 0x1u) || (ap == 0x3u);

    if (unpriv) {
        *r  = unpriv_read;
        *rw = unpriv_write;
    } else {
        *r  = priv_read;
        *rw = priv_write;
    }
}

mm_u32 mm_tt_resp(const struct mm_cpu *cpu, const struct mm_scs *scs, mm_u32 addr,
                   mm_bool alt, mm_bool forceunpriv)
{
    mm_u32 result = 0;
    enum mm_sec_state query_sec;
    mm_u32 rbar, rlar;
    mm_bool mpu_match;
    mm_bool sau_says_secure = MM_FALSE;
    mm_bool unpriv;
    const struct mm_target_cfg *cfg = mm_target_current_cfg();

    /* Determine security state for query:
     * - If alt=1 and we're in Secure state, query Non-secure MPU
     * - Otherwise query current security state's MPU */
    if (alt && cpu->sec_state != MM_NONSECURE) {  /* Secure state */
        query_sec = MM_NONSECURE;
    } else {
        query_sec = cpu->sec_state;
    }
    unpriv = forceunpriv || !mm_cpu_get_privileged(cpu);

    /* Query SAU attribution (only valid when executed from Secure state) */
    if (cpu->sec_state != MM_NONSECURE) {  /* Secure state */
        enum mm_sau_attr sau_attr = MM_SAU_SECURE;
        mm_u32 sau_region = 0u;
        mm_bool sau_valid = mm_sau_attr_region_for_addr(scs, addr, &sau_attr, &sau_region);

        sau_says_secure = (sau_attr == MM_SAU_SECURE || sau_attr == MM_SAU_NSC);

        /* Tentatively set S bit from SAU; IDAU may override below. */
        if (sau_says_secure) {
            result |= TT_RESP_S;
        }

        if (sau_valid) {
            result |= TT_RESP_SRVALID;
            result |= ((sau_region & 0xFFu) << 8);
        }
    }

    /* Query MPU for region match and permissions */
    mpu_match = mm_mpu_region_lookup(scs, query_sec, addr, &rbar, &rlar);
    result |= mm_mpu_allows_access(scs, query_sec, addr, !unpriv, MM_MPU_ACCESS_READ) ?
              TT_RESP_R : 0u;
    result |= mm_mpu_allows_access(scs, query_sec, addr, !unpriv, MM_MPU_ACCESS_WRITE) ?
              TT_RESP_RW : 0u;

    if (mpu_match) {
        /* NSR/NSRW: Non-secure permission view, available from Secure state. */
        if (cpu->sec_state != MM_NONSECURE) {
            mm_u32 ns_rbar, ns_rlar;
            mm_bool ns_mpu_match = mm_mpu_region_lookup(scs, MM_NONSECURE, addr, &ns_rbar, &ns_rlar);
            if (ns_mpu_match) {
                mm_u32 ns_ap = (ns_rbar >> 1) & 0x3u;
                mm_bool ns_r, ns_rw;
                tt_decode_perms(ns_ap, unpriv, &ns_r, &ns_rw);
                result |= (ns_r  ? TT_RESP_NSR  : 0u);
                result |= (ns_rw ? TT_RESP_NSRW : 0u);
            }
        }

        /* MREGION/MRVALID combined in bit 0 for simplicity */
        result |= TT_RESP_MRVALID;
    }

    if (cfg != 0 && cfg->tz_attr_for_addr != 0) {
        enum mm_sau_attr idau_attr = MM_SAU_SECURE;
        mm_u32 idau_region = 0u;
        if (cfg->tz_attr_for_addr(addr, &idau_attr, &idau_region)) {
            mm_bool idau_says_secure = (idau_attr != MM_SAU_NONSECURE);
            result |= TT_RESP_IRVALID;
            result |= ((idau_region & 0xFFu) << 24);
            /* DDI0553 B6.2: Secure if SAU OR IDAU says Secure; NS only if both say NS. */
            if (sau_says_secure || idau_says_secure) {
                result |= TT_RESP_S;
            } else {
                result &= ~TT_RESP_S;
            }
        }
    }

    return result;
}
