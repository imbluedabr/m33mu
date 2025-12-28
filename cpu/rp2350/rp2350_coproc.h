/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef M33MU_CPU_RP2350_COPROC_H
#define M33MU_CPU_RP2350_COPROC_H

#include "m33mu/types.h"

void mm_rp2350_coproc_reset(void);
mm_bool mm_rp2350_dcp_mcrr(mm_u8 op1, mm_u8 crm, mm_u32 lo, mm_u32 hi);
mm_bool mm_rp2350_dcp_mrrc(mm_u8 op1, mm_u8 crm, mm_u32 *lo_out, mm_u32 *hi_out);
mm_bool mm_rp2350_dcp_mrc(mm_u8 op1, mm_u8 crn, mm_u8 crm, mm_u8 op2, mm_bool peek, mm_u32 *value_out);
mm_bool mm_rp2350_dcp_cdp(mm_u8 op1, mm_u8 op2, mm_u8 crd, mm_u8 crn, mm_u8 crm);

#endif /* M33MU_CPU_RP2350_COPROC_H */
