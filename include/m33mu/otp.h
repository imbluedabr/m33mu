/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef M33MU_OTP_H
#define M33MU_OTP_H

#include "m33mu/types.h"

#define MM_OTP_FLAG_FINAL_LOCK (1u << 0)

struct mm_otp {
    mm_u8 *data;
    mm_u32 size;
    mm_u32 flags;
    mm_bool loaded;
    mm_bool write_enabled;
    char path[256];
};

void mm_otp_init(struct mm_otp *otp, const char *target_name, mm_u32 size);
mm_bool mm_otp_read(struct mm_otp *otp, mm_u32 offset, mm_u8 *dst, mm_u32 len);
mm_bool mm_otp_write(struct mm_otp *otp, mm_u32 offset, const mm_u8 *src, mm_u32 len);
mm_u8 *mm_otp_data(struct mm_otp *otp);
mm_u32 mm_otp_flags(struct mm_otp *otp);
mm_bool mm_otp_set_flags(struct mm_otp *otp, mm_u32 set_mask);
void mm_otp_set_write_enabled(struct mm_otp *otp, mm_bool enabled);

#endif /* M33MU_OTP_H */
