/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "m33mu/otp.h"

static int test_read_rejects_overflowed_range(void)
{
    struct mm_otp otp;
    mm_u8 buf[4];

    memset(&otp, 0, sizeof(otp));
    otp.data = (mm_u8 *)malloc(16u);
    if (otp.data == 0) return 1;
    memset(otp.data, 0xff, 16u);
    otp.size = 16u;
    otp.loaded = MM_TRUE;

    memset(buf, 0, sizeof(buf));
    if (mm_otp_read(&otp, 0xfffffffeu, buf, 3u) != MM_FALSE) {
        free(otp.data);
        printf("otp_test: overflowed read was accepted\n");
        return 1;
    }

    free(otp.data);
    return 0;
}

static int test_write_rejects_overflowed_range(void)
{
    struct mm_otp otp;
    static const mm_u8 src[3] = { 0u, 0u, 0u };

    memset(&otp, 0, sizeof(otp));
    otp.data = (mm_u8 *)malloc(16u);
    if (otp.data == 0) return 1;
    memset(otp.data, 0xff, 16u);
    otp.size = 16u;
    otp.loaded = MM_TRUE;
    otp.write_enabled = MM_TRUE;

    if (mm_otp_write(&otp, 0xfffffffeu, src, 3u) != MM_FALSE) {
        free(otp.data);
        printf("otp_test: overflowed write was accepted\n");
        return 1;
    }

    free(otp.data);
    return 0;
}

int main(void)
{
    if (test_read_rejects_overflowed_range() != 0) return 1;
    if (test_write_rejects_overflowed_range() != 0) return 1;
    return 0;
}
