/* stsafe.h -- STSAFE-A120 secure element simulator (I2C, m33mu integration)
 *
 * Copyright (C) 2026 wolfSSL Inc.                       (STSAFE-A120 simulator)
 * Copyright (C) 2026 Daniele Lacamera <root@danielinux.net> (m33mu integration)
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef M33MU_STSAFE_H
#define M33MU_STSAFE_H

#include "m33mu/types.h"

/* CLI spec: --stsafe:I2Cx[:addr=HEX][:file=PATH] */

#define MM_STSAFE_DEFAULT_ADDR 0x20u

struct mm_stsafe_cfg {
    int bus;
    mm_u8 addr;          /* default MM_STSAFE_DEFAULT_ADDR */
    mm_bool has_nv_path;
    char nv_path[256];
};

mm_bool mm_stsafe_parse_spec(const char *spec, struct mm_stsafe_cfg *out);
mm_bool mm_stsafe_register_cfg(const struct mm_stsafe_cfg *cfg);
void mm_stsafe_reset_all(void);
void mm_stsafe_shutdown_all(void);

#endif /* M33MU_STSAFE_H */
