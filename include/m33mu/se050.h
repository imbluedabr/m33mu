/* m33mu -- an ARMv8-M Emulator
 *
 * se050.h -- NXP SE050 secure element simulator (I2C, m33mu integration)
 *
 * Copyright (C) 2026 wolfSSL Inc.                       (SE050 simulator)
 * Copyright (C) 2026 Daniele Lacamera <root@danielinux.net> (m33mu integration)
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef M33MU_SE050_H
#define M33MU_SE050_H

#include "m33mu/types.h"

/* CLI spec: --se050:I2Cx[:addr=HEX][:file=PATH] */

#define MM_SE050_DEFAULT_ADDR 0x48u

struct mm_se050_cfg {
    int bus;
    mm_u8 addr;          /* default MM_SE050_DEFAULT_ADDR */
    mm_bool has_nv_path;
    char nv_path[256];
};

mm_bool mm_se050_parse_spec(const char *spec, struct mm_se050_cfg *out);
mm_bool mm_se050_register_cfg(const struct mm_se050_cfg *cfg);
void mm_se050_reset_all(void);
void mm_se050_shutdown_all(void);

#endif /* M33MU_SE050_H */

