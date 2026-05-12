/* tropic01.h -- TROPIC01 secure element simulator (SPI, m33mu integration)
 *
 * Copyright (C) 2026 wolfSSL Inc.                       (TROPIC01 simulator)
 * Copyright (C) 2026 Daniele Lacamera <root@danielinux.net> (m33mu integration)
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef M33MU_TROPIC01_H
#define M33MU_TROPIC01_H

#include "m33mu/types.h"

/* CLI spec: --tropic01:SPIx:cs=GPIONAME[:file=PATH] */

struct mm_tropic01_cfg {
    int bus;           /* 1-based SPI bus index (SPI1 == 1) */
    mm_bool cs_valid;
    int cs_bank;
    int cs_pin;
    mm_bool has_nv_path;
    char nv_path[256];
};

mm_bool mm_tropic01_parse_spec(const char *spec, struct mm_tropic01_cfg *out);
mm_bool mm_tropic01_register_cfg(const struct mm_tropic01_cfg *cfg);
void mm_tropic01_reset_all(void);
void mm_tropic01_shutdown_all(void);

#endif /* M33MU_TROPIC01_H */
