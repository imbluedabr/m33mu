/* atecc608.h -- ATECC608A secure element simulator (SPI, m33mu integration)
 *
 * Copyright (C) 2026 wolfSSL Inc.                       (ATECC608 simulator)
 * Copyright (C) 2026 Daniele Lacamera <root@danielinux.net> (m33mu integration)
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef M33MU_ATECC608_H
#define M33MU_ATECC608_H

#include "m33mu/types.h"

/* CLI spec: --atecc608:SPIx:cs=GPIONAME[:file=PATH] */

struct mm_atecc608_cfg {
    int bus;           /* 1-based SPI bus index (SPI1 == 1) */
    mm_bool cs_valid;
    int cs_bank;
    int cs_pin;
    mm_bool has_nv_path;
    char nv_path[256];
};

mm_bool mm_atecc608_parse_spec(const char *spec, struct mm_atecc608_cfg *out);
mm_bool mm_atecc608_register_cfg(const struct mm_atecc608_cfg *cfg);
void mm_atecc608_reset_all(void);
void mm_atecc608_shutdown_all(void);

#endif /* M33MU_ATECC608_H */
