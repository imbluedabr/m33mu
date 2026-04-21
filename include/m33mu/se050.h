/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef M33MU_SE050_H
#define M33MU_SE050_H

#include "m33mu/types.h"

#define MM_SE050_DEFAULT_ADDR 0x48u
#define MM_SE050_DEFAULT_PORT 8050

struct mm_se050_cfg {
    int bus;
    mm_u8 addr;
    char host[256];
    unsigned port;
};

mm_bool mm_se050_parse_spec(const char *spec, struct mm_se050_cfg *out);
mm_bool mm_se050_register_cfg(const struct mm_se050_cfg *cfg);
void mm_se050_reset_all(void);
void mm_se050_shutdown_all(void);

#endif /* M33MU_SE050_H */
