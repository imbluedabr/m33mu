/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef M33MU_TA100_H
#define M33MU_TA100_H

#include "m33mu/types.h"

struct mm_ta100_cfg {
    int bus; /* 1-based SPI index (SPI1 == 1) */
    mm_bool cs_valid;
    int cs_bank;
    int cs_pin;
    mm_bool has_nv_path;
    char nv_path[256];
    mm_bool has_profile;
    char profile[64];
    mm_bool has_serial;
    char serial[32];
};

struct mm_ta100_info {
    int bus;
    mm_bool cs_valid;
    int cs_bank;
    int cs_pin;
    mm_bool has_nv_path;
    char nv_path[256];
    mm_bool has_profile;
    char profile[64];
    mm_bool has_serial;
    char serial[32];
};

mm_bool mm_ta100_parse_spec(const char *spec, struct mm_ta100_cfg *out);
mm_bool mm_ta100_register_cfg(const struct mm_ta100_cfg *cfg);
void mm_ta100_reset_all(void);
void mm_ta100_shutdown_all(void);
size_t mm_ta100_count(void);
mm_bool mm_ta100_get_info(size_t index, struct mm_ta100_info *out);

#endif /* M33MU_TA100_H */
