/* IoTSAFE modem + SIM card UART simulator for m33mu
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef M33MU_IOTSAFE_UART_H
#define M33MU_IOTSAFE_UART_H

#include "m33mu/types.h"

/* CLI spec: --iotsafe-uart:<uart-base-hex>[:file=PATH] */
struct mm_iotsafe_uart_cfg {
    mm_u32 base;
    mm_bool has_nv_path;
    char nv_path[256];
};

mm_bool mm_iotsafe_uart_parse_spec(const char *spec,
                                   struct mm_iotsafe_uart_cfg *out);
mm_bool mm_iotsafe_uart_register_cfg(const struct mm_iotsafe_uart_cfg *cfg);
void mm_iotsafe_uart_reset_all(void);
void mm_iotsafe_uart_shutdown_all(void);

#endif /* M33MU_IOTSAFE_UART_H */
