/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef M33MU_CPU_RP2350_UART_SPI_H
#define M33MU_CPU_RP2350_UART_SPI_H

#include "m33mu/mmio.h"
#include "m33mu/nvic.h"

void mm_rp2350_uart_init(struct mmio_bus *bus, struct mm_nvic *nvic);
void mm_rp2350_uart_reset(void);
void mm_rp2350_uart_poll(void);

void mm_rp2350_spi_init(struct mmio_bus *bus, struct mm_nvic *nvic);
void mm_rp2350_spi_reset(void);
void mm_rp2350_spi_poll(void);

#endif /* M33MU_CPU_RP2350_UART_SPI_H */
