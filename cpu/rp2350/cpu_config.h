/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef M33MU_CPU_RP2350_CONFIG_H
#define M33MU_CPU_RP2350_CONFIG_H

#include "m33mu/target.h"

#define RP2350_FLASH_BASE_S   0x10000000u
#define RP2350_FLASH_BASE_NS  0x10000000u
#define RP2350_FLASH_SIZE     0x01000000u  /* 16 MB external flash window */

#define RP2350_RAM_BASE_S     0x20000000u
#define RP2350_RAM_BASE_NS    0x20000000u
#define RP2350_RAM_SIZE       0x00082000u  /* 520 KB */

#define RP2350_RAM_REGIONS 0
#define RP2350_RAM_REGION_COUNT 0u
#define RP2350_MPCBB_BLOCK_SIZE 0u

#define RP2350_SOC_RESET      mm_rp2350_mmio_reset
#define RP2350_SOC_REGISTER   mm_rp2350_register_mmio
#define RP2350_FLASH_BIND     mm_rp2350_flash_bind
#define RP2350_CLOCK_GET_HZ   mm_rp2350_cpu_hz
#define RP2350_USART_INIT     mm_rp2350_uart_init
#define RP2350_USART_RESET    mm_rp2350_uart_reset
#define RP2350_USART_POLL     mm_rp2350_uart_poll
#define RP2350_SPI_INIT       mm_rp2350_spi_init
#define RP2350_SPI_RESET      mm_rp2350_spi_reset
#define RP2350_SPI_POLL       mm_rp2350_spi_poll
#define RP2350_TIMER_INIT     mm_rp2350_timers_init
#define RP2350_TIMER_RESET    mm_rp2350_timers_reset
#define RP2350_TIMER_TICK     mm_rp2350_timers_tick

#define RP2350_FLAGS 0u

#endif /* M33MU_CPU_RP2350_CONFIG_H */
