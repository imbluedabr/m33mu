/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef M33MU_STM32_SPI_H
#define M33MU_STM32_SPI_H

#include "m33mu/mmio.h"
#include "m33mu/nvic.h"

#define STM32_SPI_MAX_INSTANCES 6u

struct stm32_spi_state;

struct stm32_spi_config {
    const mm_u32 *bases;
    const mm_u32 *bases_sec;
    const int *irq_map;
    const char *const *names;
    size_t count;
    mm_bool enable_snapshot;
    mm_bool poll_cs;
};

struct stm32_spi_inst {
    struct stm32_spi_state *owner;
    mm_u32 base;
    mm_u32 regs[0x50 / 4];
    mm_u8 rx_fifo[32];
    mm_u8 rx_head;
    mm_u8 rx_tail;
    mm_bool enabled;
    mm_bool transfer_active;
    mm_bool eot_pending;
    mm_u32 tsize_rem;
    int irq;
    int bus_index;
    const char *name;
};

struct stm32_spi_state {
    struct stm32_spi_inst spis[STM32_SPI_MAX_INSTANCES];
    size_t spi_count;
    struct mm_nvic *nvic;
    const struct stm32_spi_config *cfg;
};

void stm32_spi_init(struct stm32_spi_state *state,
                    const struct stm32_spi_config *cfg,
                    struct mmio_bus *bus,
                    struct mm_nvic *nvic);
void stm32_spi_poll(struct stm32_spi_state *state);
void stm32_spi_reset(struct stm32_spi_state *state);

#endif /* M33MU_STM32_SPI_H */
