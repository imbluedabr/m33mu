/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "stm32u585/stm32u585_spi.h"
#include "stm32_spi.h"

static struct stm32_spi_state g_spi;

static const mm_u32 g_bases[] = {
    0x40013000u, 0x40003800u, 0x46002000u
};

static const mm_u32 g_bases_sec[] = {
    0x50013000u, 0x50003800u, 0x56002000u
};

static const int g_irq_map[] = { 59, 60, 99 };

static const struct stm32_spi_config g_cfg = {
    g_bases,
    g_bases_sec,
    g_irq_map,
    0,
    sizeof(g_bases) / sizeof(g_bases[0]),
    MM_FALSE,
    MM_TRUE
};

void mm_stm32u585_spi_init(struct mmio_bus *bus, struct mm_nvic *nvic)
{
    stm32_spi_init(&g_spi, &g_cfg, bus, nvic);
}

void mm_stm32u585_spi_poll(void)
{
    stm32_spi_poll(&g_spi);
}

void mm_stm32u585_spi_reset(void)
{
    stm32_spi_reset(&g_spi);
}
