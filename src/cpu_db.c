/* m33mu -- an ARMv8-M Emulator
 *
 * Copyright (C) 2025  Daniele Lacamera <root@danielinux.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 */

#include <string.h>
#include "m33mu/cpu_db.h"
#include "stm32h563/stm32h563_mmio.h"
#include "stm32h563/stm32h563_timers.h"
#include "stm32h563/stm32h563_usart.h"
#include "stm32h563/stm32h563_spi.h"
#include "stm32h563/stm32h563_eth.h"
#include "stm32h563/cpu_config.h"
#include "stm32h533/stm32h533_mmio.h"
#include "stm32h533/stm32h533_timers.h"
#include "stm32h533/stm32h533_usart.h"
#include "stm32h533/stm32h533_spi.h"
#include "stm32h533/stm32h533_eth.h"
#include "stm32h533/cpu_config.h"
#include "stm32u585/stm32u585_mmio.h"
#include "stm32u585/stm32u585_timers.h"
#include "stm32u585/stm32u585_usart.h"
#include "stm32u585/stm32u585_spi.h"
#include "stm32u585/cpu_config.h"
#include "stm32l552/stm32l552_mmio.h"
#include "stm32l552/stm32l552_timers.h"
#include "stm32l552/stm32l552_usart.h"
#include "stm32l552/stm32l552_spi.h"
#include "stm32l552/cpu_config.h"
#include "mcxw71c/mcxw71c_mmio.h"
#include "mcxw71c/mcxw71c_timers.h"
#include "mcxw71c/mcxw71c_usart.h"
#include "mcxw71c/mcxw71c_spi.h"
#include "mcxw71c/cpu_config.h"
#include "mcxn947/mcxn947_mmio.h"
#include "mcxn947/mcxn947_timers.h"
#include "mcxn947/mcxn947_flexcomm.h"
#include "mcxn947/cpu_config.h"
#include "nrf5340/nrf5340_mmio.h"
#include "nrf5340/nrf5340_timers.h"
#include "nrf5340/nrf5340_uart_spi.h"
#include "nrf5340/cpu_config.h"
#include "nrf54lm20/nrf54lm20_mmio.h"
#include "nrf54lm20/nrf54lm20_timers.h"
#include "nrf54lm20/nrf54lm20_uart_spi.h"
#include "nrf54lm20/cpu_config.h"
#include "rp2350/rp2350_mmio.h"
#include "rp2350/rp2350_uart_spi.h"
#include "rp2350/rp2350_timers.h"
#include "rp2350/cpu_config.h"
#include "lpc55s69/lpc55s69_mmio.h"
#include "lpc55s69/lpc55s69_flexcomm.h"
#include "lpc55s69/lpc55s69_timers.h"
#include "lpc55s69/cpu_config.h"

struct mm_cpu_entry {
    const char *name;
    struct mm_target_cfg cfg;
};

static const struct mm_cpu_entry cpu_table[] = {
    {
        "stm32h563",
        {
            STM32H563_FLASH_BASE_S,
            STM32H563_FLASH_SIZE,
            STM32H563_FLASH_BASE_NS,
            STM32H563_FLASH_SIZE,
            STM32H563_RAM_BASE_S,
            STM32H563_RAM_SIZE,
            STM32H563_RAM_BASE_NS,
            STM32H563_RAM_SIZE,
            1,
            STM32H563_RAM_REGIONS,
            STM32H563_RAM_REGION_COUNT,
            STM32H563_MPCBB_BLOCK_SIZE,
            mm_stm32h563_mpcbb_block_secure,
            STM32H563_FLAGS,
            STM32H563_SOC_RESET,
            STM32H563_SOC_REGISTER,
            STM32H563_FLASH_BIND,
            STM32H563_CLOCK_GET_HZ,
            STM32H563_USART_INIT,
            STM32H563_USART_RESET,
            STM32H563_USART_POLL,
            STM32H563_SPI_INIT,
            STM32H563_SPI_RESET,
            STM32H563_SPI_POLL,
            STM32H563_ETH_INIT,
            STM32H563_ETH_RESET,
            STM32H563_ETH_POLL,
            STM32H563_TIMER_INIT,
            STM32H563_TIMER_RESET,
            STM32H563_TIMER_TICK
        }
    },
    {
        "stm32h533",
        {
            STM32H533_FLASH_BASE_S,
            STM32H533_FLASH_SIZE,
            STM32H533_FLASH_BASE_NS,
            STM32H533_FLASH_SIZE,
            STM32H533_RAM_BASE_S,
            STM32H533_RAM_SIZE,
            STM32H533_RAM_BASE_NS,
            STM32H533_RAM_SIZE,
            1,
            STM32H533_RAM_REGIONS,
            STM32H533_RAM_REGION_COUNT,
            STM32H533_MPCBB_BLOCK_SIZE,
            mm_stm32h533_mpcbb_block_secure,
            STM32H533_FLAGS,
            STM32H533_SOC_RESET,
            STM32H533_SOC_REGISTER,
            STM32H533_FLASH_BIND,
            STM32H533_CLOCK_GET_HZ,
            STM32H533_USART_INIT,
            STM32H533_USART_RESET,
            STM32H533_USART_POLL,
            STM32H533_SPI_INIT,
            STM32H533_SPI_RESET,
            STM32H533_SPI_POLL,
            STM32H533_ETH_INIT,
            STM32H533_ETH_RESET,
            STM32H533_ETH_POLL,
            STM32H533_TIMER_INIT,
            STM32H533_TIMER_RESET,
            STM32H533_TIMER_TICK
        }
    },
    {
        "stm32u585",
        {
            STM32U585_FLASH_BASE_S,
            STM32U585_FLASH_SIZE,
            STM32U585_FLASH_BASE_NS,
            STM32U585_FLASH_SIZE,
            STM32U585_RAM_BASE_S,
            STM32U585_RAM_SIZE,
            STM32U585_RAM_BASE_NS,
            STM32U585_RAM_SIZE,
            1,
            STM32U585_RAM_REGIONS,
            STM32U585_RAM_REGION_COUNT,
            STM32U585_MPCBB_BLOCK_SIZE,
            mm_stm32u585_mpcbb_block_secure,
            STM32U585_FLAGS,
            STM32U585_SOC_RESET,
            STM32U585_SOC_REGISTER,
            STM32U585_FLASH_BIND,
            STM32U585_CLOCK_GET_HZ,
            STM32U585_USART_INIT,
            STM32U585_USART_RESET,
            STM32U585_USART_POLL,
            STM32U585_SPI_INIT,
            STM32U585_SPI_RESET,
            STM32U585_SPI_POLL,
            0,
            0,
            0,
            STM32U585_TIMER_INIT,
            STM32U585_TIMER_RESET,
            STM32U585_TIMER_TICK
        }
    },
    {
        "stm32l552",
        {
            STM32L552_FLASH_BASE_S,
            STM32L552_FLASH_SIZE,
            STM32L552_FLASH_BASE_NS,
            STM32L552_FLASH_SIZE,
            STM32L552_RAM_BASE_S,
            STM32L552_RAM_SIZE,
            STM32L552_RAM_BASE_NS,
            STM32L552_RAM_SIZE,
            1,
            STM32L552_RAM_REGIONS,
            STM32L552_RAM_REGION_COUNT,
            STM32L552_MPCBB_BLOCK_SIZE,
            mm_stm32l552_mpcbb_block_secure,
            STM32L552_FLAGS,
            STM32L552_SOC_RESET,
            STM32L552_SOC_REGISTER,
            STM32L552_FLASH_BIND,
            STM32L552_CLOCK_GET_HZ,
            STM32L552_USART_INIT,
            STM32L552_USART_RESET,
            STM32L552_USART_POLL,
            STM32L552_SPI_INIT,
            STM32L552_SPI_RESET,
            STM32L552_SPI_POLL,
            0,
            0,
            0,
            STM32L552_TIMER_INIT,
            STM32L552_TIMER_RESET,
            STM32L552_TIMER_TICK
        }
    },
    {
        "mcxw71c",
        {
            MCXW71C_FLASH_BASE_S,
            MCXW71C_FLASH_SIZE,
            MCXW71C_FLASH_BASE_NS,
            MCXW71C_FLASH_SIZE,
            MCXW71C_RAM_BASE_S,
            MCXW71C_RAM_SIZE,
            MCXW71C_RAM_BASE_NS,
            MCXW71C_RAM_SIZE,
            1,
            MCXW71C_RAM_REGIONS,
            MCXW71C_RAM_REGION_COUNT,
            MCXW71C_MPCBB_BLOCK_SIZE,
            0,
            MCXW71C_FLAGS,
            MCXW71C_SOC_RESET,
            MCXW71C_SOC_REGISTER,
            MCXW71C_FLASH_BIND,
            MCXW71C_CLOCK_GET_HZ,
            MCXW71C_USART_INIT,
            MCXW71C_USART_RESET,
            MCXW71C_USART_POLL,
            MCXW71C_SPI_INIT,
            MCXW71C_SPI_RESET,
            MCXW71C_SPI_POLL,
            0,
            0,
            0,
            MCXW71C_TIMER_INIT,
            MCXW71C_TIMER_RESET,
            MCXW71C_TIMER_TICK
        }
    },
    {
        "mcxn947",
        {
            MCXN947_FLASH_BASE_S,
            MCXN947_FLASH_SIZE,
            MCXN947_FLASH_BASE_NS,
            MCXN947_FLASH_SIZE,
            MCXN947_RAM_BASE_S,
            MCXN947_RAM_SIZE,
            MCXN947_RAM_BASE_NS,
            MCXN947_RAM_SIZE,
            1,
            MCXN947_RAM_REGIONS,
            MCXN947_RAM_REGION_COUNT,
            MCXN947_MPCBB_BLOCK_SIZE,
            mm_mcxn947_mpcbb_block_secure,
            MCXN947_FLAGS,
            MCXN947_SOC_RESET,
            MCXN947_SOC_REGISTER,
            MCXN947_FLASH_BIND,
            MCXN947_CLOCK_GET_HZ,
            MCXN947_USART_INIT,
            MCXN947_USART_RESET,
            MCXN947_USART_POLL,
            MCXN947_SPI_INIT,
            MCXN947_SPI_RESET,
            MCXN947_SPI_POLL,
            0,
            0,
            0,
            MCXN947_TIMER_INIT,
            MCXN947_TIMER_RESET,
            MCXN947_TIMER_TICK
        }
    },
    {
        "nrf5340",
        {
            NRF5340_FLASH_BASE_S,
            NRF5340_FLASH_SIZE,
            NRF5340_FLASH_BASE_NS,
            NRF5340_FLASH_SIZE,
            NRF5340_RAM_BASE_S,
            NRF5340_RAM_SIZE,
            NRF5340_RAM_BASE_NS,
            NRF5340_RAM_SIZE,
            1,
            NRF5340_RAM_REGIONS,
            NRF5340_RAM_REGION_COUNT,
            NRF5340_MPCBB_BLOCK_SIZE,
            0,
            NRF5340_FLAGS,
            NRF5340_SOC_RESET,
            NRF5340_SOC_REGISTER,
            NRF5340_FLASH_BIND,
            NRF5340_CLOCK_GET_HZ,
            NRF5340_USART_INIT,
            NRF5340_USART_RESET,
            NRF5340_USART_POLL,
            NRF5340_SPI_INIT,
            NRF5340_SPI_RESET,
            NRF5340_SPI_POLL,
            0,
            0,
            0,
            NRF5340_TIMER_INIT,
            NRF5340_TIMER_RESET,
            NRF5340_TIMER_TICK
        }
    },
    {
        "nrf54lm20",
        {
            NRF54LM20_FLASH_BASE_S,
            NRF54LM20_FLASH_SIZE,
            NRF54LM20_FLASH_BASE_NS,
            NRF54LM20_FLASH_SIZE,
            NRF54LM20_RAM_BASE_S,
            NRF54LM20_RAM_SIZE,
            NRF54LM20_RAM_BASE_NS,
            NRF54LM20_RAM_SIZE,
            1,
            NRF54LM20_RAM_REGIONS,
            NRF54LM20_RAM_REGION_COUNT,
            NRF54LM20_MPCBB_BLOCK_SIZE,
            0,
            NRF54LM20_FLAGS,
            NRF54LM20_SOC_RESET,
            NRF54LM20_SOC_REGISTER,
            NRF54LM20_FLASH_BIND,
            NRF54LM20_CLOCK_GET_HZ,
            NRF54LM20_USART_INIT,
            NRF54LM20_USART_RESET,
            NRF54LM20_USART_POLL,
            NRF54LM20_SPI_INIT,
            NRF54LM20_SPI_RESET,
            NRF54LM20_SPI_POLL,
            0,
            0,
            0,
            NRF54LM20_TIMER_INIT,
            NRF54LM20_TIMER_RESET,
            NRF54LM20_TIMER_TICK
        }
    },
    {
        "rp2350",
        {
            RP2350_FLASH_BASE_S,
            RP2350_FLASH_SIZE,
            RP2350_FLASH_BASE_NS,
            RP2350_FLASH_SIZE,
            RP2350_RAM_BASE_S,
            RP2350_RAM_SIZE,
            RP2350_RAM_BASE_NS,
            RP2350_RAM_SIZE,
            2,
            RP2350_RAM_REGIONS,
            RP2350_RAM_REGION_COUNT,
            RP2350_MPCBB_BLOCK_SIZE,
            0,
            RP2350_FLAGS,
            RP2350_SOC_RESET,
            RP2350_SOC_REGISTER,
            RP2350_FLASH_BIND,
            RP2350_CLOCK_GET_HZ,
            RP2350_USART_INIT,
            RP2350_USART_RESET,
            RP2350_USART_POLL,
            RP2350_SPI_INIT,
            RP2350_SPI_RESET,
            RP2350_SPI_POLL,
            0,
            0,
            0,
            RP2350_TIMER_INIT,
            RP2350_TIMER_RESET,
            RP2350_TIMER_TICK
        }
    },
    {
        "lpc55s69",
        {
            LPC55S69_FLASH_BASE_S,
            LPC55S69_FLASH_SIZE,
            LPC55S69_FLASH_BASE_NS,
            LPC55S69_FLASH_SIZE,
            LPC55S69_RAM_BASE_S,
            LPC55S69_RAM_SIZE,
            LPC55S69_RAM_BASE_NS,
            LPC55S69_RAM_SIZE,
            1,
            LPC55S69_RAM_REGIONS,
            LPC55S69_RAM_REGION_COUNT,
            LPC55S69_MPCBB_BLOCK_SIZE,
            LPC55S69_MPCBB_SECURE,
            LPC55S69_FLAGS,
            LPC55S69_SOC_RESET,
            LPC55S69_SOC_REGISTER,
            LPC55S69_FLASH_BIND,
            LPC55S69_CLOCK_GET_HZ,
            LPC55S69_USART_INIT,
            LPC55S69_USART_RESET,
            LPC55S69_USART_POLL,
            LPC55S69_SPI_INIT,
            LPC55S69_SPI_RESET,
            LPC55S69_SPI_POLL,
            0,
            0,
            0,
            LPC55S69_TIMER_INIT,
            LPC55S69_TIMER_RESET,
            LPC55S69_TIMER_TICK
        }
    }
};

const char *mm_cpu_default_name(void)
{
    return cpu_table[0].name;
}

size_t mm_cpu_count(void)
{
    return sizeof(cpu_table) / sizeof(cpu_table[0]);
}

const char *mm_cpu_name_at(size_t idx)
{
    if (idx >= mm_cpu_count()) {
        return 0;
    }
    return cpu_table[idx].name;
}

mm_bool mm_cpu_lookup(const char *name, struct mm_target_cfg *cfg_out)
{
    size_t i;
    if (name == 0 || cfg_out == 0) {
        return MM_FALSE;
    }
    for (i = 0; i < sizeof(cpu_table) / sizeof(cpu_table[0]); ++i) {
        if (strcmp(name, cpu_table[i].name) == 0) {
            *cfg_out = cpu_table[i].cfg;
            return MM_TRUE;
        }
    }
    return MM_FALSE;
}
