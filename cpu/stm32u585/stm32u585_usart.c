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

#include "stm32u585/stm32u585_usart.h"
#include "stm32u585/stm32u585_mmio.h"
#include "stm32_usart.h"

static struct stm32_usart_state g_usart;

static mm_bool clock_apb2_usart1(struct stm32_usart_inst *u)
{
    if (u->rcc_regs == 0) return MM_TRUE;
    return ((u->rcc_regs[0xa4 / 4] >> 14) & 1u) != 0u;
}

static mm_bool clock_apb1enr1_generic(struct stm32_usart_inst *u)
{
    mm_u32 bit = 0;
    switch (u->index) {
    case 1: bit = 17; break;
    case 2: bit = 18; break;
    case 3: bit = 19; break;
    case 4: bit = 20; break;
    default: return MM_TRUE;
    }
    if (u->rcc_regs == 0) return MM_TRUE;
    return ((u->rcc_regs[0x9c / 4] >> bit) & 1u) != 0u;
}

static mm_bool clock_apb3_lpuart1(struct stm32_usart_inst *u)
{
    if (u->rcc_regs == 0) return MM_TRUE;
    return ((u->rcc_regs[0xa8 / 4] >> 6) & 1u) != 0u;
}

void mm_stm32u585_usart_poll(void)
{
    stm32_usart_poll(&g_usart);
}

void mm_stm32u585_usart_init(struct mmio_bus *bus, struct mm_nvic *nvic)
{
    static const mm_u32 bases[] = {
        0x40013800u, 0x40004400u, 0x40004800u, 0x40004C00u,
        0x40005000u, 0x46002400u
    };
    static const int irq_map[] = { 61, 62, 63, 64, 65, 66 };
    static const char *labels[] = {
        "USART1", "USART2", "USART3", "UART4", "UART5", "LPUART1"
    };
    mm_u32 *tz1 = mm_stm32u585_tzsc_regs();
    mm_u32 *tz1_cfgr1 = (tz1 != 0) ? tz1 + (0x10u / 4u) : 0;
    mm_u32 *tz1_cfgr2 = (tz1 != 0) ? tz1 + (0x14u / 4u) : 0;
    mm_u32 *tz2 = mm_stm32u585_tzsc2_regs();
    mm_u32 *tz2_cfgr1 = (tz2 != 0) ? tz2 + (0x10u / 4u) : 0;
    size_t i;
    stm32_usart_state_init(&g_usart, sizeof(bases) / sizeof(bases[0]), nvic);
    mm_stm32u585_rng_set_nvic(nvic);
    for (i = 0; i < g_usart.usart_count; ++i) {
        struct stm32_usart_inst *u;
        stm32_usart_register_instance(&g_usart, bus, i, bases[i], irq_map[i], labels[i],
                                      MM_FALSE, MM_FALSE, MM_FALSE);
        u = &g_usart.usarts[i];
        u->rcc_regs = mm_stm32u585_rcc_regs();
        u->watch_macro = (i == 2u) ? MM_TRUE : MM_FALSE;
        u->sec_reg = tz1_cfgr1;
        if (i == 0) {
            u->clock_on = clock_apb2_usart1;
            u->sec_bitmask = (1u << 3);
            u->sec_reg = tz1_cfgr2;
        } else if (i >= 1 && i <= 4) {
            u->clock_on = clock_apb1enr1_generic;
            u->sec_bitmask = (1u << (i + 8u));
        } else {
            u->clock_on = clock_apb3_lpuart1;
            u->sec_reg = tz2_cfgr1;
            u->sec_bitmask = (1u << 1);
        }
    }
}

void mm_stm32u585_usart_reset(void)
{
    stm32_usart_reset(&g_usart);
}
