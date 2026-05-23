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

#ifndef M33MU_STM32_USART_H
#define M33MU_STM32_USART_H

#include "m33mu/mmio.h"
#include "m33mu/nvic.h"
#include "m33mu/target_hal.h"

#define STM32_USART_MAX_INSTANCES 13u

struct stm32_usart_state;

struct stm32_usart_inst {
    struct stm32_usart_state *owner;
    mm_u32 index;
    mm_u32 base;
    mm_u32 regs[0x30 / 4];
    struct mm_uart_io io;
    char label[16];
    mm_bool enabled;
    int irq;
    mm_u32 *rcc_regs;
    mm_u32 *rcc_regs_s;
    mm_bool (*clock_on)(struct stm32_usart_inst *u);
    volatile mm_u32 *sec_reg;
    mm_u32 sec_bitmask;
    mm_bool secure_only;
    enum mm_sec_state current_sec;
    mm_u8 macro_match;
    mm_bool watch_macro;
    mm_bool rx_trace;
    mm_bool has_tc;
};

struct stm32_usart_state {
    struct stm32_usart_inst usarts[STM32_USART_MAX_INSTANCES];
    size_t usart_count;
    struct mm_nvic *nvic;
};

mm_bool stm32_usart_uart_rx_trace_enabled(void);
void stm32_usart_state_init(struct stm32_usart_state *state,
                            size_t count,
                            struct mm_nvic *nvic);
void stm32_usart_register_instance(struct stm32_usart_state *state,
                                   struct mmio_bus *bus,
                                   size_t idx,
                                   mm_u32 base,
                                   int irq,
                                   const char *label,
                                   mm_bool snapshot,
                                   mm_bool has_tc,
                                   mm_bool rx_trace);
void stm32_usart_poll(struct stm32_usart_state *state);
void stm32_usart_reset(struct stm32_usart_state *state);

#endif /* M33MU_STM32_USART_H */
