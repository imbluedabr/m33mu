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

#include <stdio.h>
#include <string.h>
#include "m33mu/mmio.h"
#include "m33mu/nvic.h"
#include "stm32_timers.h"

static mm_u32 g_rcc_regs[64];
static mm_u32 g_tzsc_regs[64];
static int g_exti_calls;
static mm_u64 g_watchdog_cycles;

static mm_u32 *fake_rcc_regs(void)
{
    return g_rcc_regs;
}

static mm_u32 *fake_tzsc_regs(void)
{
    return g_tzsc_regs;
}

static void fake_exti_set_nvic(struct mm_nvic *nvic)
{
    (void)nvic;
    ++g_exti_calls;
}

static void fake_watchdog_tick(mm_u64 cycles)
{
    g_watchdog_cycles += cycles;
}

static void reset_fakes(void)
{
    memset(g_rcc_regs, 0, sizeof(g_rcc_regs));
    memset(g_tzsc_regs, 0, sizeof(g_tzsc_regs));
    g_exti_calls = 0;
    g_watchdog_cycles = 0u;
    mmio_set_active_sec(MM_SECURE);
}

static int test_clock_gate_offset_controls_ticks(void)
{
    struct stm32_timers_state state;
    struct stm32_timer_soc soc;
    struct mm_nvic nvic;
    struct mmio_bus bus;
    struct mmio_region regions[16];
    mm_u32 value = 0;

    reset_fakes();
    memset(&state, 0, sizeof(state));
    memset(&soc, 0, sizeof(soc));
    mm_nvic_init(&nvic);
    mmio_bus_init(&bus, regions, 16);

    soc.apb1enr_offset = 0x58u;
    soc.rcc_regs = fake_rcc_regs;
    soc.tzsc_regs = fake_tzsc_regs;
    soc.exti_set_nvic = fake_exti_set_nvic;
    soc.watchdog_tick = fake_watchdog_tick;

    stm32_timers_init(&state, &soc, &bus, &nvic);
    if (g_exti_calls != 1) return 1;

    if (!mmio_bus_write(&bus, 0x40000000u + 0x2Cu, 4, 9u)) return 1;
    if (!mmio_bus_write(&bus, 0x40000000u + 0x00u, 4, 1u)) return 1;

    stm32_timers_tick(&state, 10u);
    if (!mmio_bus_read(&bus, 0x40000000u + 0x24u, 4, &value)) return 1;
    if (value != 0u) return 1;

    g_rcc_regs[0x58u / 4u] = 1u;
    stm32_timers_tick(&state, 3u);
    if (!mmio_bus_read(&bus, 0x40000000u + 0x24u, 4, &value)) return 1;
    if (value != 3u) return 1;
    if (g_watchdog_cycles != 13u) return 1;
    return 0;
}

static int test_secure_alias_blocks_nonsecure_access(void)
{
    struct stm32_timers_state state;
    struct stm32_timer_soc soc;
    struct mm_nvic nvic;
    struct mmio_bus bus;
    struct mmio_region regions[16];
    mm_u32 value = 0;

    reset_fakes();
    memset(&state, 0, sizeof(state));
    memset(&soc, 0, sizeof(soc));
    mm_nvic_init(&nvic);
    mmio_bus_init(&bus, regions, 16);

    soc.apb1enr_offset = 0x9cu;
    soc.rcc_regs = fake_rcc_regs;
    soc.tzsc_regs = fake_tzsc_regs;

    stm32_timers_init(&state, &soc, &bus, &nvic);
    g_rcc_regs[0x9cu / 4u] = 1u;
    g_tzsc_regs[0x10u / 4u] = 1u;

    mmio_set_active_sec(MM_NONSECURE);
    if (!mmio_bus_write(&bus, 0x40000000u + 0x10000000u + 0x2Cu, 4, 7u)) return 1;
    if (!mmio_bus_read(&bus, 0x40000000u + 0x10000000u + 0x2Cu, 4, &value)) return 1;
    if (value != 0u) return 1;

    mmio_set_active_sec(MM_SECURE);
    if (!mmio_bus_write(&bus, 0x40000000u + 0x2Cu, 4, 7u)) return 1;
    if (!mmio_bus_read(&bus, 0x40000000u + 0x2Cu, 4, &value)) return 1;
    if (value != 7u) return 1;
    return 0;
}

int main(void)
{
    struct { const char *name; int (*fn)(void); } tests[] = {
        { "clock_gate_offset", test_clock_gate_offset_controls_ticks },
        { "secure_alias", test_secure_alias_blocks_nonsecure_access },
    };
    int failures = 0;
    int i;
    const int count = (int)(sizeof(tests) / sizeof(tests[0]));
    for (i = 0; i < count; ++i) {
        if (tests[i].fn() != 0) {
            ++failures;
            printf("FAIL: %s\n", tests[i].name);
        } else {
            printf("PASS: %s\n", tests[i].name);
        }
    }
    if (failures != 0) {
        printf("stm32_timers_test: %d failure(s)\n", failures);
        return 1;
    }
    return 0;
}
