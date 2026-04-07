/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include "m33mu/mmio.h"
#include "m33mu/nvic.h"
#include "mcxn947/mcxn947_timers.h"
#include "rp2350/rp2350_mmio.h"
#include "rp2350/rp2350_timers.h"

#define MCXN947_LPTMR0_BASE 0x4004A000u
#define LPTMR_CSR 0x00u
#define LPTMR_PSR 0x04u
#define LPTMR_CMR 0x08u
#define LPTMR_CNR 0x0Cu
#define CSR_TEN (1u << 0)

#define RP2350_TIMER0_BASE 0x400b0000u
#define TIMER_TIMEHR 0x008u
#define TIMER_TIMELR 0x00Cu

static int test_mcxn947_prescaler_accumulates_fractional_cycles(void)
{
    struct mmio_bus bus;
    struct mmio_region regions[8];
    struct mm_nvic nvic;
    mm_u32 value = 0u;

    mmio_bus_init(&bus, regions, 8);
    mm_nvic_init(&nvic);
    mm_mcxn947_timers_reset();
    mm_mcxn947_timers_init(&bus, &nvic);

    if (!mmio_bus_write(&bus, MCXN947_LPTMR0_BASE + LPTMR_PSR, 4u, 0u)) return 1;
    if (!mmio_bus_write(&bus, MCXN947_LPTMR0_BASE + LPTMR_CMR, 4u, 100u)) return 1;
    if (!mmio_bus_write(&bus, MCXN947_LPTMR0_BASE + LPTMR_CSR, 4u, CSR_TEN)) return 1;

    mm_mcxn947_timers_tick(1u);
    if (!mmio_bus_read(&bus, MCXN947_LPTMR0_BASE + LPTMR_CNR, 4u, &value) || value != 0u) return 1;

    mm_mcxn947_timers_tick(1u);
    if (!mmio_bus_read(&bus, MCXN947_LPTMR0_BASE + LPTMR_CNR, 4u, &value) || value != 1u) return 1;

    return 0;
}

static int test_rp2350_timer_read_latch_uses_valid_flag(void)
{
    struct mmio_bus bus;
    struct mmio_region regions[8];
    struct mm_nvic nvic;
    mm_u32 low = 0u;
    mm_u32 high = 0u;
    mm_u64 hz;
    mm_u64 cycles;

    mmio_bus_init(&bus, regions, 8);
    mm_nvic_init(&nvic);
    mm_rp2350_timers_reset();
    mm_rp2350_timers_init(&bus, &nvic);

    if (!mmio_bus_read(&bus, RP2350_TIMER0_BASE + TIMER_TIMELR, 4u, &low)) return 1;
    if (low != 0u) return 1;

    hz = mm_rp2350_cpu_hz();
    if (hz == 0u) return 1;
    cycles = ((1ull << 32) + 17ull) * (hz / 1000000ull);
    mm_rp2350_timers_tick(cycles);

    if (!mmio_bus_read(&bus, RP2350_TIMER0_BASE + TIMER_TIMEHR, 4u, &high)) return 1;
    if (high != 0u) return 1;

    if (!mmio_bus_read(&bus, RP2350_TIMER0_BASE + TIMER_TIMEHR, 4u, &high)) return 1;
    if (high == 0u) return 1;

    return 0;
}

int main(void)
{
    struct {
        const char *name;
        int (*fn)(void);
    } tests[] = {
        { "mcxn947_prescaler_accum", test_mcxn947_prescaler_accumulates_fractional_cycles },
        { "rp2350_timer_latch_valid", test_rp2350_timer_read_latch_uses_valid_flag },
    };
    int failures = 0;
    int i;

    for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); ++i) {
        if (tests[i].fn() != 0) {
            ++failures;
            printf("FAIL: %s\n", tests[i].name);
        } else {
            printf("PASS: %s\n", tests[i].name);
        }
    }
    return failures == 0 ? 0 : 1;
}
