/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>
#include "m33mu/memmap.h"
#include "m33mu/mmio.h"
#include "nrf5340/nrf5340_mmio.h"
#include "nrf5340/nrf5340_timers.h"
#include "nrf5340/nrf5340_uart_spi.h"
#include "nrf54lm20/nrf54lm20_timers.h"
#include "pic32ck/pic32ck_mmio.h"
#include "pic32ck/pic32ck_sercom.h"
#include "rp2350/rp2350_mmio.h"

#define NRF5340_CLOCK_BASE_NS 0x40005000u
#define NRF5340_RTC0_BASE_NS  0x40014000u
#define NRF5340_WDT0_BASE_NS  0x40018000u
#define NRF5340_TIMER0_BASE_NS 0x4000F000u
#define NRF5340_SERIAL0_BASE  0x40008000u

#define TIMER_TASKS_START      0x000u
#define TIMER_EVENTS_COMPARE0  0x140u
#define TIMER_PRESCALER        0x510u
#define TIMER_CC0              0x540u
#define WDT_EVENTS_TIMEOUT     0x100u
#define CLOCK_EVENTS_HFCLKSTARTED 0x100u
#define RTC_EVENTS_TICK        0x100u
#define SERIAL_EVENTS_RXDRDY   0x108u

#define NRF54LM20_TIMER0_BASE_NS 0x40055000u

#define RP2350_BOOTRAM_WRITE_ONCE0 (RP2350_BOOTRAM_BASE + 0x800u)
#define RP2350_BOOTRAM_WRITE_ONCE1 (RP2350_BOOTRAM_BASE + 0x804u)

static int test_scs_reads_are_raz(void)
{
    struct mm_memmap map;
    struct mmio_region regions[4];
    mm_u32 value = 0xA5A5A5A5u;

    mm_memmap_init(&map, regions, 4u);
    if (!mm_memmap_read(&map, MM_SECURE, 0xE000EF9Cu, 4u, &value)) return 1;
    if (value != 0u) return 1;
    if (mm_memmap_read(&map, MM_SECURE, 0xDEADBEEFu, 4u, &value)) return 1;
    return 0;
}

static int test_nrf_nonzero_event_writes_ignored(void)
{
    struct mmio_bus bus;
    struct mmio_region regions[32];
    mm_u32 value = 0u;

    mmio_bus_init(&bus, regions, 32);
    mm_nrf5340_mmio_reset();
    if (!mm_nrf5340_register_mmio(&bus)) return 1;
    mm_nrf5340_timers_reset();
    mm_nrf5340_timers_init(&bus, 0);
    mm_nrf5340_usart_reset();
    mm_nrf5340_usart_init(&bus, 0);

    if (!mmio_bus_write(&bus, NRF5340_WDT0_BASE_NS + WDT_EVENTS_TIMEOUT, 4u, 1u)) return 1;
    if (!mmio_bus_read(&bus, NRF5340_WDT0_BASE_NS + WDT_EVENTS_TIMEOUT, 4u, &value) || value != 0u) return 1;

    if (!mmio_bus_write(&bus, NRF5340_CLOCK_BASE_NS + CLOCK_EVENTS_HFCLKSTARTED, 4u, 0xFFFFFFFFu)) return 1;
    if (!mmio_bus_read(&bus, NRF5340_CLOCK_BASE_NS + CLOCK_EVENTS_HFCLKSTARTED, 4u, &value) || value != 0u) return 1;

    if (!mmio_bus_write(&bus, NRF5340_RTC0_BASE_NS + RTC_EVENTS_TICK, 4u, 1u)) return 1;
    if (!mmio_bus_read(&bus, NRF5340_RTC0_BASE_NS + RTC_EVENTS_TICK, 4u, &value) || value != 0u) return 1;

    if (!mmio_bus_write(&bus, NRF5340_TIMER0_BASE_NS + TIMER_EVENTS_COMPARE0, 4u, 1u)) return 1;
    if (!mmio_bus_read(&bus, NRF5340_TIMER0_BASE_NS + TIMER_EVENTS_COMPARE0, 4u, &value) || value != 0u) return 1;

    if (!mmio_bus_write(&bus, NRF5340_SERIAL0_BASE + SERIAL_EVENTS_RXDRDY, 4u, 1u)) return 1;
    if (!mmio_bus_read(&bus, NRF5340_SERIAL0_BASE + SERIAL_EVENTS_RXDRDY, 4u, &value) || value != 0u) return 1;

    return 0;
}

static int test_nrf54_timer_compare_crossing_fires(void)
{
    struct mmio_bus bus;
    struct mmio_region regions[16];
    mm_u32 value = 0u;

    mmio_bus_init(&bus, regions, 16);
    mm_nrf54lm20_timers_reset();
    mm_nrf54lm20_timers_init(&bus, 0);

    if (!mmio_bus_write(&bus, NRF54LM20_TIMER0_BASE_NS + TIMER_PRESCALER, 4u, 1u)) return 1;
    if (!mmio_bus_write(&bus, NRF54LM20_TIMER0_BASE_NS + TIMER_CC0, 4u, 5u)) return 1;
    if (!mmio_bus_write(&bus, NRF54LM20_TIMER0_BASE_NS + TIMER_TASKS_START, 4u, 1u)) return 1;

    mm_nrf54lm20_timers_tick(12u);

    if (!mmio_bus_read(&bus, NRF54LM20_TIMER0_BASE_NS + TIMER_EVENTS_COMPARE0, 4u, &value)) return 1;
    if (value != 1u) return 1;
    return 0;
}

static int test_rp2350_bootram_write_once_locks(void)
{
    struct mmio_bus bus;
    struct mmio_region regions[64];
    mm_u32 value = 0u;

    mmio_bus_init(&bus, regions, 64);
    mm_rp2350_mmio_reset();
    if (!mm_rp2350_register_mmio(&bus)) return 1;

    if (!mmio_bus_write(&bus, RP2350_BOOTRAM_WRITE_ONCE0, 4u, 0x03u)) return 1;
    if (!mmio_bus_write(&bus, RP2350_BOOTRAM_WRITE_ONCE0, 4u, 0x0Cu)) return 1;
    if (!mmio_bus_read(&bus, RP2350_BOOTRAM_WRITE_ONCE0, 4u, &value) || value != 0x03u) return 1;

    if (!mmio_bus_write(&bus, RP2350_BOOTRAM_WRITE_ONCE1, 4u, 0xAA55AA55u)) return 1;
    if (!mmio_bus_write(&bus, RP2350_BOOTRAM_WRITE_ONCE1, 4u, 0xFFFFFFFFu)) return 1;
    if (!mmio_bus_read(&bus, RP2350_BOOTRAM_WRITE_ONCE1, 4u, &value) || value != 0xAA55AA55u) return 1;

    return 0;
}

int main(void)
{
    struct {
        const char *name;
        int (*fn)(void);
    } tests[] = {
        { "scs_reads_are_raz", test_scs_reads_are_raz },
        { "nrf_nonzero_event_writes_ignored", test_nrf_nonzero_event_writes_ignored },
        { "nrf54_timer_compare_crossing_fires", test_nrf54_timer_compare_crossing_fires },
        { "rp2350_bootram_write_once_locks", test_rp2350_bootram_write_once_locks },
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
