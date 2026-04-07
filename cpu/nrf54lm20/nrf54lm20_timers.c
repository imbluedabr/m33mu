/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "nrf54lm20/nrf54lm20_timers.h"
#include "nrf54lm20/nrf54lm20_mmio.h"
#include "nrf_timers.h"

static struct nrf_timers_state g_timers;

void mm_nrf54lm20_timers_init(struct mmio_bus *bus, struct mm_nvic *nvic)
{
    static const mm_u32 bases_ns[] = {
        0x40055000u, 0x40085000u, 0x400CA000u, 0x400CB000u,
        0x400CC000u, 0x400CD000u, 0x400CE000u
    };
    static const mm_u32 bases_s[] = {
        0x50055000u, 0x50085000u, 0x500CA000u, 0x500CB000u,
        0x500CC000u, 0x500CD000u, 0x500CE000u
    };
    static const int irqs[] = { 85, 133, 202, 203, 204, 205, 206 };
    if (bus == 0) return;
    mm_nrf54lm20_mmio_set_nvic(nvic);
    nrf_timers_register(&g_timers, bus, nvic, bases_ns, bases_s, irqs, 7u);
}

void mm_nrf54lm20_timers_reset(void)
{
    nrf_timers_reset(&g_timers);
}

void mm_nrf54lm20_timers_tick(mm_u64 cycles)
{
    size_t i;
    mm_nrf54lm20_grtc_tick(cycles);
    for (i = 0; i < g_timers.count; ++i) {
        struct nrf_timer_state *t = &g_timers.timers[i];
        mm_u64 ticks;
        mm_u64 div;
        mm_u32 prescaler;
        mm_u32 mask;
        mm_u32 old;
        mm_u32 now;
        mm_u32 j;
        if (!t->running) continue;
        prescaler = t->regs[0x510u / 4u] & 0xFu;
        div = 1ull << prescaler;
        t->accum += cycles;
        ticks = t->accum / div;
        if (ticks == 0u) continue;
        t->accum -= ticks * div;
        mask = nrf_timer_bitmask(t);
        old = t->counter;
        now = (old + (mm_u32)ticks) & mask;
        t->counter = now;
        if (now == old) continue;
        for (j = 0; j < NRF_TIMER_MAX_CC; ++j) {
            mm_u32 cc = t->cc[j] & mask;
            if (old <= now) {
                if (cc > old && cc <= now) {
                    nrf_timer_set_event(t, (mm_u32)j);
                }
            } else if (cc > old || cc <= now) {
                nrf_timer_set_event(t, (mm_u32)j);
            }
        }
    }
}
