/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <string.h>
#include "nrf54lm20/nrf54lm20_timers.h"
#include "nrf54lm20/nrf54lm20_mmio.h"
#include "m33mu/mmio.h"
#include "m33mu/nvic.h"

#define TIMER_SIZE     0x1000u

#define TIMER_TASKS_START 0x000u
#define TIMER_TASKS_STOP  0x004u
#define TIMER_TASKS_COUNT 0x008u
#define TIMER_TASKS_CLEAR 0x00Cu
#define TIMER_TASKS_SHUTDOWN 0x010u
#define TIMER_EVENTS_COMPARE0 0x140u

#define TIMER_SHORTS 0x200u
#define TIMER_INTENSET 0x304u
#define TIMER_INTENCLR 0x308u
#define TIMER_MODE 0x504u
#define TIMER_BITMODE 0x508u
#define TIMER_PRESCALER 0x510u
#define TIMER_CC0 0x540u

#define TIMER_MAX_CC 6u

struct timer_state {
    mm_u32 regs[TIMER_SIZE / 4];
    mm_u32 cc[TIMER_MAX_CC];
    mm_u32 counter;
    mm_u64 accum;
    mm_bool running;
    int irq;
};

static struct timer_state timers[7];
static struct mm_nvic *g_nvic = 0;

static mm_u32 timer_bitmask(const struct timer_state *t)
{
    mm_u32 mode = t->regs[TIMER_BITMODE / 4] & 0x3u;
    if (mode == 0u) return 0xFFFFu;
    if (mode == 1u) return 0xFFu;
    if (mode == 2u) return 0xFFFFFFu;
    return 0xFFFFFFFFu;
}

static void timer_raise_irq(struct timer_state *t, mm_u32 ch)
{
    mm_u32 mask = (1u << ch);
    if (g_nvic == 0) return;
    if ((t->regs[TIMER_INTENSET / 4] & mask) == 0u) return;
    mm_nvic_set_pending(g_nvic, (mm_u32)t->irq, MM_TRUE);
}

static void timer_set_event(struct timer_state *t, mm_u32 ch)
{
    mm_u32 off = TIMER_EVENTS_COMPARE0 + ch * 4u;
    t->regs[off / 4] = 1u;
    timer_raise_irq(t, ch);
}

static mm_bool timer_read(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out)
{
    struct timer_state *t = (struct timer_state *)opaque;
    if (t == 0 || value_out == 0 || size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > TIMER_SIZE) return MM_FALSE;

    if (offset >= TIMER_CC0 && offset < TIMER_CC0 + TIMER_MAX_CC * 4u && size_bytes == 4) {
        mm_u32 idx = (offset - TIMER_CC0) / 4u;
        *value_out = t->cc[idx];
        return MM_TRUE;
    }
    if (offset == TIMER_TASKS_COUNT && size_bytes == 4) {
        *value_out = t->counter;
        return MM_TRUE;
    }

    *value_out = t->regs[offset / 4];
    return MM_TRUE;
}

static mm_bool timer_write(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 value)
{
    struct timer_state *t = (struct timer_state *)opaque;
    if (t == 0 || size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if ((offset + size_bytes) > TIMER_SIZE) return MM_FALSE;

    if (offset == TIMER_TASKS_START && size_bytes == 4) {
        if ((value & 1u) != 0u) {
            t->running = MM_TRUE;
        }
        return MM_TRUE;
    }
    if (offset == TIMER_TASKS_STOP && size_bytes == 4) {
        if ((value & 1u) != 0u) {
            t->running = MM_FALSE;
        }
        return MM_TRUE;
    }
    if (offset == TIMER_TASKS_CLEAR && size_bytes == 4) {
        if ((value & 1u) != 0u) {
            t->counter = 0u;
        }
        return MM_TRUE;
    }
    if (offset == TIMER_TASKS_COUNT && size_bytes == 4) {
        if ((value & 1u) != 0u) {
            t->counter = (t->counter + 1u) & timer_bitmask(t);
        }
        return MM_TRUE;
    }
    if (offset == TIMER_TASKS_SHUTDOWN && size_bytes == 4) {
        if ((value & 1u) != 0u) {
            t->running = MM_FALSE;
        }
        return MM_TRUE;
    }
    if (offset >= TIMER_EVENTS_COMPARE0 && offset < TIMER_EVENTS_COMPARE0 + TIMER_MAX_CC * 4u && size_bytes == 4) {
        if (value == 0u) {
            t->regs[offset / 4] = 0u;
        } else {
            t->regs[offset / 4] = value;
        }
        return MM_TRUE;
    }
    if (offset == TIMER_INTENSET && size_bytes == 4) {
        t->regs[TIMER_INTENSET / 4] |= value;
        return MM_TRUE;
    }
    if (offset == TIMER_INTENCLR && size_bytes == 4) {
        t->regs[TIMER_INTENSET / 4] &= ~value;
        return MM_TRUE;
    }
    if (offset >= TIMER_CC0 && offset < TIMER_CC0 + TIMER_MAX_CC * 4u && size_bytes == 4) {
        mm_u32 idx = (offset - TIMER_CC0) / 4u;
        t->cc[idx] = value;
        return MM_TRUE;
    }

    t->regs[offset / 4] = value;
    return MM_TRUE;
}

void mm_nrf54lm20_timers_init(struct mmio_bus *bus, struct mm_nvic *nvic)
{
    struct mmio_region reg;
    static const mm_u32 bases_ns[] = {
        0x40055000u, /* TIMER00 */
        0x40085000u, /* TIMER10 */
        0x400CA000u, /* TIMER20 */
        0x400CB000u, /* TIMER21 */
        0x400CC000u, /* TIMER22 */
        0x400CD000u, /* TIMER23 */
        0x400CE000u  /* TIMER24 */
    };
    static const mm_u32 bases_s[] = {
        0x50055000u,
        0x50085000u,
        0x500CA000u,
        0x500CB000u,
        0x500CC000u,
        0x500CD000u,
        0x500CE000u
    };
    static const int irqs[] = { 85, 133, 202, 203, 204, 205, 206 };
    size_t i;

    if (bus == 0) return;

    g_nvic = nvic;
    mm_nrf54lm20_mmio_set_nvic(nvic);

    memset(&timers, 0, sizeof(timers));
    for (i = 0; i < sizeof(timers) / sizeof(timers[0]); ++i) {
        timers[i].irq = irqs[i];
    }

    reg.size = TIMER_SIZE;
    reg.read = timer_read;
    reg.write = timer_write;

    for (i = 0; i < sizeof(timers) / sizeof(timers[0]); ++i) {
        reg.base = bases_ns[i];
        reg.opaque = &timers[i];
        if (!mmio_bus_register_region(bus, &reg)) return;
        reg.base = bases_s[i];
        if (!mmio_bus_register_region(bus, &reg)) return;
    }
}

void mm_nrf54lm20_timers_reset(void)
{
    memset(&timers, 0, sizeof(timers));
}

void mm_nrf54lm20_timers_tick(mm_u64 cycles)
{
    size_t i;
    mm_nrf54lm20_grtc_tick(cycles);
    for (i = 0; i < sizeof(timers) / sizeof(timers[0]); ++i) {
        struct timer_state *t = &timers[i];
        mm_u64 ticks;
        mm_u64 div;
        mm_u32 prescaler;
        mm_u32 mask;
        mm_u32 old;
        mm_u32 j;

        if (!t->running) continue;
        prescaler = t->regs[TIMER_PRESCALER / 4] & 0xFu;
        div = 1ull << prescaler;
        t->accum += cycles;
        ticks = t->accum / div;
        if (ticks == 0u) continue;
        t->accum -= ticks * div;

        mask = timer_bitmask(t);
        old = t->counter;
        t->counter = (t->counter + (mm_u32)ticks) & mask;
        if (t->counter == old) continue;

        for (j = 0; j < TIMER_MAX_CC; ++j) {
            if (t->cc[j] == t->counter) {
                timer_set_event(t, (mm_u32)j);
            }
        }
    }
}
