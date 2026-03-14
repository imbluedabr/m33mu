/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <string.h>
#include "lpc55s69/lpc55s69_timers.h"
#include "lpc55s69/lpc55s69_mmio.h"
#include "m33mu/mmio.h"
#include "m33mu/nvic.h"

/* AHBCLKCTRL1 bit 0 = MRT clock; PRESETCTRL1 bit 0 = MRT reset */
#define MRT_AHBCLKCTRL_OFFSET 0x204u
#define MRT_AHBCLKCTRL_BIT    0u

static mm_bool mrt_periph_active(void)
{
    return mm_lpc55s69_syscon_periph_active(MRT_AHBCLKCTRL_OFFSET,
                                            MRT_AHBCLKCTRL_BIT);
}

/*
 * Multi-Rate Timer (MRT0) — LPC55S69
 *
 * Base address: 0x4000D000 (NS), 0x5000D000 (S)
 * 4 independent down-counting channels.
 * External interrupt: IRQ10 (MRT_IRQn = 10).
 *
 * Channel n register layout (offset 0x10 * n):
 *   INTVAL  +0x00  interval value (bits [30:0]) + LOAD flag (bit 31)
 *   TIMER   +0x04  current timer value (read-only)
 *   CTRL    +0x08  INTEN (bit 0), MODE (bits [2:1])
 *   STAT    +0x0C  INTFLAG (bit 0, w1c), RUN (bit 1)
 *
 * Global registers:
 *   MODCFG  +0xF0  number of channels, bits counter, etc.
 *   IDLE_CH +0xF4  next idle channel (read-only)
 *   IRQ_FLAG +0xF8 global interrupt flag (one bit per channel, w1c)
 */

#define MRT0_BASE      0x4000D000u
#define MRT0_SEC_BASE  0x5000D000u
#define MRT0_IRQ       10u          /* MRT_IRQn */

#define MRT_CHAN_COUNT  4u
#define MRT_CHAN_STRIDE 0x10u

#define MRT_OFF_INTVAL  0x00u
#define MRT_OFF_TIMER   0x04u
#define MRT_OFF_CTRL    0x08u
#define MRT_OFF_STAT    0x0Cu
#define MRT_OFF_MODCFG  0xF0u
#define MRT_OFF_IDLE_CH 0xF4u
#define MRT_OFF_IRQFLAG 0xF8u

#define MRT_SIZE        0x100u

/* INTVAL bit fields */
#define INTVAL_IVALUE_MASK 0x7FFFFFFFu
#define INTVAL_LOAD        (1u << 31)

/* CTRL bit fields */
#define CTRL_INTEN       (1u << 0)
#define CTRL_MODE_SHIFT  1u
#define CTRL_MODE_MASK   (0x3u << CTRL_MODE_SHIFT)
#define MODE_REPEAT      0u
#define MODE_ONESHOT     1u
#define MODE_ONESHOT_BUS 2u

/* STAT bit fields */
#define STAT_INTFLAG     (1u << 0)   /* write 1 to clear */
#define STAT_RUN         (1u << 1)

/* IRQ_FLAG bit per channel */
#define IRQFLAG_CH(n)    (1u << (n))

struct mrt_chan {
    mm_u32 intval;   /* loaded interval (31-bit) */
    mm_u32 counter;  /* current count */
    mm_u32 ctrl;
    mm_u32 stat;
};

static struct mrt_chan mrt_channels[MRT_CHAN_COUNT];
static mm_u32 mrt_irqflag;
static struct mm_nvic *g_mrt_nvic;

/* -------------------------------------------------------------------------
 * MMIO read/write
 * ------------------------------------------------------------------------- */

static mm_bool mrt_read(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                        mm_u32 *value_out)
{
    mm_u32 chan;
    mm_u32 chan_off;

    (void)opaque;
    if (value_out == 0 || size_bytes == 0 || size_bytes > 4u)
        return MM_FALSE;
    if ((offset + size_bytes) > MRT_SIZE)
        return MM_FALSE;
    if (!mrt_periph_active())
        return MM_FALSE;

    *value_out = 0;

    /* Global registers */
    if (offset == MRT_OFF_MODCFG) {
        /* number of channels = 4, bits = 31 */
        *value_out = ((MRT_CHAN_COUNT - 1u) & 0xFu) |
                     ((31u & 0x1Fu) << 4u);
        return MM_TRUE;
    }
    if (offset == MRT_OFF_IDLE_CH) {
        /* Return first channel whose STAT.RUN is 0 */
        mm_u32 i;
        for (i = 0; i < MRT_CHAN_COUNT; ++i) {
            if ((mrt_channels[i].stat & STAT_RUN) == 0u) {
                *value_out = i << 4u;
                return MM_TRUE;
            }
        }
        *value_out = MRT_CHAN_COUNT << 4u;
        return MM_TRUE;
    }
    if (offset == MRT_OFF_IRQFLAG) {
        *value_out = mrt_irqflag;
        return MM_TRUE;
    }

    /* Per-channel registers */
    if (offset < MRT_CHAN_COUNT * MRT_CHAN_STRIDE) {
        chan     = offset / MRT_CHAN_STRIDE;
        chan_off = offset % MRT_CHAN_STRIDE;
        switch (chan_off) {
        case MRT_OFF_INTVAL:
            *value_out = mrt_channels[chan].intval & INTVAL_IVALUE_MASK;
            return MM_TRUE;
        case MRT_OFF_TIMER:
            *value_out = mrt_channels[chan].counter;
            return MM_TRUE;
        case MRT_OFF_CTRL:
            *value_out = mrt_channels[chan].ctrl;
            return MM_TRUE;
        case MRT_OFF_STAT:
            *value_out = mrt_channels[chan].stat;
            return MM_TRUE;
        default:
            return MM_TRUE;
        }
    }

    return MM_TRUE;
}

static mm_bool mrt_write(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                         mm_u32 value)
{
    mm_u32 chan;
    mm_u32 chan_off;

    (void)opaque;
    if (size_bytes == 0 || size_bytes > 4u)
        return MM_FALSE;
    if ((offset + size_bytes) > MRT_SIZE)
        return MM_FALSE;
    if (!mrt_periph_active())
        return MM_FALSE;

    /* Global IRQ_FLAG: write 1 to clear */
    if (offset == MRT_OFF_IRQFLAG) {
        mrt_irqflag &= ~value;
        if (mrt_irqflag == 0u && g_mrt_nvic != 0)
            mm_nvic_set_pending(g_mrt_nvic, MRT0_IRQ, MM_FALSE);
        return MM_TRUE;
    }

    /* Per-channel registers */
    if (offset >= MRT_CHAN_COUNT * MRT_CHAN_STRIDE)
        return MM_TRUE;

    chan     = offset / MRT_CHAN_STRIDE;
    chan_off = offset % MRT_CHAN_STRIDE;

    switch (chan_off) {
    case MRT_OFF_INTVAL: {
        mm_u32 ivalue = value & INTVAL_IVALUE_MASK;
        mrt_channels[chan].intval = ivalue;
        if ((value & INTVAL_LOAD) != 0u || ivalue == 0u ||
            mrt_channels[chan].counter == 0u) {
            /* Load immediately: LOAD bit set, stopping timer, or timer was stopped */
            mrt_channels[chan].counter = ivalue;
        }
        if (ivalue == 0u) {
            mrt_channels[chan].stat &= ~STAT_RUN;
        } else {
            mrt_channels[chan].stat |= STAT_RUN;
        }
        break;
    }
    case MRT_OFF_CTRL:
        mrt_channels[chan].ctrl = value & (CTRL_INTEN | CTRL_MODE_MASK);
        break;
    case MRT_OFF_STAT:
        /* INTFLAG is write-1-to-clear */
        if ((value & STAT_INTFLAG) != 0u) {
            mrt_channels[chan].stat &= ~STAT_INTFLAG;
            mrt_irqflag &= ~IRQFLAG_CH(chan);
            if (mrt_irqflag == 0u && g_mrt_nvic != 0)
                mm_nvic_set_pending(g_mrt_nvic, MRT0_IRQ, MM_FALSE);
        }
        break;
    default:
        break;
    }

    return MM_TRUE;
}

/* -------------------------------------------------------------------------
 * Timer tick (called each emulation step)
 * ------------------------------------------------------------------------- */

void mm_lpc55s69_timers_tick(mm_u64 cycles)
{
    mm_u32 i;
    mm_bool fired = MM_FALSE;
    mm_u32 step = (mm_u32)((cycles > 0xFFFFFFFFu) ? 0xFFFFFFFFu : cycles);

    if (step == 0u) return;
    if (!mrt_periph_active()) return;

    for (i = 0; i < MRT_CHAN_COUNT; ++i) {
        struct mrt_chan *ch = &mrt_channels[i];
        mm_u32 mode;

        if ((ch->stat & STAT_RUN) == 0u) continue;
        if (ch->counter == 0u)           continue;

        mode = (ch->ctrl >> CTRL_MODE_SHIFT) & 0x3u;

        if (ch->counter <= step) {
            /* Counter expires this tick */
            ch->counter = 0u;
            ch->stat |= STAT_INTFLAG;
            mrt_irqflag |= IRQFLAG_CH(i);
            fired = MM_TRUE;

            if (mode == MODE_REPEAT && ch->intval > 0u) {
                /* Reload and keep running */
                ch->counter = ch->intval;
            } else {
                /* One-shot: stop */
                ch->stat &= ~STAT_RUN;
            }
        } else {
            ch->counter -= step;
        }
    }

    if (fired) {
        if (g_mrt_nvic != 0)
            mm_nvic_set_pending(g_mrt_nvic, MRT0_IRQ, MM_TRUE);
    }
}

/* -------------------------------------------------------------------------
 * Init / reset
 * ------------------------------------------------------------------------- */

void mm_lpc55s69_timers_init(struct mmio_bus *bus, struct mm_nvic *nvic)
{
    struct mmio_region reg;
    g_mrt_nvic = nvic;
    memset(mrt_channels, 0, sizeof(mrt_channels));
    mrt_irqflag = 0u;

    reg.base   = MRT0_BASE;
    reg.size   = MRT_SIZE;
    reg.opaque = 0;
    reg.read   = mrt_read;
    reg.write  = mrt_write;
    mmio_bus_register_region(bus, &reg);

    /* Secure alias */
    reg.base = MRT0_SEC_BASE;
    mmio_bus_register_region(bus, &reg);
}

void mm_lpc55s69_timers_reset(void)
{
    memset(mrt_channels, 0, sizeof(mrt_channels));
    mrt_irqflag = 0u;
    g_mrt_nvic = 0;
}
