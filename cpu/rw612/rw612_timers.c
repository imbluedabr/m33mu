/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * RW612 multi-rate timers (MRT0, MRT1).  4 down-counter channels per block
 * with INTVAL/TIMER/CTRL/STAT registers — same shape as LPC55S69 / MCXN947
 * MRTs, so the NXP fsl_mrt driver works against this stub unchanged.
 */

#include <string.h>
#include "rw612/rw612_timers.h"
#include "rw612/rw612_mmio.h"
#include "m33mu/mmio.h"
#include "m33mu/nvic.h"

#define MRT_INSTANCE_COUNT 2u
#define MRT_CHAN_COUNT     4u
#define MRT_CHAN_STRIDE    0x10u
#define MRT_SIZE           0x100u

#define MRT_OFF_INTVAL     0x00u
#define MRT_OFF_TIMER      0x04u
#define MRT_OFF_CTRL       0x08u
#define MRT_OFF_STAT       0x0Cu
#define MRT_OFF_MODCFG     0xF0u
#define MRT_OFF_IDLE_CH    0xF4u
#define MRT_OFF_IRQFLAG    0xF8u

#define INTVAL_IVALUE_MASK 0x7FFFFFFFu
#define INTVAL_LOAD        (1u << 31)

#define CTRL_INTEN         (1u << 0)
#define CTRL_MODE_SHIFT    1u
#define CTRL_MODE_MASK     (0x3u << CTRL_MODE_SHIFT)
#define MODE_REPEAT        0u

#define STAT_INTFLAG       (1u << 0)
#define STAT_RUN           (1u << 1)

#define IRQFLAG_CH(n)      (1u << (n))

struct mrt_chan {
    mm_u32 intval;
    mm_u32 counter;
    mm_u32 ctrl;
    mm_u32 stat;
};

struct mrt_inst {
    mm_u32  base;
    mm_u32  irq;
    mm_u32  pscctl_offset;
    mm_u32  pscctl_bit;
    mm_u32  domain;
    struct mrt_chan ch[MRT_CHAN_COUNT];
    mm_u32  irqflag;
};

static struct mrt_inst mrts[MRT_INSTANCE_COUNT];
static struct mm_nvic *g_mrt_nvic;

static mm_bool mrt_active(const struct mrt_inst *m)
{
    return mm_rw612_clkctl_periph_active(m->domain, m->pscctl_offset, m->pscctl_bit);
}

static mm_bool mrt_read(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                        mm_u32 *value_out)
{
    struct mrt_inst *m = (struct mrt_inst *)opaque;
    mm_u32 chan, chan_off, i;

    if (m == 0 || value_out == 0 || size_bytes == 0 || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > MRT_SIZE) return MM_FALSE;
    if (!mrt_active(m)) return MM_FALSE;

    *value_out = 0;
    if (offset == MRT_OFF_MODCFG) {
        *value_out = ((MRT_CHAN_COUNT - 1u) & 0xFu) | ((31u & 0x1Fu) << 4u);
        return MM_TRUE;
    }
    if (offset == MRT_OFF_IDLE_CH) {
        for (i = 0; i < MRT_CHAN_COUNT; ++i) {
            if ((m->ch[i].stat & STAT_RUN) == 0u) {
                *value_out = i << 4u;
                return MM_TRUE;
            }
        }
        *value_out = MRT_CHAN_COUNT << 4u;
        return MM_TRUE;
    }
    if (offset == MRT_OFF_IRQFLAG) {
        *value_out = m->irqflag;
        return MM_TRUE;
    }
    if (offset < MRT_CHAN_COUNT * MRT_CHAN_STRIDE) {
        chan     = offset / MRT_CHAN_STRIDE;
        chan_off = offset % MRT_CHAN_STRIDE;
        switch (chan_off) {
        case MRT_OFF_INTVAL: *value_out = m->ch[chan].intval & INTVAL_IVALUE_MASK; return MM_TRUE;
        case MRT_OFF_TIMER:  *value_out = m->ch[chan].counter; return MM_TRUE;
        case MRT_OFF_CTRL:   *value_out = m->ch[chan].ctrl;    return MM_TRUE;
        case MRT_OFF_STAT:   *value_out = m->ch[chan].stat;    return MM_TRUE;
        default: return MM_TRUE;
        }
    }
    return MM_TRUE;
}

static mm_bool mrt_write(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                         mm_u32 value)
{
    struct mrt_inst *m = (struct mrt_inst *)opaque;
    mm_u32 chan, chan_off;

    if (m == 0 || size_bytes == 0 || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > MRT_SIZE) return MM_FALSE;
    if (!mrt_active(m)) return MM_FALSE;

    if (offset == MRT_OFF_IRQFLAG) {
        m->irqflag &= ~value;
        if (m->irqflag == 0u && g_mrt_nvic != 0)
            mm_nvic_set_pending(g_mrt_nvic, m->irq, MM_FALSE);
        return MM_TRUE;
    }
    if (offset >= MRT_CHAN_COUNT * MRT_CHAN_STRIDE) return MM_TRUE;

    chan     = offset / MRT_CHAN_STRIDE;
    chan_off = offset % MRT_CHAN_STRIDE;

    switch (chan_off) {
    case MRT_OFF_INTVAL: {
        mm_u32 ivalue = value & INTVAL_IVALUE_MASK;
        m->ch[chan].intval = ivalue;
        if ((value & INTVAL_LOAD) != 0u || ivalue == 0u || m->ch[chan].counter == 0u) {
            m->ch[chan].counter = ivalue;
        }
        if (ivalue == 0u) m->ch[chan].stat &= ~STAT_RUN;
        else              m->ch[chan].stat |=  STAT_RUN;
        break;
    }
    case MRT_OFF_CTRL:
        m->ch[chan].ctrl = value & (CTRL_INTEN | CTRL_MODE_MASK);
        break;
    case MRT_OFF_STAT:
        if ((value & STAT_INTFLAG) != 0u) {
            m->ch[chan].stat &= ~STAT_INTFLAG;
            m->irqflag &= ~IRQFLAG_CH(chan);
            if (m->irqflag == 0u && g_mrt_nvic != 0)
                mm_nvic_set_pending(g_mrt_nvic, m->irq, MM_FALSE);
        }
        break;
    default: break;
    }
    return MM_TRUE;
}

void mm_rw612_timers_tick(mm_u64 cycles)
{
    mm_u32 inst, i;
    mm_u32 step = (mm_u32)((cycles > 0xFFFFFFFFu) ? 0xFFFFFFFFu : cycles);
    if (step == 0u) return;

    for (inst = 0; inst < MRT_INSTANCE_COUNT; ++inst) {
        struct mrt_inst *m = &mrts[inst];
        mm_bool fired = MM_FALSE;
        if (!mrt_active(m)) continue;
        for (i = 0; i < MRT_CHAN_COUNT; ++i) {
            struct mrt_chan *ch = &m->ch[i];
            mm_u32 mode;
            if ((ch->stat & STAT_RUN) == 0u) continue;
            if (ch->counter == 0u) continue;
            mode = (ch->ctrl >> CTRL_MODE_SHIFT) & 0x3u;
            if (ch->counter <= step) {
                ch->counter = 0u;
                ch->stat |= STAT_INTFLAG;
                m->irqflag |= IRQFLAG_CH(i);
                fired = MM_TRUE;
                if (mode == MODE_REPEAT && ch->intval > 0u) {
                    ch->counter = ch->intval;
                } else {
                    ch->stat &= ~STAT_RUN;
                }
            } else {
                ch->counter -= step;
            }
        }
        if (fired && g_mrt_nvic != 0)
            mm_nvic_set_pending(g_mrt_nvic, m->irq, MM_TRUE);
    }
}

void mm_rw612_timers_init(struct mmio_bus *bus, struct mm_nvic *nvic)
{
    static const struct {
        mm_u32 base;
        mm_u32 irq;
        mm_u32 domain;
        mm_u32 pscctl_offset;
        mm_u32 pscctl_bit;
    } defs[MRT_INSTANCE_COUNT] = {
        { 0x4002D000u, 14u, 0u, 0x10u, 8u },  /* MRT0 */
        { 0x4003F000u, 15u, 0u, 0x10u, 9u },  /* MRT1 */
    };
    mm_u32 inst;

    g_mrt_nvic = nvic;
    memset(mrts, 0, sizeof(mrts));

    for (inst = 0; inst < MRT_INSTANCE_COUNT; ++inst) {
        struct mmio_region reg;
        mrts[inst].base          = defs[inst].base;
        mrts[inst].irq           = defs[inst].irq;
        mrts[inst].domain        = defs[inst].domain;
        mrts[inst].pscctl_offset = defs[inst].pscctl_offset;
        mrts[inst].pscctl_bit    = defs[inst].pscctl_bit;

        memset(&reg, 0, sizeof(reg));
        reg.base   = defs[inst].base;
        reg.size   = MRT_SIZE;
        reg.opaque = &mrts[inst];
        reg.read   = mrt_read;
        reg.write  = mrt_write;
        mmio_bus_register_region(bus, &reg);
        reg.base = defs[inst].base + 0x10000000u;
        mmio_bus_register_region(bus, &reg);
    }
}

void mm_rw612_timers_reset(void)
{
    memset(mrts, 0, sizeof(mrts));
    g_mrt_nvic = 0;
}
