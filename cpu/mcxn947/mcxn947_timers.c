/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <string.h>
#include "mcxn947/mcxn947_timers.h"
#include "mcxn947/mcxn947_mmio.h"
#include "m33mu/mmio.h"
#include "m33mu/nvic.h"

/* LPTMR0 base address and IRQ */
#define LPTMR0_BASE 0x4004A000u
#define LPTMR0_IRQ  143
#define LPTMR_SIZE  0x10u

/* LPTMR register offsets */
#define LPTMR_CSR 0x00u
#define LPTMR_PSR 0x04u
#define LPTMR_CMR 0x08u
#define LPTMR_CNR 0x0Cu

/* CSR bit fields */
#define CSR_TEN  (1u << 0)   /* Timer Enable */
#define CSR_TMS  (1u << 1)   /* Timer Mode Select */
#define CSR_TFC  (1u << 2)   /* Timer Free-Running Counter */
#define CSR_TPP  (1u << 3)   /* Timer Pin Polarity */
#define CSR_TPS_SHIFT 4
#define CSR_TPS_MASK (0x3u << CSR_TPS_SHIFT)
#define CSR_TIE  (1u << 6)   /* Timer Interrupt Enable */
#define CSR_TCF  (1u << 7)   /* Timer Compare Flag */
#define CSR_TDRE (1u << 8)   /* Timer DMA Request Enable */

/* PSR bit fields */
#define PSR_PCS_SHIFT 0
#define PSR_PCS_MASK (0x3u << PSR_PCS_SHIFT)
#define PSR_PBYP (1u << 2)   /* Prescaler Bypass */
#define PSR_PRESCALE_SHIFT 3
#define PSR_PRESCALE_MASK (0xFu << PSR_PRESCALE_SHIFT)

struct lptmr_state {
    mm_u32 regs[LPTMR_SIZE / 4];
    mm_u32 counter;  /* Internal counter value */
};

static struct lptmr_state lptmr0;
static struct mm_nvic *g_nvic = 0;

static mm_bool lptmr_clocked(void)
{
    /* LPTMR0 is always clocked from FRO12M, doesn't need SYSCON enable */
    return MM_TRUE;
}

static mm_bool lptmr_read(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out)
{
    struct lptmr_state *t = (struct lptmr_state *)opaque;
    if (t == 0 || value_out == 0 || size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if (!lptmr_clocked()) return MM_FALSE;
    if ((offset + size_bytes) > LPTMR_SIZE) return MM_FALSE;

    if (offset == LPTMR_CNR && size_bytes == 4) {
        /* Reading CNR returns current counter value */
        *value_out = t->counter;
        return MM_TRUE;
    }

    memcpy(value_out, (mm_u8 *)t->regs + offset, size_bytes);
    return MM_TRUE;
}

static mm_bool lptmr_write(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 value)
{
    struct lptmr_state *t = (struct lptmr_state *)opaque;
    if (t == 0 || size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if (!lptmr_clocked()) return MM_FALSE;
    if ((offset + size_bytes) > LPTMR_SIZE) return MM_FALSE;

    if (size_bytes == 4) {
        if (offset == LPTMR_CSR) {
            mm_u32 old_csr = t->regs[LPTMR_CSR / 4];
            mm_u32 new_csr = value;

            /* Writing 1 to TCF clears it */
            if ((value & CSR_TCF) != 0u) {
                new_csr &= ~CSR_TCF;
            } else {
                new_csr |= (old_csr & CSR_TCF);
            }

            /* If timer is being enabled, reset counter */
            if ((new_csr & CSR_TEN) != 0u && (old_csr & CSR_TEN) == 0u) {
                t->counter = 0;
            }

            /* If timer is being disabled, stop it */
            if ((new_csr & CSR_TEN) == 0u) {
                t->counter = 0;
            }

            t->regs[LPTMR_CSR / 4] = new_csr;
            return MM_TRUE;
        }

        if (offset == LPTMR_CNR) {
            /* Writing any value to CNR resets counter to 0 */
            t->counter = 0;
            t->regs[LPTMR_CSR / 4] &= ~CSR_TCF;
            return MM_TRUE;
        }
    }

    memcpy((mm_u8 *)t->regs + offset, &value, size_bytes);
    return MM_TRUE;
}

void mm_mcxn947_timers_tick(mm_u64 cycles)
{
    mm_u32 csr = lptmr0.regs[LPTMR_CSR / 4];
    mm_u32 psr = lptmr0.regs[LPTMR_PSR / 4];
    mm_u32 cmr = lptmr0.regs[LPTMR_CMR / 4];
    mm_u32 prescale;
    mm_u32 divisor;
    mm_u32 step;

    if (!lptmr_clocked()) return;

    /* Timer not enabled */
    if ((csr & CSR_TEN) == 0u) return;

    /* Timer in pulse counter mode (not time counter) */
    if ((csr & CSR_TMS) != 0u) return;

    /* Calculate prescaler divisor */
    if ((psr & PSR_PBYP) != 0u) {
        divisor = 1;  /* Bypass mode */
    } else {
        prescale = (psr >> PSR_PRESCALE_SHIFT) & 0xFu;
        /* Prescaler divides by 2^(prescale+1) */
        divisor = 2u << prescale;
    }

    /* Apply prescaler */
    step = (mm_u32)((cycles > 0xffffffffu) ? 0xffffffffu : cycles);
    step = step / divisor;
    if (step == 0u) return;

    /* Increment counter */
    lptmr0.counter += step;

    /* Check for compare match */
    if (lptmr0.counter >= cmr) {
        /* Set compare flag */
        lptmr0.regs[LPTMR_CSR / 4] |= CSR_TCF;

        /* Reset counter if not free-running */
        if ((csr & CSR_TFC) == 0u) {
            lptmr0.counter = 0;
        } else {
            /* Free-running mode: wrap at 16-bit boundary */
            lptmr0.counter &= 0xFFFFu;
        }

        /* Trigger interrupt if enabled */
        if ((csr & CSR_TIE) != 0u && g_nvic != 0) {
            mm_nvic_set_pending(g_nvic, LPTMR0_IRQ, MM_TRUE);
        }
    }
}

void mm_mcxn947_timers_init(struct mmio_bus *bus, struct mm_nvic *nvic)
{
    struct mmio_region reg;

    g_nvic = nvic;
    mm_mcxn947_gpio_set_nvic(nvic);

    memset(&lptmr0, 0, sizeof(lptmr0));

    /* Register LPTMR0 (non-secure) */
    reg.base = LPTMR0_BASE;
    reg.size = LPTMR_SIZE;
    reg.opaque = &lptmr0;
    reg.read = lptmr_read;
    reg.write = lptmr_write;
    mmio_bus_register_region(bus, &reg);

    /* Register secure alias */
    reg.base = LPTMR0_BASE + 0x10000000u;
    mmio_bus_register_region(bus, &reg);
}

void mm_mcxn947_timers_reset(void)
{
    memset(&lptmr0, 0, sizeof(lptmr0));
    g_nvic = 0;
}
