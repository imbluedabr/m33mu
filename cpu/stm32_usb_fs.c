/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "stm32_usb_fs.h"
#include "m33mu/mmio.h"
#include "m33mu/nvic.h"
#include "m33mu/usbdev.h"

#define USB_SIZE     0x400u

#define USB_CNTR     0x40u
#define USB_ISTR     0x44u
#define USB_DADDR    0x4Cu
#define USB_BTABLE   0x50u

#define USB_EP_CTR_RX  (1u << 15)
#define USB_EP_DTOG_RX (1u << 14)
#define USB_EP_STAT_RX (3u << 12)
#define USB_EP_SETUP   (1u << 11)
#define USB_EP_TYPE    (3u << 9)
#define USB_EP_KIND    (1u << 8)
#define USB_EP_CTR_TX  (1u << 7)
#define USB_EP_DTOG_TX (1u << 6)
#define USB_EP_STAT_TX (3u << 4)
#define USB_EP_EA      (0xFu << 0)

#define USB_EP_STAT_NAK      2u
#define USB_EP_STAT_VALID    3u

#define USB_CNTR_CTRM (1u << 15)

#define USB_ISTR_CTR  (1u << 15)
#define USB_ISTR_DIR  (1u << 4)
#define USB_ISTR_ID_MASK 0xFu
#define USB_ISTR_RESET (1u << 10)

#define USB_DADDR_EF  (1u << 7)

static int g_usb_trace = -1;
static int g_usb_pma_trace = -1;

static mm_bool usb_trace_enabled(void)
{
    if (g_usb_trace < 0) {
        const char *v = getenv("M33MU_USB_TRACE");
        g_usb_trace = (v && v[0] != '\0') ? 1 : 0;
    }
    return g_usb_trace ? MM_TRUE : MM_FALSE;
}

static mm_bool usb_pma_trace_enabled(void)
{
    if (g_usb_pma_trace < 0) {
        const char *v = getenv("M33MU_USB_PMA_TRACE");
        g_usb_pma_trace = (v && v[0] != '\0') ? 1 : 0;
    }
    return g_usb_pma_trace ? MM_TRUE : MM_FALSE;
}

static void usb_trace(const char *fmt, ...)
{
    va_list ap;
    if (!usb_trace_enabled()) return;
    va_start(ap, fmt);
    fprintf(stderr, "[USB_TRACE] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

static mm_u16 usb_pma_read16(const struct stm32_usb_fs_state *s, mm_u32 addr)
{
    mm_u16 v = 0;
    if (addr + 1u >= s->cfg->pma_size) return 0;
    v = (mm_u16)s->pma[addr];
    v |= (mm_u16)((mm_u16)s->pma[addr + 1u] << 8);
    return v;
}

static void usb_pma_write16(struct stm32_usb_fs_state *s, mm_u32 addr, mm_u16 v)
{
    if (addr + 1u >= s->cfg->pma_size) return;
    s->pma[addr] = (mm_u8)(v & 0xFFu);
    s->pma[addr + 1u] = (mm_u8)((v >> 8) & 0xFFu);
}

static mm_u32 usb_pma_read32(const struct stm32_usb_fs_state *s, mm_u32 addr)
{
    mm_u32 v = 0;
    if (addr + 3u >= s->cfg->pma_size) return 0;
    v |= (mm_u32)s->pma[addr + 0u];
    v |= (mm_u32)s->pma[addr + 1u] << 8;
    v |= (mm_u32)s->pma[addr + 2u] << 16;
    v |= (mm_u32)s->pma[addr + 3u] << 24;
    return v;
}

static void usb_pma_write32(struct stm32_usb_fs_state *s, mm_u32 addr, mm_u32 v)
{
    if (addr + 3u >= s->cfg->pma_size) return;
    s->pma[addr + 0u] = (mm_u8)(v & 0xFFu);
    s->pma[addr + 1u] = (mm_u8)((v >> 8) & 0xFFu);
    s->pma[addr + 2u] = (mm_u8)((v >> 16) & 0xFFu);
    s->pma[addr + 3u] = (mm_u8)((v >> 24) & 0xFFu);
}

static mm_u32 usb_pma_resolve_addr(const struct stm32_usb_fs_state *s, mm_u32 addr, mm_u32 len)
{
    if (addr + len <= s->cfg->pma_size) return addr;
    if (!s->cfg->pma_32bit && (addr * 2u) + len <= s->cfg->pma_size) return addr * 2u;
    return addr;
}

static void usb_raise_irq(struct stm32_usb_fs_state *s)
{
    if (s->nvic != 0 && (s->regs[USB_CNTR / 4u] & USB_CNTR_CTRM) != 0u) {
        usb_trace("raise irq USB_FS (ctrm set)");
        mm_nvic_set_pending(s->nvic, s->cfg->irq, MM_TRUE);
    }
}

static void usb_set_istr(struct stm32_usb_fs_state *s, mm_u32 ep, mm_bool dir_out)
{
    mm_u32 istr = s->regs[USB_ISTR / 4u];
    istr |= USB_ISTR_CTR;
    istr &= ~USB_ISTR_ID_MASK;
    istr |= (ep & USB_ISTR_ID_MASK);
    if (dir_out) {
        istr |= USB_ISTR_DIR;
    } else {
        istr &= ~USB_ISTR_DIR;
    }
    s->regs[USB_ISTR / 4u] = istr;
    usb_trace("set ISTR ep=%u dir_out=%u istr=0x%08x", ep, dir_out ? 1u : 0u, istr);
    usb_raise_irq(s);
}

static void usb_bus_reset(void *opaque)
{
    struct stm32_usb_fs_state *s = (struct stm32_usb_fs_state *)opaque;
    s->regs[USB_ISTR / 4u] |= USB_ISTR_RESET;
    usb_trace("usb bus reset (ISTR=0x%08x)", s->regs[USB_ISTR / 4u]);
    usb_raise_irq(s);
}

static mm_u32 usb_ep_read(struct stm32_usb_fs_state *s, int ep)
{
    if (ep < 0 || ep >= 8) return 0;
    if (s->ep[ep] != s->last_ep_read[ep]) {
        usb_trace("ep_read ep=%d val=0x%08x", ep, s->ep[ep]);
        s->last_ep_read[ep] = s->ep[ep];
    }
    return s->ep[ep];
}

static void usb_ep_write(struct stm32_usb_fs_state *s, int ep, mm_u32 value)
{
    mm_u32 old;
    mm_u32 reg;
    mm_bool ctr_any = MM_FALSE;
    int i;
    if (ep < 0 || ep >= 8) return;
    old = s->ep[ep];
    reg = old;
    if ((value & USB_EP_CTR_RX) == 0u) {
        reg &= ~USB_EP_CTR_RX;
        reg &= ~USB_EP_SETUP;
    }
    if ((value & USB_EP_CTR_TX) == 0u) {
        reg &= ~USB_EP_CTR_TX;
    }
    if ((value & USB_EP_DTOG_RX) != 0u) {
        reg ^= USB_EP_DTOG_RX;
    }
    if ((value & USB_EP_DTOG_TX) != 0u) {
        reg ^= USB_EP_DTOG_TX;
    }
    if ((value & USB_EP_STAT_RX) != 0u) {
        reg ^= (value & USB_EP_STAT_RX);
    }
    if ((value & USB_EP_STAT_TX) != 0u) {
        reg ^= (value & USB_EP_STAT_TX);
    }
    reg &= ~(USB_EP_EA | USB_EP_KIND | USB_EP_TYPE);
    reg |= (value & (USB_EP_EA | USB_EP_KIND | USB_EP_TYPE));
    s->ep[ep] = reg;
    for (i = 0; i < 8; ++i) {
        if ((s->ep[i] & (USB_EP_CTR_RX | USB_EP_CTR_TX)) != 0u) {
            ctr_any = MM_TRUE;
            break;
        }
    }
    if (!ctr_any) {
        s->regs[USB_ISTR / 4u] &= ~USB_ISTR_CTR;
    }
    usb_trace("ep_write ep=%d val=0x%08x -> reg=0x%08x", ep, value, reg);
}

static mm_u32 usb_btable_base(const struct stm32_usb_fs_state *s)
{
    return s->regs[USB_BTABLE / 4u] & 0xFFF8u;
}

static void usb_get_ep_btable(const struct stm32_usb_fs_state *s, int ep, mm_u16 *tx_addr, mm_u16 *tx_count, mm_u16 *rx_addr, mm_u16 *rx_count)
{
    mm_u32 btable = usb_btable_base(s);
    mm_u32 base = btable + (mm_u32)ep * 8u;
    if (s->cfg->pma_32bit) {
        if (tx_addr || tx_count) {
            mm_u32 v = usb_pma_read32(s, base + 0u);
            if (tx_addr) *tx_addr = (mm_u16)(v & 0xFFFCu);
            if (tx_count) *tx_count = (mm_u16)((v >> 16) & 0x03FFu);
        }
        if (rx_addr || rx_count) {
            mm_u32 v = usb_pma_read32(s, base + 4u);
            if (rx_addr) *rx_addr = (mm_u16)(v & 0xFFFCu);
            if (rx_count) *rx_count = (mm_u16)((v >> 16) & 0x03FFu);
        }
    } else {
        if (tx_addr) *tx_addr = usb_pma_read16(s, base + 0u);
        if (tx_count) *tx_count = usb_pma_read16(s, base + 2u);
        if (rx_addr) *rx_addr = usb_pma_read16(s, base + 4u);
        if (rx_count) *rx_count = usb_pma_read16(s, base + 6u);
    }
}

static void usb_set_rx_count(struct stm32_usb_fs_state *s, int ep, mm_u16 count)
{
    mm_u32 btable = usb_btable_base(s);
    mm_u32 base = btable + (mm_u32)ep * 8u;
    if (s->cfg->pma_32bit) {
        mm_u32 current = usb_pma_read32(s, base + 4u);
        mm_u32 next = (current & ~0x03FF0000u) | ((mm_u32)(count & 0x03FFu) << 16);
        usb_pma_write32(s, base + 4u, next);
    } else {
        mm_u16 current = usb_pma_read16(s, base + 6u);
        mm_u16 next = (current & 0xFC00u) | (count & 0x03FFu);
        usb_pma_write16(s, base + 6u, next);
    }
}

static mm_bool usb_ep_out(void *opaque, int ep, const mm_u8 *data, mm_u32 len, mm_bool setup)
{
    struct stm32_usb_fs_state *s = (struct stm32_usb_fs_state *)opaque;
    mm_u32 reg;
    mm_u16 rx_addr;
    mm_u16 rx_count;
    mm_u32 addr;
    mm_u32 i;
    if (ep < 0 || ep >= 8) return MM_FALSE;
    if ((s->regs[USB_DADDR / 4u] & USB_DADDR_EF) == 0u) return MM_FALSE;
    reg = usb_ep_read(s, ep);
    if (((reg >> 12) & 0x3u) != USB_EP_STAT_VALID) {
        if (!(setup && ep == 0)) {
            return MM_FALSE;
        }
    }
    usb_get_ep_btable(s, ep, 0, 0, &rx_addr, &rx_count);
    (void)rx_count;
    addr = usb_pma_resolve_addr(s, rx_addr, len);
    for (i = 0; i < len && (addr + i) < s->cfg->pma_size; ++i) {
        s->pma[addr + i] = data ? data[i] : 0u;
    }
    usb_set_rx_count(s, ep, (mm_u16)len);
    reg |= USB_EP_CTR_RX;
    if (setup) {
        reg |= USB_EP_SETUP;
        if (ep == 0 && data && len >= 8u) {
            memcpy(s->last_setup, data, 8u);
            s->last_setup_valid = MM_TRUE;
        }
    }
    reg &= ~USB_EP_STAT_RX;
    reg |= (USB_EP_STAT_NAK << 12);
    s->ep[ep] = reg;
    usb_set_istr(s, (mm_u32)ep, MM_TRUE);
    return MM_TRUE;
}

static mm_bool usb_ep_in(void *opaque, int ep, mm_u8 *data, mm_u32 *len_inout)
{
    struct stm32_usb_fs_state *s = (struct stm32_usb_fs_state *)opaque;
    mm_u32 reg;
    mm_u16 tx_addr;
    mm_u16 tx_count;
    mm_u32 addr;
    mm_u32 i;
    mm_u32 len;
    if (ep < 0 || ep >= 8 || data == 0 || len_inout == 0) return MM_FALSE;
    if ((s->regs[USB_DADDR / 4u] & USB_DADDR_EF) == 0u) return MM_FALSE;
    reg = usb_ep_read(s, ep);
    if (((reg >> 4) & 0x3u) != USB_EP_STAT_VALID) {
        return MM_FALSE;
    }
    usb_get_ep_btable(s, ep, &tx_addr, &tx_count, 0, 0);
    len = (mm_u32)(tx_count & 0x03FFu);
    if (len > *len_inout) len = *len_inout;
    addr = usb_pma_resolve_addr(s, tx_addr, len);
    for (i = 0; i < len && (addr + i) < s->cfg->pma_size; ++i) {
        data[i] = s->pma[addr + i];
    }
    *len_inout = len;
    reg |= USB_EP_CTR_TX;
    reg &= ~USB_EP_STAT_TX;
    reg |= (USB_EP_STAT_NAK << 4);
    s->ep[ep] = reg;
    usb_set_istr(s, (mm_u32)ep, MM_FALSE);
    return MM_TRUE;
}

static const struct mm_usbdev_ops usb_ops = {
    usb_ep_out,
    usb_ep_in,
    usb_bus_reset
};

static mm_bool usb_read(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out)
{
    struct stm32_usb_fs_state *s = (struct stm32_usb_fs_state *)opaque;
    mm_u32 v = 0;
    if (value_out == 0 || size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if (offset < 0x20u && (offset % 4u) == 0u) {
        v = usb_ep_read(s, (int)(offset / 4u));
    } else if (offset < USB_SIZE && (offset % 4u) == 0u) {
        v = s->regs[offset / 4u];
    } else {
        return MM_FALSE;
    }
    if (size_bytes == 2u) {
        v &= 0xFFFFu;
    }
    *value_out = v;
    return MM_TRUE;
}

static mm_bool usb_write(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 value)
{
    struct stm32_usb_fs_state *s = (struct stm32_usb_fs_state *)opaque;
    if (size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if (offset < 0x20u && (offset % 4u) == 0u) {
        if (size_bytes == 2u) value &= 0xFFFFu;
        usb_ep_write(s, (int)(offset / 4u), value);
        return MM_TRUE;
    }
    if (offset < USB_SIZE && (offset % 4u) == 0u) {
        if (size_bytes == 2u) {
            mm_u32 reg = s->regs[offset / 4u];
            mm_u32 lo = value & 0xFFFFu;
            if (offset == USB_ISTR) {
                reg = (reg & 0xFFFF0000u) | ((reg & 0xFFFFu) & lo);
            } else {
                reg = (reg & 0xFFFF0000u) | lo;
            }
            s->regs[offset / 4u] = reg;
            return MM_TRUE;
        }
        if (offset == USB_ISTR) {
            s->regs[offset / 4u] &= value;
        } else {
            s->regs[offset / 4u] = value;
        }
        return MM_TRUE;
    }
    return MM_FALSE;
}

static mm_bool usb_pma_read(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out)
{
    struct stm32_usb_fs_state *s = (struct stm32_usb_fs_state *)opaque;
    mm_u32 v = 0;
    mm_u32 i;
    if (value_out == 0 || size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if (offset + size_bytes > s->cfg->pma_size) return MM_FALSE;
    for (i = 0; i < size_bytes; ++i) {
        v |= ((mm_u32)s->pma[offset + i]) << (8u * i);
    }
    *value_out = v;
    return MM_TRUE;
}

static mm_bool usb_pma_write(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 value)
{
    struct stm32_usb_fs_state *s = (struct stm32_usb_fs_state *)opaque;
    mm_u32 i;
    if (size_bytes == 0 || size_bytes > 4) return MM_FALSE;
    if (offset + size_bytes > s->cfg->pma_size) return MM_FALSE;
    for (i = 0; i < size_bytes; ++i) {
        s->pma[offset + i] = (mm_u8)((value >> (8u * i)) & 0xFFu);
    }
    if (usb_pma_trace_enabled() && offset < 0x40u) {
        printf("[USB_PMA_BTABLE] off=0x%03x size=%u val=0x%08x\n",
               (unsigned)offset, (unsigned)size_bytes, (unsigned)value);
    }
    return MM_TRUE;
}

mm_bool stm32_usb_fs_register_mmio(struct stm32_usb_fs_state *state,
                                   const struct stm32_usb_fs_config *cfg,
                                   struct mmio_bus *bus)
{
    struct mmio_region reg;
    int i;
    if (state == 0 || cfg == 0 || bus == 0) return MM_FALSE;
    memset(state, 0, sizeof(*state));
    state->cfg = cfg;
    for (i = 0; i < 8; ++i) {
        state->last_ep_read[i] = 0xFFFFFFFFu;
        state->last_tx_stat[i] = 0xFFu;
        state->last_tx_count[i] = 0xFFFFu;
    }
    state->regs[USB_BTABLE / 4u] = 0u;
    if (!mm_usbdev_register(&usb_ops, state)) {
    }
    memset(&reg, 0, sizeof(reg));
    reg.base = cfg->usb_base;
    reg.size = USB_SIZE;
    reg.opaque = state;
    reg.read = usb_read;
    reg.write = usb_write;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;
    reg.base = cfg->usb_sec_base;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;
    reg.base = cfg->pma_base;
    reg.size = cfg->pma_size;
    reg.read = usb_pma_read;
    reg.write = usb_pma_write;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;
    reg.base = cfg->pma_sec_base;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;
    return MM_TRUE;
}

void stm32_usb_fs_set_nvic(struct stm32_usb_fs_state *state, struct mm_nvic *nvic)
{
    const char *env;
    if (state == 0 || state->cfg == 0) {
        return;
    }
    state->nvic = nvic;
    if (nvic != 0) {
        env = getenv("M33MU_USB_NONSECURE_IRQ");
        mm_nvic_set_itns(nvic, state->cfg->irq, (env != 0 && env[0] != '\0') ? MM_TRUE : MM_FALSE);
    }
}

void stm32_usb_fs_reset(struct stm32_usb_fs_state *state)
{
    const struct stm32_usb_fs_config *cfg;
    if (state == 0) {
        return;
    }
    cfg = state->cfg;
    memset(state, 0, sizeof(*state));
    state->cfg = cfg;
    if (cfg != 0) {
        state->regs[USB_BTABLE / 4u] = 0u;
    }
}
