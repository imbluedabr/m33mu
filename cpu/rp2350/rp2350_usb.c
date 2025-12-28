/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include "rp2350/rp2350_usb.h"
#include "rp2350/rp2350_mmio.h"
#include "m33mu/usbdev.h"
#include "m33mu/nvic.h"

#define USB_BASE       0x50110000u
#define USB_SIZE       0x1000u
#define USB_DPRAM_BASE 0x50100000u
#define USB_DPRAM_SIZE 0x1000u

#define USB_ADDR_ENDP0 0x000u
#define USB_MAIN_CTRL  0x040u
#define USB_SIE_CTRL   0x04cu
#define USB_SIE_STATUS 0x050u
#define USB_BUFF_STATUS 0x058u
#define USB_BUFF_CPU_SHOULD_HANDLE 0x05cu
#define USB_INTR       0x08cu
#define USB_INTE       0x090u
#define USB_INTF       0x094u
#define USB_INTS       0x098u

#define MAIN_CTRL_CONTROLLER_EN (1u << 0)

#define SIE_CTRL_PULLUP_EN (1u << 16)
#define SIE_CTRL_RESET_BUS (1u << 13)

#define INTR_BUFF_STATUS (1u << 4)
#define INTR_TRANS_COMPLETE (1u << 3)
#define INTR_SETUP_REQ (1u << 16)
#define INTR_BUS_RESET (1u << 12)

#define USB_IRQ 14

#define DPRAM_SETUP_PACKET_LOW  0x000u
#define DPRAM_SETUP_PACKET_HIGH 0x004u
#define DPRAM_EP1_IN_CTRL 0x008u
#define DPRAM_EP1_OUT_CTRL 0x00cu
#define DPRAM_EP0_IN_BUF_CTRL 0x080u
#define DPRAM_EP0_OUT_BUF_CTRL 0x084u

#define EP_CTRL_ENABLE (1u << 31)
#define EP_CTRL_BUF_ADDR_MASK 0xffffu

#define BUF_CTRL_LENGTH_MASK 0x3ffu
#define BUF_CTRL_AVAILABLE (1u << 10)
#define BUF_CTRL_STALL (1u << 11)
#define BUF_CTRL_RESET (1u << 12)
#define BUF_CTRL_PID (1u << 13)
#define BUF_CTRL_LAST (1u << 14)
#define BUF_CTRL_FULL (1u << 15)
#define BUF_CTRL_LENGTH_SHIFT 0
#define BUF_CTRL_LENGTH1_SHIFT 16
#define BUF_CTRL_AVAILABLE1 (1u << 26)
#define BUF_CTRL_FULL1 (1u << 31)

#define EP0_OUT_BUF_BASE 0x100u
#define EP0_IN_BUF_BASE  0x140u
#define EP0_BUF_SIZE 64u

struct rp2350_usb {
    mm_u32 regs[USB_SIZE / 4u];
    mm_u8 dpram[USB_DPRAM_SIZE];
    struct mm_nvic *nvic;
};

static struct rp2350_usb g_usb;
static int g_usb_trace = -1;

static mm_bool usb_trace_enabled(void)
{
    if (g_usb_trace < 0) {
        const char *v = getenv("M33MU_USB_TRACE");
        g_usb_trace = (v && v[0] != '\0') ? 1 : 0;
    }
    return g_usb_trace ? MM_TRUE : MM_FALSE;
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

static mm_u32 dpram_read32(mm_u32 offset)
{
    mm_u32 v = 0u;
    if (offset + 3u >= USB_DPRAM_SIZE) return 0u;
    v |= (mm_u32)g_usb.dpram[offset + 0u];
    v |= (mm_u32)g_usb.dpram[offset + 1u] << 8;
    v |= (mm_u32)g_usb.dpram[offset + 2u] << 16;
    v |= (mm_u32)g_usb.dpram[offset + 3u] << 24;
    return v;
}

static void dpram_write32(mm_u32 offset, mm_u32 value)
{
    if (offset + 3u >= USB_DPRAM_SIZE) return;
    g_usb.dpram[offset + 0u] = (mm_u8)(value & 0xffu);
    g_usb.dpram[offset + 1u] = (mm_u8)((value >> 8) & 0xffu);
    g_usb.dpram[offset + 2u] = (mm_u8)((value >> 16) & 0xffu);
    g_usb.dpram[offset + 3u] = (mm_u8)((value >> 24) & 0xffu);
}

static mm_bool usb_controller_enabled(void)
{
    if (mm_rp2350_reset_asserted(RP2350_RESET_USBCTRL)) return MM_FALSE;
    if (!mm_rp2350_clock_peri_enabled()) return MM_FALSE;
    if ((g_usb.regs[USB_MAIN_CTRL / 4u] & MAIN_CTRL_CONTROLLER_EN) == 0u) return MM_FALSE;
    if ((g_usb.regs[USB_SIE_CTRL / 4u] & SIE_CTRL_PULLUP_EN) == 0u) return MM_FALSE;
    return MM_TRUE;
}

static mm_u32 dpram_ep_ctrl_offset(int ep, mm_bool in)
{
    if (ep <= 0) return 0u;
    return (mm_u32)(DPRAM_EP1_IN_CTRL + (mm_u32)(ep - 1) * 8u + (in ? 0u : 4u));
}

static mm_u32 dpram_ep_buf_ctrl_offset(int ep, mm_bool in)
{
    return (mm_u32)(DPRAM_EP0_IN_BUF_CTRL + (mm_u32)ep * 8u + (in ? 0u : 4u));
}

static mm_u32 ep_buffer_address(int ep, mm_bool in)
{
    if (ep == 0) {
        return in ? EP0_IN_BUF_BASE : EP0_OUT_BUF_BASE;
    }
    return dpram_read32(dpram_ep_ctrl_offset(ep, in)) & EP_CTRL_BUF_ADDR_MASK;
}

static mm_bool ep_enabled(int ep, mm_bool in)
{
    if (ep == 0) return MM_TRUE;
    return (dpram_read32(dpram_ep_ctrl_offset(ep, in)) & EP_CTRL_ENABLE) != 0u;
}

static mm_bool buf_available(mm_u32 ctrl)
{
    return (ctrl & BUF_CTRL_AVAILABLE) != 0u;
}

static mm_u32 buf_length(mm_u32 ctrl)
{
    return ctrl & BUF_CTRL_LENGTH_MASK;
}

static mm_u32 buf_set_length(mm_u32 ctrl, mm_u32 len)
{
    ctrl &= ~BUF_CTRL_LENGTH_MASK;
    ctrl |= (len & BUF_CTRL_LENGTH_MASK);
    return ctrl;
}

static void usb_update_ints(void)
{
    mm_u32 intr = g_usb.regs[USB_INTR / 4u];
    mm_u32 inte = g_usb.regs[USB_INTE / 4u];
    mm_u32 intf = g_usb.regs[USB_INTF / 4u];
    mm_u32 ints = (intr & inte) | intf;
    g_usb.regs[USB_INTS / 4u] = ints;
    if (ints != 0u && g_usb.nvic != 0) {
        mm_nvic_set_pending(g_usb.nvic, USB_IRQ, MM_TRUE);
    }
}

static void usb_set_buff_status(int ep, mm_bool in)
{
    mm_u32 bit = (mm_u32)(ep * 2 + (in ? 0 : 1));
    g_usb.regs[USB_BUFF_STATUS / 4u] |= (1u << bit);
    g_usb.regs[USB_BUFF_CPU_SHOULD_HANDLE / 4u] |= (1u << bit);
    g_usb.regs[USB_INTR / 4u] |= (INTR_BUFF_STATUS | INTR_TRANS_COMPLETE);
    usb_update_ints();
}

static mm_bool usb_ep_out(void *opaque, int ep, const mm_u8 *data, mm_u32 len, mm_bool setup)
{
    mm_u32 buf_ctrl_off;
    mm_u32 buf_ctrl;
    mm_u32 buf_addr;
    mm_u32 i;

    (void)opaque;
    if (!usb_controller_enabled()) return MM_FALSE;
    if (ep < 0 || ep > 15) return MM_FALSE;
    if (!ep_enabled(ep, MM_FALSE)) return MM_FALSE;

    buf_ctrl_off = dpram_ep_buf_ctrl_offset(ep, MM_FALSE);
    buf_ctrl = dpram_read32(buf_ctrl_off);
    if (!buf_available(buf_ctrl)) {
        return MM_FALSE;
    }

    buf_addr = ep_buffer_address(ep, MM_FALSE);
    if (buf_addr + len > USB_DPRAM_SIZE) {
        len = (buf_addr < USB_DPRAM_SIZE) ? (USB_DPRAM_SIZE - buf_addr) : 0u;
    }
    for (i = 0; i < len; ++i) {
        g_usb.dpram[buf_addr + i] = data ? data[i] : 0u;
    }
    buf_ctrl = buf_set_length(buf_ctrl, len);
    buf_ctrl &= ~BUF_CTRL_AVAILABLE;
    buf_ctrl |= BUF_CTRL_FULL | BUF_CTRL_LAST;
    dpram_write32(buf_ctrl_off, buf_ctrl);

    if (setup && ep == 0 && data != 0 && len >= 8u) {
        dpram_write32(DPRAM_SETUP_PACKET_LOW,
                      (mm_u32)data[0] | ((mm_u32)data[1] << 8) |
                      ((mm_u32)data[2] << 16) | ((mm_u32)data[3] << 24));
        dpram_write32(DPRAM_SETUP_PACKET_HIGH,
                      (mm_u32)data[4] | ((mm_u32)data[5] << 8) |
                      ((mm_u32)data[6] << 16) | ((mm_u32)data[7] << 24));
        g_usb.regs[USB_INTR / 4u] |= INTR_SETUP_REQ;
    }

    usb_set_buff_status(ep, MM_FALSE);
    usb_trace("rp2350 usb ep_out ep=%d len=%u setup=%u", ep, (unsigned)len, setup ? 1u : 0u);
    return MM_TRUE;
}

static mm_bool usb_ep_in(void *opaque, int ep, mm_u8 *data, mm_u32 *len_inout)
{
    mm_u32 buf_ctrl_off;
    mm_u32 buf_ctrl;
    mm_u32 buf_addr;
    mm_u32 len;
    mm_u32 i;

    (void)opaque;
    if (!usb_controller_enabled()) return MM_FALSE;
    if (ep < 0 || ep > 15) return MM_FALSE;
    if (!ep_enabled(ep, MM_TRUE)) return MM_FALSE;
    if (data == 0 || len_inout == 0) return MM_FALSE;

    buf_ctrl_off = dpram_ep_buf_ctrl_offset(ep, MM_TRUE);
    buf_ctrl = dpram_read32(buf_ctrl_off);
    if (!buf_available(buf_ctrl)) {
        return MM_FALSE;
    }

    len = buf_length(buf_ctrl);
    if (len > *len_inout) {
        len = *len_inout;
    }

    buf_addr = ep_buffer_address(ep, MM_TRUE);
    if (buf_addr + len > USB_DPRAM_SIZE) {
        len = (buf_addr < USB_DPRAM_SIZE) ? (USB_DPRAM_SIZE - buf_addr) : 0u;
    }

    for (i = 0; i < len; ++i) {
        data[i] = g_usb.dpram[buf_addr + i];
    }
    *len_inout = len;

    buf_ctrl &= ~BUF_CTRL_AVAILABLE;
    buf_ctrl &= ~BUF_CTRL_FULL;
    dpram_write32(buf_ctrl_off, buf_ctrl);

    usb_set_buff_status(ep, MM_TRUE);
    usb_trace("rp2350 usb ep_in ep=%d len=%u", ep, (unsigned)len);
    return MM_TRUE;
}

static void usb_bus_reset(void *opaque)
{
    (void)opaque;
    g_usb.regs[USB_INTR / 4u] |= INTR_BUS_RESET;
    usb_update_ints();
}

static const struct mm_usbdev_ops usb_ops = {
    usb_ep_out,
    usb_ep_in,
    usb_bus_reset
};

static mm_bool usb_mmio_read(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out)
{
    struct rp2350_usb *u = (struct rp2350_usb *)opaque;
    mm_u32 val;
    if (u == 0 || value_out == 0 || size_bytes == 0u || size_bytes > 4u) return MM_FALSE;
    if (offset + size_bytes > USB_SIZE) return MM_FALSE;

    if (offset == USB_INTS && size_bytes == 4u) {
        usb_update_ints();
        *value_out = u->regs[USB_INTS / 4u];
        return MM_TRUE;
    }
    if (offset == USB_BUFF_STATUS && size_bytes == 4u) {
        *value_out = u->regs[USB_BUFF_STATUS / 4u];
        return MM_TRUE;
    }
    if (offset == USB_BUFF_CPU_SHOULD_HANDLE && size_bytes == 4u) {
        *value_out = u->regs[USB_BUFF_CPU_SHOULD_HANDLE / 4u];
        return MM_TRUE;
    }

    val = u->regs[offset / 4u];
    *value_out = val;
    return MM_TRUE;
}

static mm_bool usb_mmio_write(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 value)
{
    struct rp2350_usb *u = (struct rp2350_usb *)opaque;
    if (u == 0 || size_bytes == 0u || size_bytes > 4u) return MM_FALSE;
    if (offset + size_bytes > USB_SIZE) return MM_FALSE;

    if (offset == USB_INTR && size_bytes == 4u) {
        u->regs[USB_INTR / 4u] &= ~value;
        usb_update_ints();
        return MM_TRUE;
    }
    if (offset == USB_INTE && size_bytes == 4u) {
        u->regs[USB_INTE / 4u] = value;
        usb_update_ints();
        return MM_TRUE;
    }
    if (offset == USB_INTF && size_bytes == 4u) {
        u->regs[USB_INTF / 4u] |= value;
        usb_update_ints();
        return MM_TRUE;
    }
    if (offset == USB_BUFF_STATUS && size_bytes == 4u) {
        u->regs[USB_BUFF_STATUS / 4u] &= ~value;
        u->regs[USB_BUFF_CPU_SHOULD_HANDLE / 4u] &= ~value;
        usb_update_ints();
        return MM_TRUE;
    }
    if (offset == USB_BUFF_CPU_SHOULD_HANDLE && size_bytes == 4u) {
        u->regs[USB_BUFF_CPU_SHOULD_HANDLE / 4u] &= ~value;
        usb_update_ints();
        return MM_TRUE;
    }

    u->regs[offset / 4u] = value;
    if (offset == USB_SIE_CTRL && (value & SIE_CTRL_RESET_BUS) != 0u) {
        g_usb.regs[USB_INTR / 4u] |= INTR_BUS_RESET;
        usb_update_ints();
    }
    usb_update_ints();
    return MM_TRUE;
}

static mm_bool dpram_read(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out)
{
    mm_u32 val = 0u;
    (void)opaque;
    if (value_out == 0 || size_bytes == 0u || size_bytes > 4u) return MM_FALSE;
    if (offset + size_bytes > USB_DPRAM_SIZE) return MM_FALSE;

    if (size_bytes == 4u) {
        val = dpram_read32(offset);
    } else {
        mm_u32 i;
        for (i = 0; i < size_bytes; ++i) {
            val |= (mm_u32)g_usb.dpram[offset + i] << (8u * i);
        }
    }
    *value_out = val;
    return MM_TRUE;
}

static mm_bool dpram_write(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 value)
{
    mm_u32 i;
    (void)opaque;
    if (size_bytes == 0u || size_bytes > 4u) return MM_FALSE;
    if (offset + size_bytes > USB_DPRAM_SIZE) return MM_FALSE;

    if (size_bytes == 4u) {
        dpram_write32(offset, value);
    } else {
        for (i = 0; i < size_bytes; ++i) {
            g_usb.dpram[offset + i] = (mm_u8)((value >> (8u * i)) & 0xffu);
        }
    }
    return MM_TRUE;
}

mm_bool mm_rp2350_usb_register_mmio(struct mmio_bus *bus)
{
    struct mmio_region reg;
    if (bus == 0) return MM_FALSE;
    memset(&g_usb, 0, sizeof(g_usb));
    if (!mm_usbdev_register(&usb_ops, &g_usb)) {
        /* USB/IP inactive if no frontend is used. */
    }

    memset(&reg, 0, sizeof(reg));
    reg.base = USB_BASE;
    reg.size = USB_SIZE;
    reg.opaque = &g_usb;
    reg.read = usb_mmio_read;
    reg.write = usb_mmio_write;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    reg.base = USB_DPRAM_BASE;
    reg.size = USB_DPRAM_SIZE;
    reg.opaque = &g_usb;
    reg.read = dpram_read;
    reg.write = dpram_write;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    return MM_TRUE;
}

void mm_rp2350_usb_set_nvic(struct mm_nvic *nvic)
{
    g_usb.nvic = nvic;
    if (nvic != 0) {
        mm_nvic_set_itns(nvic, USB_IRQ, MM_TRUE);
    }
}

void mm_rp2350_usb_reset(void)
{
    memset(&g_usb, 0, sizeof(g_usb));
}
