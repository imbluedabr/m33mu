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

#include "m33mu/nvic.h"
#include "m33mu/mmio.h"
#include "m33mu/scs.h"
#include "m33mu/vector.h"
#include <stdlib.h>
#include <stdio.h>

#define AIRCR_PRIGROUP_SHIFT 8u
#define AIRCR_PRIGROUP_MASK (0x7u << AIRCR_PRIGROUP_SHIFT)

static mm_nvic_enable_hook_t g_enable_hook = 0;
static void *g_enable_hook_opaque = 0;
static int nvic_trace_level(void)
{
    static mm_bool init = MM_FALSE;
    static int level = 0;
    const char *env;
    if (init) {
        return level;
    }
    env = getenv("M33MU_NVIC_TRACE");
    if (env != 0 && env[0] != '\0') {
        level = 1;
    }
    init = MM_TRUE;
    return level;
}

static void clear_masks(struct mm_nvic *n)
{
    size_t i;
    for (i = 0; i < (MM_MAX_IRQ + 31) / 32; ++i) {
        n->enable_mask[i] = 0;
        n->pending_mask[i] = 0;
        n->active_mask[i] = 0;
        n->itns_mask[i] = 0;
    }
}

void mm_nvic_init(struct mm_nvic *nvic)
{
    size_t i;
    clear_masks(nvic);
    for (i = 0; i < MM_MAX_IRQ; ++i) {
        nvic->priority[i] = 0xffu;
    }
}

static mm_bool bitop(mm_u32 *arr, mm_u32 idx, mm_bool set)
{
    mm_u32 word = idx / 32u;
    mm_u32 bit = idx % 32u;
    mm_u32 mask = 1u << bit;
    if (word >= (MM_MAX_IRQ + 31u) / 32u) {
        return MM_FALSE;
    }
    if (set) {
        arr[word] |= mask;
    } else {
        arr[word] &= ~mask;
    }
    return MM_TRUE;
}

void mm_nvic_set_enable(struct mm_nvic *nvic, mm_u32 irq, mm_bool enable)
{
    bitop(nvic->enable_mask, irq, enable);
    if (g_enable_hook != 0) {
        g_enable_hook(irq, enable, g_enable_hook_opaque);
    }
}

void mm_nvic_set_pending(struct mm_nvic *nvic, mm_u32 irq, mm_bool pending)
{
    mm_u32 word;
    mm_u32 mask;
    if (nvic == 0) return;
    word = irq / 32u;
    mask = 1u << (irq % 32u);
    if (word >= (MM_MAX_IRQ + 31u) / 32u) return;
    if (pending) {
        nvic->pending_mask[word] |= mask;
    } else {
        nvic->pending_mask[word] &= ~mask;
    }
    if (nvic_trace_level() >= 1) {
        printf("[NVIC_PENDING_SET] irq=%lu pending=%u mask=0x%08lx\n",
               (unsigned long)irq,
               pending ? 1u : 0u,
               (unsigned long)nvic->pending_mask[word]);
    }
}

void mm_nvic_set_itns(struct mm_nvic *nvic, mm_u32 irq, mm_bool target_nonsecure)
{
    bitop(nvic->itns_mask, irq, target_nonsecure);
}

enum mm_sec_state mm_nvic_irq_target_sec(const struct mm_nvic *nvic, mm_u32 irq)
{
    mm_u32 word = irq / 32u;
    mm_u32 bit = irq % 32u;
    mm_u32 mask = 1u << bit;
    if (nvic == 0) {
        return MM_SECURE;
    }
    if (word >= (MM_MAX_IRQ + 31u) / 32u) {
        return MM_SECURE;
    }
    return ((nvic->itns_mask[word] & mask) != 0u) ? MM_NONSECURE : MM_SECURE;
}

void mm_nvic_set_active(struct mm_nvic *nvic, mm_u32 irq, mm_bool active)
{
    mm_u32 word = irq / 32u;
    mm_u32 bit = irq % 32u;
    mm_u32 mask = 1u << bit;
    if (nvic == 0) return;
    if (word >= (MM_MAX_IRQ + 31u) / 32u) return;
    if (active) nvic->active_mask[word] |= mask;
    else nvic->active_mask[word] &= ~mask;
}

mm_bool mm_nvic_any_pending_enabled(const struct mm_nvic *nvic)
{
    size_t i;
    if (nvic == 0) return MM_FALSE;
    for (i = 0; i < (MM_MAX_IRQ + 31u) / 32u; ++i) {
        if ((nvic->pending_mask[i] & nvic->enable_mask[i]) != 0u) {
            return MM_TRUE;
        }
    }
    return MM_FALSE;
}

mm_bool mm_nvic_any_pending(const struct mm_nvic *nvic)
{
    size_t i;
    if (nvic == 0) return MM_FALSE;
    for (i = 0; i < (MM_MAX_IRQ + 31u) / 32u; ++i) {
        if (nvic->pending_mask[i] != 0u) {
            return MM_TRUE;
        }
    }
    return MM_FALSE;
}

void mm_nvic_set_enable_hook(mm_nvic_enable_hook_t hook, void *opaque)
{
    g_enable_hook = hook;
    g_enable_hook_opaque = opaque;
}

void mm_nvic_notify_enable_mask(mm_u32 idx, mm_u32 old_mask, mm_u32 new_mask)
{
    mm_u32 changed;
    mm_u32 bit;
    if (g_enable_hook == 0) return;
    changed = old_mask ^ new_mask;
    if (changed == 0u) return;
    for (bit = 0; bit < 32u; ++bit) {
        mm_u32 mask = 1u << bit;
        if ((changed & mask) != 0u) {
            mm_u32 irq = idx * 32u + bit;
            mm_bool enabled = (new_mask & mask) != 0u ? MM_TRUE : MM_FALSE;
            g_enable_hook(irq, enabled, g_enable_hook_opaque);
        }
    }
}

mm_bool mm_nvic_is_pending(const struct mm_nvic *nvic, mm_u32 irq)
{
    mm_u32 word = irq / 32u;
    mm_u32 bit = irq % 32u;
    mm_u32 mask = 1u << bit;
    if (word >= (MM_MAX_IRQ + 31u) / 32u) {
        return MM_FALSE;
    }
    return (nvic->pending_mask[word] & mask) != 0u;
}

static mm_bool primask_blocks_target(const struct mm_cpu *cpu, enum mm_sec_state target_sec)
{
    if (cpu == 0) {
        return MM_FALSE;
    }
    if (target_sec == MM_NONSECURE) {
        return cpu->primask_ns != 0u;
    }
    return cpu->primask_s != 0u;
}

static mm_bool faultmask_blocks_target(const struct mm_cpu *cpu, enum mm_sec_state target_sec)
{
    if (cpu == 0) {
        return MM_FALSE;
    }
    if (target_sec == MM_NONSECURE) {
        return cpu->faultmask_ns != 0u;
    }
    return cpu->faultmask_s != 0u;
}

static mm_u8 basepri_for_target(const struct mm_cpu *cpu, enum mm_sec_state target_sec)
{
    if (cpu == 0) {
        return 0u;
    }
    return (target_sec == MM_NONSECURE) ? (mm_u8)(cpu->basepri_ns & 0xFFu)
                                        : (mm_u8)(cpu->basepri_s & 0xFFu);
}

static mm_u8 prigroup_for_target(const struct mm_scs *scs, enum mm_sec_state target_sec)
{
    mm_u32 aircr;
    if (scs == 0) {
        return 0u;
    }
    aircr = (target_sec == MM_NONSECURE) ? scs->aircr_ns : scs->aircr_s;
    return (mm_u8)((aircr & AIRCR_PRIGROUP_MASK) >> AIRCR_PRIGROUP_SHIFT);
}

static mm_u8 preempt_priority_value(mm_u8 prio, mm_u8 prigroup)
{
    mm_u8 sub_bits;
    if (prigroup > 7u) {
        prigroup = 7u;
    }
    sub_bits = (mm_u8)(prigroup + 1u);
    if (sub_bits >= 8u) {
        return 0u;
    }
    return (mm_u8)(prio & (mm_u8)(0xFFu << sub_bits));
}

static mm_u8 system_exc_priority_for_current(const struct mm_cpu *cpu,
                                             const struct mm_scs *scs,
                                             mm_u32 exc_num)
{
    enum mm_sec_state sec;
    if (cpu == 0 || scs == 0) {
        return 0xFFu;
    }
    sec = cpu->sec_state;
    switch (exc_num) {
    case MM_VECT_MEMMANAGE:
        return (mm_u8)(((sec == MM_NONSECURE) ? scs->shpr1_ns : scs->shpr1_s) & 0xFFu);
    case MM_VECT_BUSFAULT:
        return (mm_u8)((((sec == MM_NONSECURE) ? scs->shpr1_ns : scs->shpr1_s) >> 8) & 0xFFu);
    case MM_VECT_USAGEFAULT:
        return (mm_u8)((((sec == MM_NONSECURE) ? scs->shpr1_ns : scs->shpr1_s) >> 16) & 0xFFu);
    case MM_VECT_SECUREFAULT:
        return (mm_u8)((((sec == MM_NONSECURE) ? scs->shpr1_ns : scs->shpr1_s) >> 24) & 0xFFu);
    case MM_VECT_SVCALL:
        return (mm_u8)((((sec == MM_NONSECURE) ? scs->shpr2_ns : scs->shpr2_s) >> 24) & 0xFFu);
    case MM_VECT_PENDSV:
        return (mm_u8)((((sec == MM_NONSECURE) ? scs->shpr3_ns : scs->shpr3_s) >> 16) & 0xFFu);
    case MM_VECT_SYSTICK:
        return (mm_u8)((((sec == MM_NONSECURE) ? scs->shpr3_ns : scs->shpr3_s) >> 24) & 0xFFu);
    case MM_VECT_NMI:
    case MM_VECT_HARDFAULT:
        return 0u;
    default:
        return 0xFFu;
    }
}

static mm_bool irq_can_preempt_current(const struct mm_nvic *nvic,
                                       const struct mm_cpu *cpu,
                                       const struct mm_scs *scs,
                                       mm_u32 irq)
{
    mm_u32 active_exc;
    mm_u8 current_prio;
    mm_u8 current_preempt;
    mm_u8 irq_prio;
    mm_u8 irq_preempt;
    mm_u8 prigroup;
    if (nvic == 0 || cpu == 0 || scs == 0) {
        return MM_TRUE;
    }
    if (cpu->mode != MM_HANDLER) {
        return MM_TRUE;
    }
    active_exc = cpu->xpsr & 0x1FFu;
    if (active_exc == 0u) {
        return MM_TRUE;
    }
    if (active_exc >= 16u) {
        current_prio = nvic->priority[active_exc - 16u];
    } else {
        current_prio = system_exc_priority_for_current(cpu, scs, active_exc);
    }
    irq_prio = nvic->priority[irq];
    prigroup = prigroup_for_target(scs, cpu->sec_state);
    current_preempt = preempt_priority_value(current_prio, prigroup);
    irq_preempt = preempt_priority_value(irq_prio, prigroup);
    (void)irq_prio;
    (void)current_prio;
    return (irq_preempt < current_preempt) ? MM_TRUE : MM_FALSE;
}

static mm_bool basepri_blocks_target(const struct mm_cpu *cpu,
                                     enum mm_sec_state target_sec,
                                     const struct mm_scs *scs,
                                     mm_u8 irq_prio)
{
    mm_u8 basepri = basepri_for_target(cpu, target_sec);
    mm_u8 prigroup = prigroup_for_target(scs, target_sec);
    if (basepri == 0u) {
        return MM_FALSE;
    }
    if (irq_prio == 0u) {
        return MM_FALSE;
    }
    return preempt_priority_value(irq_prio, prigroup) >=
           preempt_priority_value(basepri, prigroup) ? MM_TRUE : MM_FALSE;
}

static mm_bool usb_trace_enabled(void)
{
    static int cached = -1;
    if (cached < 0) {
        const char *v = getenv("M33MU_USB_TRACE");
        cached = (v && v[0] != '\0') ? 1 : 0;
    }
    return cached ? MM_TRUE : MM_FALSE;
}

static void usb_trace_irq14_mask(mm_bool masked, enum mm_sec_state tsec, const struct mm_cpu *cpu)
{
    static mm_bool last_ns = MM_FALSE;
    static mm_bool last_s = MM_FALSE;
    mm_bool *last = (tsec == MM_NONSECURE) ? &last_ns : &last_s;
    if (!usb_trace_enabled()) return;
    if (masked) {
        if (!*last) {
            if (tsec == MM_NONSECURE) {
                fprintf(stderr, "[USB_TRACE] irq14 masked by PRIMASK_NS=%u\n",
                        cpu ? (unsigned)cpu->primask_ns : 0u);
            } else {
                fprintf(stderr, "[USB_TRACE] irq14 masked by PRIMASK_S=%u\n",
                        cpu ? (unsigned)cpu->primask_s : 0u);
            }
        }
        *last = MM_TRUE;
        return;
    }
    if (*last) {
        if (tsec == MM_NONSECURE) {
            fprintf(stderr, "[USB_TRACE] irq14 unmasked PRIMASK_NS=%u\n",
                    cpu ? (unsigned)cpu->primask_ns : 0u);
        } else {
            fprintf(stderr, "[USB_TRACE] irq14 unmasked PRIMASK_S=%u\n",
                    cpu ? (unsigned)cpu->primask_s : 0u);
        }
    }
    *last = MM_FALSE;
}

int mm_nvic_select_routed_ex(const struct mm_nvic *nvic,
                             const struct mm_cpu *cpu,
                             const struct mm_scs *scs,
                             enum mm_sec_state *target_sec_out)
{
    mm_u32 best_irq = 0xffffffffu;
    mm_u8 best_prio = 0xffu;
    mm_u32 irq;

    for (irq = 0; irq < MM_MAX_IRQ; ++irq) {
        mm_u32 word = irq / 32u;
        mm_u32 bit = irq % 32u;
        mm_u32 mask = 1u << bit;
        enum mm_sec_state tsec;
        if ((nvic->enable_mask[word] & mask) == 0u) {
            continue;
        }
        if ((nvic->pending_mask[word] & mask) == 0u) {
            continue;
        }
        if ((nvic->active_mask[word] & mask) != 0u) {
            continue;
        }
        tsec = mm_nvic_irq_target_sec(nvic, irq);
        if (primask_blocks_target(cpu, tsec)) {
            if (irq == 14u) {
                usb_trace_irq14_mask(MM_TRUE, tsec, cpu);
            }
            continue;
        }
        if (faultmask_blocks_target(cpu, tsec)) {
            continue;
        }
        if (basepri_blocks_target(cpu, tsec, scs, nvic->priority[irq])) {
            continue;
        }
        if (!irq_can_preempt_current(nvic, cpu, scs, irq)) {
            continue;
        }
        if (irq == 14u) {
            usb_trace_irq14_mask(MM_FALSE, tsec, cpu);
        }
        if (best_irq == 0xffffffffu || nvic->priority[irq] < best_prio) {
            best_prio = nvic->priority[irq];
            best_irq = irq;
        }
    }
    if (best_irq == 0xffffffffu) {
        return -1;
    }
    if (target_sec_out) {
        *target_sec_out = mm_nvic_irq_target_sec(nvic, best_irq);
    }
    if (nvic_trace_level() >= 1) {
        printf("[NVIC_SELECT] irq=%lu target_sec=%d prio=0x%02x\n",
               (unsigned long)best_irq,
               (int)mm_nvic_irq_target_sec(nvic, best_irq),
               (unsigned)nvic->priority[best_irq]);
    }
    return (int)best_irq;
}

int mm_nvic_select_routed(const struct mm_nvic *nvic, const struct mm_cpu *cpu, enum mm_sec_state *target_sec_out)
{
    return mm_nvic_select_routed_ex(nvic, cpu, 0, target_sec_out);
}

int mm_nvic_select(const struct mm_nvic *nvic, const struct mm_cpu *cpu)
{
    return mm_nvic_select_ex(nvic, cpu, 0);
}

int mm_nvic_select_ex(const struct mm_nvic *nvic, const struct mm_cpu *cpu, const struct mm_scs *scs)
{
    return mm_nvic_select_routed_ex(nvic, cpu, scs, 0);
}

struct mm_nvic_mmio {
    struct mm_nvic *nvic;
};

static mm_bool nvic_mmio_read(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out)
{
    struct mm_nvic_mmio *ctx = (struct mm_nvic_mmio *)opaque;
    if (ctx == 0 || ctx->nvic == 0 || value_out == 0) {
        return MM_FALSE;
    }
    /* Only support IPR byte/word reads; map 0xE000E400.. */
    if (offset >= 0x100u) {
        return MM_FALSE;
    }
    if (size_bytes == 1u) {
        mm_u32 idx = offset;
        if (idx >= MM_MAX_IRQ) {
            *value_out = 0xFFu;
            return MM_TRUE;
        }
        *value_out = ctx->nvic->priority[idx] & 0xFFu;
        return MM_TRUE;
    }
    if (size_bytes == 4u && (offset % 4u) == 0u) {
        mm_u32 i;
        mm_u32 val = 0;
        for (i = 0; i < 4u; ++i) {
            mm_u32 idx = offset + i;
            mm_u8 p = 0xFFu;
            if (idx < MM_MAX_IRQ) {
                p = ctx->nvic->priority[idx];
            }
            val |= ((mm_u32)p) << (i * 8u);
        }
        *value_out = val;
        return MM_TRUE;
    }
    return MM_FALSE;
}

static mm_bool nvic_mmio_write(void *opaque, mm_u32 offset, mm_u32 size_bytes, mm_u32 value)
{
    struct mm_nvic_mmio *ctx = (struct mm_nvic_mmio *)opaque;
    if (ctx == 0 || ctx->nvic == 0) {
        return MM_FALSE;
    }
    if (offset >= 0x100u) {
        return MM_FALSE;
    }
    if (size_bytes == 1u) {
        mm_u32 idx = offset;
        if (idx < MM_MAX_IRQ) {
            ctx->nvic->priority[idx] = (mm_u8)(value & 0xFFu);
        }
        return MM_TRUE;
    }
    if (size_bytes == 4u && (offset % 4u) == 0u) {
        mm_u32 i;
        for (i = 0; i < 4u; ++i) {
            mm_u32 idx = offset + i;
            mm_u8 p = (mm_u8)((value >> (i * 8u)) & 0xFFu);
            if (idx < MM_MAX_IRQ) {
                ctx->nvic->priority[idx] = p;
            }
        }
        return MM_TRUE;
    }
    return MM_FALSE;
}

mm_bool mm_nvic_register_mmio(struct mm_nvic *nvic, struct mmio_bus *bus)
{
    static struct mm_nvic_mmio ctx;
    struct mmio_region reg;

    ctx.nvic = nvic;
    reg.base = 0xE000E400u;
    reg.size = 0x100u;
    reg.opaque = &ctx;
    reg.read = nvic_mmio_read;
    reg.write = nvic_mmio_write;
    return mmio_bus_register_region(bus, &reg);
}
