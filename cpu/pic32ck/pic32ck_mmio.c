/* m33mu -- an ARMv8-M Emulator
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <string.h>
#include <stdio.h>
#include "pic32ck/pic32ck_mmio.h"
#include "pic32ck/cpu_config.h"
#include "m33mu/memmap.h"
#include "m33mu/mmio.h"
#include "m33mu/nvic.h"

/* periph_stub -- lightweight register-file stub */
struct periph_stub {
    mm_u32  size;
    mm_u32 *regs;
};

static mm_bool stub_read(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                         mm_u32 *value_out)
{
    const struct periph_stub *ps = (const struct periph_stub *)opaque;
    if (ps == 0 || value_out == 0 || size_bytes == 0 || size_bytes > 4u)
        return MM_FALSE;
    if ((offset + size_bytes) > ps->size) return MM_FALSE;
    memcpy(value_out, (const mm_u8 *)ps->regs + offset, size_bytes);
    return MM_TRUE;
}

static mm_bool stub_write(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                          mm_u32 value)
{
    struct periph_stub *ps = (struct periph_stub *)opaque;
    if (ps == 0 || size_bytes == 0 || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > ps->size) return MM_FALSE;
    memcpy((mm_u8 *)ps->regs + offset, &value, size_bytes);
    return MM_TRUE;
}

#define DECL_STUB(N, S) \
    static mm_u32 N##_regs[(S) / 4u]; \
    static struct periph_stub N##_stub = { (S), N##_regs }

static mm_bool stub_reg_one(struct mmio_bus *bus, struct periph_stub *ps,
                            mm_u32 base)
{
    struct mmio_region reg;
    reg.base   = base;
    reg.size   = ps->size;
    reg.opaque = ps;
    reg.read   = stub_read;
    reg.write  = stub_write;
    return mmio_bus_register_region(bus, &reg);
}

/* MCLK (0x44012000, size 0x60) */
/* CLKMSK[0..8] at offsets 0x3C..0x5C */
#define MCLK_BASE    0x44012000u
#define MCLK_SIZE    0x60u
#define MCLK_CLKMSK0 0x3Cu
static mm_u32 mclk_regs[MCLK_SIZE / 4u];

static mm_bool mclk_read(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                         mm_u32 *value_out)
{
    (void)opaque;
    if (value_out == 0 || size_bytes == 0 || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > MCLK_SIZE) return MM_FALSE;
    memcpy(value_out, (mm_u8 *)mclk_regs + offset, size_bytes);
    return MM_TRUE;
}

static mm_bool mclk_write(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                          mm_u32 value)
{
    (void)opaque;
    if (size_bytes == 0 || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > MCLK_SIZE) return MM_FALSE;
    memcpy((mm_u8 *)mclk_regs + offset, &value, size_bytes);
    return MM_TRUE;
}

mm_bool mm_pic32ck_mclk_periph_active(mm_u32 clkmsk_reg, mm_u32 clkmsk_bit)
{
    mm_u32 off, val;
    if (clkmsk_reg > 8u) return MM_FALSE;
    off = MCLK_CLKMSK0 + clkmsk_reg * 4u;
    memcpy(&val, (mm_u8 *)mclk_regs + off, 4u);
    return ((val >> clkmsk_bit) & 1u) != 0u ? MM_TRUE : MM_FALSE;
}

/* OSCCTRL (0x4400C000, size 0xC0) */
/* STATUS at offset 0x10: bit24=PLL0LOCK, bit16=DFLLRDY, bit8=XOSCRDY, bit0=XOSCRDY0 */
/* SYNCBUSY at 0x78: always 0 (no sync delays in emulator) */
#define OSCCTRL_BASE     0x4400C000u
#define OSCCTRL_SIZE     0xC0u
#define OSCCTRL_STATUS   0x10u
#define OSCCTRL_SYNCBUSY 0x78u
static mm_u32 oscctrl_regs[OSCCTRL_SIZE / 4u];

static mm_bool oscctrl_read(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                            mm_u32 *value_out)
{
    (void)opaque;
    if (value_out == 0 || size_bytes == 0 || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > OSCCTRL_SIZE) return MM_FALSE;
    if ((offset & ~3u) == (OSCCTRL_STATUS & ~3u)) {
        /* PLL0LOCK(24)|DFLLRDY(16)|XOSCRDY(8)|XOSCRDY0(0) all set */
        mm_u32 v = 0x01010101u;
        memcpy(value_out, (mm_u8 *)&v + (offset & 3u), size_bytes);
        return MM_TRUE;
    }
    if ((offset & ~3u) == (OSCCTRL_SYNCBUSY & ~3u)) {
        mm_u32 v = 0u;
        memcpy(value_out, (mm_u8 *)&v + (offset & 3u), size_bytes);
        return MM_TRUE;
    }
    memcpy(value_out, (mm_u8 *)oscctrl_regs + offset, size_bytes);
    return MM_TRUE;
}

static mm_bool oscctrl_write(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                             mm_u32 value)
{
    (void)opaque;
    if (size_bytes == 0 || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > OSCCTRL_SIZE) return MM_FALSE;
    memcpy((mm_u8 *)oscctrl_regs + offset, &value, size_bytes);
    return MM_TRUE;
}

/* SUPC (0x44008000, size 0x30) */
/* STATUS at offset 0x0C:
 *   bit8=ADDVREGRDY0 (additional regulator ready -- needed by PLL0 init)
 *   bit4=BORVDDIOB, bit1=LVDRDY, bit0=LVDET
 * VREGCTRL at 0x1C (accept writes, return written value)
 * SYNCBUSY at 0x10: always 0
 */
#define SUPC_BASE    0x44008000u
#define SUPC_SIZE    0x30u
#define SUPC_STATUS  0x0Cu
static mm_u32 supc_regs[SUPC_SIZE / 4u];

static mm_bool supc_read(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                         mm_u32 *value_out)
{
    (void)opaque;
    if (value_out == 0 || size_bytes == 0 || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > SUPC_SIZE) return MM_FALSE;
    if ((offset & ~3u) == (SUPC_STATUS & ~3u)) {
        /* ADDVREGRDY0(8)|BORVDDIOB(4)|LVDRDY(1)|LVDET(0) all set */
        mm_u32 v = 0x00000113u;
        memcpy(value_out, (mm_u8 *)&v + (offset & 3u), size_bytes);
        return MM_TRUE;
    }
    memcpy(value_out, (mm_u8 *)supc_regs + offset, size_bytes);
    return MM_TRUE;
}

static mm_bool supc_write(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                          mm_u32 value)
{
    (void)opaque;
    if (size_bytes == 0 || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > SUPC_SIZE) return MM_FALSE;
    memcpy((mm_u8 *)supc_regs + offset, &value, size_bytes);
    return MM_TRUE;
}

/* FCR -- Flash Controller Read (0x44002000, size 0x20) */
/* STATUS at offset 0x08 always 0x1 (READY) */
#define FCR_BASE    0x44002000u
#define FCR_SIZE    0x20u
#define FCR_STATUS  0x08u
static mm_u32 fcr_regs[FCR_SIZE / 4u];

static mm_bool fcr_read(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                        mm_u32 *value_out)
{
    (void)opaque;
    if (value_out == 0 || size_bytes == 0 || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > FCR_SIZE) return MM_FALSE;
    if (offset == FCR_STATUS && size_bytes == 4u) {
        *value_out = 0x1u;
        return MM_TRUE;
    }
    memcpy(value_out, (mm_u8 *)fcr_regs + offset, size_bytes);
    return MM_TRUE;
}

static mm_bool fcr_write(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                         mm_u32 value)
{
    (void)opaque;
    if (size_bytes == 0 || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > FCR_SIZE) return MM_FALSE;
    memcpy((mm_u8 *)fcr_regs + offset, &value, size_bytes);
    return MM_TRUE;
}

/* FCW -- Flash Write Controller (0x44004000, size 0x200) */
/* INTFLAG at 0x14: DONE=bit0, write-1-to-clear; MUTEX at 0x08 */
#define FCW_BASE    0x44004000u
#define FCW_SIZE    0x200u
#define FCW_CTRLA   0x00u
#define FCW_STATUS  0x18u
#define FCW_INTFLAG 0x14u
static mm_u32 fcw_regs[FCW_SIZE / 4u];
static mm_u8 *g_flash_ptr;
static mm_u32 g_flash_size;

static mm_bool fcw_read(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                        mm_u32 *value_out)
{
    (void)opaque;
    if (value_out == 0 || size_bytes == 0 || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > FCW_SIZE) return MM_FALSE;
    if (offset == FCW_STATUS) {
        *value_out = 0x0u;  /* BUSY=0: not busy / ready */
        return MM_TRUE;
    }
    memcpy(value_out, (mm_u8 *)fcw_regs + offset, size_bytes);
    return MM_TRUE;
}

static mm_bool fcw_write(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                         mm_u32 value)
{
    (void)opaque;
    if (size_bytes == 0 || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > FCW_SIZE) return MM_FALSE;
    memcpy((mm_u8 *)fcw_regs + offset, &value, size_bytes);
    if (offset == FCW_CTRLA) {
        fcw_regs[FCW_INTFLAG / 4u] |= 0x1u;
    }
    if (offset == FCW_INTFLAG) {
        fcw_regs[FCW_INTFLAG / 4u] &= ~value;
    }
    return MM_TRUE;
}

/* GCLK (0x44010000, size 0x200)
 * SYNCBUSY at 0x04: always 0 (no sync delays in emulator)
 * GENCTRL[n] at 0x20+n*4: accept r/w
 * PCHCTRL[n] at 0x80+n*4: read back with CHEN (bit6) always set so
 *   firmware does not spin waiting for clock enable confirmation.
 */
#define GCLK_BASE     0x44010000u
#define GCLK_SIZE     0x200u
#define GCLK_SYNCBUSY 0x04u
#define GCLK_PCHCTRL0 0x80u
static mm_u32 gclk_regs[GCLK_SIZE / 4u];

static mm_bool gclk_read(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                         mm_u32 *value_out)
{
    (void)opaque;
    if (value_out == 0 || size_bytes == 0 || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > GCLK_SIZE) return MM_FALSE;
    /* SYNCBUSY always 0 */
    if ((offset & ~3u) == (GCLK_SYNCBUSY & ~3u)) {
        mm_u32 v = 0u;
        memcpy(value_out, (mm_u8 *)&v + (offset & 3u), size_bytes);
        return MM_TRUE;
    }
    /* PCHCTRL[n]: return stored value with CHEN (bit6) always set */
    if (offset >= GCLK_PCHCTRL0 && offset < GCLK_SIZE) {
        mm_u32 v;
        memcpy(&v, (mm_u8 *)gclk_regs + (offset & ~3u), 4u);
        v |= (1u << 6);  /* CHEN always set */
        memcpy(value_out, (mm_u8 *)&v + (offset & 3u), size_bytes);
        return MM_TRUE;
    }
    memcpy(value_out, (mm_u8 *)gclk_regs + offset, size_bytes);
    return MM_TRUE;
}

static mm_bool gclk_write(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                          mm_u32 value)
{
    (void)opaque;
    if (size_bytes == 0 || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > GCLK_SIZE) return MM_FALSE;
    memcpy((mm_u8 *)gclk_regs + offset, &value, size_bytes);
    return MM_TRUE;
}

/* PORT (0x44800000, size 0x200 -- 4 port groups A-D, stride 0x80)
 * Each group has set/clear/toggle aliases for DIR and OUT.
 * Layout per group (offset within group):
 *   0x00 DIR    0x04 DIRCLR  0x08 DIRSET  0x0C DIRTGL
 *   0x10 OUT    0x14 OUTCLR  0x18 OUTSET  0x1C OUTTGL
 *   0x20 IN     0x24 CTRL    0x28 WRCONFIG
 *   0x30 EVCTRL
 *   0x40 PINCFG[0..31]  (1 byte each)
 *   0x60 PMUX[0..15]    (1 byte each, 2 pins per byte)
 */
#define PORT_BASE       0x44800000u
#define PORT_SIZE       0x200u
#define PORT_GROUP_SIZE 0x80u
#define PORT_NGROUPS    4u

/* Group register offsets (byte offsets within a group) */
#define PG_DIR    0x00u
#define PG_DIRCLR 0x04u
#define PG_DIRSET 0x08u
#define PG_DIRTGL 0x0Cu
#define PG_OUT    0x10u
#define PG_OUTCLR 0x14u
#define PG_OUTSET 0x18u
#define PG_OUTTGL 0x1Cu
#define PG_IN     0x20u

/* Per-group state */
struct port_group_state {
    mm_u32 dir;
    mm_u32 out;
    mm_u32 in;
    mm_u8  pincfg[32];
    mm_u8  pmux[16];
    mm_u32 evctrl;
    mm_u32 ctrl;
    mm_u32 wrconfig;
};
static struct port_group_state port_groups[PORT_NGROUPS];

static mm_bool port_read(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                         mm_u32 *value_out)
{
    mm_u32 grp_idx, grp_off, val;
    struct port_group_state *g;
    (void)opaque;
    if (value_out == 0 || size_bytes == 0 || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > PORT_SIZE) return MM_FALSE;
    grp_idx = offset / PORT_GROUP_SIZE;
    grp_off = offset % PORT_GROUP_SIZE;
    if (grp_idx >= PORT_NGROUPS) { *value_out = 0; return MM_TRUE; }
    g = &port_groups[grp_idx];
    switch (grp_off & ~3u) {
    case PG_DIR:    val = g->dir; break;
    case PG_DIRCLR: val = g->dir; break;
    case PG_DIRSET: val = g->dir; break;
    case PG_DIRTGL: val = g->dir; break;
    case PG_OUT:    val = g->out; break;
    case PG_OUTCLR: val = g->out; break;
    case PG_OUTSET: val = g->out; break;
    case PG_OUTTGL: val = g->out; break;
    case PG_IN:     val = g->in;  break;
    default:        val = 0;      break;
    }
    /* Handle sub-word reads */
    memcpy(value_out, (mm_u8 *)&val + (grp_off & 3u), size_bytes);
    return MM_TRUE;
}

static mm_bool port_write(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                          mm_u32 value)
{
    mm_u32 grp_idx, grp_off;
    struct port_group_state *g;
    (void)opaque;
    if (size_bytes == 0 || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > PORT_SIZE) return MM_FALSE;
    grp_idx = offset / PORT_GROUP_SIZE;
    grp_off = offset % PORT_GROUP_SIZE;
    if (grp_idx >= PORT_NGROUPS) return MM_TRUE;
    g = &port_groups[grp_idx];
    /* Expand sub-word writes to 32-bit for set/clr registers */
    if (size_bytes < 4u) {
        mm_u32 tmp = 0u;
        memcpy(&tmp, &value, size_bytes);
        value = tmp;
    }
    switch (grp_off) {
    case PG_DIR:    g->dir  = value;          break;
    case PG_DIRCLR: g->dir &= ~value;         break;
    case PG_DIRSET: g->dir |=  value;         break;
    case PG_DIRTGL: g->dir ^=  value;         break;
    case PG_OUT:    g->out  = value;           break;
    case PG_OUTCLR: g->out &= ~value;          break;
    case PG_OUTSET: g->out |=  value;          break;
    case PG_OUTTGL: g->out ^=  value;          break;
    case PG_IN:     g->in   = value;           break;
    default:        break;
    }
    return MM_TRUE;
}

/* Generic peripheral stubs */
/* TRNG (0x45024000, size 0x24)
 * CTRLA   [0x00]: ENABLE=bit1
 * INTFLAG [0x0A]: DATARDY=bit0 -- always set (data always ready)
 * DATA    [0x20]: random data -- return pseudo-random value
 */
#define TRNG_BASE    0x45024000u
#define TRNG_SIZE    0x24u
#define TRNG_INTFLAG 0x0Au
#define TRNG_DATA    0x20u
static mm_u32 trng_regs[TRNG_SIZE / 4u];
static mm_u32 trng_counter;

static mm_bool trng_read(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                         mm_u32 *value_out)
{
    (void)opaque;
    if (value_out == 0 || size_bytes == 0 || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > TRNG_SIZE) return MM_FALSE;
    if (offset == TRNG_INTFLAG && size_bytes == 1u) {
        *value_out = 0x1u;  /* DATARDY always set */
        return MM_TRUE;
    }
    if (offset == TRNG_DATA && size_bytes == 4u) {
        /* Simple LCG for deterministic pseudo-random output */
        trng_counter = trng_counter * 1664525u + 1013904223u;
        *value_out = trng_counter ^ 0xA5A5A5A5u;
        return MM_TRUE;
    }
    memcpy(value_out, (mm_u8 *)trng_regs + offset, size_bytes);
    return MM_TRUE;
}

static mm_bool trng_write(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                          mm_u32 value)
{
    (void)opaque;
    if (size_bytes == 0 || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > TRNG_SIZE) return MM_FALSE;
    memcpy((mm_u8 *)trng_regs + offset, &value, size_bytes);
    return MM_TRUE;
}

DECL_STUB(osc32kctrl, 0x20u);   /* 0x44016000 */
DECL_STUB(pm,         0x20u);   /* 0x44010000 */
DECL_STUB(wdt,        0x10u);   /* 0x44011000 */
DECL_STUB(rtc,        0x80u);   /* 0x44013000 */
DECL_STUB(eic,        0x40u);   /* 0x44015000 */
DECL_STUB(eic_sec,    0x40u);   /* 0x44015200 */
DECL_STUB(pac,        0x80u);   /* 0x44000000 */
DECL_STUB(idau,       0x40u);   /* 0x44003000 */
DECL_STUB(dma0,       0x100u);  /* 0x44110000 */
DECL_STUB(dma1,       0x100u);  /* 0x44120000 */
DECL_STUB(freqm,      0x20u);   /* 0x44017000 */

void mm_pic32ck_mmio_reset(void)
{
    memset(mclk_regs,       0, sizeof(mclk_regs));
    memset(oscctrl_regs,    0, sizeof(oscctrl_regs));
    memset(supc_regs,       0, sizeof(supc_regs));
    memset(fcr_regs,        0, sizeof(fcr_regs));
    memset(fcw_regs,        0, sizeof(fcw_regs));
    memset(gclk_regs,       0, sizeof(gclk_regs));
    memset(trng_regs,       0, sizeof(trng_regs));
    trng_counter = 0x12345678u;
    memset(port_groups,     0, sizeof(port_groups));
    memset(osc32kctrl_regs, 0, sizeof(osc32kctrl_regs));
    memset(pm_regs,         0, sizeof(pm_regs));
    memset(wdt_regs,        0, sizeof(wdt_regs));
    memset(rtc_regs,        0, sizeof(rtc_regs));
    memset(eic_regs,        0, sizeof(eic_regs));
    memset(eic_sec_regs,    0, sizeof(eic_sec_regs));
    memset(pac_regs,        0, sizeof(pac_regs));
    memset(idau_regs,       0, sizeof(idau_regs));
    memset(dma0_regs,       0, sizeof(dma0_regs));
    memset(dma1_regs,       0, sizeof(dma1_regs));
    memset(freqm_regs,      0, sizeof(freqm_regs));
    g_flash_ptr  = 0;
    g_flash_size = 0u;
}

mm_bool mm_pic32ck_register_mmio(struct mmio_bus *bus)
{
    struct mmio_region reg;

    /* MCLK */
    reg.base   = MCLK_BASE;
    reg.size   = MCLK_SIZE;
    reg.opaque = 0;
    reg.read   = mclk_read;
    reg.write  = mclk_write;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    /* OSCCTRL */
    reg.base   = OSCCTRL_BASE;
    reg.size   = OSCCTRL_SIZE;
    reg.opaque = 0;
    reg.read   = oscctrl_read;
    reg.write  = oscctrl_write;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    /* SUPC */
    reg.base   = SUPC_BASE;
    reg.size   = SUPC_SIZE;
    reg.opaque = 0;
    reg.read   = supc_read;
    reg.write  = supc_write;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    /* FCR */
    reg.base   = FCR_BASE;
    reg.size   = FCR_SIZE;
    reg.opaque = 0;
    reg.read   = fcr_read;
    reg.write  = fcr_write;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    /* FCW */
    reg.base   = FCW_BASE;
    reg.size   = FCW_SIZE;
    reg.opaque = 0;
    reg.read   = fcw_read;
    reg.write  = fcw_write;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    /* TRNG */
    reg.base   = TRNG_BASE;
    reg.size   = TRNG_SIZE;
    reg.opaque = 0;
    reg.read   = trng_read;
    reg.write  = trng_write;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    /* GCLK */
    reg.base   = GCLK_BASE;
    reg.size   = GCLK_SIZE;
    reg.opaque = 0;
    reg.read   = gclk_read;
    reg.write  = gclk_write;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    /* PORT (NS + Secure alias) */
    reg.base   = PORT_BASE;
    reg.size   = PORT_SIZE;
    reg.opaque = 0;
    reg.read   = port_read;
    reg.write  = port_write;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;
    /* Secure alias at 0x44801000 -- share same handler */
    reg.base   = 0x44801000u;
    if (!mmio_bus_register_region(bus, &reg)) return MM_FALSE;

    /* Generic stubs */
    if (!stub_reg_one(bus, &osc32kctrl_stub, 0x4400E000u)) return MM_FALSE;
    if (!stub_reg_one(bus, &pm_stub,          0x44006000u)) return MM_FALSE;
    if (!stub_reg_one(bus, &wdt_stub,         0x44016000u)) return MM_FALSE;
    if (!stub_reg_one(bus, &rtc_stub,         0x44018000u)) return MM_FALSE;
    if (!stub_reg_one(bus, &eic_stub,         0x4401A000u)) return MM_FALSE;
    if (!stub_reg_one(bus, &eic_sec_stub,     0x4401B000u)) return MM_FALSE;
    if (!stub_reg_one(bus, &pac_stub,         0x4401C000u)) return MM_FALSE;
    if (!stub_reg_one(bus, &idau_stub,        0x4480C000u)) return MM_FALSE;
    if (!stub_reg_one(bus, &dma0_stub,        0x44802000u)) return MM_FALSE;
    if (!stub_reg_one(bus, &dma1_stub,        0x44804000u)) return MM_FALSE;
    if (!stub_reg_one(bus, &freqm_stub,       0x44014000u)) return MM_FALSE;
    /* DSU not mapped — omit */

    return MM_TRUE;
}

void mm_pic32ck_flash_bind(struct mm_memmap *map,
                               mm_u8 *flash, mm_u32 flash_size,
                               const struct mm_flash_persist *persist,
                               mm_u32 flags)
{
    (void)map; (void)persist; (void)flags;
    g_flash_ptr  = flash;
    g_flash_size = flash_size;
}

mm_u64 mm_pic32ck_cpu_hz(void)
{
    return 96000000ULL;
}
