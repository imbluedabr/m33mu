/* m33mu -- an ARMv8-M Emulator
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <string.h>
#include "pic32ck/pic32ck_timers.h"
#include "m33mu/mmio.h"
#include "m33mu/nvic.h"

/*
 * PIC32CK-SG TCC (Timer/Counter for Control) -- 8 instances
 * TCC0-3: 0x44818000, 0x4481A000, 0x4481C000, 0x4481E000
 * TCC4-7: 0x45008000, 0x4500A000, 0x4500C000, 0x4500E000
 *
 * This implementation is a pure stub: all registers accept writes,
 * reads return the last written value, and SYNCBUSY always reads 0.
 */

#define TCC_COUNT  8
#define TCC_SIZE   0x100u

#define TCC_SYNCBUSY  0x08u

static const mm_u32 tcc_bases[TCC_COUNT] = {
    0x44818000u,  /* TCC0 */
    0x4481A000u,  /* TCC1 */
    0x4481C000u,  /* TCC2 */
    0x4481E000u,  /* TCC3 */
    0x45008000u,  /* TCC4 */
    0x4500A000u,  /* TCC5 */
    0x4500C000u,  /* TCC6 */
    0x4500E000u,  /* TCC7 */
};

struct tcc_inst {
    mm_u32 regs[TCC_SIZE / 4u];
};

static struct tcc_inst tcc_insts[TCC_COUNT];

static mm_bool tcc_read(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                        mm_u32 *value_out)
{
    struct tcc_inst *t = (struct tcc_inst *)opaque;
    if (t == 0 || value_out == 0 || size_bytes == 0 || size_bytes > 4u)
        return MM_FALSE;
    if ((offset + size_bytes) > TCC_SIZE) return MM_FALSE;
    /* SYNCBUSY always 0 */
    if (offset == TCC_SYNCBUSY && size_bytes == 4u) {
        *value_out = 0;
        return MM_TRUE;
    }
    memcpy(value_out, (mm_u8 *)t->regs + offset, size_bytes);
    return MM_TRUE;
}

static mm_bool tcc_write(void *opaque, mm_u32 offset, mm_u32 size_bytes,
                         mm_u32 value)
{
    struct tcc_inst *t = (struct tcc_inst *)opaque;
    if (t == 0 || size_bytes == 0 || size_bytes > 4u) return MM_FALSE;
    if ((offset + size_bytes) > TCC_SIZE) return MM_FALSE;
    memcpy((mm_u8 *)t->regs + offset, &value, size_bytes);
    return MM_TRUE;
}

void mm_pic32ck_timers_init(struct mmio_bus *bus, struct mm_nvic *nvic)
{
    int i;
    (void)nvic;
    memset(tcc_insts, 0, sizeof(tcc_insts));
    for (i = 0; i < TCC_COUNT; ++i) {
        struct mmio_region reg;
        reg.base   = tcc_bases[i];
        reg.size   = TCC_SIZE;
        reg.opaque = &tcc_insts[i];
        reg.read   = tcc_read;
        reg.write  = tcc_write;
        mmio_bus_register_region(bus, &reg);
    }
}

void mm_pic32ck_timers_reset(void)
{
    memset(tcc_insts, 0, sizeof(tcc_insts));
}

void mm_pic32ck_timers_tick(mm_u64 cycles)
{
    /* TCC stub: no real counting */
    (void)cycles;
}
