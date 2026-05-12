/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * LPC55S69 CASPER peripheral model.
 * Implements RSA mod-exp via mp_exptmod (wolfMath public API).
 * ECC scalar-mul opcodes set STATUS.ERROR with a one-shot warning;
 * a public wolfSSL scalar-mul API is not available.
 *
 * Register layout per NXP LPC55S69 User Manual / CMSIS PERI_CASPER.h:
 *   0x00  CTRL0   opcode + trigger
 *   0x04  CTRL1   control options
 *   0x08  LOADER  pointer to modulus / curve params (stash only)
 *   0x0C  STATUS  BUSY/DONE/ERROR
 *   0x10  INTENSET interrupt enables (set)
 *   0x14  INTENCLR interrupt enables (clear)
 *   0x20  AREG    pointer to base / input A
 *   0x24  BREG    pointer to exponent / input B
 *   0x28  CREG    pointer to modulus
 *   0x2C  DREG    pointer to auxiliary (not used for RSA)
 *   0x30  RES0    pointer to result word 0
 *   0x34  RES1    pointer to result word 1
 *   0x38  RES2    pointer to result word 2
 *   0x3C  RES3    pointer to result word 3
 *   0x60  MASK    blinding mask (plain RAM)
 *   0x64  REMASK  re-blinding mask (plain RAM)
 *   0x80  LOCK    lock register (plain RAM)
 *   0xFFC ID      part identifier (not within 0x84-byte region)
 *
 * Note: the region size is 0x84 (132 bytes), covering offsets 0x00..0x83.
 * RES0..3 at 0x30..0x3C, MASK/REMASK at 0x60/0x64, and LOCK at 0x80
 * all fit within 0x84.
 */

#ifndef LPC55S69_CASPER_H
#define LPC55S69_CASPER_H

#include "m33mu/types.h"

struct mm_nvic;
struct mm_memmap;

/* -------------------------------------------------------------------------
 * Size of the CASPER MMIO region
 * ------------------------------------------------------------------------- */
#define CASPER_SIZE 0x84u

/*
 * CASPER peripheral state.
 * Defined here (not just forward-declared) so lpc55s69_mmio.c can embed
 * the struct as a static variable without heap allocation.
 */
struct mm_lpc55_casper {
    /* Raw register backing store (covers offsets 0x00..0x83) */
    mm_u32 regs[CASPER_SIZE / 4u];

    /* NVIC pointer for IRQ delivery (CASPER_IRQn = 57) */
    struct mm_nvic *nvic;

    /* Memory map pointer — needed to read operands from emulated RAM */
    struct mm_memmap *map;

    /* Interrupt enable shadow (mirrors INTENSET register) */
    mm_u32 intenset;

    /* One-shot ECC warning guard */
    mm_bool ecc_warned;
};

/* Initialise and bind the peripheral. */
mm_bool mm_lpc55_casper_init(struct mm_lpc55_casper *cas,
                             struct mm_nvic *nvic,
                             struct mm_memmap *map);

/* Reset peripheral state (preserves nvic/map pointers). */
mm_bool mm_lpc55_casper_reset(struct mm_lpc55_casper *cas);

/* MMIO callbacks registered by lpc55s69_mmio.c. */
mm_bool mm_lpc55_casper_read(void *opaque, mm_u32 offset,
                             mm_u32 size_bytes, mm_u32 *value_out);
mm_bool mm_lpc55_casper_write(void *opaque, mm_u32 offset,
                              mm_u32 size_bytes, mm_u32 value);

/*
 * CP=1 coprocessor entry points called from execute.c MCR/MRC dispatch.
 * These route to the same internal MMIO handler for symmetric behaviour;
 * MCUXpresso fsl_casper.c uses MCR p1,... for fast operand writes which
 * map directly to offset-addressed register writes.
 */
mm_bool mm_lpc55_casper_cp_mcr(struct mm_lpc55_casper *cas,
                               mm_u8 op1, mm_u8 crn, mm_u8 crm, mm_u8 op2,
                               mm_u32 value);
mm_bool mm_lpc55_casper_cp_mrc(struct mm_lpc55_casper *cas,
                               mm_u8 op1, mm_u8 crn, mm_u8 crm, mm_u8 op2,
                               mm_u32 *value_out);

/*
 * Global accessor — execute.c calls this to get the CASPER instance pointer
 * when cpu->has_casper_cp is set.  lpc55s69_mmio.c registers the instance
 * via mm_lpc55_casper_set_global() during init.
 */
struct mm_lpc55_casper *mm_lpc55_casper_get_global(void);
void mm_lpc55_casper_set_global(struct mm_lpc55_casper *cas);

#endif /* LPC55S69_CASPER_H */
