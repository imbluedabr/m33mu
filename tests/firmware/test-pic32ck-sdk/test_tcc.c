/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * PIC32CK TCC (Timer/Counter for Control) register access test.
 * Tests TCC0-TCC3 (APB-A) and TCC4 (APB-B) basic register read/write.
 * No tick counting -- just verifies register access works.
 */
#include <stdio.h>
#include <stdint.h>

/* TCC register layout (offsets) */
#define TCC_CTRLA       0x00u
#define TCC_CTRLBCLR    0x04u
#define TCC_CTRLBSET    0x05u
#define TCC_SYNCBUSY    0x08u
#define TCC_DRVCTRL     0x18u
#define TCC_EVCTRL      0x20u
#define TCC_INTENCLR    0x24u
#define TCC_INTENSET    0x28u
#define TCC_INTFLAG     0x2Cu
#define TCC_STATUS      0x30u
#define TCC_COUNT       0x34u
#define TCC_PATT        0x38u
#define TCC_WAVE        0x3Cu
#define TCC_PER         0x40u
#define TCC_CC0         0x44u
#define TCC_CC1         0x48u
#define TCC_CC2         0x4Cu
#define TCC_CC3         0x50u

static const uint32_t tcc_bases[] = {
    0x44818000u,  /* TCC0 */
    0x4481A000u,  /* TCC1 */
    0x4481C000u,  /* TCC2 */
    0x4481E000u,  /* TCC3 */
    0x45008000u,  /* TCC4 */
};

#define NTCC 5u

static int test_tcc_instance(int idx, uint32_t base)
{
    volatile uint8_t  *b8  = (volatile uint8_t *)base;
    volatile uint32_t *b32 = (volatile uint32_t *)base;
    int ok = 1;

    /* SYNCBUSY must read 0 (emulator always returns 0) */
    uint32_t sb = b32[TCC_SYNCBUSY / 4u];
    ok &= (sb == 0u);

    /* Write PRESCALER=4 (bits [10:8]=100) to CTRLA and read back */
    uint32_t ctrla_val = (4u << 8u);
    b32[TCC_CTRLA / 4u] = ctrla_val;
    ok &= (b32[TCC_CTRLA / 4u] == ctrla_val);

    /* Write PER and CC0 */
    uint32_t per_val = 9999u;
    uint32_t cc0_val = 4999u;
    b32[TCC_PER / 4u] = per_val;
    b32[TCC_CC0 / 4u] = cc0_val;
    ok &= (b32[TCC_PER / 4u] == per_val);
    ok &= (b32[TCC_CC0 / 4u] == cc0_val);

    /* WAVE: WAVEGEN=NPWM (mode 2) */
    b32[TCC_WAVE / 4u] = 2u;
    ok &= (b32[TCC_WAVE / 4u] == 2u);

    /* Enable TCC: CTRLA |= ENABLE (bit 1) */
    b32[TCC_CTRLA / 4u] |= (1u << 1u);
    ok &= ((b32[TCC_CTRLA / 4u] & (1u << 1u)) != 0u);

    /* COUNT should remain 0 (static emulator) */
    /* We just verify it is readable without fault */
    (void)b32[TCC_COUNT / 4u];

    return ok;
}

int main(void)
{
    int all = 1;
    printf("=== PIC32CK TCC test ===\n");

    for (unsigned i = 0u; i < NTCC; ++i) {
        int ok = test_tcc_instance((int)i, tcc_bases[i]);
        printf("TCC%u: %s\n", i, ok ? "PASS" : "FAIL");
        all &= ok;
    }

    printf("=== %s ===\n", all ? "ALL PASS" : "SOME FAIL");
    return all ? 0 : 1;
}
