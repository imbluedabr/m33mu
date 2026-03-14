/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * PIC32CK PORT/GPIO test -- direct register access.
 * Tests PORT GROUP A DIR, OUT, IN, OUTSET, OUTCLR registers.
 */
#include <stdio.h>
#include <stdint.h>

/* PORT base: 0x44800000, groups stride 0x80 */
#define PORT_BASE          0x44800000u
#define PORT_GROUP(g)      ((volatile uint32_t *)(PORT_BASE + (g)*0x80u))

/* Group register offsets (in uint32_t units from GROUP base) */
#define PORT_DIR_OFF       0u   /* 0x00 */
#define PORT_DIRCLR_OFF    1u   /* 0x04 */
#define PORT_DIRSET_OFF    2u   /* 0x08 */
#define PORT_DIRTGL_OFF    3u   /* 0x0C */
#define PORT_OUT_OFF       4u   /* 0x10 */
#define PORT_OUTCLR_OFF    5u   /* 0x14 */
#define PORT_OUTSET_OFF    6u   /* 0x18 */
#define PORT_OUTTGL_OFF    7u   /* 0x1C */
#define PORT_IN_OFF        8u   /* 0x20 */

#define GROUP_A            0u
#define PIN_BIT            (1u << 10)  /* Use PA10 for test */

int main(void)
{
    int all = 1;
    volatile uint32_t *grp = PORT_GROUP(GROUP_A);

    printf("=== PIC32CK GPIO test ===\n");

    /* --- Test 1: DIRSET / DIRCLR --- */
    grp[PORT_DIRCLR_OFF] = PIN_BIT;  /* ensure cleared */
    int t1 = ((grp[PORT_DIR_OFF] & PIN_BIT) == 0u);
    grp[PORT_DIRSET_OFF] = PIN_BIT;
    int t1b = ((grp[PORT_DIR_OFF] & PIN_BIT) != 0u);
    printf("DIR set/clr: %s\n", (t1 && t1b) ? "PASS" : "FAIL");
    all &= t1 && t1b;

    /* --- Test 2: OUTSET / OUTCLR --- */
    grp[PORT_OUTCLR_OFF] = PIN_BIT;
    int t2 = ((grp[PORT_OUT_OFF] & PIN_BIT) == 0u);
    grp[PORT_OUTSET_OFF] = PIN_BIT;
    int t2b = ((grp[PORT_OUT_OFF] & PIN_BIT) != 0u);
    printf("OUT set/clr: %s\n", (t2 && t2b) ? "PASS" : "FAIL");
    all &= t2 && t2b;

    /* --- Test 3: DIR OUT independent for another pin --- */
    {
        uint32_t pin2 = (1u << 5u);
        grp[PORT_DIRSET_OFF] = pin2;
        grp[PORT_OUTSET_OFF] = pin2;
        int t3 = ((grp[PORT_DIR_OFF] & pin2) != 0u)
               && ((grp[PORT_OUT_OFF] & pin2) != 0u);
        grp[PORT_OUTCLR_OFF] = pin2;
        int t3b = ((grp[PORT_OUT_OFF] & pin2) == 0u);
        printf("DIR+OUT PA5: %s\n", (t3 && t3b) ? "PASS" : "FAIL");
        all &= t3 && t3b;
    }

    /* --- Test 4: Multiple groups do not interfere --- */
    {
        volatile uint32_t *grpB = PORT_GROUP(1u);
        uint32_t mask_a = (1u << 2u);
        uint32_t mask_b = (1u << 3u);
        grp[PORT_DIRSET_OFF]  = mask_a;
        grpB[PORT_DIRSET_OFF] = mask_b;
        int t4 = ((grp[PORT_DIR_OFF] & mask_b) == 0u)    /* A not set with B mask */
              && ((grpB[PORT_DIR_OFF] & mask_a) == 0u);  /* B not set with A mask */
        printf("group isolation: %s\n", t4 ? "PASS" : "FAIL");
        all &= t4;
    }

    printf("=== %s ===\n", all ? "ALL PASS" : "SOME FAIL");
    return all ? 0 : 1;
}
