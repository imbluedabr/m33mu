/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * PIC32CK FCW (Flash Write Controller) register test.
 * FCW base: 0x44004000
 * Actual register layout from PIC32CK2051GC01144 datasheet:
 *   CTRLA    0x00   CTRLB    0x04   MUTEX   0x08
 *   INTENCLR 0x0C   INTENSET 0x10   INTFLAG 0x14
 *   STATUS   0x18   KEY      0x1C   ADDR    0x20
 *   SRCADDR  0x24   DATA[0]  0x28 .. DATA[7] 0x44
 *   SWAP     0x48
 */
#include <stdio.h>
#include <stdint.h>

#define FCW_BASE         0x44004000u
#define FCW_CTRLA        (*(volatile uint32_t *)(FCW_BASE + 0x00u))
#define FCW_INTFLAG      (*(volatile uint32_t *)(FCW_BASE + 0x14u))
#define FCW_STATUS       (*(volatile uint32_t *)(FCW_BASE + 0x18u))
#define FCW_KEY          (*(volatile uint32_t *)(FCW_BASE + 0x1Cu))
#define FCW_ADDR         (*(volatile uint32_t *)(FCW_BASE + 0x20u))
#define FCW_SRCADDR      (*(volatile uint32_t *)(FCW_BASE + 0x24u))
#define FCW_DATA(n)      (*(volatile uint32_t *)(FCW_BASE + 0x28u + (n)*4u))
#define FCW_SWAP         (*(volatile uint32_t *)(FCW_BASE + 0x48u))

#define FCW_STATUS_BUSY  (1u << 0)
#define FCW_INTFLAG_DONE (1u << 0)

#define FCW_WRKEY        0x91C32C01u

static void fcw_wait_busy(void)
{
    while ((FCW_STATUS & FCW_STATUS_BUSY) != 0u) { }
}

int main(void)
{
    int all = 1;
    printf("=== PIC32CK FCW test ===\n");

    /* Test 1: STATUS reads not-busy at init */
    fcw_wait_busy();
    int t1 = ((FCW_STATUS & FCW_STATUS_BUSY) == 0u);
    printf("FCW not busy at init: %s\n", t1 ? "PASS" : "FAIL");
    all &= t1;

    /* Test 2: FCW NO_OP sequence (SDK FCW_Initialize pattern)
     * Write KEY then CTRLA with NVMOP=0 (NO_OP).
     * Emulator sets INTFLAG.DONE on any CTRLA write.
     */
    fcw_wait_busy();
    FCW_KEY   = FCW_WRKEY;
    FCW_ADDR  = 0u;
    FCW_CTRLA = 0u;  /* NVMOP=NO_OP */
    int t2 = ((FCW_INTFLAG & FCW_INTFLAG_DONE) != 0u);
    printf("FCW DONE after CTRLA write: %s\n", t2 ? "PASS" : "FAIL");
    all &= t2;

    /* Test 3: Clear DONE by writing 1 to INTFLAG.DONE */
    FCW_INTFLAG = FCW_INTFLAG_DONE;
    int t3 = ((FCW_INTFLAG & FCW_INTFLAG_DONE) == 0u);
    printf("FCW DONE cleared: %s\n", t3 ? "PASS" : "FAIL");
    all &= t3;

    /* Test 4: Write DATA registers (verify no fault, check read-back) */
    for (int i = 0; i < 8; ++i) {
        FCW_DATA(i) = (uint32_t)(0xA0000000u | (uint32_t)i);
    }
    int t4 = (FCW_DATA(0) == 0xA0000000u) && (FCW_DATA(7) == 0xA0000007u);
    printf("FCW DATA r/w: %s\n", t4 ? "PASS" : "FAIL");
    all &= t4;

    /* Test 5: SWAP register read/write */
    FCW_SWAP = 0u;
    int t5 = (FCW_SWAP == 0u);
    printf("FCW SWAP r/w: %s\n", t5 ? "PASS" : "FAIL");
    all &= t5;

    /* Test 6: SRCADDR */
    FCW_SRCADDR = 0x20001000u;
    int t6 = (FCW_SRCADDR == 0x20001000u);
    printf("FCW SRCADDR r/w: %s\n", t6 ? "PASS" : "FAIL");
    all &= t6;

    printf("=== %s ===\n", all ? "ALL PASS" : "SOME FAIL");
    return all ? 0 : 1;
}
