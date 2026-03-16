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
#define FCW_OP_SDW       1u
#define FCW_OP_QDW       2u
#define FCW_OP_ROW       3u
#define FCW_OP_PAGE_ERASE 4u

#define TEST_FLASH_ADDR  0x0C1FF000u

static volatile uint32_t *const test_flash = (volatile uint32_t *)TEST_FLASH_ADDR;
static uint32_t row_buf[256];

static void fcw_wait_busy(void)
{
    while ((FCW_STATUS & FCW_STATUS_BUSY) != 0u) { }
}

int main(void)
{
    int all = 1;
    int i;
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

    /* Test 4: Erase a page and verify the backing flash changes. */
    FCW_KEY = FCW_WRKEY;
    FCW_ADDR = TEST_FLASH_ADDR;
    FCW_CTRLA = FCW_OP_PAGE_ERASE;
    fcw_wait_busy();
    int t4 = 1;
    for (i = 0; i < 8; ++i) {
        if (test_flash[i] != 0xFFFFFFFFu) {
            t4 = 0;
        }
    }
    printf("FCW page erase: %s\n", t4 ? "PASS" : "FAIL");
    all &= t4;

    /* Test 5: Quad double-word program updates emulated flash. */
    for (i = 0; i < 8; ++i) {
        FCW_DATA(i) = (uint32_t)(0xA0000000u | (uint32_t)i);
    }
    FCW_KEY = FCW_WRKEY;
    FCW_ADDR = TEST_FLASH_ADDR;
    FCW_CTRLA = FCW_OP_QDW;
    fcw_wait_busy();
    int t5 = 1;
    for (i = 0; i < 8; ++i) {
        if (test_flash[i] != (uint32_t)(0xA0000000u | (uint32_t)i)) {
            t5 = 0;
        }
    }
    printf("FCW quad program: %s\n", t5 ? "PASS" : "FAIL");
    all &= t5;

    /* Test 6: Row program copies data from RAM via SRCADDR. */
    for (i = 0; i < 256; ++i) {
        row_buf[i] = 0x5A5A0000u | (uint32_t)i;
    }
    FCW_KEY = FCW_WRKEY;
    FCW_ADDR = TEST_FLASH_ADDR;
    FCW_CTRLA = FCW_OP_PAGE_ERASE;
    fcw_wait_busy();
    FCW_SRCADDR = (uint32_t)row_buf;
    FCW_KEY = FCW_WRKEY;
    FCW_ADDR = TEST_FLASH_ADDR;
    FCW_CTRLA = FCW_OP_ROW;
    fcw_wait_busy();
    int t6 = 1;
    for (i = 0; i < 8; ++i) {
        if (test_flash[i] != row_buf[i]) {
            t6 = 0;
        }
    }
    printf("FCW row program: %s\n", t6 ? "PASS" : "FAIL");
    all &= t6;

    /* Test 7: SWAP register read/write */
    FCW_SWAP = 0u;
    int t7 = (FCW_SWAP == 0u);
    printf("FCW SWAP r/w: %s\n", t7 ? "PASS" : "FAIL");
    all &= t7;

    printf("=== %s ===\n", all ? "ALL PASS" : "SOME FAIL");
    return all ? 0 : 1;
}
