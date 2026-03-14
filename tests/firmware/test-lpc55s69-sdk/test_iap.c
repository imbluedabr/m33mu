/* m33mu -- LPC55S69 SDK IAP/flash test
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Exercises fsl_iap.c against the emulated ROM API (bootloader tree at
 * 0x130010f0).  Tests: FLASH_Init, FLASH_GetProperty, FLASH_Erase,
 * FLASH_Program, FLASH_VerifyErase.
 *
 * Uses sector 1 (offset 0x8000, size 32KB) to avoid disturbing the
 * vector table in sector 0.
 */
#include <stdio.h>
#include <string.h>
#include "fsl_iap.h"

/* Test sector — sector 1 starts at 32768 = 0x8000 */
#define TEST_SECTOR      1u
#define TEST_ADDR        (TEST_SECTOR * 32768u)
#define PAGE_SIZE        512u
#define SECTOR_SIZE      32768u
#define ERASE_KEY        kFLASH_ApiEraseKey

static flash_config_t g_flash;

static const char *status_str(status_t s)
{
    return s == kStatus_Success ? "ok" : "FAIL";
}

int main(void)
{
    status_t st;
    uint32_t prop;
    uint8_t page_buf[PAGE_SIZE];
    uint32_t i;
    int pass = 1;

    printf("=== IAP/flash test ===\n");

    printf("A\n");
    /* Try stub region NS at 0x03002000 */
    printf("stub0=0x%08lx\n", (unsigned long)*(volatile uint32_t *)0x03002000u);
    printf("B\n");
    /* Try tree NS at 0x030010f0 */
    printf("tree=0x%08lx\n", (unsigned long)*(volatile uint32_t *)0x030010f4u);
    printf("C\n");
    /* Try tree S at 0x130010f4 */
    printf("trees=0x%08lx\n", (unsigned long)*(volatile uint32_t *)0x130010f4u);
    printf("D\n");

    /* Init */
    memset(&g_flash, 0, sizeof(g_flash));
    st = FLASH_Init(&g_flash);
    printf("FLASH_Init: %s (st=%ld)\n", status_str(st), (long)st);
    if (st != kStatus_Success) { pass = 0; goto done; }

    /* Properties */
    st = FLASH_GetProperty(&g_flash, kFLASH_PropertyPflashSectorSize, &prop);
    printf("sector_size: %lu  exp 32768  %s\n", (unsigned long)prop,
           prop == 32768u ? "PASS" : "FAIL");
    if (prop != 32768u) pass = 0;

    st = FLASH_GetProperty(&g_flash, kFLASH_PropertyPflashTotalSize, &prop);
    printf("total_size:  %lu  exp 645120  %s\n", (unsigned long)prop,
           prop == 645120u ? "PASS" : "FAIL");
    if (prop != 645120u) pass = 0;

    st = FLASH_GetProperty(&g_flash, kFLASH_PropertyPflashPageSize, &prop);
    printf("page_size:   %lu  exp 512  %s\n", (unsigned long)prop,
           prop == 512u ? "PASS" : "FAIL");
    if (prop != 512u) pass = 0;

    /* Erase sector 1 */
    st = FLASH_Erase(&g_flash, TEST_ADDR, SECTOR_SIZE, ERASE_KEY);
    printf("FLASH_Erase sector1: %s\n", status_str(st));
    if (st != kStatus_Success) { pass = 0; goto done; }

    /* VerifyErase — should pass after erase */
    st = FLASH_VerifyErase(&g_flash, TEST_ADDR, SECTOR_SIZE);
    printf("FLASH_VerifyErase after erase: %s  %s\n", status_str(st),
           st == kStatus_Success ? "PASS" : "FAIL");
    if (st != kStatus_Success) pass = 0;

    /* Program first page with pattern */
    for (i = 0u; i < PAGE_SIZE; ++i) {
        page_buf[i] = (uint8_t)(i & 0xFFu);
    }
    st = FLASH_Program(&g_flash, TEST_ADDR, page_buf, PAGE_SIZE);
    printf("FLASH_Program page0: %s\n", status_str(st));
    if (st != kStatus_Success) { pass = 0; goto done; }

    /* VerifyErase after program — should FAIL (not blank) */
    st = FLASH_VerifyErase(&g_flash, TEST_ADDR, PAGE_SIZE);
    printf("FLASH_VerifyErase after program: %s  %s\n", status_str(st),
           st != kStatus_Success ? "PASS(not blank)" : "FAIL(should not be blank)");
    if (st == kStatus_Success) pass = 0;

    /* Verify data was written correctly */
    {
        const uint8_t *flash_ptr = (const uint8_t *)TEST_ADDR;
        int data_ok = 1;
        for (i = 0u; i < PAGE_SIZE; ++i) {
            if (flash_ptr[i] != (uint8_t)(i & 0xFFu)) { data_ok = 0; break; }
        }
        printf("Data verify: %s\n", data_ok ? "PASS" : "FAIL");
        if (!data_ok) pass = 0;
    }

    /* Re-erase and verify blank again */
    st = FLASH_Erase(&g_flash, TEST_ADDR, SECTOR_SIZE, ERASE_KEY);
    st = FLASH_VerifyErase(&g_flash, TEST_ADDR, SECTOR_SIZE);
    printf("Re-erase + verify: %s\n", st == kStatus_Success ? "PASS" : "FAIL");
    if (st != kStatus_Success) pass = 0;

done:
    printf("=== %s ===\n", pass ? "ALL PASS" : "SOME FAIL");
    return pass ? 0 : 1;
}
