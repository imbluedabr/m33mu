/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * PIC32CK SERCOM USART smoke test.
 * Verifies that printf output reaches the emulator stdout.
 */
#include <stdio.h>
#include <string.h>

static int test_printf(void)
{
    const char *msg = "hello pic32ck";
    printf("%s\n", msg);
    return 1;
}

static int test_numbers(void)
{
    int ok = 1;
    ok &= (1 + 1 == 2);
    ok &= (0xDEAD ^ 0xBEEF) == 0x6042;
    printf("numbers: %s\n", ok ? "PASS" : "FAIL");
    return ok;
}

int main(void)
{
    int all = 1;
    printf("=== PIC32CK uart test ===\n");
    all &= test_printf();
    all &= test_numbers();
    printf("=== %s ===\n", all ? "ALL PASS" : "SOME FAIL");
    return all ? 0 : 1;
}
