/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * PIC32CK SDK UART test -- verifies SDK-style clock + SERCOM0 init.
 */
#include <stdio.h>
#include <string.h>

static int test_printf(void)
{
    printf("hello from sdk uart\n");
    return 1;
}

static int test_sprintf(void)
{
    char buf[32];
    int n = sprintf(buf, "0x%08X", 0xDEADBEEFu);
    int ok = (n == 10) && (strcmp(buf, "0xDEADBEEF") == 0);
    printf("sprintf: %s\n", ok ? "PASS" : "FAIL");
    return ok;
}

static int test_numbers(void)
{
    int ok = 1;
    ok &= (1 + 1 == 2);
    ok &= ((0xDEAD ^ 0xBEEF) == 0x6042);
    printf("numbers: %s\n", ok ? "PASS" : "FAIL");
    return ok;
}

int main(void)
{
    int all = 1;
    printf("=== PIC32CK SDK uart test ===\n");
    all &= test_printf();
    all &= test_sprintf();
    all &= test_numbers();
    printf("=== %s ===\n", all ? "ALL PASS" : "SOME FAIL");
    return all ? 0 : 1;
}
