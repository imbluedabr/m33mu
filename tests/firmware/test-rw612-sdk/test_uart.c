/* m33mu -- RW612 UART smoke test.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Validates that FlexComm0 USART comes up under the emu_board.c bring-up
 * sequence and that printf() routes a full string to UART backend.
 */
#include <stdio.h>

int main(void)
{
    printf("RW612 UART OK\n");
    printf("=== ALL PASS ===\n");
    return 0;
}
