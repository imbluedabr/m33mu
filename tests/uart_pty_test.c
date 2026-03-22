/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "m33mu/target_hal.h"

static int test_uart_open_disables_slave_echo_and_canonical_mode(void)
{
    struct mm_uart_io io;
    struct termios tio;
    int slave_fd;

    mm_uart_io_init(&io);
    if (!mm_uart_io_open(&io, 0x40000000u)) {
        printf("uart_pty_test: failed to open UART PTY\n");
        return 1;
    }

    slave_fd = open(io.name, O_RDWR | O_NOCTTY);
    if (slave_fd < 0) {
        printf("uart_pty_test: failed to reopen slave PTY %s\n", io.name);
        mm_uart_io_close(&io);
        return 1;
    }
    if (tcgetattr(slave_fd, &tio) != 0) {
        printf("uart_pty_test: tcgetattr failed for %s\n", io.name);
        close(slave_fd);
        mm_uart_io_close(&io);
        return 1;
    }

    if ((tio.c_lflag & ECHO) != 0u) {
        printf("uart_pty_test: slave PTY still has ECHO enabled\n");
        close(slave_fd);
        mm_uart_io_close(&io);
        return 1;
    }
    if ((tio.c_lflag & ICANON) != 0u) {
        printf("uart_pty_test: slave PTY still has ICANON enabled\n");
        close(slave_fd);
        mm_uart_io_close(&io);
        return 1;
    }

    close(slave_fd);
    mm_uart_io_close(&io);
    return 0;
}

int main(void)
{
    if (test_uart_open_disables_slave_echo_and_canonical_mode() != 0) {
        return 1;
    }
    printf("uart_pty_test: ok\n");
    return 0;
}
