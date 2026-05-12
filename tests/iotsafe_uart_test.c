/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <stdio.h>
#include <string.h>

#include "m33mu/iotsafe_uart.h"
#include "m33mu/target_hal.h"

static int failures;

static void send_text(struct mm_uart_io *io, const char *text)
{
    size_t i;
    for (i = 0; text[i] != '\0'; ++i) {
        mm_uart_io_queue_tx(io, (mm_u8)text[i]);
    }
    (void)mm_uart_io_flush(io);
}

static void read_reply(struct mm_uart_io *io, char *buf, size_t buf_sz)
{
    size_t off = 0;
    while (off + 1u < buf_sz) {
        if (mm_uart_io_has_rx(io)) {
            buf[off++] = (char)mm_uart_io_read(io);
            continue;
        }
        if (!mm_uart_io_poll(io)) {
            break;
        }
    }
    buf[off] = '\0';
}

static void expect_contains(const char *haystack, const char *needle, const char *what)
{
    if (strstr(haystack, needle) == 0) {
        printf("iotsafe_uart_test: missing %s\n", what);
        printf("reply was: %s\n", haystack);
        failures++;
    }
}

int main(void)
{
    struct mm_iotsafe_uart_cfg cfg;
    struct mm_uart_io io;
    char reply[8192];

#ifndef M33MU_HAS_WOLFSSL
    printf("iotsafe_uart_test: skipped (wolfSSL integration disabled)\n");
    return 0;
#endif

    if (!mm_iotsafe_uart_parse_spec("0x40004400:file=/tmp/iotsafe_uart_test.bin", &cfg)) {
        printf("iotsafe_uart_test: parse failed\n");
        return 1;
    }
    if (!mm_iotsafe_uart_register_cfg(&cfg)) {
        printf("iotsafe_uart_test: register failed\n");
        return 1;
    }

    mm_uart_io_init(&io);
    if (!mm_uart_io_open(&io, cfg.base)) {
        printf("iotsafe_uart_test: open failed\n");
        mm_iotsafe_uart_shutdown_all();
        return 1;
    }

    send_text(&io, "ATE0\r\n");
    read_reply(&io, reply, sizeof(reply));
    expect_contains(reply, "OK", "ATE0 OK");

    send_text(&io, "AT+CSIM=24,\"01A4040007A0000005590010\"\r\n");
    read_reply(&io, reply, sizeof(reply));
    expect_contains(reply, "+CSIM:", "applet select response");
    expect_contains(reply, "9000", "applet select status");

    send_text(&io, "AT+CSIM=10,\"8184000008\"\r\n");
    read_reply(&io, reply, sizeof(reply));
    expect_contains(reply, "+CSIM:", "getrandom response");
    expect_contains(reply, "9000", "getrandom status");

    send_text(&io, "AT+CSIM=18,\"81B900000484021234\"\r\n");
    read_reply(&io, reply, sizeof(reply));
    expect_contains(reply, "34454943864104", "keygen public key tlv");
    expect_contains(reply, "9000", "keygen status");

    send_text(&io, "AT+CSIM=18,\"81CD00000485021234\"\r\n");
    read_reply(&io, reply, sizeof(reply));
    expect_contains(reply, "34454943864104", "read key public key tlv");
    expect_contains(reply, "9000", "read key status");

    /* IoT SAFE wire encoding mirrors wolfSSL's `(byte*)&id_var` convention:
     * host-native byte order. On all current m33mu targets (Cortex-M33 LE
     * and the host x86_64 LE) that is little-endian, so file id 0x0002 is
     * sent as wire bytes `02 00`. The simulator echoes those wire bytes
     * back verbatim in the file-id TLV. */
    send_text(&io, "AT+CSIM=18,\"81CBC3000483020200\"\r\n");
    read_reply(&io, reply, sizeof(reply));
    expect_contains(reply, "83020200", "file id tlv");
    expect_contains(reply, "2002", "file size tlv");
    expect_contains(reply, "9000", "getdata status");

    mm_uart_io_close(&io);
    mm_iotsafe_uart_shutdown_all();

    if (failures != 0) {
        printf("iotsafe_uart_test: %d failure(s)\n", failures);
        return 1;
    }
    printf("iotsafe_uart_test: ok\n");
    return 0;
}
