/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "m33mu/memmap.h"

#include "../src/gdbstub.c"

static int test_gdb_send_packet_keeps_full_1020_char_payload(void)
{
    int fds[2];
    char payload[1021];
    char out[1032];
    ssize_t n;
    size_t i;
    unsigned char csum = 0;

    if (pipe(fds) != 0) {
        printf("gdbstub_packet_test: pipe failed\n");
        return 1;
    }

    for (i = 0; i < 1020u; ++i) {
        payload[i] = (char)((i & 1u) ? 'b' : 'a');
        csum += (unsigned char)payload[i];
    }
    payload[1020] = '\0';

    gdb_send_packet(fds[1], payload);
    close(fds[1]);
    n = read(fds[0], out, sizeof(out));
    close(fds[0]);

    if (n != 1024) {
        printf("gdbstub_packet_test: packet len=%ld expected=1024\n", (long)n);
        return 1;
    }
    if (out[0] != '$') {
        printf("gdbstub_packet_test: missing packet prefix\n");
        return 1;
    }
    if (memcmp(out + 1, payload, 1020u) != 0) {
        printf("gdbstub_packet_test: payload truncated or corrupted\n");
        return 1;
    }
    if (out[1021] != '#') {
        printf("gdbstub_packet_test: missing checksum separator\n");
        return 1;
    }
    if (out[1022] != nibble_to_hex((mm_u8)((csum >> 4) & 0x0fu)) ||
        out[1023] != nibble_to_hex((mm_u8)(csum & 0x0fu))) {
        printf("gdbstub_packet_test: checksum mismatch\n");
        return 1;
    }
    return 0;
}

static int test_monitor_fault_clock_with_argument_adds_clock(void)
{
    int fds[2];
    struct mm_gdb_stub stub;
    struct mm_memmap map;
    char payload[512];
    char encoded[sizeof(payload)];
    const char *cmd = "monitor fault clock 123";
    struct mmio_region regions[1];

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        printf("gdbstub_packet_test: socketpair failed\n");
        return 1;
    }

    memset(&stub, 0, sizeof(stub));
    memset(&map, 0, sizeof(map));
    memset(regions, 0, sizeof(regions));
    mm_memmap_init(&map, regions, 1u);
    mm_gdb_stub_init(&stub);
    stub.connected = MM_TRUE;
    stub.client_fd = fds[1];

    strcpy(payload, "qRcmd,");
    if (hex_encode_bytes(cmd, strlen(cmd), encoded, sizeof(encoded)) == 0u) {
        printf("gdbstub_packet_test: failed to encode monitor command\n");
        close(fds[0]);
        close(fds[1]);
        return 1;
    }
    strcat(payload, encoded);
    gdb_send_packet(fds[0], payload);

    mm_gdb_stub_handle(&stub, 0, &map);

    close(fds[0]);
    close(fds[1]);

    if (stub.fault_clock_count != 1u || stub.fault_clocks[0] != 123u) {
        printf("gdbstub_packet_test: monitor fault clock argument was not accepted\n");
        return 1;
    }

    return 0;
}

int main(void)
{
    if (test_gdb_send_packet_keeps_full_1020_char_payload() != 0) return 1;
    if (test_monitor_fault_clock_with_argument_adds_clock() != 0) return 1;
    {
        struct mm_gdb_stub stub;
        struct mm_memmap map;
        struct mmio_region regions[1];
        mm_u8 flash[8] = {
            0x00, 0xbf, /* nop */
            0x42, 0xf4, 0x80, 0x22, /* 32-bit Thumb insn */
            0x00, 0xbf /* nop */
        };

        memset(regions, 0, sizeof(regions));
        memset(&map, 0, sizeof(map));
        mm_memmap_init(&map, regions, 1u);
        map.flash.buffer = flash;
        map.flash.length = sizeof(flash);
        map.flash.base = 0x08000000u;
        map.flash_base_s = 0x08000000u;
        map.flash_base_ns = 0x08000000u;
        map.flash_size_s = sizeof(flash);
        map.flash_size_ns = sizeof(flash);

        mm_gdb_stub_init(&stub);
        if (!gdb_install_breakpoint(&stub, &map, MM_NONSECURE, 0x08000004u)) {
            printf("gdbstub_packet_test: failed to install canonicalized breakpoint\n");
            return 1;
        }
        if (!stub.breakpoints[0].valid || stub.breakpoints[0].addr != 0x08000003u ||
            stub.breakpoints[0].len != 4u) {
            printf("gdbstub_packet_test: breakpoint was not canonicalized to 32-bit boundary\n");
            return 1;
        }
        if (flash[2] != 0x00 || flash[3] != 0xbe || flash[4] != 0x00 || flash[5] != 0xbe) {
            printf("gdbstub_packet_test: 32-bit breakpoint patch was not written at instruction start\n");
            return 1;
        }
        if (!gdb_remove_breakpoint(&stub, &map, MM_NONSECURE, 0x08000004u)) {
            printf("gdbstub_packet_test: failed to remove canonicalized breakpoint\n");
            return 1;
        }
        if (flash[2] != 0x42 || flash[3] != 0xf4 || flash[4] != 0x80 || flash[5] != 0x22) {
            printf("gdbstub_packet_test: 32-bit breakpoint restore failed\n");
            return 1;
        }
    }
    return 0;
}
