/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "m33mu/snapshot.h"

static int test_snapshot_skip_rejects_overflowed_len(void)
{
    struct mm_snapshot_reader r;
    mm_u8 buf[8];

    memset(buf, 0, sizeof(buf));
    mm_snapshot_reader_init(&r, buf, (mm_u32)sizeof(buf));
    r.offset = 1u;

    if (mm_snapshot_skip(&r, 0xffffffffu) != MM_FALSE) {
        printf("snapshot_test: skip accepted overflowed len\n");
        return 1;
    }
    return 0;
}

static int test_snapshot_begin_section_rejects_overflowed_len(void)
{
    struct mm_snapshot_reader r;
    struct mm_snapshot_reader section;
    mm_u8 buf[8];
    mm_u32 len = 0xffffffffu;

    memset(buf, 0, sizeof(buf));
    memcpy(buf, &len, sizeof(len));
    mm_snapshot_reader_init(&r, buf, (mm_u32)sizeof(buf));

    if (mm_snapshot_reader_begin_section(&r, &section) != MM_FALSE) {
        printf("snapshot_test: begin_section accepted overflowed len\n");
        return 1;
    }
    return 0;
}

static int test_snapshot_write_rejects_overflowed_len(void)
{
    struct mm_snapshot_writer w;
    mm_u8 buf[8];
    mm_u8 src[1] = { 0 };
    pid_t pid;
    int status;

    mm_snapshot_writer_init(&w, buf, (mm_u32)sizeof(buf));
    w.used = 1u;

    pid = fork();
    if (pid < 0) {
        printf("snapshot_test: fork failed\n");
        return 1;
    }
    if (pid == 0) {
        _exit(mm_snapshot_write(&w, src, 0xffffffffu) == MM_FALSE ? 0 : 2);
    }
    if (waitpid(pid, &status, 0) < 0) {
        printf("snapshot_test: waitpid failed\n");
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        printf("snapshot_test: write overflow child status=%d\n", status);
        return 1;
    }
    return 0;
}

int main(void)
{
    if (test_snapshot_skip_rejects_overflowed_len() != 0) return 1;
    if (test_snapshot_begin_section_rejects_overflowed_len() != 0) return 1;
    if (test_snapshot_write_rejects_overflowed_len() != 0) return 1;
    return 0;
}
