/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#include "../src/m33mu/ta100.c"

static int run_genkey_child(void)
{
#ifdef M33MU_HAS_WOLFSSL
    struct mm_ta100 ta;
    mm_u8 cmd[6] = { 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u };
    memset(&ta, 0, sizeof(ta));
    setenv("M33MU_TA100_ECC", "1", 1);
    ta100_cmd_genkey(&ta, cmd, sizeof(cmd));
    if (ta.rsp_len < 1u || ta.rsp_buf[0] != TA100_STATUS_EXEC_ERROR) {
        return 1;
    }
#endif
    return 0;
}

static int run_sign_child(void)
{
#ifdef M33MU_HAS_WOLFSSL
    struct mm_ta100 ta;
    mm_u8 cmd[6] = { 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u };
    memset(&ta, 0, sizeof(ta));
    memset(ta.temp_nonce, 0x5au, sizeof(ta.temp_nonce));
    ta.temp_nonce_valid = MM_TRUE;
    setenv("M33MU_TA100_ECC", "1", 1);
    ta100_cmd_sign(&ta, cmd, sizeof(cmd));
    if (ta.rsp_len < 1u || ta.rsp_buf[0] != TA100_STATUS_EXEC_ERROR) {
        return 1;
    }
#endif
    return 0;
}

static int expect_child_success(int (*fn)(void), const char *name)
{
    pid_t pid = fork();
    int status;

    if (pid < 0) {
        printf("ta100_nv_null_test: fork failed for %s\n", name);
        return 1;
    }
    if (pid == 0) {
        _exit(fn() == 0 ? 0 : 1);
    }
    if (waitpid(pid, &status, 0) < 0) {
        printf("ta100_nv_null_test: waitpid failed for %s\n", name);
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        printf("ta100_nv_null_test: %s child failed status=0x%x\n", name, status);
        return 1;
    }
    return 0;
}

int main(void)
{
    if (expect_child_success(run_genkey_child, "genkey") != 0) return 1;
    if (expect_child_success(run_sign_child, "sign") != 0) return 1;
    return 0;
}
