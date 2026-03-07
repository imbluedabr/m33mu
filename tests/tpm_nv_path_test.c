/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <stdio.h>
#include <string.h>

#define mm_tpm_tis_parse_spec test_mm_tpm_tis_parse_spec
#define mm_tpm_tis_register_cfg test_mm_tpm_tis_register_cfg
#define mm_tpm_tis_reset_all test_mm_tpm_tis_reset_all
#define mm_tpm_tis_shutdown_all test_mm_tpm_tis_shutdown_all
#define mm_tpm_tis_count test_mm_tpm_tis_count
#define mm_tpm_tis_get_info test_mm_tpm_tis_get_info
#include "../src/m33mu/tpm_tis.c"
#undef mm_tpm_tis_parse_spec
#undef mm_tpm_tis_register_cfg
#undef mm_tpm_tis_reset_all
#undef mm_tpm_tis_shutdown_all
#undef mm_tpm_tis_count
#undef mm_tpm_tis_get_info

static int test_tpm_nv_path_respects_output_bound(void)
{
    struct tpm_nv_store nv;
    struct {
        char path[320];
        char guard[32];
    } frame;
    char name[96];
    char expected_guard[sizeof(frame.guard)];

    memset(&nv, 0, sizeof(nv));
    memset(&frame, 0, sizeof(frame));
    memset(name, 'b', sizeof(name) - 1u);
    name[sizeof(name) - 1u] = '\0';
    memset(nv.base, 'a', sizeof(nv.base) - 1u);
    nv.base[sizeof(nv.base) - 1u] = '\0';
    memset(frame.guard, 'Z', sizeof(frame.guard));
    memcpy(expected_guard, frame.guard, sizeof(frame.guard));

    tpm_nv_path(frame.path, sizeof(frame.path), &nv, name);

    if (memcmp(frame.guard, expected_guard, sizeof(frame.guard)) != 0) {
        printf("tpm_nv_path_test: guard overwritten by path builder\n");
        return 1;
    }
    if (frame.path[sizeof(frame.path) - 1u] != '\0') {
        printf("tpm_nv_path_test: output buffer not terminated\n");
        return 1;
    }

    return 0;
}

int main(void)
{
    if (test_tpm_nv_path_respects_output_bound() != 0) return 1;
    return 0;
}
