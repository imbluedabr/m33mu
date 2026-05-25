/* m33mu -- an ARMv8-M Emulator
 *
 * Copyright (C) 2025  Daniele Lacamera <root@danielinux.net>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Regression for issue #8: writes to DWT_CYCCNT (0xE0001004) from
 * privileged firmware should not raise a MemManage fault. The Internal
 * PPB (0xE0000000..0xE000FFFF) is outside the SAU/MPU-controlled memory
 * map in this emulator, so the prot interceptor must let it through.
 */

#include <stdio.h>
#include <string.h>
#include "m33mu/memmap.h"
#include "m33mu/mem_prot.h"
#include "m33mu/scs.h"
#include "m33mu/core_sys.h"

static int run(void)
{
    struct mm_memmap map;
    struct mmio_region regions[8];
    struct mm_scs scs;
    struct mm_prot_ctx prot;
    struct mm_core_sys core_sys;
    mm_u64 vcycles = 0;
    mm_u32 value = 0;

    memset(&map, 0, sizeof(map));
    memset(&core_sys, 0, sizeof(core_sys));
    core_sys.dwt.vcycles = &vcycles;

    mm_memmap_init(&map, regions, sizeof(regions) / sizeof(regions[0]));
    mm_scs_init(&scs, 0);
    mm_prot_init(&prot, &scs, 0, 0);
    mm_memmap_set_interceptor(&map, mm_prot_interceptor, &prot);

    if (!mm_core_sys_register(&map.mmio, &core_sys)) {
        fprintf(stderr, "core_sys register failed\n");
        return 1;
    }

    /* Interceptor must allow ITM (0xE0000000), DWT (0xE0001000) and
     * FPB (0xE0002000) — none of these are inside the SCS window. */
    if (!mm_prot_interceptor(&prot, MM_ACCESS_WRITE, MM_SECURE, 0xE0000000u, 4u)) {
        fprintf(stderr, "ITM blocked\n");
        return 1;
    }
    if (!mm_prot_interceptor(&prot, MM_ACCESS_WRITE, MM_SECURE, 0xE0001004u, 4u)) {
        fprintf(stderr, "DWT_CYCCNT blocked\n");
        return 1;
    }
    if (!mm_prot_interceptor(&prot, MM_ACCESS_WRITE, MM_SECURE, 0xE0002000u, 4u)) {
        fprintf(stderr, "FPB blocked\n");
        return 1;
    }

    /* End-to-end: mimic the firmware in issue #8.
     *   DWT->CYCCNT = 0;
     *   DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
     * Both writes must succeed, and CYCCNT must read back as zero +
     * the virtual cycle base. */
    if (!mm_memmap_write(&map, MM_SECURE, 0xE0001004u, 4u, 0u)) {
        fprintf(stderr, "DWT_CYCCNT write faulted\n");
        return 1;
    }
    if (!mm_memmap_write(&map, MM_SECURE, 0xE0001000u, 4u, 0x1u /* CYCCNTENA */)) {
        fprintf(stderr, "DWT_CTRL write faulted\n");
        return 1;
    }
    if (!mm_memmap_read(&map, MM_SECURE, 0xE0001000u, 4u, &value)) {
        fprintf(stderr, "DWT_CTRL read faulted\n");
        return 1;
    }
    if ((value & 0x1u) == 0u) {
        fprintf(stderr, "DWT_CTRL.CYCCNTENA did not latch (got 0x%08lx)\n",
                (unsigned long)value);
        return 1;
    }
    if (!mm_memmap_read(&map, MM_SECURE, 0xE0001004u, 4u, &value)) {
        fprintf(stderr, "DWT_CYCCNT read faulted\n");
        return 1;
    }

    /* Non-secure privileged code must also reach the PPB. */
    if (!mm_memmap_write(&map, MM_NONSECURE, 0xE0001004u, 4u, 0u)) {
        fprintf(stderr, "DWT_CYCCNT write faulted from NS\n");
        return 1;
    }

    return 0;
}

int main(void)
{
    if (run() != 0) {
        return 1;
    }
    printf("ppb_dwt_access_test: OK\n");
    return 0;
}
