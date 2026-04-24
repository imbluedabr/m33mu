/* m33mu -- an ARMv8-M Emulator
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "m33mu/mmio.h"
#include "m33mu/memmap.h"
#include "m33mu/cpu.h"
#include "mcxn947/mcxn947_mmio.h"
#include "mcxn947/mcxn947_romapi.h"
#include "mcxn947/mcxn947_secure.h"

#define ROMAPI_STUB_IAP_API_INIT   0x1303f230u
#define ROMAPI_STUB_EFUSE_READ     0x1303f210u
#define SYSCON_BASE                0x40000000u
#define SYSCON_PRESETCTRL0         0x100u
#define SYSCON_AHBCLKCTRL0         0x200u
#define PUF_BASE                   0x40024000u
#define ELS_BASE                   0x40026000u

#define SEC_REG_CMD                0x000u
#define SEC_REG_STATUS             0x004u
#define SEC_REG_ARG0               0x008u
#define SEC_REG_RESULT0            0x020u
#define SEC_REG_RESULT1            0x024u
#define SEC_REG_KEYIN0             0x080u
#define SEC_REG_KEYIN1             0x084u
#define SEC_REG_KEYIN2             0x088u
#define SEC_REG_KEYIN3             0x08Cu

#define SEC_STATUS_DONE            (1u << 1)
#define PUF_CMD_DERIVE             0x2u
#define ELS_CMD_GENERATE           0x1u

static void test_init_map(struct mm_memmap *map, struct mmio_region *regions, size_t cap)
{
    mm_memmap_init(map, regions, cap);
    mm_mcxn947_mmio_reset();
    (void)mm_mcxn947_register_mmio(&map->mmio);
}

static int test_secure_mmio_and_puf(void)
{
    struct mm_memmap map;
    struct mmio_region regions[64];
    mm_u32 value;

    test_init_map(&map, regions, 64u);
    mmio_set_active_sec(MM_SECURE);

    if (!mmio_bus_write(&map.mmio, PUF_BASE + SEC_REG_ARG0, 4u, 3u)) return 1;
    if (!mmio_bus_write(&map.mmio, PUF_BASE + SEC_REG_KEYIN0, 4u, 0x11111111u)) return 1;
    if (!mmio_bus_write(&map.mmio, PUF_BASE + SEC_REG_KEYIN1, 4u, 0x22222222u)) return 1;
    if (!mmio_bus_write(&map.mmio, PUF_BASE + SEC_REG_KEYIN2, 4u, 0x33333333u)) return 1;
    if (!mmio_bus_write(&map.mmio, PUF_BASE + SEC_REG_KEYIN3, 4u, 0x44444444u)) return 1;
    if (!mmio_bus_write(&map.mmio, PUF_BASE + SEC_REG_CMD, 4u, PUF_CMD_DERIVE)) return 1;
    if (!mmio_bus_read(&map.mmio, PUF_BASE + SEC_REG_STATUS, 4u, &value)) return 1;
    if ((value & SEC_STATUS_DONE) == 0u) return 1;
    if (!mmio_bus_read(&map.mmio, PUF_BASE + SEC_REG_RESULT0, 4u, &value)) return 1;
    if (value != 0xCAFE0003u) return 1;

    mmio_set_active_sec(MM_NONSECURE);
    if (mmio_bus_read(&map.mmio, PUF_BASE + SEC_REG_RESULT1, 4u, &value)) return 1;
    return 0;
}

static int test_els_command_and_attestation_stability(void)
{
    struct mm_memmap map;
    struct mmio_region regions[64];
    mm_u8 flash[256];
    mm_u8 m1[32];
    mm_u8 m2[32];
    mm_u8 m3[32];
    struct mcxn947_attestation_blob blob1;
    struct mcxn947_attestation_blob blob2;
    mm_u32 value;
    mm_u32 reg;

    memset(flash, 0xA5, sizeof(flash));
    test_init_map(&map, regions, 64u);
    mm_mcxn947_flash_bind(&map, flash, sizeof(flash), 0, 0u);
    mmio_set_active_sec(MM_SECURE);
    if (!mmio_bus_read(&map.mmio, SYSCON_BASE + SYSCON_AHBCLKCTRL0, 4u, &reg)) return 1;
    reg |= (1u << 25);
    if (!mmio_bus_write(&map.mmio, SYSCON_BASE + SYSCON_AHBCLKCTRL0, 4u, reg)) return 1;
    if (!mmio_bus_read(&map.mmio, SYSCON_BASE + SYSCON_PRESETCTRL0, 4u, &reg)) return 1;
    reg |= (1u << 25);
    if (!mmio_bus_write(&map.mmio, SYSCON_BASE + SYSCON_PRESETCTRL0, 4u, reg)) return 1;

    if (!mmio_bus_write(&map.mmio, ELS_BASE + SEC_REG_ARG0, 4u, 1u)) {
        printf("els arg write failed\n");
        return 1;
    }
    if (!mmio_bus_write(&map.mmio, ELS_BASE + SEC_REG_CMD, 4u, ELS_CMD_GENERATE)) {
        printf("els cmd write failed\n");
        return 1;
    }
    if (!mmio_bus_read(&map.mmio, ELS_BASE + SEC_REG_STATUS, 4u, &value)) {
        printf("els status read failed\n");
        return 1;
    }
    if ((value & SEC_STATUS_DONE) == 0u) {
        printf("els command did not complete: 0x%08lx\n", (unsigned long)value);
        return 1;
    }

    if (!mm_mcxn947_secure_measurement(m1)) {
        printf("measurement read 1 failed\n");
        return 1;
    }
    if (!mm_mcxn947_secure_attest(&blob1)) {
        printf("attest 1 failed\n");
        return 1;
    }
    mm_mcxn947_secure_reset();
    mm_mcxn947_flash_bind(&map, flash, sizeof(flash), 0, 0u);
    if (!mm_mcxn947_secure_measurement(m2)) {
        printf("measurement read 2 failed\n");
        return 1;
    }
    if (!mm_mcxn947_secure_attest(&blob2)) {
        printf("attest 2 failed\n");
        return 1;
    }
    if (memcmp(m1, m2, sizeof(m1)) != 0) {
        printf("measurement changed across reset\n");
        return 1;
    }
    if (memcmp(blob1.signature, blob2.signature, sizeof(blob1.signature)) != 0) {
        printf("signature changed across reset\n");
        return 1;
    }

    flash[0] ^= 0x5Au;
    if (!mm_mcxn947_secure_measurement(m3)) return 1;
    if (memcmp(m1, m3, sizeof(m1)) == 0) {
        printf("measurement did not change after flash edit\n");
        return 1;
    }
    return 0;
}

static int test_lifecycle_changes_attestation(void)
{
    mm_u8 before[32];
    mm_u8 after[32];

    unsetenv("M33MU_MCXN947_LIFECYCLE");
    mm_mcxn947_secure_reset();
    if (!mm_mcxn947_secure_measurement(before)) return 1;

    setenv("M33MU_MCXN947_LIFECYCLE", "se", 1);
    mm_mcxn947_secure_reset();
    if (!mm_mcxn947_secure_measurement(after)) return 1;
    unsetenv("M33MU_MCXN947_LIFECYCLE");
    mm_mcxn947_secure_reset();

    return memcmp(before, after, sizeof(before)) == 0 ? 1 : 0;
}

static int test_romapi_secure_only_and_els_clock_gate(void)
{
    struct mm_memmap map;
    struct mmio_region regions[64];
    struct mm_cpu cpu;
    mm_u32 reg;

    memset(&cpu, 0, sizeof(cpu));
    test_init_map(&map, regions, 64u);
    mmio_set_active_sec(MM_SECURE);

    cpu.sec_state = MM_NONSECURE;
    cpu.r[15] = ROMAPI_STUB_EFUSE_READ | 1u;
    cpu.r[14] = 0x20000001u;
    cpu.r[0] = 43u;
    cpu.r[1] = 0u;
    if (!mm_mcxn947_romapi_handle(&cpu, &map)) return 1;
    if (cpu.r[0] == 0u) return 1;

    if (!mmio_bus_read(&map.mmio, SYSCON_BASE + SYSCON_AHBCLKCTRL0, 4u, &reg)) return 1;
    reg &= ~(1u << 25);
    if (!mmio_bus_write(&map.mmio, SYSCON_BASE + SYSCON_AHBCLKCTRL0, 4u, reg)) return 1;

    memset(&cpu, 0, sizeof(cpu));
    cpu.sec_state = MM_SECURE;
    cpu.r[15] = ROMAPI_STUB_IAP_API_INIT | 1u;
    cpu.r[14] = 0x20000001u;
    if (!mm_mcxn947_romapi_handle(&cpu, &map)) return 1;
    if (cpu.r[0] == 0u) return 1;

    reg |= (1u << 25);
    if (!mmio_bus_write(&map.mmio, SYSCON_BASE + SYSCON_AHBCLKCTRL0, 4u, reg)) return 1;
    if (!mmio_bus_read(&map.mmio, SYSCON_BASE + SYSCON_PRESETCTRL0, 4u, &reg)) return 1;
    reg |= (1u << 25);
    if (!mmio_bus_write(&map.mmio, SYSCON_BASE + SYSCON_PRESETCTRL0, 4u, reg)) return 1;

    memset(&cpu, 0, sizeof(cpu));
    cpu.sec_state = MM_SECURE;
    cpu.r[15] = ROMAPI_STUB_IAP_API_INIT | 1u;
    cpu.r[14] = 0x20000001u;
    if (!mm_mcxn947_romapi_handle(&cpu, &map)) return 1;
    return cpu.r[0] == 0u ? 0 : 1;
}

int main(void)
{
    struct {
        const char *name;
        int (*fn)(void);
    } tests[] = {
        { "secure_mmio_and_puf", test_secure_mmio_and_puf },
        { "els_attestation_stability", test_els_command_and_attestation_stability },
        { "lifecycle_changes_attestation", test_lifecycle_changes_attestation },
        { "romapi_secure_only_and_els_gate", test_romapi_secure_only_and_els_clock_gate }
    };
    int failures;
    int i;

    failures = 0;
    for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); ++i) {
        if (tests[i].fn() != 0) {
            ++failures;
            printf("FAIL: %s\n", tests[i].name);
        } else {
            printf("PASS: %s\n", tests[i].name);
        }
    }
    return failures == 0 ? 0 : 1;
}
